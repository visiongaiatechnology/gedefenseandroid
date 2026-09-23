package main

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type engine struct {
	ctx         context.Context
	cancel      context.CancelFunc
	tun         *os.File
	teleFile    *os.File
	policy      *threatPolicy
	privacy     *privacyPolicy
	packageGate *packageEgressGate
	telemetry   *telemetry
	writer      *tunWriter
	tcp         *tcpManager
	udp         *udpManager
	fragments   *fragmentReassembler
	flowLimit   *flowLimiter
	tunMTU      int
	egressMode  egressMode
	wireGuard   *wireGuardTransport
	closed      sync.Once
	active      atomic.Bool
}

func newEngine(tunFD, telemetryFD int, policy *threatPolicy, privacy *privacyPolicy, packageGate *packageEgressGate, mode egressMode, wireGuardMTU int, wireGuardConfig []byte, wireGuardProtector wireGuardSocketProtector) (*engine, error) {
	if tunFD < 0 || telemetryFD < 0 || policy == nil {
		return nil, errors.New("invalid engine inputs")
	}
	if mode > egressWireGuardStrict {
		return nil, errors.New("invalid egress mode")
	}
	if mode != egressDirect && (wireGuardMTU < minWireGuardMTU || wireGuardMTU > maxWireGuardMTU) {
		return nil, errors.New("invalid wireguard mtu")
	}
	tun := os.NewFile(uintptr(tunFD), "gedefense-tun")
	tele := os.NewFile(uintptr(telemetryFD), "gedefense-telemetry")
	if tun == nil || tele == nil {
		if tun != nil {
			_ = tun.Close()
		}
		if tele != nil {
			_ = tele.Close()
		}
		return nil, errors.New("invalid file descriptor")
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &engine{ctx: ctx, cancel: cancel, tun: tun, teleFile: tele, policy: policy, privacy: privacy, packageGate: packageGate, tunMTU: wireGuardMTU, egressMode: mode}
	e.telemetry = newTelemetry(tele)
	e.writer = newTunWriter(tun)
	if mode == egressDirect {
		e.flowLimit = &flowLimiter{}
		e.tcp = newTCPManager(ctx, policy, privacy, packageGate, e.writer, e.telemetry, e.flowLimit)
		e.udp = newUDPManager(ctx, policy, privacy, packageGate, e.writer, e.telemetry, e.flowLimit)
		e.fragments = newFragmentReassembler()
	} else {
		wg, err := newWireGuardTransport(wireGuardConfig, wireGuardMTU, e.writer, e.telemetry, wireGuardProtector)
		clear(wireGuardConfig)
		if err != nil {
			if e.packageGate != nil {
				e.packageGate.close()
			}
			e.writer.close()
			e.telemetry.close()
			_ = tun.Close()
			_ = tele.Close()
			cancel()
			return nil, err
		}
		e.wireGuard = wg
	}
	return e, nil
}

func (e *engine) run() {
	if !e.active.CompareAndSwap(false, true) {
		return
	}
	defer e.close()
	buf := make([]byte, maxPacketBytes)
	for {
		if e.packageGate != nil && e.packageGate.isEnabled() && e.packageGate.failedState() {
			e.telemetry.unsupported("package_egress_gate_failure")
			return
		}
		if e.telemetry.criticalLost.Load() {
			e.telemetry.unsupported("critical_telemetry_overflow")
			return
		}
		select {
		case <-e.ctx.Done():
			return
		default:
		}
		n, err := e.tun.Read(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && e.ctx.Err() == nil {
				e.telemetry.unsupported("tun_read_failure")
			}
			return
		}
		if n <= 0 || n > len(buf) {
			continue
		}
		raw := buf[:n]
		packet, err := parsePacket(raw)
		if e.egressMode != egressDirect {
			if errors.Is(err, errFragmented) && packet.Dst.IsValid() {
				if e.packageGate != nil && e.packageGate.isEnabled() {
					e.telemetry.quarantineBlocked(packet)
					continue
				}
				match := e.policy.match(packet.Dst)
				if match.Action == actionBlock {
					e.telemetry.blocked(packet, match, packet.TotalLen)
					continue
				}
				packetLen := packet.TotalLen
				if packetLen <= 0 || packetLen > len(raw) {
					continue
				}
				if !e.wireGuard.send(raw[:packetLen], packet, match) {
					e.telemetry.unsupported("wireguard_egress_backpressure")
					return
				}
				continue
			}
			if err != nil {
				continue
			}
			if e.packageGate != nil && !e.packageGate.allow(packet) {
				e.telemetry.quarantineBlocked(packet)
				continue
			}
			if action := e.privacy.encryptedDNSAction(packet); action != privacyAllow {
				e.telemetry.encryptedDNS(packet, action)
				if action == privacyBlock {
					continue
				}
			}
			if e.handlePrivacyDNS(packet, e.tunMTU) {
				continue
			}
			match := e.policy.match(packet.Dst)
			if match.Action == actionBlock {
				e.telemetry.blocked(packet, match, packet.TotalLen)
				continue
			}
			if !e.wireGuard.send(raw[:packet.TotalLen], packet, match) {
				e.telemetry.unsupported("wireguard_egress_backpressure")
				return
			}
			continue
		}
		if errors.Is(err, errFragmented) {
			if packet.Fragment == nil {
				e.telemetry.unsupported("fragmented_packet_unsupported")
				continue
			}
			reassembled, complete, fragErr := e.fragments.offer(*packet.Fragment, time.Now())
			if fragErr != nil {
				e.telemetry.unsupported("fragment_reassembly_rejected")
				continue
			}
			if !complete {
				continue
			}
			packet, err = parsePacket(reassembled)
		}
		if err != nil {
			continue
		}
		switch packet.Protocol {
		case protoTCP:
			e.tcp.handle(packet)
		case protoUDP:
			e.udp.handle(packet)
		default:
			// The beta transports TCP/UDP. Local kernel-control and unsupported L4 protocols are
			// intentionally ignored instead of being misclassified as policy failures.
			continue
		}
	}
}

func (e *engine) handlePrivacyDNS(packet parsedPacket, mtu int) bool {
	if e.privacy == nil || packet.Protocol != protoUDP || !packet.HasPorts || packet.DstPort != 53 || len(packet.UDP.Payload) == 0 {
		return false
	}
	name := parseDNSQueryName(packet.UDP.Payload)
	if name == "" {
		return false
	}
	decision := e.privacy.decide(name)
	if decision.Action == privacyAllow {
		return false
	}
	e.telemetry.privacy(packet, name, decision)
	if decision.Action != privacyBlock {
		return false
	}
	response := buildDNSBlockedResponse(packet.UDP.Payload)
	if len(response) == 0 {
		return true
	}
	packets := buildUDPPackets(packet.Version, packet.Dst, packet.Src, packet.DstPort, packet.SrcPort, response, mtu)
	for _, raw := range packets {
		if !e.writer.send(raw) {
			return true
		}
	}
	return true
}

func (e *engine) powerStateChanged() {
	e.telemetry.powerStateChanged()
	if e.tcp != nil {
		e.tcp.powerStateChanged()
	}
}

func (e *engine) setPackageGateEnabled(enabled bool) {
	if e == nil || e.packageGate == nil {
		return
	}
	e.packageGate.setEnabled(enabled)
	// Direct-mode sockets created before a quarantine policy change have already passed the
	// Android owner check. Close them so the next packet/flow must be attributed again.
	if e.tcp != nil {
		e.tcp.closeAll("package_gate_policy_change")
	}
	if e.udp != nil {
		e.udp.closeAll("package_gate_policy_change")
	}
}

func (e *engine) close() {
	e.closed.Do(func() {
		e.cancel()
		if e.tcp != nil {
			e.tcp.closeAll("engine_stop")
		}
		if e.udp != nil {
			e.udp.closeAll("engine_stop")
		}
		if e.wireGuard != nil {
			e.wireGuard.close()
		}
		if e.packageGate != nil {
			e.packageGate.close()
		}
		e.writer.close()
		e.telemetry.close()
		// Let the telemetry writer flush its bounded queue before the fd disappears.
		time.Sleep(20 * time.Millisecond)
		_ = e.tun.Close()
		_ = e.teleFile.Close()
		e.active.Store(false)
	})
}
