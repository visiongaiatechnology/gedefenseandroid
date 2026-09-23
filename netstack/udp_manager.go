package main

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type udpFlow struct {
	manager   *udpManager
	key       flowKey
	stats     *flowTelemetry
	version   uint8
	conn      *net.UDPConn
	closed    atomic.Bool
	closeOnce sync.Once
}

type udpManager struct {
	ctx         context.Context
	policy      *threatPolicy
	privacy     *privacyPolicy
	packageGate *packageEgressGate
	writer      *tunWriter
	telemetry   *telemetry
	flowLimit   *flowLimiter
	mu          sync.Mutex
	flows       map[flowKey]*udpFlow
	readBuffers sync.Pool
}

func newUDPManager(ctx context.Context, p *threatPolicy, privacy *privacyPolicy, gate *packageEgressGate, w *tunWriter, t *telemetry, limit *flowLimiter) *udpManager {
	m := &udpManager{ctx: ctx, policy: p, privacy: privacy, packageGate: gate, writer: w, telemetry: t, flowLimit: limit, flows: make(map[flowKey]*udpFlow)}
	m.readBuffers.New = func() any { return make([]byte, 65527) }
	return m
}

func (m *udpManager) handle(p parsedPacket) {
	if !p.HasPorts {
		return
	}
	key := keyFromPacket(p)
	m.mu.Lock()
	existing := m.flows[key]
	m.mu.Unlock()
	if existing == nil && m.packageGate != nil && !m.packageGate.allow(p) {
		m.telemetry.quarantineBlocked(p)
		return
	}
	if existing == nil {
		if action := m.privacy.encryptedDNSAction(p); action != privacyAllow {
			m.telemetry.encryptedDNS(p, action)
			if action == privacyBlock {
				return
			}
		}
	}
	if m.handlePrivacyDNS(p) {
		return
	}
	match := m.policy.match(p.Dst)
	if match.Action == actionBlock {
		m.telemetry.blocked(p, match, p.TotalLen)
		return
	}
	m.mu.Lock()
	f := m.flows[key]
	if f == nil {
		if len(m.flows) >= maxUDPFlows || len(m.flows) >= maxConcurrentFlows {
			m.mu.Unlock()
			return
		}
		if !m.flowLimit.acquire() {
			m.mu.Unlock()
			return
		}
		network := "udp6"
		if p.Dst.Is4() {
			network = "udp4"
		}
		dialer := net.Dialer{Timeout: tcpDialTimeout, Control: controlSocketForUnderlyingNetwork}
		connAny, err := dialer.DialContext(m.ctx, network, net.JoinHostPort(p.Dst.String(), itoaPort(p.DstPort)))
		if err != nil {
			m.flowLimit.release()
			m.mu.Unlock()
			return
		}
		conn, ok := connAny.(*net.UDPConn)
		if !ok {
			_ = connAny.Close()
			m.flowLimit.release()
			m.mu.Unlock()
			return
		}
		stats := &flowTelemetry{ID: nextNativeFlowID(), Protocol: protoUDP, Version: p.Version, Src: p.Src, Dst: p.Dst, SrcPort: p.SrcPort, DstPort: p.DstPort, Action: match.Action, Bits: match.Bits}
		f = &udpFlow{manager: m, key: key, stats: stats, version: p.Version, conn: conn}
		m.flows[key] = f
		m.telemetry.register(stats)
		go f.readRemote()
	}
	m.mu.Unlock()
	if len(p.UDP.Payload) == 0 {
		return
	}
	if p.DstPort == 53 {
		if name := parseDNSQueryName(p.UDP.Payload); name != "" {
			m.telemetry.dnsQuery(f.stats.ID, name)
		}
	}
	_ = f.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if n, err := f.conn.Write(p.UDP.Payload); err == nil {
		f.stats.Tx.Add(uint64(n))
		// Refresh the in-flight read deadline on outbound activity. This makes the socket itself the
		// idle timer and removes the need for a periodic manager sweeper.
		_ = f.conn.SetReadDeadline(time.Now().Add(currentUDPIdleTimeout()))
	} else {
		f.close("udp_write")
	}
}

func (m *udpManager) handlePrivacyDNS(p parsedPacket) bool {
	if m.privacy == nil || p.DstPort != 53 || len(p.UDP.Payload) == 0 {
		return false
	}
	name := parseDNSQueryName(p.UDP.Payload)
	if name == "" {
		return false
	}
	decision := m.privacy.decide(name)
	if decision.Action == privacyAllow {
		return false
	}
	m.telemetry.privacy(p, name, decision)
	if decision.Action != privacyBlock {
		return false
	}
	response := buildDNSBlockedResponse(p.UDP.Payload)
	if len(response) == 0 {
		return true
	}
	packets := buildUDPPackets(p.Version, p.Dst, p.Src, p.DstPort, p.SrcPort, response, fullFlowMTU)
	for _, packet := range packets {
		if !m.writer.send(packet) {
			break
		}
	}
	return true
}

func (f *udpFlow) readRemote() {
	buf := f.manager.readBuffers.Get().([]byte)
	defer f.manager.readBuffers.Put(buf)
	for !f.closed.Load() {
		_ = f.conn.SetReadDeadline(time.Now().Add(currentUDPIdleTimeout()))
		n, err := f.conn.Read(buf)
		if n > 0 {
			payload := append([]byte(nil), buf[:n]...)
			packets := buildUDPPackets(f.version, f.key.Dst, f.key.Src, f.key.DstPort, f.key.SrcPort, payload, fullFlowMTU)
			if len(packets) == 0 {
				f.close("udp_response_too_large")
				return
			}
			for _, packet := range packets {
				if !f.manager.writer.send(packet) {
					f.close("tun_backpressure")
					return
				}
			}
			f.stats.Rx.Add(uint64(n))
		}
		if err != nil {
			f.close("udp_idle")
			return
		}
	}
}

func (f *udpFlow) close(reason string) {
	f.closeOnce.Do(func() {
		f.closed.Store(true)
		_ = f.conn.Close()
		f.manager.mu.Lock()
		delete(f.manager.flows, f.key)
		f.manager.mu.Unlock()
		f.manager.flowLimit.release()
		f.manager.telemetry.closeFlow(f.stats, reason)
	})
}

func (m *udpManager) closeAll(reason string) {
	m.mu.Lock()
	list := make([]*udpFlow, 0, len(m.flows))
	for _, f := range m.flows {
		list = append(list, f)
	}
	m.mu.Unlock()
	for _, f := range list {
		f.close(reason)
	}
}
