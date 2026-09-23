package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"
)

type trackedPacketFlow struct {
	stats        *flowTelemetry
	lastActivity time.Time
}

type icmpEchoKey struct {
	Version uint8
	Src     netip.Addr
	Dst     netip.Addr
	ID      uint16
	Seq     uint16
}

type packetFlowTracker struct {
	telemetry         *telemetry
	mu                sync.Mutex
	flows             map[flowKey]*trackedPacketFlow
	icmpEcho          map[icmpEchoKey]time.Time
	outboundFragments map[fragmentKey]time.Time
	inboundFragments  map[fragmentKey]time.Time
	done              chan struct{}
	wg                sync.WaitGroup
	closeOnce         sync.Once
}

func newPacketFlowTracker(t *telemetry) *packetFlowTracker {
	tracker := &packetFlowTracker{
		telemetry:         t,
		flows:             make(map[flowKey]*trackedPacketFlow),
		icmpEcho:          make(map[icmpEchoKey]time.Time),
		outboundFragments: make(map[fragmentKey]time.Time),
		inboundFragments:  make(map[fragmentKey]time.Time),
		done:              make(chan struct{}),
	}
	tracker.wg.Add(1)
	go tracker.sweepLoop()
	return tracker
}

func (t *packetFlowTracker) handleOutbound(p parsedPacket, match policyMatch, raw []byte) bool {
	if p.Fragment != nil {
		return t.handleOutboundFragment(p, match, raw)
	}
	if p.Protocol == protoICMPv4 || p.Protocol == protoICMPv6 {
		key, ok := outboundICMPEchoKey(p, raw)
		if !ok {
			return true
		}
		now := time.Now()
		t.mu.Lock()
		if _, exists := t.icmpEcho[key]; !exists && len(t.flows)+len(t.icmpEcho) >= maxConcurrentFlows {
			t.mu.Unlock()
			return false
		}
		t.icmpEcho[key] = now
		t.mu.Unlock()
		return true
	}
	if !p.HasPorts || (p.Protocol != protoTCP && p.Protocol != protoUDP) {
		return false
	}
	now := time.Now()
	key := keyFromPacket(p)
	t.mu.Lock()
	tracked := t.flows[key]
	if tracked == nil {
		if len(t.flows)+len(t.icmpEcho) >= maxConcurrentFlows {
			t.mu.Unlock()
			return false
		}
		if p.Protocol == protoTCP && (p.TCP.Flags&tcpSYN == 0 || p.TCP.Flags&tcpACK != 0) {
			t.mu.Unlock()
			return false
		}
		stats := &flowTelemetry{
			ID: nextNativeFlowID(), Protocol: p.Protocol, Version: p.Version,
			Src: p.Src, Dst: p.Dst, SrcPort: p.SrcPort, DstPort: p.DstPort,
			Action: match.Action, Bits: match.Bits,
		}
		tracked = &trackedPacketFlow{stats: stats, lastActivity: now}
		t.flows[key] = tracked
		t.telemetry.register(stats)
	} else {
		tracked.lastActivity = now
	}
	if p.Protocol == protoTCP {
		tracked.stats.Tx.Add(uint64(len(p.TCP.Payload)))
	} else {
		tracked.stats.Tx.Add(uint64(len(p.UDP.Payload)))
	}
	stats := tracked.stats
	closeNow := p.Protocol == protoTCP && p.TCP.Flags&tcpRST != 0
	t.mu.Unlock()

	if p.Protocol == protoUDP && p.DstPort == 53 {
		if name := parseDNSQueryName(p.UDP.Payload); name != "" {
			t.telemetry.dnsQuery(stats.ID, name)
		}
	}
	if closeNow {
		t.closeKey(key, "tcp_rst")
	}
	return true
}

func (t *packetFlowTracker) handleInbound(raw []byte) bool {
	p, err := parsePacket(raw)
	if err != nil {
		if errors.Is(err, errFragmented) && p.Fragment != nil {
			return t.handleInboundFragment(p, raw)
		}
		return false
	}
	return t.handleInboundParsed(p, raw)
}

func (t *packetFlowTracker) handleInboundParsed(p parsedPacket, raw []byte) bool {
	if p.Protocol == protoICMPv4 || p.Protocol == protoICMPv6 {
		return t.handleInboundICMP(p, raw)
	}
	if !p.HasPorts || (p.Protocol != protoTCP && p.Protocol != protoUDP) {
		return false
	}
	reverse := flowKey{Protocol: p.Protocol, Src: p.Dst, Dst: p.Src, SrcPort: p.DstPort, DstPort: p.SrcPort}
	now := time.Now()
	t.mu.Lock()
	tracked := t.flows[reverse]
	if tracked == nil {
		t.mu.Unlock()
		return false
	}
	tracked.lastActivity = now
	if p.Protocol == protoTCP {
		tracked.stats.Rx.Add(uint64(len(p.TCP.Payload)))
	} else {
		tracked.stats.Rx.Add(uint64(len(p.UDP.Payload)))
	}
	closeNow := p.Protocol == protoTCP && p.TCP.Flags&tcpRST != 0
	t.mu.Unlock()
	if closeNow {
		t.closeKey(reverse, "tcp_rst")
	}
	return true
}

func (t *packetFlowTracker) handleOutboundFragment(p parsedPacket, match policyMatch, raw []byte) bool {
	f := p.Fragment
	if f == nil {
		return false
	}
	key := fragmentKey{Version: f.Version, Protocol: f.Protocol, Src: f.Src, Dst: f.Dst, ID: f.ID}
	now := time.Now()
	if f.Offset != 0 {
		return t.refreshFragmentState(t.outboundFragments, key, now)
	}
	first, ok := parseFirstFragmentTransport(p)
	if !ok || !t.handleOutbound(first, match, raw) {
		return false
	}
	if !f.More {
		return true
	}
	return t.rememberFragmentState(t.outboundFragments, key, now)
}

func (t *packetFlowTracker) handleInboundFragment(p parsedPacket, raw []byte) bool {
	f := p.Fragment
	if f == nil {
		return false
	}
	key := fragmentKey{Version: f.Version, Protocol: f.Protocol, Src: f.Src, Dst: f.Dst, ID: f.ID}
	now := time.Now()
	if f.Offset != 0 {
		return t.refreshFragmentState(t.inboundFragments, key, now)
	}
	first, ok := parseFirstFragmentTransport(p)
	if !ok || !t.handleInboundParsed(first, raw) {
		return false
	}
	if !f.More {
		return true
	}
	return t.rememberFragmentState(t.inboundFragments, key, now)
}

func parseFirstFragmentTransport(p parsedPacket) (parsedPacket, bool) {
	f := p.Fragment
	if f == nil || f.Offset != 0 {
		return parsedPacket{}, false
	}
	data := f.Data
	p.Fragment = nil
	p.Fragmented = false
	switch p.Protocol {
	case protoTCP:
		if len(data) < 20 {
			return parsedPacket{}, false
		}
		hlen := int(data[12]>>4) * 4
		if hlen < 20 || hlen > len(data) {
			return parsedPacket{}, false
		}
		p.SrcPort = binary.BigEndian.Uint16(data[0:2])
		p.DstPort = binary.BigEndian.Uint16(data[2:4])
		p.HasPorts = true
		p.TCP = tcpSegment{
			Seq: binary.BigEndian.Uint32(data[4:8]), Ack: binary.BigEndian.Uint32(data[8:12]),
			Flags: data[13], Window: binary.BigEndian.Uint16(data[14:16]), Payload: data[hlen:],
		}
	case protoUDP:
		if len(data) < 8 || binary.BigEndian.Uint16(data[4:6]) < 8 {
			return parsedPacket{}, false
		}
		p.SrcPort = binary.BigEndian.Uint16(data[0:2])
		p.DstPort = binary.BigEndian.Uint16(data[2:4])
		p.HasPorts = true
		p.UDP = udpDatagram{Payload: data[8:]}
	case protoICMPv4, protoICMPv6:
		if len(data) < 8 {
			return parsedPacket{}, false
		}
	default:
		return parsedPacket{}, false
	}
	return p, true
}

func (t *packetFlowTracker) rememberFragmentState(states map[fragmentKey]time.Time, key fragmentKey, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := states[key]; !exists && len(states) >= maxFragmentDatagrams {
		return false
	}
	states[key] = now
	return true
}

func (t *packetFlowTracker) refreshFragmentState(states map[fragmentKey]time.Time, key fragmentKey, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := states[key]; !ok {
		return false
	}
	states[key] = now
	return true
}

func (t *packetFlowTracker) handleInboundICMP(p parsedPacket, raw []byte) bool {
	if p.L4Offset < 0 || p.L4Offset+8 > p.TotalLen || p.TotalLen > len(raw) {
		return false
	}
	icmp := raw[p.L4Offset:p.TotalLen]
	typeCode := icmp[0]
	if (p.Version == 4 && p.Protocol == protoICMPv4 && typeCode == 0) ||
		(p.Version == 6 && p.Protocol == protoICMPv6 && typeCode == 129) {
		key := icmpEchoKey{
			Version: p.Version,
			Src:     p.Dst,
			Dst:     p.Src,
			ID:      binary.BigEndian.Uint16(icmp[4:6]),
			Seq:     binary.BigEndian.Uint16(icmp[6:8]),
		}
		t.mu.Lock()
		_, ok := t.icmpEcho[key]
		if ok {
			delete(t.icmpEcho, key)
		}
		t.mu.Unlock()
		return ok
	}
	if !isRelatedICMPError(p.Protocol, typeCode) {
		return false
	}
	quoted := icmp[8:]
	if key, ok := parseQuotedFlowKey(quoted); ok {
		t.mu.Lock()
		tracked := t.flows[key]
		if tracked != nil {
			tracked.lastActivity = time.Now()
		}
		t.mu.Unlock()
		return tracked != nil
	}
	if key, ok := parseQuotedICMPEchoKey(quoted); ok {
		t.mu.Lock()
		_, tracked := t.icmpEcho[key]
		t.mu.Unlock()
		return tracked
	}
	return false
}

func outboundICMPEchoKey(p parsedPacket, raw []byte) (icmpEchoKey, bool) {
	if p.L4Offset < 0 || p.L4Offset+8 > p.TotalLen || p.TotalLen > len(raw) {
		return icmpEchoKey{}, false
	}
	icmp := raw[p.L4Offset:p.TotalLen]
	switch {
	case p.Version == 4 && p.Protocol == protoICMPv4:
		if icmp[0] != 8 {
			return icmpEchoKey{}, false
		}
	case p.Version == 6 && p.Protocol == protoICMPv6:
		if icmp[0] != 128 {
			return icmpEchoKey{}, false
		}
	default:
		return icmpEchoKey{}, false
	}
	return icmpEchoKey{
		Version: p.Version,
		Src:     p.Src,
		Dst:     p.Dst,
		ID:      binary.BigEndian.Uint16(icmp[4:6]),
		Seq:     binary.BigEndian.Uint16(icmp[6:8]),
	}, true
}

func isRelatedICMPError(protocol, typeCode uint8) bool {
	switch protocol {
	case protoICMPv4:
		return typeCode == 3 || typeCode == 11 || typeCode == 12
	case protoICMPv6:
		return typeCode >= 1 && typeCode <= 4
	default:
		return false
	}
}

func parseQuotedFlowKey(raw []byte) (flowKey, bool) {
	_, protocol, src, dst, l4Offset, ok := parseQuotedIPHeader(raw)
	if !ok || (protocol != protoTCP && protocol != protoUDP) || l4Offset+4 > len(raw) {
		return flowKey{}, false
	}
	return flowKey{
		Protocol: protocol,
		Src:      src,
		Dst:      dst,
		SrcPort:  binary.BigEndian.Uint16(raw[l4Offset : l4Offset+2]),
		DstPort:  binary.BigEndian.Uint16(raw[l4Offset+2 : l4Offset+4]),
	}, true
}

func parseQuotedICMPEchoKey(raw []byte) (icmpEchoKey, bool) {
	version, protocol, src, dst, l4Offset, ok := parseQuotedIPHeader(raw)
	if !ok || l4Offset+8 > len(raw) {
		return icmpEchoKey{}, false
	}
	icmp := raw[l4Offset:]
	switch {
	case version == 4 && protocol == protoICMPv4:
		if icmp[0] != 8 {
			return icmpEchoKey{}, false
		}
	case version == 6 && protocol == protoICMPv6:
		if icmp[0] != 128 {
			return icmpEchoKey{}, false
		}
	default:
		return icmpEchoKey{}, false
	}
	return icmpEchoKey{
		Version: version,
		Src:     src,
		Dst:     dst,
		ID:      binary.BigEndian.Uint16(icmp[4:6]),
		Seq:     binary.BigEndian.Uint16(icmp[6:8]),
	}, true
}

func parseQuotedIPHeader(raw []byte) (version, protocol uint8, src, dst netip.Addr, l4Offset int, ok bool) {
	if len(raw) < 1 {
		return 0, 0, netip.Addr{}, netip.Addr{}, 0, false
	}
	switch raw[0] >> 4 {
	case 4:
		if len(raw) < 20 {
			return 0, 0, netip.Addr{}, netip.Addr{}, 0, false
		}
		ihl := int(raw[0]&0x0f) * 4
		if ihl < 20 || ihl > len(raw) {
			return 0, 0, netip.Addr{}, netip.Addr{}, 0, false
		}
		frag := binary.BigEndian.Uint16(raw[6:8])
		if frag&0x1fff != 0 {
			return 0, 0, netip.Addr{}, netip.Addr{}, 0, false
		}
		return 4, raw[9],
			netip.AddrFrom4([4]byte{raw[12], raw[13], raw[14], raw[15]}),
			netip.AddrFrom4([4]byte{raw[16], raw[17], raw[18], raw[19]}),
			ihl, true
	case 6:
		if len(raw) < 40 {
			return 0, 0, netip.Addr{}, netip.Addr{}, 0, false
		}
		next := raw[6]
		off := 40
		for hops := 0; isIPv6Extension(next); hops++ {
			if hops >= 8 || off+2 > len(raw) {
				return 0, 0, netip.Addr{}, netip.Addr{}, 0, false
			}
			old := next
			next = raw[off]
			var size int
			switch old {
			case 44:
				if off+8 > len(raw) {
					return 0, 0, netip.Addr{}, netip.Addr{}, 0, false
				}
				fragField := binary.BigEndian.Uint16(raw[off+2 : off+4])
				if (fragField>>3)&0x1fff != 0 {
					return 0, 0, netip.Addr{}, netip.Addr{}, 0, false
				}
				size = 8
			case 51:
				size = (int(raw[off+1]) + 2) * 4
			default:
				size = (int(raw[off+1]) + 1) * 8
			}
			if size <= 0 || off+size > len(raw) {
				return 0, 0, netip.Addr{}, netip.Addr{}, 0, false
			}
			off += size
		}
		return 6, next, addr16(raw[8:24]), addr16(raw[24:40]), off, true
	default:
		return 0, 0, netip.Addr{}, netip.Addr{}, 0, false
	}
}

func (t *packetFlowTracker) sweepLoop() {
	defer t.wg.Done()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			now := time.Now()
			var expired []flowKey
			t.mu.Lock()
			for key, flow := range t.flows {
				idle := currentTCPIdleTimeout(false)
				if key.Protocol == protoUDP {
					idle = currentUDPIdleTimeout()
				}
				if now.Sub(flow.lastActivity) >= idle {
					expired = append(expired, key)
				}
			}
			for key, lastActivity := range t.icmpEcho {
				if now.Sub(lastActivity) >= icmpEchoIdleTimeout {
					delete(t.icmpEcho, key)
				}
			}
			for key, lastActivity := range t.outboundFragments {
				if now.Sub(lastActivity) >= fragmentReassemblyTimeout {
					delete(t.outboundFragments, key)
				}
			}
			for key, lastActivity := range t.inboundFragments {
				if now.Sub(lastActivity) >= fragmentReassemblyTimeout {
					delete(t.inboundFragments, key)
				}
			}
			t.mu.Unlock()
			for _, key := range expired {
				t.closeKey(key, "idle")
			}
			timer.Reset(15 * time.Second)
		case <-t.done:
			return
		}
	}
}

func (t *packetFlowTracker) closeKey(key flowKey, reason string) {
	t.mu.Lock()
	tracked := t.flows[key]
	if tracked != nil {
		delete(t.flows, key)
	}
	t.mu.Unlock()
	if tracked != nil {
		t.telemetry.closeFlow(tracked.stats, reason)
	}
}

func (t *packetFlowTracker) close() {
	t.closeOnce.Do(func() {
		close(t.done)
		t.wg.Wait()
		t.mu.Lock()
		snapshot := make([]*trackedPacketFlow, 0, len(t.flows))
		for _, flow := range t.flows {
			snapshot = append(snapshot, flow)
		}
		t.flows = make(map[flowKey]*trackedPacketFlow)
		t.icmpEcho = make(map[icmpEchoKey]time.Time)
		t.outboundFragments = make(map[fragmentKey]time.Time)
		t.inboundFragments = make(map[fragmentKey]time.Time)
		t.mu.Unlock()
		for _, flow := range snapshot {
			t.telemetry.closeFlow(flow.stats, "engine_stop")
		}
	})
}
