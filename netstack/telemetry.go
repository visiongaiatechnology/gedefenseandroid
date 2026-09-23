package main

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type flowTelemetry struct {
	ID       uint64
	Protocol uint8
	Version  uint8
	Src      netip.Addr
	Dst      netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Action   threatAction
	Bits     uint64
	Tx       atomic.Uint64
	Rx       atomic.Uint64
}

type telemetryFrame struct {
	line     string
	critical bool
}

type telemetry struct {
	writer       *bufio.Writer
	queue        chan telemetryFrame
	wake         chan struct{}
	stop         chan struct{}
	closed       sync.Once
	mu           sync.Mutex
	flows        map[uint64]*flowTelemetry
	dropped      atomic.Uint64
	criticalLost atomic.Bool
}

func newTelemetry(w io.Writer) *telemetry {
	t := &telemetry{
		writer: bufio.NewWriterSize(w, 32*1024),
		queue:  make(chan telemetryFrame, maxTelemetryQueue),
		wake:   make(chan struct{}, 1),
		stop:   make(chan struct{}),
		flows:  make(map[uint64]*flowTelemetry),
	}
	go t.writeLoop()
	go t.snapshotLoop()
	return t
}

func (t *telemetry) register(f *flowTelemetry) {
	t.mu.Lock()
	if len(t.flows) < maxConcurrentFlows {
		t.flows[f.ID] = f
	}
	t.mu.Unlock()
	t.emitCritical(fmt.Sprintf("O\t%d\t%d\t%d\t%s\t%d\t%s\t%d\t%d\t%d\n", f.ID, f.Protocol, f.Version, f.Src, f.SrcPort, f.Dst, f.DstPort, f.Action, f.Bits))
	t.signalActivity()
}

func (t *telemetry) blocked(p parsedPacket, m policyMatch, bytes int) {
	t.emitCritical(fmt.Sprintf("B\t%d\t%d\t%s\t%d\t%s\t%d\t%d\t%d\t%d\n", p.Protocol, p.Version, p.Src, p.SrcPort, p.Dst, p.DstPort, m.Action, m.Bits, bytes))
}

func (t *telemetry) quarantineBlocked(p parsedPacket) {
	if !p.HasPorts || (p.Protocol != protoTCP && p.Protocol != protoUDP) {
		return
	}
	t.emitCritical(fmt.Sprintf("Q\t%d\t%d\t%s\t%d\t%s\t%d\t%d\n", p.Protocol, p.Version, p.Src, p.SrcPort, p.Dst, p.DstPort, p.TotalLen))
}

func (t *telemetry) dnsQuery(flowID uint64, name string) {
	if flowID == 0 || len(name) == 0 || len(name) > 253 {
		return
	}
	t.emit(fmt.Sprintf("D\t%d\t%s\n", flowID, name))
}

func (t *telemetry) privacy(p parsedPacket, domain string, decision privacyDecision) {
	if len(domain) == 0 || len(domain) > 253 || len(decision.RuleID) < 3 || len(decision.RuleID) > 96 {
		return
	}
	if decision.Action != privacyObserve && decision.Action != privacyBlock {
		return
	}
	line := fmt.Sprintf(
		"P\t%d\t%d\t%s\t%d\t%s\t%d\t%s\t%s\n",
		decision.Action, p.Protocol, p.Src, p.SrcPort, p.Dst, p.DstPort, domain, decision.RuleID,
	)
	if decision.Action == privacyBlock {
		t.emitCritical(line)
	} else {
		t.emit(line)
	}
}

func (t *telemetry) encryptedDNS(p parsedPacket, action privacyAction) {
	if !p.HasPorts || p.DstPort != 853 || (p.Protocol != protoTCP && p.Protocol != protoUDP) ||
		(action != privacyObserve && action != privacyBlock) {
		return
	}
	transport := "dot"
	if p.Protocol == protoUDP {
		transport = "doq"
	}
	line := fmt.Sprintf("Y\t%d\t%d\t%s\t%d\t%s\t%d\t%s\n", action, p.Protocol, p.Src, p.SrcPort, p.Dst, p.DstPort, transport)
	if action == privacyBlock {
		t.emitCritical(line)
	} else {
		t.emit(line)
	}
}

func (t *telemetry) unsupported(reason string) {
	if len(reason) > 64 {
		reason = reason[:64]
	}
	t.emitCritical("E\t" + reason + "\n")
}

func (t *telemetry) closeFlow(f *flowTelemetry, reason string) {
	t.mu.Lock()
	delete(t.flows, f.ID)
	t.mu.Unlock()
	if len(reason) > 48 {
		reason = reason[:48]
	}
	t.emitCritical(fmt.Sprintf("C\t%d\t%d\t%d\t%s\n", f.ID, f.Tx.Load(), f.Rx.Load(), reason))
}

func (t *telemetry) emit(line string) {
	select {
	case t.queue <- telemetryFrame{line: line}:
	default:
		t.dropped.Add(1)
	}
}

func (t *telemetry) emitCritical(line string) {
	select {
	case t.queue <- telemetryFrame{line: line, critical: true}:
	default:
		t.dropped.Add(1)
		t.criticalLost.Store(true)
	}
}

func (t *telemetry) signalActivity() {
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

func (t *telemetry) powerStateChanged() { t.signalActivity() }

func (t *telemetry) activeFlowCount() int {
	t.mu.Lock()
	count := len(t.flows)
	t.mu.Unlock()
	return count
}

func (t *telemetry) flowSnapshot() []*flowTelemetry {
	t.mu.Lock()
	out := make([]*flowTelemetry, 0, len(t.flows))
	for _, f := range t.flows {
		out = append(out, f)
	}
	t.mu.Unlock()
	return out
}

func resetTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}

func (t *telemetry) snapshotLoop() {
	timer := time.NewTimer(currentTelemetryInterval(0))
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			flows := t.flowSnapshot()
			for _, f := range flows {
				t.emit(fmt.Sprintf("U\t%d\t%d\t%d\n", f.ID, f.Tx.Load(), f.Rx.Load()))
			}
			timer.Reset(currentTelemetryInterval(len(flows)))
		case <-t.wake:
			resetTimer(timer, currentTelemetryInterval(t.activeFlowCount()))
		case <-t.stop:
			return
		}
	}
}

func (t *telemetry) writeLoop() {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	var flushC <-chan time.Time

	flush := func() {
		if t.writer.Buffered() > 0 {
			_ = t.writer.Flush()
		}
		flushC = nil
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	scheduleFlush := func() {
		if flushC != nil {
			return
		}
		resetTimer(timer, 250*time.Millisecond)
		flushC = timer.C
	}
	writeFrame := func(frame telemetryFrame) {
		_, _ = t.writer.WriteString(frame.line)
		if frame.critical || t.writer.Buffered() >= 8*1024 {
			flush()
		} else {
			scheduleFlush()
		}
	}

	for {
		select {
		case frame := <-t.queue:
			writeFrame(frame)
		case <-flushC:
			flush()
		case <-t.stop:
			for {
				select {
				case frame := <-t.queue:
					writeFrame(frame)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (t *telemetry) close() {
	t.closed.Do(func() { close(t.stop) })
}
