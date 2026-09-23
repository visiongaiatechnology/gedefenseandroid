package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type outboundSegment struct {
	seq     uint32
	flags   uint8
	payload []byte
	sentAt  time.Time
	retries uint8
}

func (s outboundSegment) wireLen() uint32 {
	n := uint32(len(s.payload))
	if s.flags&tcpFIN != 0 {
		n++
	}
	if s.flags&tcpSYN != 0 {
		n++
	}
	return n
}

type upstreamWrite struct {
	payload []byte
	fin     bool
	pooled  bool
}

type tcpFlow struct {
	manager *tcpManager
	key     flowKey
	stats   *flowTelemetry
	version uint8

	mu                    sync.Mutex
	conn                  *net.TCPConn
	clientNext            uint32
	serverISN             uint32
	serverNext            uint32
	clientWindow          uint32
	clientWindowScale     uint8
	windowScaleNegotiated bool
	clientMSS             uint16
	established           bool
	clientFIN             bool
	serverFIN             bool
	serverFINAck          bool
	closed                bool
	unacked               []outboundSegment
	unackedBytes          int
	upstream              chan upstreamWrite
	ackNotify             chan struct{}
	done                  chan struct{}
	handshakeReady        chan struct{}
	handshakeAcked        bool
	closeOnce             sync.Once
	lastActivity          atomic.Int64
}

type tcpManager struct {
	ctx           context.Context
	policy        *threatPolicy
	privacy       *privacyPolicy
	packageGate   *packageEgressGate
	writer        *tunWriter
	telemetry     *telemetry
	flowLimit     *flowLimiter
	mu            sync.Mutex
	flows         map[flowKey]*tcpFlow
	halfOpen      atomic.Int32
	unackedBudget atomic.Int64
	dialQueue     chan *tcpFlow
	sweepWake     chan struct{}
	tcpBuffers    sync.Pool
}

func newTCPManager(ctx context.Context, p *threatPolicy, privacy *privacyPolicy, gate *packageEgressGate, w *tunWriter, t *telemetry, limit *flowLimiter) *tcpManager {
	m := &tcpManager{
		ctx: ctx, policy: p, privacy: privacy, packageGate: gate, writer: w, telemetry: t, flowLimit: limit,
		flows: make(map[flowKey]*tcpFlow), dialQueue: make(chan *tcpFlow, maxHalfOpenTCP),
		sweepWake: make(chan struct{}, 1),
	}
	m.tcpBuffers.New = func() any { return make([]byte, maxTCPSegmentPayload) }
	for i := 0; i < maxTCPDialWorkers; i++ {
		go m.dialWorker()
	}
	go m.sweepLoop()
	return m
}

func (m *tcpManager) dialWorker() {
	for {
		select {
		case f := <-m.dialQueue:
			if f != nil {
				f.dial()
			}
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *tcpManager) handle(p parsedPacket) {
	if !p.HasPorts {
		return
	}
	key := keyFromPacket(p)
	m.mu.Lock()
	f := m.flows[key]
	m.mu.Unlock()
	if f == nil {
		if p.TCP.Flags&tcpSYN == 0 || p.TCP.Flags&tcpACK != 0 {
			return
		}
		if m.packageGate != nil && !m.packageGate.allow(p) {
			m.telemetry.quarantineBlocked(p)
			m.writer.send(buildTCPPacket(p.Version, p.Dst, p.Src, p.DstPort, p.SrcPort, 0, p.TCP.Seq+1, tcpRST|tcpACK, 0, nil, 0, false))
			return
		}
		if action := m.privacy.encryptedDNSAction(p); action != privacyAllow {
			m.telemetry.encryptedDNS(p, action)
			if action == privacyBlock {
				m.writer.send(buildTCPPacket(p.Version, p.Dst, p.Src, p.DstPort, p.SrcPort, 0, p.TCP.Seq+1, tcpRST|tcpACK, 0, nil, 0, false))
				return
			}
		}
		match := m.policy.match(p.Dst)
		if match.Action == actionBlock {
			m.telemetry.blocked(p, match, p.TotalLen)
			m.writer.send(buildTCPPacket(p.Version, p.Dst, p.Src, p.DstPort, p.SrcPort, 0, p.TCP.Seq+1, tcpRST|tcpACK, 0, nil, 0, false))
			return
		}
		if m.halfOpen.Load() >= maxHalfOpenTCP {
			return
		}
		if !m.flowLimit.acquire() {
			return
		}
		m.mu.Lock()
		if len(m.flows) >= maxConcurrentFlows {
			m.mu.Unlock()
			m.flowLimit.release()
			return
		}
		if existing := m.flows[key]; existing != nil {
			m.mu.Unlock()
			m.flowLimit.release()
			existing.handleClient(p)
			return
		}
		var err error
		f, err = m.newFlow(p, match)
		if err != nil {
			m.mu.Unlock()
			m.flowLimit.release()
			// TCP ISNs are security-sensitive. Entropy failure is fail-closed; never fall back
			// to predictable time-derived sequence numbers.
			m.writer.send(buildTCPPacket(p.Version, p.Dst, p.Src, p.DstPort, p.SrcPort, 0, p.TCP.Seq+1, tcpRST|tcpACK, 0, nil, 0, false))
			return
		}
		m.flows[key] = f
		m.halfOpen.Add(1)
		m.mu.Unlock()
		m.signalSweep()
		select {
		case m.dialQueue <- f:
		default:
			f.sendResetToClient()
			f.close("dial_queue_full")
		}
		return
	}
	f.handleClient(p)
}

func (m *tcpManager) newFlow(p parsedPacket, match policyMatch) (*tcpFlow, error) {
	isn, err := randomUint32()
	if err != nil {
		return nil, err
	}
	mss := p.TCP.MSS
	if mss == 0 || mss > defaultMSS {
		mss = defaultMSS
	}
	stats := &flowTelemetry{
		ID: nextNativeFlowID(), Protocol: protoTCP, Version: p.Version,
		Src: p.Src, Dst: p.Dst, SrcPort: p.SrcPort, DstPort: p.DstPort,
		Action: match.Action, Bits: match.Bits,
	}
	f := &tcpFlow{
		manager: m, key: keyFromPacket(p), stats: stats, version: p.Version,
		clientNext: p.TCP.Seq + 1, serverISN: isn, serverNext: isn + 1,
		clientWindow:      effectiveTCPWindow(p.TCP.Window, p.TCP.WindowScale, p.TCP.WindowScalePresent),
		clientWindowScale: p.TCP.WindowScale, windowScaleNegotiated: p.TCP.WindowScalePresent, clientMSS: mss,
		upstream: make(chan upstreamWrite, maxTCPUpstreamQueue), ackNotify: make(chan struct{}, 1),
		done: make(chan struct{}), handshakeReady: make(chan struct{}),
	}
	f.touch()
	m.telemetry.register(stats)
	return f, nil
}

func (f *tcpFlow) dial() {
	network := "tcp6"
	if f.key.Dst.Is4() {
		network = "tcp4"
	}
	d := net.Dialer{Timeout: tcpDialTimeout, KeepAlive: 30 * time.Second, Control: controlSocketForUnderlyingNetwork}
	conn, err := d.DialContext(f.manager.ctx, network, net.JoinHostPort(f.key.Dst.String(), itoaPort(f.key.DstPort)))
	if err != nil {
		f.sendResetToClient()
		f.close("dial_failed")
		return
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		f.close("non_tcp_socket")
		return
	}
	_ = tcp.SetNoDelay(true)
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		_ = tcp.Close()
		return
	}
	f.conn = tcp
	f.established = true
	f.mu.Unlock()
	f.manager.halfOpen.Add(-1)
	f.sendSynAck()
	go f.upstreamWriter()
	go f.remoteReader()
}

func (f *tcpFlow) handleClient(p parsedPacket) {
	f.touch()
	seg := p.TCP
	if seg.Flags&tcpRST != 0 {
		f.close("client_rst")
		return
	}

	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.clientWindow = effectiveTCPWindow(seg.Window, f.clientWindowScale, f.windowScaleNegotiated)
	if seg.Flags&tcpACK != 0 {
		f.applyAckLocked(seg.Ack)
		if !f.handshakeAcked && seg.Ack == f.serverISN+1 {
			f.handshakeAcked = true
			close(f.handshakeReady)
		}
	}
	if seg.Flags&tcpSYN != 0 && f.established {
		f.mu.Unlock()
		f.sendSynAck()
		return
	}
	if !f.established {
		f.mu.Unlock()
		return
	}

	if len(seg.Payload) > 0 {
		if seg.Seq != f.clientNext {
			ack := f.clientNext
			seq := f.serverNext
			f.mu.Unlock()
			f.sendAck(seq, ack)
			return
		}
		copyPayload := f.manager.getTCPBuffer(len(seg.Payload))
		copy(copyPayload, seg.Payload)
		select {
		case f.upstream <- upstreamWrite{payload: copyPayload, pooled: true}:
			f.clientNext += uint32(len(copyPayload))
			f.stats.Tx.Add(uint64(len(copyPayload)))
		default:
			f.manager.putTCPBuffer(copyPayload)
			// Backpressure: do not advance ACK. The local kernel will retransmit.
			ack := f.clientNext
			seq := f.serverNext
			f.mu.Unlock()
			f.sendAck(seq, ack)
			return
		}
	}
	if seg.Flags&tcpFIN != 0 && !f.clientFIN {
		finSeq := seg.Seq + uint32(len(seg.Payload))
		if finSeq == f.clientNext {
			// Never acknowledge a FIN until ownership has transferred to the bounded
			// upstream queue. Otherwise queue pressure could make the client believe
			// half-close succeeded while the remote socket remains writable forever.
			select {
			case f.upstream <- upstreamWrite{fin: true}:
				f.clientNext++
				f.clientFIN = true
			default:
				ack := f.clientNext
				seq := f.serverNext
				f.mu.Unlock()
				f.sendAck(seq, ack)
				return
			}
		}
	}
	ack := f.clientNext
	seq := f.serverNext
	shouldClose := f.clientFIN && f.serverFIN && f.serverFINAck
	f.mu.Unlock()
	f.sendAck(seq, ack)
	if shouldClose {
		f.close("graceful")
	}
}

func (f *tcpFlow) applyAckLocked(ack uint32) {
	if seqLess(ack, f.serverISN+1) || seqLess(f.serverNext, ack) {
		return
	}
	kept := f.unacked[:0]
	bytes := 0
	released := 0
	for _, s := range f.unacked {
		end := s.seq + s.wireLen()
		if seqLE(end, ack) {
			if s.flags&tcpFIN != 0 {
				f.serverFINAck = true
			}
			if len(s.payload) > 0 {
				released += len(s.payload)
				f.manager.putTCPBuffer(s.payload)
			}
			continue
		}
		kept = append(kept, s)
		bytes += len(s.payload)
	}
	f.unacked = kept
	f.unackedBytes = bytes
	if released > 0 {
		f.manager.releaseUnacked(released)
	}
	select {
	case f.ackNotify <- struct{}{}:
	default:
	}
}

func (f *tcpFlow) close(reason string) {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		wasHalfOpen := !f.established
		f.closed = true
		conn := f.conn
		releaseBytes := f.unackedBytes
		for i := range f.unacked {
			if len(f.unacked[i].payload) > 0 {
				f.manager.putTCPBuffer(f.unacked[i].payload)
			}
		}
		f.unacked = nil
		f.unackedBytes = 0
		f.mu.Unlock()
		if releaseBytes > 0 {
			f.manager.releaseUnacked(releaseBytes)
		}
		close(f.done)
		for {
			select {
			case item := <-f.upstream:
				if item.pooled {
					f.manager.putTCPBuffer(item.payload)
				}
			default:
				goto drained
			}
		}
	drained:
		if wasHalfOpen {
			f.manager.halfOpen.Add(-1)
		}
		if conn != nil {
			_ = conn.Close()
		}
		f.manager.mu.Lock()
		delete(f.manager.flows, f.key)
		f.manager.mu.Unlock()
		f.manager.flowLimit.release()
		f.manager.telemetry.closeFlow(f.stats, reason)
	})
}

func (f *tcpFlow) touch() { f.lastActivity.Store(time.Now().UnixNano()) }

func (m *tcpManager) signalSweep() {
	select {
	case m.sweepWake <- struct{}{}:
	default:
	}
}

func (m *tcpManager) powerStateChanged() { m.signalSweep() }

func (m *tcpManager) snapshotFlows() []*tcpFlow {
	m.mu.Lock()
	list := make([]*tcpFlow, 0, len(m.flows))
	for _, f := range m.flows {
		list = append(list, f)
	}
	m.mu.Unlock()
	return list
}

func tcpSweepUrgent(list []*tcpFlow) bool {
	for _, f := range list {
		f.mu.Lock()
		urgent := !f.established || len(f.unacked) > 0
		f.mu.Unlock()
		if urgent {
			return true
		}
	}
	return false
}

func (m *tcpManager) nextSweepInterval() time.Duration {
	list := m.snapshotFlows()
	return currentTCPHousekeepingInterval(tcpSweepUrgent(list), len(list) > 0)
}

func (m *tcpManager) sweepLoop() {
	timer := time.NewTimer(m.nextSweepInterval())
	defer timer.Stop()
	for {
		select {
		case now := <-timer.C:
			list := m.snapshotFlows()
			for _, f := range list {
				last := time.Unix(0, f.lastActivity.Load())
				f.mu.Lock()
				half := !f.established
				f.mu.Unlock()
				if now.Sub(last) > currentTCPIdleTimeout(half) {
					f.close("idle_timeout")
					continue
				}
				if !f.retransmit(now) {
					f.close("retransmit_exhausted")
				}
			}
			resetTimer(timer, m.nextSweepInterval())
		case <-m.sweepWake:
			resetTimer(timer, m.nextSweepInterval())
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *tcpManager) closeAll(reason string) {
	m.mu.Lock()
	list := make([]*tcpFlow, 0, len(m.flows))
	for _, f := range m.flows {
		list = append(list, f)
	}
	m.mu.Unlock()
	for _, f := range list {
		f.close(reason)
	}
}

func effectiveTCPWindow(raw uint16, scale uint8, negotiated bool) uint32 {
	if !negotiated {
		return uint32(raw)
	}
	if scale > 14 {
		scale = 14
	}
	window := uint64(raw) << scale
	if window > uint64(maxTCPUnackedBytes) {
		window = uint64(maxTCPUnackedBytes)
	}
	return uint32(window)
}

func (m *tcpManager) reserveUnacked(n int) bool {
	if n <= 0 || n > maxTCPUnackedBytes {
		return false
	}
	for {
		current := m.unackedBudget.Load()
		if current+int64(n) > maxTCPGlobalUnackedBytes {
			return false
		}
		if m.unackedBudget.CompareAndSwap(current, current+int64(n)) {
			return true
		}
	}
}

func (m *tcpManager) releaseUnacked(n int) {
	if n <= 0 {
		return
	}
	remaining := m.unackedBudget.Add(-int64(n))
	if remaining < 0 {
		m.unackedBudget.Store(0)
	}
}

func (m *tcpManager) getTCPBuffer(n int) []byte {
	if n <= 0 || n > maxTCPSegmentPayload {
		return make([]byte, n)
	}
	b := m.tcpBuffers.Get().([]byte)
	return b[:n]
}

func (m *tcpManager) putTCPBuffer(b []byte) {
	if cap(b) != maxTCPSegmentPayload {
		return
	}
	m.tcpBuffers.Put(b[:maxTCPSegmentPayload])
}

func randomUint32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint32(b[:])
	if v == 0 {
		return 0, errors.New("zero tcp isn rejected")
	}
	return v, nil
}
func seqLess(a, b uint32) bool { return int32(a-b) < 0 }
func seqLE(a, b uint32) bool   { return a == b || seqLess(a, b) }
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func itoaPort(p uint16) string { return strconv.Itoa(int(p)) }
