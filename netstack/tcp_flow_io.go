package main

import "time"

func (f *tcpFlow) upstreamWriter() {
	for {
		select {
		case <-f.done:
			return
		case item := <-f.upstream:
			f.mu.Lock()
			conn := f.conn
			closed := f.closed
			f.mu.Unlock()
			if closed || conn == nil {
				if item.pooled {
					f.manager.putTCPBuffer(item.payload)
				}
				return
			}
			if len(item.payload) > 0 {
				_ = conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
				_, err := conn.Write(item.payload)
				if item.pooled {
					f.manager.putTCPBuffer(item.payload)
				}
				if err != nil {
					f.close("upstream_write")
					return
				}
				f.touch()
			}
			if item.fin {
				_ = conn.CloseWrite()
			}
		case <-f.manager.ctx.Done():
			return
		}
	}
}

func (f *tcpFlow) remoteReader() {
	// Do not inject upstream payload before the client has acknowledged our SYN-ACK.
	// Some protocols send a server banner immediately after connect; gating here keeps
	// the local TCP state machine standards-conformant and bounded.
	select {
	case <-f.handshakeReady:
	case <-time.After(tcpHandshakeAckTimeout):
		f.close("handshake_ack_timeout")
		return
	case <-f.done:
		return
	case <-f.manager.ctx.Done():
		return
	}

	buf := f.manager.getTCPBuffer(maxTCPSegmentPayload)
	defer f.manager.putTCPBuffer(buf)
	for {
		f.mu.Lock()
		conn := f.conn
		closed := f.closed
		f.mu.Unlock()
		if closed || conn == nil {
			return
		}
		n, err := conn.Read(buf)
		if n > 0 {
			data := f.manager.getTCPBuffer(n)
			copy(data, buf[:n])
			if !f.sendRemoteData(data) {
				f.manager.putTCPBuffer(data)
				f.close("client_backpressure")
				return
			}
			f.stats.Rx.Add(uint64(n))
			f.touch()
		}
		if err != nil {
			f.sendServerFIN()
			return
		}
	}
}

func (f *tcpFlow) sendRemoteData(data []byte) bool {
	deadline := time.Now().Add(20 * time.Second)
	for {
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return false
		}
		window := int(f.clientWindow)
		if window > 0 && f.unackedBytes+len(data) <= minInt(window, maxTCPUnackedBytes) && f.manager.reserveUnacked(len(data)) {
			seq := f.serverNext
			f.serverNext += uint32(len(data))
			seg := outboundSegment{seq: seq, flags: tcpACK | tcpPSH, payload: data, sentAt: time.Now()}
			f.unacked = append(f.unacked, seg)
			f.unackedBytes += len(data)
			ack := f.clientNext
			f.mu.Unlock()
			f.manager.signalSweep()
			if !f.manager.writer.send(buildTCPPacket(f.version, f.key.Dst, f.key.Src, f.key.DstPort, f.key.SrcPort, seq, ack, seg.flags, 65535, data, 0, false)) {
				return false
			}
			return true
		}
		f.mu.Unlock()
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-f.ackNotify:
		case <-time.After(100 * time.Millisecond):
		case <-f.done:
			return false
		case <-f.manager.ctx.Done():
			return false
		}
	}
}

func (f *tcpFlow) sendServerFIN() {
	f.mu.Lock()
	if f.closed || f.serverFIN {
		f.mu.Unlock()
		return
	}
	seq := f.serverNext
	f.serverNext++
	f.serverFIN = true
	seg := outboundSegment{seq: seq, flags: tcpFIN | tcpACK, sentAt: time.Now()}
	f.unacked = append(f.unacked, seg)
	ack := f.clientNext
	f.mu.Unlock()
	f.manager.signalSweep()
	f.manager.writer.send(buildTCPPacket(f.version, f.key.Dst, f.key.Src, f.key.DstPort, f.key.SrcPort, seq, ack, seg.flags, 65535, nil, 0, false))
}

func (f *tcpFlow) sendSynAck() {
	f.mu.Lock()
	if f.closed || !f.established {
		f.mu.Unlock()
		return
	}
	seq, ack, mss := f.serverISN, f.clientNext, f.clientMSS
	f.mu.Unlock()
	f.manager.writer.send(buildTCPPacket(f.version, f.key.Dst, f.key.Src, f.key.DstPort, f.key.SrcPort, seq, ack, tcpSYN|tcpACK, 65535, nil, mss, f.windowScaleNegotiated))
}

func (f *tcpFlow) sendAck(seq, ack uint32) {
	f.manager.writer.send(buildTCPPacket(f.version, f.key.Dst, f.key.Src, f.key.DstPort, f.key.SrcPort, seq, ack, tcpACK, 65535, nil, 0, false))
}

func (f *tcpFlow) sendResetToClient() {
	f.mu.Lock()
	ack := f.clientNext
	f.mu.Unlock()
	f.manager.writer.send(buildTCPPacket(f.version, f.key.Dst, f.key.Src, f.key.DstPort, f.key.SrcPort, 0, ack, tcpRST|tcpACK, 0, nil, 0, false))
}

func (f *tcpFlow) retransmit(now time.Time) bool {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return false
	}
	var packets [][]byte
	for i := range f.unacked {
		s := &f.unacked[i]
		if now.Sub(s.sentAt) < retransmitAfter {
			continue
		}
		if s.retries >= 4 {
			f.mu.Unlock()
			return false
		}
		s.retries++
		s.sentAt = now
		packets = append(packets, buildTCPPacket(f.version, f.key.Dst, f.key.Src, f.key.DstPort, f.key.SrcPort, s.seq, f.clientNext, s.flags, 65535, s.payload, 0, false))
	}
	f.mu.Unlock()
	for _, p := range packets {
		if !f.manager.writer.send(p) {
			return false
		}
	}
	return true
}
