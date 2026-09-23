package main

import (
	"errors"
	"io"
	"os"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

const wireGuardTunBatchSize = 32

// wireGuardTun is an in-process Layer-3 boundary between GaiaNet policy enforcement
// and upstream wireguard-go. It never owns an Android VpnService or kernel TUN.
type wireGuardTun struct {
	mtu      int
	writer   *tunWriter
	tracker  *packetFlowTracker
	inbound  chan []byte
	events   chan wgtun.Event
	done     chan struct{}
	closeOne sync.Once
	pool     sync.Pool
}

func newWireGuardTun(mtu int, writer *tunWriter, tracker *packetFlowTracker) (*wireGuardTun, error) {
	if mtu < minWireGuardMTU || mtu > maxWireGuardMTU || writer == nil || tracker == nil {
		return nil, errors.New("invalid wireguard tun inputs")
	}
	t := &wireGuardTun{
		mtu:     mtu,
		writer:  writer,
		tracker: tracker,
		inbound: make(chan []byte, maxWireGuardPacketQueue),
		events:  make(chan wgtun.Event, 2),
		done:    make(chan struct{}),
	}
	t.pool.New = func() any { return make([]byte, mtu) }
	return t, nil
}

func (t *wireGuardTun) File() *os.File { return nil }

func (t *wireGuardTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) || offset < 0 {
		return 0, io.ErrShortBuffer
	}
	var first []byte
	select {
	case <-t.done:
		return 0, os.ErrClosed
	case first = <-t.inbound:
		if first == nil {
			return 0, os.ErrClosed
		}
	}

	count := 0
	copyOne := func(packet []byte) error {
		defer t.putPacket(packet)
		if count >= len(bufs) || offset > len(bufs[count]) || len(packet) > len(bufs[count])-offset {
			return io.ErrShortBuffer
		}
		copy(bufs[count][offset:], packet)
		sizes[count] = len(packet)
		count++
		return nil
	}
	if err := copyOne(first); err != nil {
		return 0, err
	}
	for count < len(bufs) && count < wireGuardTunBatchSize {
		select {
		case packet := <-t.inbound:
			if packet == nil {
				return count, nil
			}
			if err := copyOne(packet); err != nil {
				return count, err
			}
		default:
			return count, nil
		}
	}
	return count, nil
}

func (t *wireGuardTun) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 0 {
		return 0, io.ErrShortBuffer
	}
	written := 0
	for _, buf := range bufs {
		if offset > len(buf) {
			return written, io.ErrShortBuffer
		}
		packet := buf[offset:]
		if len(packet) == 0 || len(packet) > t.mtu {
			return written, errors.New("invalid wireguard packet size")
		}
		// Only responses belonging to a flow that GaiaNet observed outbound are
		// admitted back into Android. A peer cannot inject unsolicited TCP/UDP.
		if !t.tracker.handleInbound(packet) {
			written++
			continue
		}
		if !t.writer.send(append([]byte(nil), packet...)) {
			return written, io.ErrClosedPipe
		}
		written++
	}
	return written, nil
}

func (t *wireGuardTun) MTU() (int, error)          { return t.mtu, nil }
func (t *wireGuardTun) Name() (string, error)      { return "gedefense-wg", nil }
func (t *wireGuardTun) Events() <-chan wgtun.Event { return t.events }
func (t *wireGuardTun) BatchSize() int             { return wireGuardTunBatchSize }

func (t *wireGuardTun) Close() error {
	t.closeOne.Do(func() {
		close(t.done)
		close(t.events)
	})
	return nil
}

func (t *wireGuardTun) enqueue(packet []byte) bool {
	if len(packet) == 0 || len(packet) > t.mtu {
		return false
	}
	copyBuf := t.getPacket(len(packet))
	copy(copyBuf, packet)
	select {
	case <-t.done:
		t.putPacket(copyBuf)
		return false
	case t.inbound <- copyBuf:
		return true
	default:
		t.putPacket(copyBuf)
		return false
	}
}

func (t *wireGuardTun) getPacket(size int) []byte {
	if size <= t.mtu {
		buf := t.pool.Get().([]byte)
		return buf[:size]
	}
	return make([]byte, size)
}

func (t *wireGuardTun) putPacket(buf []byte) {
	if cap(buf) == t.mtu {
		clear(buf)
		t.pool.Put(buf[:t.mtu])
	}
}
