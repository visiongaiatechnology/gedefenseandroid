package main

import (
	"io"
	"sync"
)

type tunWriter struct {
	w      io.WriteCloser
	queue  chan []byte
	stop   chan struct{}
	closed sync.Once
}

func newTunWriter(w io.WriteCloser) *tunWriter {
	t := &tunWriter{w: w, queue: make(chan []byte, maxTunWriteQueue), stop: make(chan struct{})}
	go t.loop()
	return t
}

func (t *tunWriter) send(packet []byte) bool {
	if len(packet) == 0 || len(packet) > maxPacketBytes {
		return false
	}
	select {
	case <-t.stop:
		return false
	default:
	}
	select {
	case t.queue <- packet:
		return true
	case <-t.stop:
		return false
	default:
		return false
	}
}

func (t *tunWriter) loop() {
	for {
		select {
		case p := <-t.queue:
			n, err := t.w.Write(p)
			if err != nil || n != len(p) {
				// Closing the shared TUN descriptor interrupts the engine's blocking read,
				// making a write-side failure fail closed instead of silently blackholing data.
				t.close()
				return
			}
		case <-t.stop:
			return
		}
	}
}

func (t *tunWriter) close() {
	t.closed.Do(func() {
		close(t.stop)
		_ = t.w.Close()
	})
}
