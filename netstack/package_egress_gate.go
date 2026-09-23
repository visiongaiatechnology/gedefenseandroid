package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	packageGateRequestSize  = 48
	packageGateResponseSize = 12
	packageGateQueryTimeout = 400 * time.Millisecond
	packageGateCacheTTL     = 30 * time.Second
	packageGateMaxCache     = 4096
	packageGateVerdictAllow = byte(1)
	packageGateVerdictDeny  = byte(2)
)

var (
	packageGateRequestMagic  = [4]byte{'G', 'D', 'Q', '1'}
	packageGateResponseMagic = [4]byte{'G', 'D', 'A', 'Q'}
)

type packageGateCacheEntry struct {
	allow   bool
	expires time.Time
}

// packageEgressGate is a session-scoped, fail-closed oracle used only while Android reports at
// least one quarantined package. The helper never attempts to infer Android UIDs itself; Android's
// ConnectivityManager remains the authority for mapping a five-tuple to a UID/package. The binary
// protocol is fixed-size and bounded. Any protocol, timeout or ownership-resolution failure denies
// the queried new flow while the gate is enabled.
type packageEgressGate struct {
	conn    net.Conn
	mu      sync.Mutex
	enabled atomic.Bool
	failed  atomic.Bool
	nextID  atomic.Uint32
	cache   map[flowKey]packageGateCacheEntry
}

func newPackageEgressGate(fd int, enabled bool) (*packageEgressGate, error) {
	if fd < 0 {
		return nil, errors.New("package egress gate fd invalid")
	}
	file := os.NewFile(uintptr(fd), "gedefense-package-egress-gate")
	if file == nil {
		return nil, errors.New("package egress gate file invalid")
	}
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}
	g := &packageEgressGate{conn: conn, cache: make(map[flowKey]packageGateCacheEntry)}
	g.enabled.Store(enabled)
	return g, nil
}

func (g *packageEgressGate) setEnabled(enabled bool) {
	if g == nil {
		return
	}
	g.enabled.Store(enabled)
	g.mu.Lock()
	clear(g.cache)
	g.mu.Unlock()
}

func (g *packageEgressGate) isEnabled() bool {
	return g != nil && g.enabled.Load()
}

func (g *packageEgressGate) failedState() bool {
	return g != nil && g.failed.Load()
}

func (g *packageEgressGate) allow(p parsedPacket) bool {
	if g == nil || !g.enabled.Load() {
		return true
	}
	if g.failed.Load() || !p.HasPorts || (p.Protocol != protoTCP && p.Protocol != protoUDP) || !p.Src.IsValid() || !p.Dst.IsValid() {
		return false
	}
	key := keyFromPacket(p)
	now := time.Now()

	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.enabled.Load() {
		return true
	}
	if entry, ok := g.cache[key]; ok {
		if now.Before(entry.expires) {
			return entry.allow
		}
		delete(g.cache, key)
	}
	if len(g.cache) >= packageGateMaxCache {
		clear(g.cache)
	}
	allow, err := g.queryLocked(p, now)
	if err != nil {
		g.failed.Store(true)
		clear(g.cache)
		return false
	}
	g.cache[key] = packageGateCacheEntry{allow: allow, expires: now.Add(packageGateCacheTTL)}
	return allow
}

func (g *packageEgressGate) queryLocked(p parsedPacket, now time.Time) (bool, error) {
	if g.conn == nil {
		return false, errors.New("package egress gate unavailable")
	}
	requestID := g.nextID.Add(1)
	if requestID == 0 {
		requestID = g.nextID.Add(1)
	}
	var request [packageGateRequestSize]byte
	copy(request[:4], packageGateRequestMagic[:])
	binary.BigEndian.PutUint32(request[4:8], requestID)
	request[8] = p.Protocol
	request[9] = p.Version
	// bytes 10..11 are reserved and remain zero.
	src := p.Src.As16()
	dst := p.Dst.As16()
	copy(request[12:28], src[:])
	copy(request[28:44], dst[:])
	binary.BigEndian.PutUint16(request[44:46], p.SrcPort)
	binary.BigEndian.PutUint16(request[46:48], p.DstPort)

	deadline := now.Add(packageGateQueryTimeout)
	if err := g.conn.SetDeadline(deadline); err != nil {
		return false, err
	}
	if err := writeFull(g.conn, request[:]); err != nil {
		return false, err
	}
	var response [packageGateResponseSize]byte
	if _, err := io.ReadFull(g.conn, response[:]); err != nil {
		return false, err
	}
	if response[0] != packageGateResponseMagic[0] || response[1] != packageGateResponseMagic[1] ||
		response[2] != packageGateResponseMagic[2] || response[3] != packageGateResponseMagic[3] {
		return false, errors.New("package egress gate response magic invalid")
	}
	if binary.BigEndian.Uint32(response[4:8]) != requestID || response[9] != 0 || response[10] != 0 || response[11] != 0 {
		return false, errors.New("package egress gate response invalid")
	}
	switch response[8] {
	case packageGateVerdictAllow:
		return true, nil
	case packageGateVerdictDeny:
		return false, nil
	default:
		return false, errors.New("package egress gate verdict invalid")
	}
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}

func (g *packageEgressGate) close() {
	if g == nil {
		return
	}
	g.enabled.Store(false)
	g.failed.Store(true)
	g.mu.Lock()
	clear(g.cache)
	if g.conn != nil {
		_ = g.conn.Close()
		g.conn = nil
	}
	g.mu.Unlock()
}
