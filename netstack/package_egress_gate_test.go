package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestPackageEgressGateDisabledDoesNotQuery(t *testing.T) {
	left, right := socketPairForPackageGate(t)
	defer left.Close()
	defer right.Close()
	gate, err := newPackageEgressGate(int(left.Fd()), false)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	p := testPackageGatePacket()
	if !gate.allow(p) {
		t.Fatal("disabled package gate denied traffic")
	}
}

func TestPackageEgressGateAllowsAndCachesVerdict(t *testing.T) {
	left, right := socketPairForPackageGate(t)
	defer left.Close()
	defer right.Close()
	gate, err := newPackageEgressGate(int(left.Fd()), true)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()

	queries := make(chan uint32, 2)
	go serveOnePackageGateVerdict(t, right, packageGateVerdictAllow, queries)
	p := testPackageGatePacket()
	if !gate.allow(p) {
		t.Fatal("allow verdict was rejected")
	}
	if !gate.allow(p) {
		t.Fatal("cached allow verdict was rejected")
	}
	select {
	case <-queries:
	case <-time.After(time.Second):
		t.Fatal("package gate query missing")
	}
	select {
	case <-queries:
		t.Fatal("cached flow unexpectedly queried Android twice")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestPackageEgressGateDenyAndProtocolFailureFailClosed(t *testing.T) {
	left, right := socketPairForPackageGate(t)
	defer left.Close()
	defer right.Close()
	gate, err := newPackageEgressGate(int(left.Fd()), true)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()

	queries := make(chan uint32, 1)
	go serveOnePackageGateVerdict(t, right, packageGateVerdictDeny, queries)
	if gate.allow(testPackageGatePacket()) {
		t.Fatal("deny verdict allowed traffic")
	}

	gate.setEnabled(true)
	go func() {
		var req [packageGateRequestSize]byte
		if _, err := io.ReadFull(right, req[:]); err != nil {
			return
		}
		var bad [packageGateResponseSize]byte
		copy(bad[:4], []byte("BAD!"))
		binary.BigEndian.PutUint32(bad[4:8], binary.BigEndian.Uint32(req[4:8]))
		bad[8] = packageGateVerdictAllow
		_, _ = right.Write(bad[:])
	}()
	p := testPackageGatePacket()
	p.DstPort++
	if gate.allow(p) {
		t.Fatal("invalid response failed open")
	}
	p.DstPort++
	if gate.allow(p) {
		t.Fatal("failed gate did not remain fail-closed")
	}
}

func TestPackageEgressGateRejectsUnattributablePacketWhenEnabled(t *testing.T) {
	left, right := socketPairForPackageGate(t)
	defer left.Close()
	defer right.Close()
	gate, err := newPackageEgressGate(int(left.Fd()), true)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	p := testPackageGatePacket()
	p.HasPorts = false
	if gate.allow(p) {
		t.Fatal("unattributable packet was allowed while package gate enabled")
	}
}

func socketPairForPackageGate(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	leftConn, rightConn := net.Pipe()
	// net.Pipe cannot be converted through FileConn. Use a Unix socketpair instead.
	_ = leftConn.Close()
	_ = rightConn.Close()
	fds, err := socketPairFiles()
	if err != nil {
		t.Fatal(err)
	}
	return fds[0], fds[1]
}

func socketPairFiles() ([2]*os.File, error) {
	var out [2]*os.File
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return out, err
	}
	out[0] = os.NewFile(uintptr(fds[0]), "package-gate-left")
	out[1] = os.NewFile(uintptr(fds[1]), "package-gate-right")
	return out, nil
}

func serveOnePackageGateVerdict(t *testing.T, file *os.File, verdict byte, queries chan<- uint32) {
	t.Helper()
	conn, err := net.FileConn(file)
	if err != nil {
		return
	}
	defer conn.Close()
	var request [packageGateRequestSize]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return
	}
	if string(request[:4]) != string(packageGateRequestMagic[:]) {
		return
	}
	id := binary.BigEndian.Uint32(request[4:8])
	queries <- id
	var response [packageGateResponseSize]byte
	copy(response[:4], packageGateResponseMagic[:])
	binary.BigEndian.PutUint32(response[4:8], id)
	response[8] = verdict
	_, _ = conn.Write(response[:])
}

func testPackageGatePacket() parsedPacket {
	return parsedPacket{
		Protocol: protoTCP,
		Version:  4,
		Src:      netip.MustParseAddr("10.0.0.2"),
		Dst:      netip.MustParseAddr("1.1.1.1"),
		SrcPort:  41000,
		DstPort:  443,
		HasPorts: true,
	}
}
