package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestBuildParseTCPIPv4(t *testing.T) {
	src := netip.MustParseAddr("203.0.113.10")
	dst := netip.MustParseAddr("198.51.100.20")
	p := buildTCPPacket(4, src, dst, 443, 51000, 100, 200, tcpACK|tcpPSH, 4096, []byte("hello"), 0, false)
	parsed, err := parsePacket(p)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Src != src || parsed.Dst != dst || parsed.SrcPort != 443 || parsed.DstPort != 51000 {
		t.Fatalf("unexpected tuple: %+v", parsed)
	}
	if string(parsed.TCP.Payload) != "hello" || parsed.TCP.Seq != 100 || parsed.TCP.Ack != 200 {
		t.Fatalf("unexpected tcp: %+v", parsed.TCP)
	}
	if got := checksum(p[:20], 0); got != 0 {
		t.Fatalf("ipv4 checksum invalid: %x", got)
	}
}

func TestBuildParseUDPIPv6(t *testing.T) {
	src := netip.MustParseAddr("2001:4860:4860::8888")
	dst := netip.MustParseAddr("2001:db8::1")
	p := buildUDPPacket(6, src, dst, 53, 53000, []byte{1, 2, 3, 4})
	parsed, err := parsePacket(p)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SrcPort != 53 || parsed.DstPort != 53000 || len(parsed.UDP.Payload) != 4 {
		t.Fatalf("unexpected udp: %+v", parsed)
	}
}

func TestFragmentRejected(t *testing.T) {
	p := make([]byte, 28)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], 28)
	binary.BigEndian.PutUint16(p[6:8], 0x2000)
	p[9] = protoUDP
	copy(p[12:16], []byte{1, 1, 1, 1})
	copy(p[16:20], []byte{8, 8, 8, 8})
	if _, err := parsePacket(p); err != errFragmented {
		t.Fatalf("expected fragment rejection, got %v", err)
	}
}

func TestTCPWindowScaleNegotiation(t *testing.T) {
	src := netip.MustParseAddr("203.0.113.10")
	dst := netip.MustParseAddr("198.51.100.20")
	p := buildTCPPacket(4, src, dst, 443, 51000, 100, 200, tcpSYN|tcpACK, 65535, nil, 1180, true)
	parsed, err := parsePacket(p)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.TCP.WindowScalePresent || parsed.TCP.WindowScale != 0 {
		t.Fatalf("expected RFC7323 window-scale option with shift zero: %+v", parsed.TCP)
	}
	if parsed.TCP.MSS != 1180 {
		t.Fatalf("unexpected MSS: %d", parsed.TCP.MSS)
	}
	if got := (p[20+12] >> 4) * 4; got != 28 {
		t.Fatalf("unexpected TCP header length: %d", got)
	}
}

func TestTCPWindowScaleClamp(t *testing.T) {
	if got := effectiveTCPWindow(65535, 14, true); got != maxTCPUnackedBytes {
		t.Fatalf("scaled peer window must be bounded by per-flow memory cap: %d", got)
	}
	if got := effectiveTCPWindow(32000, 7, false); got != 32000 {
		t.Fatalf("unnegotiated window must remain unscaled: %d", got)
	}
}
