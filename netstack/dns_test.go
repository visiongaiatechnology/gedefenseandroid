package main

import (
	"encoding/binary"
	"testing"
)

func TestParseDNSQueryName(t *testing.T) {
	q := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0, 1, 0, 1,
	}
	if got := parseDNSQueryName(q); got != "www.example.com" {
		t.Fatalf("unexpected dns name %q", got)
	}
	q[2] = 0x81
	if got := parseDNSQueryName(q); got != "" {
		t.Fatalf("response must not be observed as query: %q", got)
	}
}

func TestParseDNSQueryRejectsCompression(t *testing.T) {
	q := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1}
	if got := parseDNSQueryName(q); got != "" {
		t.Fatalf("compressed question unexpectedly accepted: %q", got)
	}
}

func TestBuildDNSBlockedResponse(t *testing.T) {
	q := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	r := buildDNSBlockedResponse(q)
	if len(r) != len(q) {
		t.Fatalf("unexpected blocked response length %d", len(r))
	}
	if r[0] != 0x12 || r[1] != 0x34 {
		t.Fatal("transaction id changed")
	}
	flags := binary.BigEndian.Uint16(r[2:4])
	if flags&0x8000 == 0 || flags&0x000f != 3 {
		t.Fatalf("expected NXDOMAIN response flags, got %#x", flags)
	}
	if binary.BigEndian.Uint16(r[4:6]) != 1 || binary.BigEndian.Uint16(r[6:8]) != 0 || binary.BigEndian.Uint16(r[10:12]) != 0 {
		t.Fatal("blocked response counts invalid")
	}
}
