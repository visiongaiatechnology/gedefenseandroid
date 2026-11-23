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

func TestWithDNSNegativeCacheSOA(t *testing.T) {
	q := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	base := buildDNSBlockedResponse(q)
	cached := withDNSNegativeCacheSOA(base, 120)
	if len(cached) <= len(base) {
		t.Fatalf("expected SOA record appended, got len=%d", len(cached))
	}
	if binary.BigEndian.Uint16(cached[8:10]) != 1 {
		t.Fatalf("expected NSCOUNT=1, got %d", binary.BigEndian.Uint16(cached[8:10]))
	}
	rrStart := len(base)
	if binary.BigEndian.Uint16(cached[rrStart:rrStart+2]) != 0xc00c {
		t.Fatalf("expected pointer to question at 0xc00c")
	}
	if binary.BigEndian.Uint16(cached[rrStart+2:rrStart+4]) != 6 {
		t.Fatalf("expected TYPE=SOA (6)")
	}
	if binary.BigEndian.Uint32(cached[rrStart+6:rrStart+10]) != 120 {
		t.Fatalf("expected SOA TTL=120")
	}
	if binary.BigEndian.Uint32(cached[len(cached)-4:]) != 120 {
		t.Fatalf("expected SOA Minimum=120")
	}
	if got := withDNSNegativeCacheSOA(nil, 120); got != nil {
		t.Fatalf("expected nil pass-through")
	}
}
