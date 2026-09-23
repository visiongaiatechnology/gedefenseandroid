package main

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestFragmentReassemblyIPv4UDP(t *testing.T) {
	src := netip.MustParseAddr("203.0.113.10")
	dst := netip.MustParseAddr("198.51.100.20")
	payload := make([]byte, 5000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	fragments := buildUDPPackets(4, src, dst, 443, 54000, payload, fullFlowMTU)
	if len(fragments) < 2 {
		t.Fatalf("expected fragments, got %d", len(fragments))
	}
	r := newFragmentReassembler()
	var final parsedPacket
	for _, raw := range fragments {
		p, err := parsePacket(raw)
		if !errors.Is(err, errFragmented) || p.Fragment == nil {
			t.Fatalf("expected fragment: %v", err)
		}
		rebuilt, complete, err := r.offer(*p.Fragment, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if complete {
			final, err = parsePacket(rebuilt)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(final.UDP.Payload) != len(payload) {
		t.Fatalf("payload mismatch: %d != %d", len(final.UDP.Payload), len(payload))
	}
	for i := range payload {
		if final.UDP.Payload[i] != payload[i] {
			t.Fatalf("byte mismatch at %d", i)
		}
	}
}

func TestFragmentReassemblyIPv6UDP(t *testing.T) {
	src := netip.MustParseAddr("2001:db8::10")
	dst := netip.MustParseAddr("2001:db8::20")
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(255 - (i % 251))
	}
	fragments := buildUDPPackets(6, src, dst, 443, 54000, payload, fullFlowMTU)
	if len(fragments) < 2 {
		t.Fatalf("expected fragments, got %d", len(fragments))
	}
	r := newFragmentReassembler()
	var final parsedPacket
	for _, raw := range fragments {
		p, err := parsePacket(raw)
		if !errors.Is(err, errFragmented) || p.Fragment == nil {
			t.Fatalf("expected fragment: %v", err)
		}
		rebuilt, complete, err := r.offer(*p.Fragment, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if complete {
			final, err = parsePacket(rebuilt)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(final.UDP.Payload) != len(payload) {
		t.Fatalf("payload mismatch: %d != %d", len(final.UDP.Payload), len(payload))
	}
}

func TestFragmentOverlapRejectsAssembly(t *testing.T) {
	r := newFragmentReassembler()
	base := ipFragment{
		Version: 4, Protocol: protoUDP,
		Src: netip.MustParseAddr("8.8.8.8"), Dst: netip.MustParseAddr("1.1.1.1"),
		ID: 42, Offset: 0, More: true, Data: make([]byte, 16),
	}
	if _, _, err := r.offer(base, time.Now()); err != nil {
		t.Fatal(err)
	}
	overlap := base
	overlap.Offset = 8
	overlap.Data = make([]byte, 16)
	if _, _, err := r.offer(overlap, time.Now()); !errors.Is(err, errFragmentOverlap) {
		t.Fatalf("expected overlap rejection, got %v", err)
	}
}
