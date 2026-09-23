package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"testing"
)

func TestPacketFlowTrackerAllowsOnlyTrackedICMPEchoReplyIPv4(t *testing.T) {
	telemetry := newTelemetry(io.Discard)
	tracker := newPacketFlowTracker(telemetry)
	defer func() {
		tracker.close()
		telemetry.close()
	}()

	local := netip.MustParseAddr("10.77.0.2")
	remote := netip.MustParseAddr("198.51.100.7")
	request := buildTestICMPEchoPacket(4, local, remote, 8, 0x1234, 7)
	parsed, err := parsePacket(request)
	if err != nil {
		t.Fatal(err)
	}
	if !tracker.handleOutbound(parsed, policyMatch{Action: actionAllow}, request) {
		t.Fatal("outbound ICMP echo registration failed")
	}

	wrong := buildTestICMPEchoPacket(4, remote, local, 0, 0x1234, 8)
	if tracker.handleInbound(wrong) {
		t.Fatal("mismatched ICMP echo reply was admitted")
	}

	reply := buildTestICMPEchoPacket(4, remote, local, 0, 0x1234, 7)
	if !tracker.handleInbound(reply) {
		t.Fatal("tracked ICMP echo reply was rejected")
	}
	if tracker.handleInbound(reply) {
		t.Fatal("replayed ICMP echo reply was admitted after state consumption")
	}
}

func TestPacketFlowTrackerRejectsUnsolicitedICMPEchoReplyIPv6(t *testing.T) {
	telemetry := newTelemetry(io.Discard)
	tracker := newPacketFlowTracker(telemetry)
	defer func() {
		tracker.close()
		telemetry.close()
	}()

	reply := buildTestICMPEchoPacket(
		6,
		netip.MustParseAddr("2001:db8::53"),
		netip.MustParseAddr("fd77::2"),
		129,
		0x4321,
		9,
	)
	if tracker.handleInbound(reply) {
		t.Fatal("unsolicited ICMPv6 echo reply was admitted")
	}
}

func TestPacketFlowTrackerAllowsRelatedICMPv4Error(t *testing.T) {
	telemetry := newTelemetry(io.Discard)
	tracker := newPacketFlowTracker(telemetry)
	defer func() {
		tracker.close()
		telemetry.close()
	}()

	local := netip.MustParseAddr("10.77.0.2")
	remote := netip.MustParseAddr("198.51.100.7")
	request := buildUDPPacket(4, local, remote, 42311, 53, []byte("request"))
	parsed, err := parsePacket(request)
	if err != nil {
		t.Fatal(err)
	}
	if !tracker.handleOutbound(parsed, policyMatch{Action: actionAllow}, request) {
		t.Fatal("outbound UDP flow registration failed")
	}

	errorPacket := buildTestICMPErrorPacket(
		4,
		netip.MustParseAddr("192.0.2.1"),
		local,
		3,
		4,
		request[:28],
	)
	if !tracker.handleInbound(errorPacket) {
		t.Fatal("ICMPv4 error quoting tracked UDP flow was rejected")
	}

	unknown := buildUDPPacket(4, local, remote, 42312, 53, []byte("unknown"))
	unsolicited := buildTestICMPErrorPacket(4, netip.MustParseAddr("192.0.2.1"), local, 3, 4, unknown[:28])
	if tracker.handleInbound(unsolicited) {
		t.Fatal("ICMPv4 error quoting unknown flow was admitted")
	}
}

func TestPacketFlowTrackerAllowsRelatedICMPv6PacketTooBig(t *testing.T) {
	telemetry := newTelemetry(io.Discard)
	tracker := newPacketFlowTracker(telemetry)
	defer func() {
		tracker.close()
		telemetry.close()
	}()

	local := netip.MustParseAddr("fd77::2")
	remote := netip.MustParseAddr("2001:db8::53")
	request := buildUDPPacket(6, local, remote, 53000, 53, []byte("request"))
	parsed, err := parsePacket(request)
	if err != nil {
		t.Fatal(err)
	}
	if !tracker.handleOutbound(parsed, policyMatch{Action: actionAllow}, request) {
		t.Fatal("outbound IPv6 UDP flow registration failed")
	}

	ptb := buildTestICMPErrorPacket(
		6,
		netip.MustParseAddr("2001:db8::1"),
		local,
		2,
		0,
		request[:48],
	)
	binary.BigEndian.PutUint32(ptb[44:48], 1280)
	if !tracker.handleInbound(ptb) {
		t.Fatal("related ICMPv6 Packet Too Big was rejected")
	}
}

func TestPacketFlowTrackerAllowsRelatedICMPEchoError(t *testing.T) {
	telemetry := newTelemetry(io.Discard)
	tracker := newPacketFlowTracker(telemetry)
	defer func() {
		tracker.close()
		telemetry.close()
	}()

	local := netip.MustParseAddr("fd77::2")
	remote := netip.MustParseAddr("2001:db8::80")
	request := buildTestICMPEchoPacket(6, local, remote, 128, 0x9911, 3)
	parsed, err := parsePacket(request)
	if err != nil {
		t.Fatal(err)
	}
	if !tracker.handleOutbound(parsed, policyMatch{Action: actionAllow}, request) {
		t.Fatal("outbound ICMPv6 echo registration failed")
	}

	unreachable := buildTestICMPErrorPacket(
		6,
		netip.MustParseAddr("2001:db8::1"),
		local,
		1,
		0,
		request,
	)
	if !tracker.handleInbound(unreachable) {
		t.Fatal("ICMPv6 error quoting tracked echo request was rejected")
	}
}

func buildTestICMPEchoPacket(version uint8, src, dst netip.Addr, typ uint8, id, seq uint16) []byte {
	ipHeaderLen := 40
	protocol := uint8(protoICMPv6)
	if version == 4 {
		ipHeaderLen = 20
		protocol = protoICMPv4
	}
	out := make([]byte, ipHeaderLen+8)
	fillIPHeader(out, version, src, dst, protocol, 8)
	off := ipHeaderLen
	out[off] = typ
	binary.BigEndian.PutUint16(out[off+4:off+6], id)
	binary.BigEndian.PutUint16(out[off+6:off+8], seq)
	return out
}

func buildTestICMPErrorPacket(version uint8, src, dst netip.Addr, typ, code uint8, quoted []byte) []byte {
	ipHeaderLen := 40
	protocol := uint8(protoICMPv6)
	if version == 4 {
		ipHeaderLen = 20
		protocol = protoICMPv4
	}
	out := make([]byte, ipHeaderLen+8+len(quoted))
	fillIPHeader(out, version, src, dst, protocol, 8+len(quoted))
	off := ipHeaderLen
	out[off] = typ
	out[off+1] = code
	copy(out[off+8:], quoted)
	return out
}

func TestPacketFlowTrackerRequiresFirstOutboundFragment(t *testing.T) {
	telemetry := newTelemetry(io.Discard)
	tracker := newPacketFlowTracker(telemetry)
	defer func() {
		tracker.close()
		telemetry.close()
	}()

	packets := buildUDPPackets(
		4,
		netip.MustParseAddr("10.77.0.2"),
		netip.MustParseAddr("198.51.100.7"),
		50000,
		443,
		make([]byte, 2400),
		1280,
	)
	if len(packets) < 2 {
		t.Fatal("test did not produce fragmented IPv4 UDP")
	}
	second, err := parsePacket(packets[1])
	if !errors.Is(err, errFragmented) {
		t.Fatalf("expected second packet to be fragment: %v", err)
	}
	if tracker.handleOutbound(second, policyMatch{Action: actionAllow}, packets[1]) {
		t.Fatal("non-initial outbound fragment was admitted without fragment state")
	}
	first, err := parsePacket(packets[0])
	if !errors.Is(err, errFragmented) {
		t.Fatalf("expected first packet to be fragment: %v", err)
	}
	if !tracker.handleOutbound(first, policyMatch{Action: actionAllow}, packets[0]) {
		t.Fatal("initial outbound UDP fragment was rejected")
	}
	if !tracker.handleOutbound(second, policyMatch{Action: actionAllow}, packets[1]) {
		t.Fatal("tracked outbound continuation fragment was rejected")
	}
}

func TestPacketFlowTrackerAdmitsOnlyRelatedInboundFragments(t *testing.T) {
	telemetry := newTelemetry(io.Discard)
	tracker := newPacketFlowTracker(telemetry)
	defer func() {
		tracker.close()
		telemetry.close()
	}()

	local := netip.MustParseAddr("10.77.0.2")
	remote := netip.MustParseAddr("198.51.100.7")
	request := buildUDPPacket(4, local, remote, 50001, 443, []byte("request"))
	parsed, err := parsePacket(request)
	if err != nil {
		t.Fatal(err)
	}
	if !tracker.handleOutbound(parsed, policyMatch{Action: actionAllow}, request) {
		t.Fatal("outbound flow registration failed")
	}

	response := buildUDPPackets(4, remote, local, 443, 50001, make([]byte, 2400), 1280)
	if len(response) < 2 {
		t.Fatal("test did not produce fragmented inbound IPv4 UDP")
	}
	if tracker.handleInbound(response[1]) {
		t.Fatal("inbound continuation fragment was admitted before initial fragment")
	}
	if !tracker.handleInbound(response[0]) {
		t.Fatal("related inbound initial fragment was rejected")
	}
	if !tracker.handleInbound(response[1]) {
		t.Fatal("related inbound continuation fragment was rejected")
	}

	unsolicited := buildUDPPackets(4, remote, local, 443, 50002, make([]byte, 2400), 1280)
	if tracker.handleInbound(unsolicited[0]) || tracker.handleInbound(unsolicited[1]) {
		t.Fatal("fragmented response for unknown flow was admitted")
	}
}

func TestPacketFlowTrackerAdmitsOnlyRelatedIPv6Fragments(t *testing.T) {
	telemetry := newTelemetry(io.Discard)
	tracker := newPacketFlowTracker(telemetry)
	defer func() {
		tracker.close()
		telemetry.close()
	}()

	local := netip.MustParseAddr("2001:db8:77::2")
	remote := netip.MustParseAddr("2001:db8:88::7")
	request := buildUDPPacket(6, local, remote, 50003, 443, []byte("request-v6"))
	parsed, err := parsePacket(request)
	if err != nil {
		t.Fatal(err)
	}
	if !tracker.handleOutbound(parsed, policyMatch{Action: actionAllow}, request) {
		t.Fatal("outbound IPv6 flow registration failed")
	}

	response := buildUDPPackets(6, remote, local, 443, 50003, make([]byte, 2400), 1280)
	if len(response) < 2 {
		t.Fatal("test did not produce fragmented inbound IPv6 UDP")
	}
	if tracker.handleInbound(response[1]) {
		t.Fatal("IPv6 continuation fragment was admitted before initial fragment")
	}
	if !tracker.handleInbound(response[0]) {
		t.Fatal("related inbound IPv6 initial fragment was rejected")
	}
	if !tracker.handleInbound(response[1]) {
		t.Fatal("related inbound IPv6 continuation fragment was rejected")
	}

	unsolicited := buildUDPPackets(6, remote, local, 443, 50004, make([]byte, 2400), 1280)
	if tracker.handleInbound(unsolicited[0]) || tracker.handleInbound(unsolicited[1]) {
		t.Fatal("fragmented IPv6 response for unknown flow was admitted")
	}
}
