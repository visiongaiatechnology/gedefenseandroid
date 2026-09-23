package main

import (
	"encoding/binary"
	"strings"
)

// parseDNSQueryName extracts only a conventional uncompressed question name. It is deliberately
// conservative: malformed/compressed/non-ASCII query names produce no telemetry and never affect forwarding.
func parseDNSQueryName(payload []byte) string {
	if len(payload) < 17 || len(payload) > maxDNSObservationBytes {
		return ""
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 != 0 { // response
		return ""
	}
	qd := binary.BigEndian.Uint16(payload[4:6])
	if qd == 0 || qd > 8 {
		return ""
	}
	off := 12
	labels := make([]string, 0, 8)
	total := 0
	for len(labels) < 64 {
		if off >= len(payload) {
			return ""
		}
		n := int(payload[off])
		off++
		if n == 0 {
			break
		}
		if n > 63 || n&0xc0 != 0 || off+n > len(payload) {
			return ""
		}
		labelBytes := payload[off : off+n]
		off += n
		for _, b := range labelBytes {
			if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_') {
				return ""
			}
		}
		label := strings.ToLower(string(labelBytes))
		if label == "" {
			return ""
		}
		labels = append(labels, label)
		total += n
		if total+len(labels)-1 > 253 {
			return ""
		}
	}
	if len(labels) == 0 || off+4 > len(payload) {
		return ""
	}
	return strings.Join(labels, ".")
}

// buildDNSBlockedResponse creates a minimal NXDOMAIN response for a conventional single-question
// DNS query. It preserves the transaction ID, opcode and recursion-desired bit, strips every answer
// and additional record, and never reflects unbounded attacker-controlled payload bytes.
func buildDNSBlockedResponse(payload []byte) []byte {
	if len(payload) < 17 || len(payload) > maxDNSObservationBytes {
		return nil
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 != 0 || binary.BigEndian.Uint16(payload[4:6]) != 1 {
		return nil
	}
	off := 12
	labels := 0
	for {
		if off >= len(payload) || labels >= 64 {
			return nil
		}
		n := int(payload[off])
		off++
		if n == 0 {
			break
		}
		if n > 63 || n&0xc0 != 0 || off+n > len(payload) {
			return nil
		}
		for _, b := range payload[off : off+n] {
			if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_') {
				return nil
			}
		}
		off += n
		labels++
	}
	if off+4 > len(payload) {
		return nil
	}
	endQuestion := off + 4
	response := make([]byte, endQuestion)
	copy(response, payload[:endQuestion])
	responseFlags := uint16(0x8000) | (flags & 0x7800) | (flags & 0x0100) | 0x0080 | 0x0003
	binary.BigEndian.PutUint16(response[2:4], responseFlags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], 0)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	return response
}
