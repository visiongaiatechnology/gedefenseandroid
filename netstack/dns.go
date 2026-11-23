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

var (
	negativeCacheMName = []byte{8, 's', 'i', 'n', 'k', 'h', 'o', 'l', 'e', 9, 'g', 'e', 'd', 'e', 'f', 'e', 'n', 's', 'e', 5, 'l', 'o', 'c', 'a', 'l', 0}
	negativeCacheRName = []byte{10, 'h', 'o', 's', 't', 'm', 'a', 's', 't', 'e', 'r', 9, 'g', 'e', 'd', 'e', 'f', 'e', 'n', 's', 'e', 5, 'l', 'o', 'c', 'a', 'l', 0}
)

// withDNSNegativeCacheSOA attaches an RFC 2308 SOA record in the Authority section so OS and app
// resolvers negatively cache blocked telemetry NXDOMAIN verdicts instead of entering battery-draining retry storms.
func withDNSNegativeCacheSOA(response []byte, ttlSeconds uint32) []byte {
	if len(response) < 17 || binary.BigEndian.Uint16(response[4:6]) != 1 || ttlSeconds == 0 {
		return response
	}
	if binary.BigEndian.Uint16(response[8:10]) != 0 || binary.BigEndian.Uint16(response[10:12]) != 0 {
		return response
	}
	rdataLen := len(negativeCacheMName) + len(negativeCacheRName) + 20
	out := make([]byte, len(response)+12+rdataLen)
	copy(out, response)
	binary.BigEndian.PutUint16(out[8:10], 1) // NSCOUNT = 1

	off := len(response)
	binary.BigEndian.PutUint16(out[off:off+2], 0xc00c)     // Name pointer to question QNAME at offset 12
	binary.BigEndian.PutUint16(out[off+2:off+4], 6)        // TYPE = SOA
	binary.BigEndian.PutUint16(out[off+4:off+6], 1)        // CLASS = IN
	binary.BigEndian.PutUint32(out[off+6:off+10], ttlSeconds)
	binary.BigEndian.PutUint16(out[off+10:off+12], uint16(rdataLen))
	off += 12

	copy(out[off:], negativeCacheMName)
	off += len(negativeCacheMName)
	copy(out[off:], negativeCacheRName)
	off += len(negativeCacheRName)

	binary.BigEndian.PutUint32(out[off:off+4], 1)           // Serial
	binary.BigEndian.PutUint32(out[off+4:off+8], 3600)      // Refresh
	binary.BigEndian.PutUint32(out[off+8:off+12], 600)      // Retry
	binary.BigEndian.PutUint32(out[off+12:off+16], 86400)   // Expire
	binary.BigEndian.PutUint32(out[off+16:off+20], ttlSeconds) // Minimum negative-cache TTL
	return out
}
