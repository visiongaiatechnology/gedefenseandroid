package main

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

// FuzzParsePacket treats every TUN byte as hostile input. The invariant is simple:
// malformed traffic may be rejected, but must never panic or escape parser bounds.
func FuzzParsePacket(f *testing.F) {
	for _, seed := range [][]byte{
		{}, {0x45}, {0x60},
		{0x45, 0, 0, 20, 0, 0, 0, 0, 64, protoTCP, 0, 0, 10, 0, 0, 1, 1, 1, 1, 1},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > maxPacketBytes+1 {
			return
		}
		_, _ = parsePacket(b)
	})
}

// FuzzLoadPolicy protects the JNI policy-file boundary. Policy input is locally produced,
// but a damaged cache or descriptor must fail closed without unbounded allocation/panic.
func FuzzLoadPolicy(f *testing.F) {
	f.Add(encodeTestPolicy(nil))
	f.Add([]byte("not-a-policy"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_, _ = loadPolicy(bytes.NewReader(b))
	})
}

func FuzzDNSQueryName(f *testing.F) {
	f.Add([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > maxDNSObservationBytes*2 {
			return
		}
		_ = parseDNSQueryName(b)
	})
}

func FuzzFragmentReassembly(f *testing.F) {
	f.Add(uint8(4), uint8(protoUDP), uint16(0), false, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	f.Fuzz(func(t *testing.T, version, protocol uint8, offsetUnits uint16, more bool, data []byte) {
		if len(data) == 0 || len(data) > 2048 {
			return
		}
		if more && len(data)%8 != 0 {
			return
		}
		if version != 4 && version != 6 {
			version = 4
		}
		src := netip.MustParseAddr("192.0.2.1")
		dst := netip.MustParseAddr("198.51.100.2")
		if version == 6 {
			src = netip.MustParseAddr("2001:db8::1")
			dst = netip.MustParseAddr("2001:db8::2")
		}
		r := newFragmentReassembler()
		_, _, _ = r.offer(ipFragment{
			Version: version, Protocol: protocol, Src: src, Dst: dst, ID: 1,
			Offset: int(offsetUnits) * 8, More: more, Data: data,
		}, time.Unix(1, 0))
	})
}
