package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var (
	errPacketTooShort = errors.New("packet too short")
	errUnsupportedIP  = errors.New("unsupported ip version")
	errFragmented     = errors.New("fragmented packet")
)

type parsedPacket struct {
	Version    uint8
	Protocol   uint8
	Src        netip.Addr
	Dst        netip.Addr
	L4Offset   int
	TotalLen   int
	SrcPort    uint16
	DstPort    uint16
	TCP        tcpSegment
	UDP        udpDatagram
	HasPorts   bool
	Fragmented bool
	Fragment   *ipFragment
}

type tcpSegment struct {
	Seq                uint32
	Ack                uint32
	Flags              uint8
	Window             uint16
	Payload            []byte
	MSS                uint16
	WindowScale        uint8
	WindowScalePresent bool
}

type udpDatagram struct {
	Payload []byte
}

const (
	protoICMPv4 = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

func parsePacket(b []byte) (parsedPacket, error) {
	if len(b) < 1 {
		return parsedPacket{}, errPacketTooShort
	}
	switch b[0] >> 4 {
	case 4:
		return parseIPv4(b)
	case 6:
		return parseIPv6(b)
	default:
		return parsedPacket{}, errUnsupportedIP
	}
}

func parseIPv4(b []byte) (parsedPacket, error) {
	if len(b) < 20 {
		return parsedPacket{}, errPacketTooShort
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || ihl > len(b) {
		return parsedPacket{}, errPacketTooShort
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < ihl || total > len(b) {
		return parsedPacket{}, errPacketTooShort
	}
	frag := binary.BigEndian.Uint16(b[6:8])
	fragmented := frag&0x3fff != 0
	src := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	dst := netip.AddrFrom4([4]byte{b[16], b[17], b[18], b[19]})
	p := parsedPacket{
		Version:    4,
		Protocol:   b[9],
		Src:        src,
		Dst:        dst,
		L4Offset:   ihl,
		TotalLen:   total,
		Fragmented: fragmented,
	}
	if fragmented {
		offset := int(frag&0x1fff) * 8
		more := frag&0x2000 != 0
		p.Fragment = &ipFragment{
			Version: 4, Protocol: b[9], Src: src, Dst: dst,
			ID: uint32(binary.BigEndian.Uint16(b[4:6])), Offset: offset, More: more,
			Data: b[ihl:total],
		}
		return p, errFragmented
	}
	return parseTransport(p, b[:total])
}

func parseIPv6(b []byte) (parsedPacket, error) {
	if len(b) < 40 {
		return parsedPacket{}, errPacketTooShort
	}
	total := 40 + int(binary.BigEndian.Uint16(b[4:6]))
	if total < 40 || total > len(b) {
		return parsedPacket{}, errPacketTooShort
	}
	next := b[6]
	off := 40
	for hops := 0; isIPv6Extension(next); hops++ {
		if hops >= 8 || off+2 > total {
			return parsedPacket{}, errPacketTooShort
		}
		old := next
		next = b[off]
		var size int
		switch old {
		case 44:
			if off+8 > total {
				return parsedPacket{}, errPacketTooShort
			}
			// VGT beta invariant: fragmented IPv6 with extension headers before the
			// Fragment header is rejected rather than canonicalized incorrectly.
			if off != 40 {
				return parsedPacket{}, errFragmented
			}
			fragField := binary.BigEndian.Uint16(b[off+2 : off+4])
			src, dst := addr16(b[8:24]), addr16(b[24:40])
			p := parsedPacket{
				Version: 6, Protocol: next,
				Src: src, Dst: dst,
				L4Offset: off + 8, TotalLen: total, Fragmented: true,
			}
			p.Fragment = &ipFragment{
				Version: 6, Protocol: next, Src: src, Dst: dst,
				ID:     binary.BigEndian.Uint32(b[off+4 : off+8]),
				Offset: int((fragField>>3)&0x1fff) * 8,
				More:   fragField&0x0001 != 0,
				Data:   b[off+8 : total],
			}
			return p, errFragmented
		case 51:
			size = (int(b[off+1]) + 2) * 4
		default:
			size = (int(b[off+1]) + 1) * 8
		}
		if size <= 0 || off+size > total {
			return parsedPacket{}, errPacketTooShort
		}
		off += size
	}
	p := parsedPacket{
		Version: 6, Protocol: next,
		Src: addr16(b[8:24]), Dst: addr16(b[24:40]),
		L4Offset: off, TotalLen: total,
	}
	return parseTransport(p, b[:total])
}

func parseTransport(p parsedPacket, b []byte) (parsedPacket, error) {
	off := p.L4Offset
	switch p.Protocol {
	case protoTCP:
		if off+20 > p.TotalLen {
			return parsedPacket{}, errPacketTooShort
		}
		hlen := int(b[off+12]>>4) * 4
		if hlen < 20 || off+hlen > p.TotalLen {
			return parsedPacket{}, errPacketTooShort
		}
		p.SrcPort = binary.BigEndian.Uint16(b[off : off+2])
		p.DstPort = binary.BigEndian.Uint16(b[off+2 : off+4])
		p.HasPorts = true
		mss, windowScale, windowScalePresent := parseTCPOptions(b[off+20 : off+hlen])
		p.TCP = tcpSegment{
			Seq: binary.BigEndian.Uint32(b[off+4 : off+8]), Ack: binary.BigEndian.Uint32(b[off+8 : off+12]),
			Flags: b[off+13], Window: binary.BigEndian.Uint16(b[off+14 : off+16]),
			Payload: b[off+hlen : p.TotalLen], MSS: mss, WindowScale: windowScale, WindowScalePresent: windowScalePresent,
		}
	case protoUDP:
		if off+8 > p.TotalLen {
			return parsedPacket{}, errPacketTooShort
		}
		udpLen := int(binary.BigEndian.Uint16(b[off+4 : off+6]))
		if udpLen < 8 || off+udpLen > p.TotalLen {
			return parsedPacket{}, errPacketTooShort
		}
		p.SrcPort = binary.BigEndian.Uint16(b[off : off+2])
		p.DstPort = binary.BigEndian.Uint16(b[off+2 : off+4])
		p.HasPorts = true
		p.UDP = udpDatagram{Payload: b[off+8 : off+udpLen]}
	}
	return p, nil
}

func parseTCPOptions(options []byte) (mss uint16, windowScale uint8, windowScalePresent bool) {
	for i := 0; i < len(options); {
		kind := options[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= len(options) {
			break
		}
		l := int(options[i+1])
		if l < 2 || i+l > len(options) {
			break
		}
		switch {
		case kind == tcpOptionMSS && l == 4:
			mss = binary.BigEndian.Uint16(options[i+2 : i+4])
		case kind == tcpOptionWindowScale && l == 3:
			windowScale = options[i+2]
			if windowScale > 14 {
				windowScale = 14
			}
			windowScalePresent = true
		}
		i += l
	}
	return
}

func isIPv6Extension(v uint8) bool {
	switch v {
	case 0, 43, 44, 51, 60, 135, 139, 140:
		return true
	default:
		return false
	}
}

func addr16(b []byte) netip.Addr {
	var a [16]byte
	copy(a[:], b)
	return netip.AddrFrom16(a)
}
