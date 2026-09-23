package main

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"
)

var ipv4ID atomic.Uint32

const (
	tcpOptionNOP         = byte(1)
	tcpOptionMSS         = byte(2)
	tcpOptionWindowScale = byte(3)
)

func buildTCPPacket(version uint8, src, dst netip.Addr, srcPort, dstPort uint16, seq, ack uint32, flags uint8, window uint16, payload []byte, synMSS uint16, negotiateWindowScale bool) []byte {
	tcpHeaderLen := 20
	if flags&tcpSYN != 0 {
		if negotiateWindowScale {
			tcpHeaderLen = 28
		} else {
			tcpHeaderLen = 24
		}
	}
	ipHeaderLen := 40
	if version == 4 {
		ipHeaderLen = 20
	}
	out := make([]byte, ipHeaderLen+tcpHeaderLen+len(payload))
	fillIPHeader(out, version, src, dst, protoTCP, tcpHeaderLen+len(payload))
	off := ipHeaderLen
	binary.BigEndian.PutUint16(out[off:off+2], srcPort)
	binary.BigEndian.PutUint16(out[off+2:off+4], dstPort)
	binary.BigEndian.PutUint32(out[off+4:off+8], seq)
	binary.BigEndian.PutUint32(out[off+8:off+12], ack)
	out[off+12] = byte(tcpHeaderLen/4) << 4
	out[off+13] = flags
	binary.BigEndian.PutUint16(out[off+14:off+16], window)
	if flags&tcpSYN != 0 {
		out[off+20] = tcpOptionMSS
		out[off+21] = 4
		if synMSS == 0 || synMSS > defaultMSS {
			synMSS = defaultMSS
		}
		binary.BigEndian.PutUint16(out[off+22:off+24], synMSS)
		if negotiateWindowScale {
			out[off+24] = tcpOptionNOP // NOP aligns the three-byte window-scale option.
			out[off+25] = tcpOptionWindowScale
			out[off+26] = 3
			out[off+27] = 0 // RFC 7323: negotiate scaling while keeping our receive scale at zero.
		}
	}
	copy(out[off+tcpHeaderLen:], payload)
	cs := checksum(out[off:], pseudoSeed(src, dst, protoTCP, len(out)-off))
	binary.BigEndian.PutUint16(out[off+16:off+18], cs)
	return out
}

func buildUDPPacket(version uint8, src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	ipHeaderLen := 40
	if version == 4 {
		ipHeaderLen = 20
	}
	udpLen := 8 + len(payload)
	out := make([]byte, ipHeaderLen+udpLen)
	fillIPHeader(out, version, src, dst, protoUDP, udpLen)
	off := ipHeaderLen
	binary.BigEndian.PutUint16(out[off:off+2], srcPort)
	binary.BigEndian.PutUint16(out[off+2:off+4], dstPort)
	binary.BigEndian.PutUint16(out[off+4:off+6], uint16(udpLen))
	copy(out[off+8:], payload)
	cs := checksum(out[off:], pseudoSeed(src, dst, protoUDP, udpLen))
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(out[off+6:off+8], cs)
	return out
}

func fillIPHeader(out []byte, version uint8, src, dst netip.Addr, proto uint8, payloadLen int) {
	if version == 4 {
		out[0] = 0x45
		binary.BigEndian.PutUint16(out[2:4], uint16(20+payloadLen))
		binary.BigEndian.PutUint16(out[4:6], uint16(ipv4ID.Add(1)))
		binary.BigEndian.PutUint16(out[6:8], 0x4000)
		out[8] = 64
		out[9] = proto
		s := src.As4()
		d := dst.As4()
		copy(out[12:16], s[:])
		copy(out[16:20], d[:])
		binary.BigEndian.PutUint16(out[10:12], checksum(out[:20], 0))
		return
	}
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:6], uint16(payloadLen))
	out[6] = proto
	out[7] = 64
	s := src.As16()
	d := dst.As16()
	copy(out[8:24], s[:])
	copy(out[24:40], d[:])
}

func buildUDPPackets(version uint8, src, dst netip.Addr, srcPort, dstPort uint16, payload []byte, mtu int) [][]byte {
	ipHeaderLen := 40
	if version == 4 {
		ipHeaderLen = 20
	}
	if mtu <= ipHeaderLen+8 || len(payload)+8 > 65535 {
		return nil
	}
	if version == 4 && ipHeaderLen+8+len(payload) > 65535 {
		return nil
	}
	if ipHeaderLen+8+len(payload) <= mtu {
		return [][]byte{buildUDPPacket(version, src, dst, srcPort, dstPort, payload)}
	}
	udp := buildUDPDatagram(src, dst, srcPort, dstPort, payload)
	if len(udp) == 0 {
		return nil
	}
	if version == 4 {
		return fragmentUDPIPv4(src, dst, udp, mtu)
	}
	return fragmentUDPIPv6(src, dst, udp, mtu)
}

func buildUDPDatagram(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	if udpLen > 65535 {
		return nil
	}
	out := make([]byte, udpLen)
	binary.BigEndian.PutUint16(out[0:2], srcPort)
	binary.BigEndian.PutUint16(out[2:4], dstPort)
	binary.BigEndian.PutUint16(out[4:6], uint16(udpLen))
	copy(out[8:], payload)
	cs := checksum(out, pseudoSeed(src, dst, protoUDP, udpLen))
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(out[6:8], cs)
	return out
}

func fragmentUDPIPv4(src, dst netip.Addr, udp []byte, mtu int) [][]byte {
	chunkMax := ((mtu - 20) / 8) * 8
	if chunkMax < 8 {
		return nil
	}
	id := uint16(ipv4ID.Add(1))
	packets := make([][]byte, 0, (len(udp)+chunkMax-1)/chunkMax)
	for offset := 0; offset < len(udp); {
		remaining := len(udp) - offset
		chunk := remaining
		if chunk > chunkMax {
			chunk = chunkMax
		}
		more := offset+chunk < len(udp)
		out := make([]byte, 20+chunk)
		out[0] = 0x45
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		binary.BigEndian.PutUint16(out[4:6], id)
		fragField := uint16(offset / 8)
		if more {
			fragField |= 0x2000
		}
		binary.BigEndian.PutUint16(out[6:8], fragField)
		out[8] = 64
		out[9] = protoUDP
		s := src.As4()
		d := dst.As4()
		copy(out[12:16], s[:])
		copy(out[16:20], d[:])
		copy(out[20:], udp[offset:offset+chunk])
		binary.BigEndian.PutUint16(out[10:12], checksum(out[:20], 0))
		packets = append(packets, out)
		offset += chunk
	}
	return packets
}

var ipv6FragmentID atomic.Uint32

func fragmentUDPIPv6(src, dst netip.Addr, udp []byte, mtu int) [][]byte {
	chunkMax := ((mtu - 48) / 8) * 8
	if chunkMax < 8 {
		return nil
	}
	id := ipv6FragmentID.Add(1)
	packets := make([][]byte, 0, (len(udp)+chunkMax-1)/chunkMax)
	for offset := 0; offset < len(udp); {
		remaining := len(udp) - offset
		chunk := remaining
		if chunk > chunkMax {
			chunk = chunkMax
		}
		more := offset+chunk < len(udp)
		out := make([]byte, 48+chunk)
		out[0] = 0x60
		binary.BigEndian.PutUint16(out[4:6], uint16(8+chunk))
		out[6] = 44
		out[7] = 64
		s := src.As16()
		d := dst.As16()
		copy(out[8:24], s[:])
		copy(out[24:40], d[:])
		out[40] = protoUDP
		fragField := uint16(offset/8) << 3
		if more {
			fragField |= 1
		}
		binary.BigEndian.PutUint16(out[42:44], fragField)
		binary.BigEndian.PutUint32(out[44:48], id)
		copy(out[48:], udp[offset:offset+chunk])
		packets = append(packets, out)
		offset += chunk
	}
	return packets
}
