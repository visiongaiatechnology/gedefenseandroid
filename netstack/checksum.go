package main

import (
	"encoding/binary"
	"net/netip"
)

func checksum(data []byte, seed uint32) uint16 {
	sum := seed
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func pseudoSeed(src, dst netip.Addr, proto uint8, length int) uint32 {
	var sum uint32
	if src.Is4() {
		s := src.As4()
		d := dst.As4()
		for i := 0; i < 4; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(s[i : i+2]))
			sum += uint32(binary.BigEndian.Uint16(d[i : i+2]))
		}
		sum += uint32(proto)
		sum += uint32(length)
		return sum
	}
	s := src.As16()
	d := dst.As16()
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(s[i : i+2]))
		sum += uint32(binary.BigEndian.Uint16(d[i : i+2]))
	}
	sum += uint32(length >> 16)
	sum += uint32(length & 0xffff)
	sum += uint32(proto)
	return sum
}
