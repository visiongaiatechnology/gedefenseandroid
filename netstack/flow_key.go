package main

import "net/netip"

type flowKey struct {
	Protocol uint8
	Src      netip.Addr
	Dst      netip.Addr
	SrcPort  uint16
	DstPort  uint16
}

func keyFromPacket(p parsedPacket) flowKey {
	return flowKey{Protocol: p.Protocol, Src: p.Src, Dst: p.Dst, SrcPort: p.SrcPort, DstPort: p.DstPort}
}
