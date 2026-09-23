package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
	"time"
)

var (
	errFragmentMalformed = errors.New("malformed ip fragment")
	errFragmentOverlap   = errors.New("overlapping ip fragment")
	errFragmentCapacity  = errors.New("fragment reassembly capacity exhausted")
)

type ipFragment struct {
	Version  uint8
	Protocol uint8
	Src      netip.Addr
	Dst      netip.Addr
	ID       uint32
	Offset   int
	More     bool
	Data     []byte
}

type fragmentKey struct {
	Version  uint8
	Protocol uint8
	Src      netip.Addr
	Dst      netip.Addr
	ID       uint32
}

type fragmentPiece struct {
	offset int
	data   []byte
}

type fragmentAssembly struct {
	key       fragmentKey
	pieces    []fragmentPiece
	finalSize int
	bytes     int
	updatedAt time.Time
}

type fragmentReassembler struct {
	assemblies map[fragmentKey]*fragmentAssembly
	bytes      int
}

func newFragmentReassembler() *fragmentReassembler {
	return &fragmentReassembler{assemblies: make(map[fragmentKey]*fragmentAssembly)}
}

func (r *fragmentReassembler) offer(f ipFragment, now time.Time) ([]byte, bool, error) {
	r.expire(now)
	if err := validateFragment(f); err != nil {
		return nil, false, err
	}
	key := fragmentKey{Version: f.Version, Protocol: f.Protocol, Src: f.Src, Dst: f.Dst, ID: f.ID}
	a := r.assemblies[key]
	if a == nil {
		if len(r.assemblies) >= maxFragmentDatagrams {
			return nil, false, errFragmentCapacity
		}
		a = &fragmentAssembly{key: key, finalSize: -1, updatedAt: now}
		r.assemblies[key] = a
	}
	if len(a.pieces) >= maxFragmentPiecesPerDatagram {
		r.remove(key)
		return nil, false, errFragmentCapacity
	}
	start, end := f.Offset, f.Offset+len(f.Data)
	for _, p := range a.pieces {
		ps, pe := p.offset, p.offset+len(p.data)
		if start < pe && ps < end {
			// Exact duplicates are tolerated because retransmitted IP fragments are legal.
			if start == ps && end == pe && equalBytes(f.Data, p.data) {
				a.updatedAt = now
				return nil, false, nil
			}
			r.remove(key)
			return nil, false, errFragmentOverlap
		}
	}
	if !f.More {
		if a.finalSize >= 0 && a.finalSize != end {
			r.remove(key)
			return nil, false, errFragmentMalformed
		}
		a.finalSize = end
	}
	if a.finalSize >= 0 && end > a.finalSize {
		r.remove(key)
		return nil, false, errFragmentMalformed
	}
	if r.bytes+len(f.Data) > maxFragmentReassemblyBytes {
		r.remove(key)
		return nil, false, errFragmentCapacity
	}
	piece := fragmentPiece{offset: start, data: append([]byte(nil), f.Data...)}
	a.pieces = append(a.pieces, piece)
	a.bytes += len(piece.data)
	r.bytes += len(piece.data)
	a.updatedAt = now

	if a.finalSize < 0 || a.finalSize > maxFragmentDatagramBytes {
		return nil, false, nil
	}
	sort.Slice(a.pieces, func(i, j int) bool { return a.pieces[i].offset < a.pieces[j].offset })
	cursor := 0
	for _, p := range a.pieces {
		if p.offset != cursor {
			return nil, false, nil
		}
		cursor += len(p.data)
	}
	if cursor != a.finalSize {
		return nil, false, nil
	}
	payload := make([]byte, a.finalSize)
	for _, p := range a.pieces {
		copy(payload[p.offset:], p.data)
	}
	r.remove(key)
	return buildCanonicalIPPacket(f.Version, f.Src, f.Dst, f.Protocol, f.ID, payload), true, nil
}

func (r *fragmentReassembler) expire(now time.Time) {
	for key, a := range r.assemblies {
		if now.Sub(a.updatedAt) > fragmentReassemblyTimeout {
			r.remove(key)
		}
	}
}

func (r *fragmentReassembler) remove(key fragmentKey) {
	a := r.assemblies[key]
	if a == nil {
		return
	}
	r.bytes -= a.bytes
	if r.bytes < 0 {
		r.bytes = 0
	}
	delete(r.assemblies, key)
}

func validateFragment(f ipFragment) error {
	if f.Version != 4 && f.Version != 6 {
		return errFragmentMalformed
	}
	if f.Protocol == 0 || !f.Src.IsValid() || !f.Dst.IsValid() || len(f.Data) == 0 {
		return errFragmentMalformed
	}
	if f.Offset < 0 || f.Offset%8 != 0 || f.Offset+len(f.Data) > maxFragmentDatagramBytes {
		return errFragmentMalformed
	}
	if f.More && len(f.Data)%8 != 0 {
		return errFragmentMalformed
	}
	return nil
}

func buildCanonicalIPPacket(version uint8, src, dst netip.Addr, protocol uint8, id uint32, payload []byte) []byte {
	if version == 4 {
		out := make([]byte, 20+len(payload))
		out[0] = 0x45
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		binary.BigEndian.PutUint16(out[4:6], uint16(id))
		out[8] = 64
		out[9] = protocol
		s := src.As4()
		d := dst.As4()
		copy(out[12:16], s[:])
		copy(out[16:20], d[:])
		binary.BigEndian.PutUint16(out[10:12], checksum(out[:20], 0))
		copy(out[20:], payload)
		return out
	}
	out := make([]byte, 40+len(payload))
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:6], uint16(len(payload)))
	out[6] = protocol
	out[7] = 64
	s := src.As16()
	d := dst.As16()
	copy(out[8:24], s[:])
	copy(out[24:40], d[:])
	copy(out[40:], payload)
	return out
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
