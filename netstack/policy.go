package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
)

type threatAction uint8

const (
	actionAllow threatAction = iota
	actionAnnotate
	actionCorrelate
	actionBlock
)

type policyMatch struct {
	Action threatAction
	Bits   uint64
}

type v6PolicyKey [16]byte

type threatPolicy struct {
	v4      map[uint8]map[uint32]policyMatch
	v6      map[uint8]map[v6PolicyKey]policyMatch
	v4Lens  []uint8
	v6Lens  []uint8
	records int
}

func loadPolicy(r io.Reader) (*threatPolicy, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	header := make([]byte, 44)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, err
	}
	if string(header[:4]) != "GDTI" || header[4] != 2 || header[5] != 0 || header[6] != 0 || header[7] != 0 {
		return nil, errors.New("invalid threat policy header")
	}
	count := int(binary.BigEndian.Uint32(header[8:12]))
	if count < 0 || count > 500000 {
		return nil, errors.New("threat policy record bound")
	}
	expectedFingerprint := header[12:44]
	hash := sha256.New()
	_, _ = hash.Write([]byte{'G', 'D', 'F', 1})

	p := &threatPolicy{v4: make(map[uint8]map[uint32]policyMatch), v6: make(map[uint8]map[v6PolicyKey]policyMatch)}
	for i := 0; i < count; i++ {
		fixed := make([]byte, 12)
		if _, err := io.ReadFull(br, fixed); err != nil {
			return nil, err
		}
		family, prefix, act := fixed[0], fixed[1], threatAction(fixed[2])
		if fixed[3] != 0 {
			return nil, errors.New("invalid threat policy reserved field")
		}
		bits := binary.BigEndian.Uint64(fixed[4:12])
		if bits == 0 || bits&^uint64((1<<threatFeedCount)-1) != 0 {
			return nil, errors.New("invalid threat policy feed bitset")
		}
		if act != actionForBits(bits) {
			return nil, errors.New("threat policy authority mismatch")
		}
		match := policyMatch{Action: act, Bits: bits}
		switch family {
		case 4:
			if prefix > 32 {
				return nil, errors.New("invalid ipv4 prefix")
			}
			addr := make([]byte, 4)
			if _, err := io.ReadFull(br, addr); err != nil {
				return nil, err
			}
			key := maskV4(binary.BigEndian.Uint32(addr), prefix)
			if binary.BigEndian.Uint32(addr) != key {
				return nil, errors.New("non-canonical ipv4 threat prefix")
			}
			m := p.v4[prefix]
			if m == nil {
				m = make(map[uint32]policyMatch)
				p.v4[prefix] = m
				p.v4Lens = append(p.v4Lens, prefix)
			}
			if _, exists := m[key]; exists {
				return nil, errors.New("duplicate ipv4 threat prefix")
			}
			m[key] = match
			_, _ = hash.Write([]byte{4, prefix})
			var bitsBuf [8]byte
			binary.BigEndian.PutUint64(bitsBuf[:], bits)
			_, _ = hash.Write(bitsBuf[:])
			_, _ = hash.Write(addr)
		case 6:
			if prefix > 128 {
				return nil, errors.New("invalid ipv6 prefix")
			}
			addr := make([]byte, 16)
			if _, err := io.ReadFull(br, addr); err != nil {
				return nil, err
			}
			key := maskV6(addr, prefix)
			if subtle.ConstantTimeCompare(addr, key[:]) != 1 {
				return nil, errors.New("non-canonical ipv6 threat prefix")
			}
			m := p.v6[prefix]
			if m == nil {
				m = make(map[v6PolicyKey]policyMatch)
				p.v6[prefix] = m
				p.v6Lens = append(p.v6Lens, prefix)
			}
			if _, exists := m[key]; exists {
				return nil, errors.New("duplicate ipv6 threat prefix")
			}
			m[key] = match
			_, _ = hash.Write([]byte{6, prefix})
			var bitsBuf [8]byte
			binary.BigEndian.PutUint64(bitsBuf[:], bits)
			_, _ = hash.Write(bitsBuf[:])
			_, _ = hash.Write(addr)
		default:
			return nil, errors.New("invalid threat policy family")
		}
		p.records++
	}
	if b, err := br.ReadByte(); err == nil {
		_ = b
		return nil, errors.New("trailing threat policy bytes")
	} else if !errors.Is(err, io.EOF) {
		return nil, err
	}
	actualFingerprint := hash.Sum(nil)
	if len(expectedFingerprint) != sha256.Size || subtle.ConstantTimeCompare(expectedFingerprint, actualFingerprint) != 1 {
		return nil, errors.New("threat policy fingerprint mismatch")
	}
	sortDesc(p.v4Lens)
	sortDesc(p.v6Lens)
	return p, nil
}

const threatFeedCount = 9

func actionForBits(bits uint64) threatAction {
	// Feed-order ABI v2 mirrors core ThreatFeedCatalog exactly:
	//   0 Feodo, 1 Spamhaus v4, 2 Spamhaus v6, 7 FireHOL L1 => BLOCK
	//   3 CINS, 4 blocklist.de, 5 Emerging Threats, 6 IPsum => CORRELATE
	//   8 Tor exits => ANNOTATE
	// Downloaded feed data can never grant itself authority; only this shipped ABI can.
	if bits&0x87 != 0 {
		return actionBlock
	}
	if bits&0x78 != 0 {
		return actionCorrelate
	}
	if bits&(1<<8) != 0 {
		return actionAnnotate
	}
	return actionAllow
}

func (p *threatPolicy) match(addr netip.Addr) policyMatch {
	var out policyMatch
	if addr.Is4() {
		a := binary.BigEndian.Uint32(addr.AsSlice())
		for _, l := range p.v4Lens {
			if hit, ok := p.v4[l][maskV4(a, l)]; ok {
				out = mergePolicy(out, hit)
			}
		}
		return out
	}
	a := addr.As16()
	for _, l := range p.v6Lens {
		if hit, ok := p.v6[l][maskV6(a[:], l)]; ok {
			out = mergePolicy(out, hit)
		}
	}
	return out
}

func mergePolicy(a, b policyMatch) policyMatch {
	if b.Action > a.Action {
		a.Action = b.Action
	}
	a.Bits |= b.Bits
	return a
}

func maskV4(v uint32, prefix uint8) uint32 {
	if prefix == 0 {
		return 0
	}
	return v & (^uint32(0) << (32 - prefix))
}

func maskV6(in []byte, prefix uint8) v6PolicyKey {
	var out v6PolicyKey
	copy(out[:], in)
	full := int(prefix / 8)
	rem := int(prefix % 8)
	if full < len(out) {
		if rem != 0 {
			out[full] &= 0xff << (8 - rem)
			full++
		}
		for i := full; i < len(out); i++ {
			out[i] = 0
		}
	}
	return out
}

func sortDesc(v []uint8) {
	for i := 1; i < len(v); i++ {
		x := v[i]
		j := i - 1
		for ; j >= 0 && v[j] < x; j-- {
			v[j+1] = v[j]
		}
		v[j+1] = x
	}
}
