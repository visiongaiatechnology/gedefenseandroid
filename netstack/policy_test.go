package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"testing"
)

type testPolicyRecord struct {
	family byte
	prefix byte
	action byte
	bits   uint64
	addr   []byte
}

func encodeTestPolicy(records []testPolicyRecord) []byte {
	var body bytes.Buffer
	hash := sha256.New()
	_, _ = hash.Write([]byte{'G', 'D', 'F', 1})
	for _, r := range records {
		body.Write([]byte{r.family, r.prefix, r.action, 0})
		_ = binary.Write(&body, binary.BigEndian, r.bits)
		body.Write(r.addr)
		_, _ = hash.Write([]byte{r.family, r.prefix})
		var bitBuf [8]byte
		binary.BigEndian.PutUint64(bitBuf[:], r.bits)
		_, _ = hash.Write(bitBuf[:])
		_, _ = hash.Write(r.addr)
	}
	var out bytes.Buffer
	out.WriteString("GDTI")
	out.Write([]byte{2, 0, 0, 0})
	_ = binary.Write(&out, binary.BigEndian, uint32(len(records)))
	out.Write(hash.Sum(nil))
	out.Write(body.Bytes())
	return out.Bytes()
}

func TestPolicyCombinesOverlappingSignals(t *testing.T) {
	encoded := encodeTestPolicy([]testPolicyRecord{
		{family: 4, prefix: 24, action: byte(actionCorrelate), bits: 1 << 3, addr: []byte{8, 8, 8, 0}},
		{family: 4, prefix: 32, action: byte(actionBlock), bits: 1 << 0, addr: []byte{8, 8, 8, 8}},
	})
	p, err := loadPolicy(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	m := p.match(netip.MustParseAddr("8.8.8.8"))
	if m.Action != actionBlock || m.Bits != (1<<3)|(1<<0) {
		t.Fatalf("unexpected match: %+v", m)
	}
	m = p.match(netip.MustParseAddr("8.8.8.9"))
	if m.Action != actionCorrelate || m.Bits != 1<<3 {
		t.Fatalf("unexpected broad match: %+v", m)
	}
}

func TestPolicyFeedAuthorityABI(t *testing.T) {
	tests := []struct {
		name string
		bit  uint
		want threatAction
	}{
		{"feodo", 0, actionBlock},
		{"spamhaus-v4", 1, actionBlock},
		{"spamhaus-v6", 2, actionBlock},
		{"cins", 3, actionCorrelate},
		{"blocklist-de", 4, actionCorrelate},
		{"emerging-threats", 5, actionCorrelate},
		{"ipsum", 6, actionCorrelate},
		{"firehol-level1", 7, actionBlock},
		{"tor-exits", 8, actionAnnotate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bits := uint64(1) << tc.bit
			if got := actionForBits(bits); got != tc.want {
				t.Fatalf("bit %d authority mismatch: got=%d want=%d", tc.bit, got, tc.want)
			}
		})
	}
	if got := actionForBits((1 << 7) | (1 << 3)); got != actionBlock {
		t.Fatalf("block authority must dominate correlate authority: got=%d", got)
	}
}

func TestPolicyAcceptsFireHOLBlockAuthority(t *testing.T) {
	encoded := encodeTestPolicy([]testPolicyRecord{
		{family: 4, prefix: 32, action: byte(actionBlock), bits: 1 << 7, addr: []byte{203, 0, 113, 7}},
	})
	if _, err := loadPolicy(bytes.NewReader(encoded)); err != nil {
		t.Fatalf("FireHOL bit 7 must be accepted as shipped block authority: %v", err)
	}
}

func TestPolicyRejectsAuthorityEscalation(t *testing.T) {
	encoded := encodeTestPolicy([]testPolicyRecord{
		{family: 4, prefix: 32, action: byte(actionBlock), bits: 1 << 8, addr: []byte{1, 1, 1, 1}},
	})
	if _, err := loadPolicy(bytes.NewReader(encoded)); err == nil {
		t.Fatal("Tor bit must never be accepted as blocking authority")
	}
}

func TestPolicyRejectsFingerprintTamperAndTrailingBytes(t *testing.T) {
	encoded := encodeTestPolicy([]testPolicyRecord{
		{family: 4, prefix: 32, action: byte(actionBlock), bits: 1 << 0, addr: []byte{1, 1, 1, 1}},
	})
	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-1] ^= 1
	if _, err := loadPolicy(bytes.NewReader(tampered)); err == nil {
		t.Fatal("tampered policy must fail fingerprint verification")
	}
	trailing := append(append([]byte(nil), encoded...), 0)
	if _, err := loadPolicy(bytes.NewReader(trailing)); err == nil {
		t.Fatal("trailing bytes must be rejected")
	}
}

func TestPolicyRejectsDuplicateAndNonCanonicalPrefixes(t *testing.T) {
	duplicate := encodeTestPolicy([]testPolicyRecord{
		{family: 4, prefix: 32, action: byte(actionBlock), bits: 1 << 0, addr: []byte{1, 1, 1, 1}},
		{family: 4, prefix: 32, action: byte(actionBlock), bits: 1 << 0, addr: []byte{1, 1, 1, 1}},
	})
	if _, err := loadPolicy(bytes.NewReader(duplicate)); err == nil {
		t.Fatal("duplicate prefix must be rejected")
	}
	nonCanonical := encodeTestPolicy([]testPolicyRecord{
		{family: 4, prefix: 24, action: byte(actionBlock), bits: 1 << 0, addr: []byte{1, 1, 1, 7}},
	})
	if _, err := loadPolicy(bytes.NewReader(nonCanonical)); err == nil {
		t.Fatal("non-canonical prefix must be rejected")
	}
}
