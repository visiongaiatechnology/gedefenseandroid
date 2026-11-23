package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"strings"
	"testing"
)

func buildSyntheticTLSClientHello(sni, alpn string, includeECH bool) []byte {
	var exts bytes.Buffer

	// GREASE extension 0x1a1a
	binary.Write(&exts, binary.BigEndian, uint16(0x1a1a))
	binary.Write(&exts, binary.BigEndian, uint16(0))

	if sni != "" {
		host := []byte(sni)
		var sniBuf bytes.Buffer
		binary.Write(&sniBuf, binary.BigEndian, uint16(3+len(host)))
		sniBuf.WriteByte(0x00)
		binary.Write(&sniBuf, binary.BigEndian, uint16(len(host)))
		sniBuf.Write(host)
		binary.Write(&exts, binary.BigEndian, tlsExtServerName)
		binary.Write(&exts, binary.BigEndian, uint16(sniBuf.Len()))
		exts.Write(sniBuf.Bytes())
	}

	if alpn != "" {
		proto := []byte(alpn)
		var alpnBuf bytes.Buffer
		binary.Write(&alpnBuf, binary.BigEndian, uint16(1+len(proto)))
		alpnBuf.WriteByte(byte(len(proto)))
		alpnBuf.Write(proto)
		binary.Write(&exts, binary.BigEndian, tlsExtALPN)
		binary.Write(&exts, binary.BigEndian, uint16(alpnBuf.Len()))
		exts.Write(alpnBuf.Bytes())
	}

	// supported_versions (TLS 1.3 = 0x0304, TLS 1.2 = 0x0303)
	binary.Write(&exts, binary.BigEndian, tlsExtSupportedVersion)
	binary.Write(&exts, binary.BigEndian, uint16(5))
	exts.Write([]byte{0x04, 0x03, 0x04, 0x03, 0x03})

	// supported_groups (x25519 = 0x001d, secp256r1 = 0x0017)
	binary.Write(&exts, binary.BigEndian, tlsExtSupportedGroups)
	binary.Write(&exts, binary.BigEndian, uint16(6))
	exts.Write([]byte{0x00, 0x04, 0x00, 0x1d, 0x00, 0x17})

	// ec_point_formats
	binary.Write(&exts, binary.BigEndian, tlsExtECPointFormats)
	binary.Write(&exts, binary.BigEndian, uint16(2))
	exts.Write([]byte{0x01, 0x00})

	if includeECH {
		binary.Write(&exts, binary.BigEndian, tlsExtECH)
		binary.Write(&exts, binary.BigEndian, uint16(4))
		exts.Write([]byte{0x00, 0x01, 0x02, 0x03})
	}

	var chBody bytes.Buffer
	chBody.Write([]byte{0x03, 0x03}) // legacy version TLS 1.2
	chBody.Write(make([]byte, 32))   // random
	chBody.WriteByte(0)              // session id len
	// ciphers: GREASE 0x2a2a, TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302)
	binary.Write(&chBody, binary.BigEndian, uint16(6))
	chBody.Write([]byte{0x2a, 0x2a, 0x13, 0x01, 0x13, 0x02})
	chBody.Write([]byte{0x01, 0x00}) // compression methods
	binary.Write(&chBody, binary.BigEndian, uint16(exts.Len()))
	chBody.Write(exts.Bytes())

	var hs bytes.Buffer
	hs.WriteByte(0x01) // ClientHello
	l := chBody.Len()
	hs.Write([]byte{byte(l >> 16), byte(l >> 8), byte(l)})
	hs.Write(chBody.Bytes())
	return hs.Bytes()
}

func wrapTLSRecord(handshake []byte) []byte {
	var rec bytes.Buffer
	rec.WriteByte(0x16)
	rec.Write([]byte{0x03, 0x01})
	binary.Write(&rec, binary.BigEndian, uint16(len(handshake)))
	rec.Write(handshake)
	return rec.Bytes()
}

func buildSyntheticQUICInitialPacket(t *testing.T, version uint32, dcid []byte, handshake []byte) []byte {
	t.Helper()
	var frames bytes.Buffer
	frames.WriteByte(0x06) // CRYPTO frame
	frames.WriteByte(0x00) // offset = 0
	if len(handshake) < 64 {
		frames.WriteByte(byte(len(handshake)))
	} else {
		v := uint16(0x4000 | len(handshake))
		binary.Write(&frames, binary.BigEndian, v)
	}
	frames.Write(handshake)
	for frames.Len() < 64 {
		frames.WriteByte(0x00) // PADDING so sample offset + 16 is valid
	}
	plaintext := frames.Bytes()

	var (
		salt     []byte
		pktType  byte
		keyLabel string
		ivLabel  string
		hpLabel  string
	)
	if version == quicVersion2 {
		salt = quicV2InitialSalt
		pktType = 0x01
		keyLabel = "quicv2 key"
		ivLabel = "quicv2 iv"
		hpLabel = "quicv2 hp"
	} else {
		salt = quicV1InitialSalt
		pktType = 0x00
		keyLabel = "quic key"
		ivLabel = "quic iv"
		hpLabel = "quic hp"
	}

	// 2-byte packet number (pnLen = 2 => low bits = 0x01), packet number = 1
	firstByte := byte(0xc0 | (pktType << 4) | 0x01)
	pnBytes := []byte{0x00, 0x01}
	remLen := len(pnBytes) + len(plaintext) + 16

	var hdr bytes.Buffer
	hdr.WriteByte(firstByte)
	binary.Write(&hdr, binary.BigEndian, version)
	hdr.WriteByte(byte(len(dcid)))
	hdr.Write(dcid)
	hdr.WriteByte(0) // scid len = 0
	hdr.WriteByte(0) // token len = 0
	binary.Write(&hdr, binary.BigEndian, uint16(0x4000|remLen))
	pnOffset := hdr.Len()
	hdr.Write(pnBytes)
	unmaskedHeader := append([]byte(nil), hdr.Bytes()...)

	initialSecret := hkdfExtractSHA256(salt, dcid)
	clientSecret := hkdfExpandLabelSHA256(initialSecret, "client in", 32)
	key := hkdfExpandLabelSHA256(clientSecret, keyLabel, 16)
	iv := hkdfExpandLabelSHA256(clientSecret, ivLabel, 12)
	hp := hkdfExpandLabelSHA256(clientSecret, hpLabel, 16)

	nonce := append([]byte(nil), iv...)
	nonce[11] ^= 0x01

	aeadBlock, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(aeadBlock)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, unmaskedHeader)

	packet := append(unmaskedHeader, ciphertext...)
	sampleOffset := pnOffset + 4
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatal(err)
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], packet[sampleOffset:sampleOffset+16])
	packet[0] ^= mask[0] & 0x0f
	for i := 0; i < len(pnBytes); i++ {
		packet[pnOffset+i] ^= mask[1+i]
	}
	return packet
}

func TestParseTLSClientHelloExtractsSNIALPNAndJA4(t *testing.T) {
	hs := buildSyntheticTLSClientHello("Telemetry.Example.COM.", "h2", true)
	rec := wrapTLSRecord(hs)
	meta, ok := parseTLSClientHello(rec)
	if !ok {
		t.Fatal("expected valid TLS ClientHello")
	}
	if meta.SNI != "telemetry.example.com" {
		t.Fatalf("unexpected SNI: %q", meta.SNI)
	}
	if meta.ALPN != "h2" {
		t.Fatalf("unexpected ALPN: %q", meta.ALPN)
	}
	if !meta.ECH {
		t.Fatal("expected ECH flag to be detected")
	}
	if len(meta.JA3Hash) != 32 {
		t.Fatalf("expected 32-char JA3 MD5 hash, got %q", meta.JA3Hash)
	}
	if !strings.HasPrefix(meta.JA4, "t13d0206h2_") {
		t.Fatalf("unexpected JA4 prefix: %q", meta.JA4)
	}
}

func TestParseQUICInitialClientHelloV1AndV2(t *testing.T) {
	hs := buildSyntheticTLSClientHello("c2.beacon.example.org", "h3", false)
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

	pktV1 := buildSyntheticQUICInitialPacket(t, quicVersion1, dcid, hs)
	metaV1, ok := parseQUICInitialClientHello(pktV1)
	if !ok {
		t.Fatal("expected QUIC v1 Initial ClientHello to parse")
	}
	if metaV1.SNI != "c2.beacon.example.org" || metaV1.ALPN != "h3" || !strings.HasPrefix(metaV1.JA4, "q13d0205h3_") {
		t.Fatalf("unexpected QUIC v1 metadata: %+v", metaV1)
	}

	pktV2 := buildSyntheticQUICInitialPacket(t, quicVersion2, dcid, hs)
	metaV2, ok := parseQUICInitialClientHello(pktV2)
	if !ok {
		t.Fatal("expected QUIC v2 Initial ClientHello to parse")
	}
	if metaV2.SNI != "c2.beacon.example.org" || metaV2.ALPN != "h3" {
		t.Fatalf("unexpected QUIC v2 metadata: %+v", metaV2)
	}
}
