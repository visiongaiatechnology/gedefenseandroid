package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

const (
	maxTLSInspectionBytes  = 4096
	maxQUICCryptoBytes     = 4096
	quicVersion1           = uint32(0x00000001)
	quicVersion2           = uint32(0x6b3343cf)
	tlsExtServerName       = uint16(0x0000)
	tlsExtSupportedGroups  = uint16(0x000a)
	tlsExtECPointFormats   = uint16(0x000b)
	tlsExtALPN             = uint16(0x0010)
	tlsExtSupportedVersion = uint16(0x002b)
	tlsExtECH              = uint16(0xfe0d)
)

var (
	quicV1InitialSalt = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
		0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
		0xcc, 0xbb, 0x7f, 0x0a,
	}
	quicV2InitialSalt = []byte{
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
		0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
		0xf9, 0xbd, 0x2e, 0xd9,
	}
)

type clientHelloMetadata struct {
	SNI       string
	ALPN      string
	JA3Hash   string
	JA4       string
	ECH       bool
	Transport string
}

// parseTLSClientHello passively parses a TLS record containing a ClientHello handshake message
// without terminating TLS or requiring any MITM CA.
func parseTLSClientHello(payload []byte) (clientHelloMetadata, bool) {
	if len(payload) < 43 {
		return clientHelloMetadata{}, false
	}
	if len(payload) > maxTLSInspectionBytes {
		payload = payload[:maxTLSInspectionBytes]
	}
	if payload[0] != 0x16 {
		return clientHelloMetadata{}, false
	}
	recVer := binary.BigEndian.Uint16(payload[1:3])
	if recVer < 0x0300 || recVer > 0x0304 {
		return clientHelloMetadata{}, false
	}
	recLen := int(binary.BigEndian.Uint16(payload[3:5]))
	body := payload[5:]
	if recLen > 0 && recLen < len(body) {
		body = body[:recLen]
	}
	return parseTLSClientHelloHandshake(body, "tls")
}

func parseTLSClientHelloHandshake(hs []byte, transport string) (clientHelloMetadata, bool) {
	if len(hs) < 38 || hs[0] != 0x01 {
		return clientHelloMetadata{}, false
	}
	msgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	body := hs[4:]
	if msgLen <= 0 {
		return clientHelloMetadata{}, false
	}
	if msgLen < len(body) {
		body = body[:msgLen]
	}
	if len(body) < 34 {
		return clientHelloMetadata{}, false
	}

	clientVer := binary.BigEndian.Uint16(body[0:2])
	if clientVer < 0x0300 || clientVer > 0x0304 {
		return clientHelloMetadata{}, false
	}
	pos := 2 + 32 // version + 32-byte random

	// Session ID
	if pos >= len(body) {
		return clientHelloMetadata{}, false
	}
	sidLen := int(body[pos])
	pos++
	if sidLen > 32 || pos+sidLen > len(body) {
		return clientHelloMetadata{}, false
	}
	pos += sidLen

	// Cipher Suites
	if pos+2 > len(body) {
		return clientHelloMetadata{}, false
	}
	csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if csLen <= 0 || csLen%2 != 0 || pos+csLen > len(body) {
		return clientHelloMetadata{}, false
	}
	ciphers := make([]uint16, 0, csLen/2)
	for i := 0; i < csLen; i += 2 {
		c := binary.BigEndian.Uint16(body[pos+i : pos+i+2])
		if !isTLSGrease(c) {
			ciphers = append(ciphers, c)
		}
	}
	pos += csLen

	// Compression Methods
	if pos >= len(body) {
		return clientHelloMetadata{}, false
	}
	compLen := int(body[pos])
	pos++
	if compLen <= 0 || pos+compLen > len(body) {
		return clientHelloMetadata{}, false
	}
	pos += compLen

	var (
		sni          string
		alpn         string
		ech          bool
		highestVer   = clientVer
		exts         []uint16
		ja4Exts      []uint16
		curves       []uint16
		pointFormats []uint8
	)

	if pos+2 <= len(body) {
		extTotalLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
		pos += 2
		if extTotalLen < 0 || pos+extTotalLen > len(body) {
			extTotalLen = len(body) - pos
		}
		end := pos + extTotalLen
		for pos+4 <= end {
			extType := binary.BigEndian.Uint16(body[pos : pos+2])
			extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
			pos += 4
			if extLen < 0 || pos+extLen > end {
				break
			}
			extData := body[pos : pos+extLen]
			pos += extLen

			if isTLSGrease(extType) {
				continue
			}
			exts = append(exts, extType)
			if extType != tlsExtServerName && extType != tlsExtALPN {
				ja4Exts = append(ja4Exts, extType)
			}

			switch extType {
			case tlsExtServerName:
				if parsed := parseSNIExtension(extData); parsed != "" {
					sni = parsed
				}
			case tlsExtALPN:
				if parsed := parseALPNExtension(extData); parsed != "" {
					alpn = parsed
				}
			case tlsExtSupportedVersion:
				if v := parseSupportedVersionsExtension(extData); v > highestVer {
					highestVer = v
				}
			case tlsExtSupportedGroups:
				curves = parseSupportedGroupsExtension(extData)
			case tlsExtECPointFormats:
				pointFormats = parseECPointFormatsExtension(extData)
			case tlsExtECH:
				ech = true
			}
		}
	}

	if sni == "" && len(ciphers) == 0 {
		return clientHelloMetadata{}, false
	}
	if transport == "" {
		transport = "tls"
	}
	return clientHelloMetadata{
		SNI:       sni,
		ALPN:      alpn,
		JA3Hash:   computeJA3Hash(clientVer, ciphers, exts, curves, pointFormats),
		JA4:       computeJA4Fingerprint(transport, highestVer, sni != "", len(ciphers), len(exts), alpn, ciphers, ja4Exts),
		ECH:       ech,
		Transport: transport,
	}, true
}

func isTLSGrease(v uint16) bool {
	return (v & 0x0f0f) == 0x0a0a && (v>>8) == (v&0xff)
}

func parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen <= 0 || 2+listLen > len(data) {
		return ""
	}
	pos := 2
	end := 2 + listLen
	for pos+3 <= end {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3
		if nameLen <= 0 || pos+nameLen > end {
			return ""
		}
		if nameType == 0x00 {
			if name := canonicalPrivacyDomain(string(data[pos : pos+nameLen])); name != "" {
				return name
			}
		}
		pos += nameLen
	}
	return ""
}

func parseALPNExtension(data []byte) string {
	if len(data) < 3 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen <= 0 || 2+listLen > len(data) {
		return ""
	}
	protoLen := int(data[2])
	if protoLen <= 0 || 3+protoLen > 2+listLen {
		return ""
	}
	raw := data[3 : 3+protoLen]
	for _, b := range raw {
		if b < 0x21 || b > 0x7e || b == '\t' || b == '\n' || b == '\r' {
			return ""
		}
	}
	if len(raw) > 32 {
		raw = raw[:32]
	}
	return strings.ToLower(string(raw))
}

func parseSupportedVersionsExtension(data []byte) uint16 {
	if len(data) < 3 {
		return 0
	}
	listLen := int(data[0])
	if listLen <= 0 || listLen%2 != 0 || 1+listLen > len(data) {
		return 0
	}
	var best uint16
	for i := 1; i+2 <= 1+listLen; i += 2 {
		v := binary.BigEndian.Uint16(data[i : i+2])
		if !isTLSGrease(v) && v >= 0x0300 && v <= 0x0304 && v > best {
			best = v
		}
	}
	return best
}

func parseSupportedGroupsExtension(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen <= 0 || listLen%2 != 0 || 2+listLen > len(data) {
		return nil
	}
	out := make([]uint16, 0, listLen/2)
	for i := 2; i+2 <= 2+listLen; i += 2 {
		g := binary.BigEndian.Uint16(data[i : i+2])
		if !isTLSGrease(g) {
			out = append(out, g)
		}
	}
	return out
}

func parseECPointFormatsExtension(data []byte) []uint8 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])
	if listLen <= 0 || 1+listLen > len(data) {
		return nil
	}
	out := make([]uint8, listLen)
	copy(out, data[1:1+listLen])
	return out
}

func computeJA3Hash(ver uint16, ciphers, exts, curves []uint16, formats []uint8) string {
	var sb strings.Builder
	sb.Grow(128)
	sb.WriteString(strconv.Itoa(int(ver)))
	sb.WriteByte(',')
	for i, c := range ciphers {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(c)))
	}
	sb.WriteByte(',')
	for i, e := range exts {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(e)))
	}
	sb.WriteByte(',')
	for i, g := range curves {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(g)))
	}
	sb.WriteByte(',')
	for i, f := range formats {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(f)))
	}
	sum := md5.Sum([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

func computeJA4Fingerprint(transport string, ver uint16, hasSNI bool, cipherCount, extCount int, alpn string, ciphers, ja4Exts []uint16) string {
	proto := byte('t')
	if transport == "quic" {
		proto = 'q'
	}
	verStr := "00"
	switch ver {
	case 0x0304:
		verStr = "13"
	case 0x0303:
		verStr = "12"
	case 0x0302:
		verStr = "11"
	case 0x0301:
		verStr = "10"
	}
	sniChar := byte('i')
	if hasSNI {
		sniChar = 'd'
	}
	if cipherCount > 99 {
		cipherCount = 99
	}
	if extCount > 99 {
		extCount = 99
	}
	alpnCode := "00"
	if len(alpn) > 0 {
		first := alpn[0]
		last := alpn[len(alpn)-1]
		if isAlphaNumASCII(first) && isAlphaNumASCII(last) {
			alpnCode = string([]byte{first, last})
		}
	}

	sortedCiphers := append([]uint16(nil), ciphers...)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	cipherHash := shortHexListHash(sortedCiphers)

	sortedExts := append([]uint16(nil), ja4Exts...)
	sort.Slice(sortedExts, func(i, j int) bool { return sortedExts[i] < sortedExts[j] })
	extHash := shortHexListHash(sortedExts)

	var sb strings.Builder
	sb.Grow(36)
	sb.WriteByte(proto)
	sb.WriteString(verStr)
	sb.WriteByte(sniChar)
	writeTwoDigits(&sb, cipherCount)
	writeTwoDigits(&sb, extCount)
	sb.WriteString(alpnCode)
	sb.WriteByte('_')
	sb.WriteString(cipherHash)
	sb.WriteByte('_')
	sb.WriteString(extHash)
	return sb.String()
}

func isAlphaNumASCII(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

func writeTwoDigits(sb *strings.Builder, v int) {
	if v < 10 {
		sb.WriteByte('0')
		sb.WriteByte(byte('0' + v))
	} else {
		sb.WriteByte(byte('0' + (v / 10)))
		sb.WriteByte(byte('0' + (v % 10)))
	}
}

func shortHexListHash(values []uint16) string {
	if len(values) == 0 {
		return "000000000000"
	}
	var sb strings.Builder
	sb.Grow(len(values)*5 - 1)
	var buf [2]byte
	var hexBuf [4]byte
	for i, v := range values {
		if i > 0 {
			sb.WriteByte(',')
		}
		binary.BigEndian.PutUint16(buf[:], v)
		hex.Encode(hexBuf[:], buf[:])
		sb.Write(hexBuf[:])
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:6])
}

// parseQUICInitialClientHello passively decrypts RFC 9000 / RFC 9001 / RFC 9369 QUIC Initial
// packets using the deterministic public DCID-derived Initial keys, extracts CRYPTO frames, and
// parses the embedded TLS 1.3 ClientHello (SNI, ALPN, JA4/JA3, ECH).
func parseQUICInitialClientHello(payload []byte) (clientHelloMetadata, bool) {
	if len(payload) < 64 {
		return clientHelloMetadata{}, false
	}
	if len(payload) > maxTLSInspectionBytes {
		payload = payload[:maxTLSInspectionBytes]
	}
	first := payload[0]
	// Long header has header form bit (0x80) and fixed bit (0x40) set.
	if (first & 0xc0) != 0xc0 {
		return clientHelloMetadata{}, false
	}
	version := binary.BigEndian.Uint32(payload[1:5])
	pktType := (first & 0x30) >> 4
	var (
		salt     []byte
		keyLabel string
		ivLabel  string
		hpLabel  string
	)
	switch version {
	case quicVersion1:
		if pktType != 0x00 {
			return clientHelloMetadata{}, false
		}
		salt = quicV1InitialSalt
		keyLabel = "quic key"
		ivLabel = "quic iv"
		hpLabel = "quic hp"
	case quicVersion2:
		if pktType != 0x01 {
			return clientHelloMetadata{}, false
		}
		salt = quicV2InitialSalt
		keyLabel = "quicv2 key"
		ivLabel = "quicv2 iv"
		hpLabel = "quicv2 hp"
	default:
		return clientHelloMetadata{}, false
	}

	pos := 5
	if pos >= len(payload) {
		return clientHelloMetadata{}, false
	}
	dcidLen := int(payload[pos])
	pos++
	if dcidLen < 0 || dcidLen > 20 || pos+dcidLen > len(payload) {
		return clientHelloMetadata{}, false
	}
	dcid := payload[pos : pos+dcidLen]
	pos += dcidLen

	if pos >= len(payload) {
		return clientHelloMetadata{}, false
	}
	scidLen := int(payload[pos])
	pos++
	if scidLen < 0 || scidLen > 20 || pos+scidLen > len(payload) {
		return clientHelloMetadata{}, false
	}
	pos += scidLen

	tokenLen, n := readQUICVarint(payload[pos:])
	if n == 0 || tokenLen > uint64(len(payload)-pos-n) {
		return clientHelloMetadata{}, false
	}
	pos += n + int(tokenLen)

	remLen, n := readQUICVarint(payload[pos:])
	if n == 0 {
		return clientHelloMetadata{}, false
	}
	pos += n
	pnOffset := pos
	if remLen < 20 || pnOffset+int(remLen) > len(payload) {
		return clientHelloMetadata{}, false
	}
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > pnOffset+int(remLen) {
		return clientHelloMetadata{}, false
	}

	initialSecret := hkdfExtractSHA256(salt, dcid)
	clientSecret := hkdfExpandLabelSHA256(initialSecret, "client in", 32)
	key := hkdfExpandLabelSHA256(clientSecret, keyLabel, 16)
	iv := hkdfExpandLabelSHA256(clientSecret, ivLabel, 12)
	hp := hkdfExpandLabelSHA256(clientSecret, hpLabel, 16)

	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return clientHelloMetadata{}, false
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], payload[sampleOffset:sampleOffset+16])

	unmaskedFirst := first ^ (mask[0] & 0x0f)
	pnLen := int(unmaskedFirst&0x03) + 1
	if pnOffset+pnLen+16 > pnOffset+int(remLen) {
		return clientHelloMetadata{}, false
	}

	var pn uint64
	header := make([]byte, pnOffset+pnLen)
	copy(header, payload[:pnOffset+pnLen])
	header[0] = unmaskedFirst
	for i := 0; i < pnLen; i++ {
		header[pnOffset+i] ^= mask[1+i]
		pn = (pn << 8) | uint64(header[pnOffset+i])
	}

	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}

	aeadBlock, err := aes.NewCipher(key)
	if err != nil {
		return clientHelloMetadata{}, false
	}
	gcm, err := cipher.NewGCM(aeadBlock)
	if err != nil {
		return clientHelloMetadata{}, false
	}
	ciphertext := payload[pnOffset+pnLen : pnOffset+int(remLen)]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return clientHelloMetadata{}, false
	}

	cryptoStream := extractQUICCryptoStream(plaintext)
	if len(cryptoStream) == 0 {
		return clientHelloMetadata{}, false
	}
	return parseTLSClientHelloHandshake(cryptoStream, "quic")
}

func extractQUICCryptoStream(frames []byte) []byte {
	var (
		buf    []byte
		maxEnd int
		pos    int
	)
	for pos < len(frames) {
		frameType, n := readQUICVarint(frames[pos:])
		if n == 0 {
			break
		}
		pos += n
		switch frameType {
		case 0x00, 0x01: // PADDING or PING
			continue
		case 0x02, 0x03: // ACK
			// largest ack, ack delay, range count, first ack range
			_, n1 := readQUICVarint(frames[pos:])
			if n1 == 0 {
				return buf[:maxEnd]
			}
			pos += n1
			_, n2 := readQUICVarint(frames[pos:])
			if n2 == 0 {
				return buf[:maxEnd]
			}
			pos += n2
			rangeCount, n3 := readQUICVarint(frames[pos:])
			if n3 == 0 {
				return buf[:maxEnd]
			}
			pos += n3
			_, n4 := readQUICVarint(frames[pos:])
			if n4 == 0 {
				return buf[:maxEnd]
			}
			pos += n4
			for r := uint64(0); r < rangeCount; r++ {
				_, ng := readQUICVarint(frames[pos:])
				if ng == 0 {
					return buf[:maxEnd]
				}
				pos += ng
				_, nr := readQUICVarint(frames[pos:])
				if nr == 0 {
					return buf[:maxEnd]
				}
				pos += nr
			}
			if frameType == 0x03 {
				for e := 0; e < 3; e++ {
					_, ne := readQUICVarint(frames[pos:])
					if ne == 0 {
						return buf[:maxEnd]
					}
					pos += ne
				}
			}
		case 0x06: // CRYPTO frame
			offset, n1 := readQUICVarint(frames[pos:])
			if n1 == 0 {
				return buf[:maxEnd]
			}
			pos += n1
			length, n2 := readQUICVarint(frames[pos:])
			if n2 == 0 || length > uint64(len(frames)-pos-n2) {
				return buf[:maxEnd]
			}
			pos += n2
			data := frames[pos : pos+int(length)]
			pos += int(length)
			if offset >= maxQUICCryptoBytes || length == 0 {
				continue
			}
			end := int(offset) + len(data)
			if end > maxQUICCryptoBytes {
				end = maxQUICCryptoBytes
				data = data[:end-int(offset)]
			}
			if buf == nil {
				buf = make([]byte, maxQUICCryptoBytes)
			}
			copy(buf[int(offset):end], data)
			if end > maxEnd {
				maxEnd = end
			}
		default:
			return buf[:maxEnd]
		}
	}
	if buf == nil || maxEnd == 0 {
		return nil
	}
	return buf[:maxEnd]
}

func readQUICVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	prefix := b[0] >> 6
	length := 1 << prefix
	if len(b) < length {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		v = (v << 8) | uint64(b[i])
	}
	return v, length
}

func hkdfExtractSHA256(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpandLabelSHA256(secret []byte, label string, length int) []byte {
	fullLabel := "tls13 " + label
	info := make([]byte, 2+1+len(fullLabel)+1)
	binary.BigEndian.PutUint16(info[0:2], uint16(length))
	info[2] = byte(len(fullLabel))
	copy(info[3:], fullLabel)
	info[3+len(fullLabel)] = 0

	mac := hmac.New(sha256.New, secret)
	mac.Write(info)
	mac.Write([]byte{0x01})
	sum := mac.Sum(nil)
	out := make([]byte, length)
	copy(out, sum[:length])
	return out
}
