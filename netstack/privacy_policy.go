package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

type privacyAction uint8

type privacyConfidence uint8

type privacyBreakageRisk uint8

const (
	privacyAllow privacyAction = iota
	privacyObserve
	privacyBlock
)

const (
	privacyLow privacyConfidence = iota
	privacyMedium
	privacyHigh
)

const (
	privacyRiskLow privacyBreakageRisk = iota
	privacyRiskMedium
	privacyRiskHigh
)

type privacyPolicyRule struct {
	ID                string
	Domain            string
	IncludeSubdomains bool
	Essential         bool
	Confidence        privacyConfidence
	BreakageRisk      privacyBreakageRisk
	Action            privacyAction
}

type privacyDecision struct {
	Action privacyAction
	RuleID string
}

type privacyPolicy struct {
	exact   map[string][]privacyPolicyRule
	suffix  map[string][]privacyPolicyRule
	count   int
	profile uint8
}

func loadPrivacyPolicy(r io.Reader) (*privacyPolicy, error) {
	if r == nil {
		return nil, errors.New("privacy policy reader missing")
	}
	br := bufio.NewReaderSize(r, 32*1024)
	header := make([]byte, 44)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, err
	}
	if string(header[:4]) != "GDPI" || header[4] != 1 || header[6] != 0 || header[7] != 0 {
		return nil, errors.New("invalid privacy policy header")
	}
	if header[5] > 3 {
		return nil, errors.New("invalid privacy profile")
	}
	count := int(binary.BigEndian.Uint32(header[8:12]))
	if count < 0 || count > 8192 {
		return nil, errors.New("privacy policy record bound")
	}
	expectedDigest := header[12:44]
	hash := sha256.New()
	policy := &privacyPolicy{
		exact:   make(map[string][]privacyPolicyRule),
		suffix:  make(map[string][]privacyPolicyRule),
		profile: header[5],
	}
	ids := make(map[string]struct{}, count)
	for i := 0; i < count; i++ {
		fixed := make([]byte, 8)
		if _, err := io.ReadFull(br, fixed); err != nil {
			return nil, err
		}
		_, _ = hash.Write(fixed)
		flags := fixed[0]
		if flags&^byte(0x03) != 0 {
			return nil, errors.New("invalid privacy policy flags")
		}
		confidence := privacyConfidence(fixed[1])
		risk := privacyBreakageRisk(fixed[2])
		action := privacyAction(fixed[3])
		if confidence > privacyHigh || risk > privacyRiskHigh || action > privacyBlock {
			return nil, errors.New("invalid privacy policy enum")
		}
		idLen := int(binary.BigEndian.Uint16(fixed[4:6]))
		domainLen := int(binary.BigEndian.Uint16(fixed[6:8]))
		if idLen < 3 || idLen > 96 || domainLen < 1 || domainLen > 253 {
			return nil, errors.New("privacy policy record size invalid")
		}
		body := make([]byte, idLen+domainLen)
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, err
		}
		_, _ = hash.Write(body)
		id := string(body[:idLen])
		domain := string(body[idLen:])
		if !validPrivacyRuleID(id) || canonicalPrivacyDomain(domain) != domain {
			return nil, errors.New("privacy policy record invalid")
		}
		if _, exists := ids[id]; exists {
			return nil, errors.New("duplicate privacy policy rule id")
		}
		ids[id] = struct{}{}
		essential := flags&0x02 != 0
		if essential && action != privacyAllow {
			return nil, errors.New("essential privacy rule must allow")
		}
		rule := privacyPolicyRule{
			ID:                id,
			Domain:            domain,
			IncludeSubdomains: flags&0x01 != 0,
			Essential:         essential,
			Confidence:        confidence,
			BreakageRisk:      risk,
			Action:            action,
		}
		if rule.IncludeSubdomains {
			policy.suffix[domain] = append(policy.suffix[domain], rule)
		} else {
			policy.exact[domain] = append(policy.exact[domain], rule)
		}
		policy.count++
	}
	if b, err := br.ReadByte(); err == nil {
		_ = b
		return nil, errors.New("trailing privacy policy bytes")
	} else if !errors.Is(err, io.EOF) {
		return nil, err
	}
	actualDigest := hash.Sum(nil)
	if subtle.ConstantTimeCompare(expectedDigest, actualDigest) != 1 {
		return nil, errors.New("privacy policy fingerprint mismatch")
	}
	return policy, nil
}

func (p *privacyPolicy) decide(rawDomain string) privacyDecision {
	if p == nil || p.count == 0 {
		return privacyDecision{Action: privacyAllow}
	}
	domain := canonicalPrivacyDomain(rawDomain)
	if domain == "" {
		return privacyDecision{Action: privacyAllow}
	}
	var selected privacyPolicyRule
	found := false
	consider := func(rule privacyPolicyRule) {
		if !found || privacyRuleHigher(rule, selected) {
			selected = rule
			found = true
		}
	}
	for _, rule := range p.exact[domain] {
		consider(rule)
	}
	cursor := domain
	for {
		for _, rule := range p.suffix[cursor] {
			consider(rule)
		}
		dot := strings.IndexByte(cursor, '.')
		if dot < 0 || dot+1 >= len(cursor) {
			break
		}
		cursor = cursor[dot+1:]
	}
	if !found {
		return privacyDecision{Action: privacyAllow}
	}
	return privacyDecision{Action: selected.Action, RuleID: selected.ID}
}

// encryptedDNSAction provides transport-level visibility for dedicated encrypted DNS ports
// without decrypting TLS. Profile 3 is STRICT and blocks standard DoT/DoQ port 853;
// Conservative/Balanced only observe. DoH on shared HTTPS/443 is handled only when a known
// resolver bootstrap domain is visible to the DNS policy; no TLS MITM or generic HTTPS blocking.
func (p *privacyPolicy) encryptedDNSAction(packet parsedPacket) privacyAction {
	if p == nil || p.profile == 0 || !packet.HasPorts || packet.DstPort != 853 ||
		(packet.Protocol != protoTCP && packet.Protocol != protoUDP) {
		return privacyAllow
	}
	if p.profile == 3 {
		return privacyBlock
	}
	return privacyObserve
}

func privacyRuleHigher(a, b privacyPolicyRule) bool {
	if a.Essential != b.Essential {
		return a.Essential
	}
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	if a.BreakageRisk != b.BreakageRisk {
		return a.BreakageRisk < b.BreakageRisk
	}
	if len(a.Domain) != len(b.Domain) {
		return len(a.Domain) > len(b.Domain)
	}
	return a.ID > b.ID
}

func canonicalPrivacyDomain(raw string) string {
	value := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if len(value) < 1 || len(value) > 253 {
		return ""
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return ""
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for i := 0; i < len(label); i++ {
			b := label[i]
			if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-') {
				return ""
			}
		}
	}
	return value
}

func validPrivacyRuleID(value string) bool {
	if len(value) < 3 || len(value) > 96 {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '.' || b == '-') {
			return false
		}
	}
	return value[0] >= 'a' && value[0] <= 'z' || value[0] >= '0' && value[0] <= '9'
}
