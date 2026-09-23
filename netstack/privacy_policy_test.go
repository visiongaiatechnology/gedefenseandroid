package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func buildPrivacyPolicyFixture(t *testing.T, rules []privacyPolicyRule, profile ...byte) []byte {
	t.Helper()
	var body bytes.Buffer
	for _, rule := range rules {
		flags := byte(0)
		if rule.IncludeSubdomains {
			flags |= 0x01
		}
		if rule.Essential {
			flags |= 0x02
		}
		id := []byte(rule.ID)
		domain := []byte(rule.Domain)
		fixed := []byte{flags, byte(rule.Confidence), byte(rule.BreakageRisk), byte(rule.Action), 0, 0, 0, 0}
		binary.BigEndian.PutUint16(fixed[4:6], uint16(len(id)))
		binary.BigEndian.PutUint16(fixed[6:8], uint16(len(domain)))
		body.Write(fixed)
		body.Write(id)
		body.Write(domain)
	}
	payload := body.Bytes()
	digest := sha256.Sum256(payload)
	out := make([]byte, 44+len(payload))
	copy(out[:4], []byte("GDPI"))
	out[4] = 1
	out[5] = 1
	if len(profile) > 0 {
		out[5] = profile[0]
	}
	binary.BigEndian.PutUint32(out[8:12], uint32(len(rules)))
	copy(out[12:44], digest[:])
	copy(out[44:], payload)
	return out
}

func TestPrivacyPolicyPrecedence(t *testing.T) {
	blob := buildPrivacyPolicyFixture(t, []privacyPolicyRule{
		{ID: "analytics-parent", Domain: "example.test", IncludeSubdomains: true, Confidence: privacyHigh, BreakageRisk: privacyRiskLow, Action: privacyBlock},
		{ID: "essential-child", Domain: "critical.example.test", IncludeSubdomains: true, Essential: true, Confidence: privacyHigh, BreakageRisk: privacyRiskLow, Action: privacyAllow},
		{ID: "observe-medium", Domain: "diag.example.test", Confidence: privacyMedium, BreakageRisk: privacyRiskMedium, Action: privacyObserve},
	})
	policy, err := loadPrivacyPolicy(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if got := policy.decide("api.example.test"); got.Action != privacyBlock || got.RuleID != "analytics-parent" {
		t.Fatalf("expected parent block, got %+v", got)
	}
	if got := policy.decide("x.critical.example.test"); got.Action != privacyAllow || got.RuleID != "essential-child" {
		t.Fatalf("essential child must override parent block, got %+v", got)
	}
	if got := policy.decide("diag.example.test"); got.Action != privacyBlock || got.RuleID != "analytics-parent" {
		// Registry precedence intentionally prefers higher confidence/lower breakage over specificity.
		t.Fatalf("precedence mismatch, got %+v", got)
	}
	if got := policy.decide("unrelated.test"); got.Action != privacyAllow || got.RuleID != "" {
		t.Fatalf("unrelated domain must allow, got %+v", got)
	}
}

func TestPrivacyPolicyRejectsTamper(t *testing.T) {
	blob := buildPrivacyPolicyFixture(t, []privacyPolicyRule{{
		ID: "analytics-rule", Domain: "metrics.example.test", Confidence: privacyHigh, BreakageRisk: privacyRiskLow, Action: privacyBlock,
	}})
	blob[len(blob)-1] ^= 0x01
	if _, err := loadPrivacyPolicy(bytes.NewReader(blob)); err == nil {
		t.Fatal("tampered policy must fail")
	}
}

func TestCanonicalPrivacyDomain(t *testing.T) {
	if got := canonicalPrivacyDomain("A.Example.TEST."); got != "a.example.test" {
		t.Fatalf("unexpected canonical domain %q", got)
	}
	for _, bad := range []string{"single", "-bad.example", "bad_.example", "../example.test"} {
		if got := canonicalPrivacyDomain(bad); got != "" {
			t.Fatalf("invalid domain accepted %q => %q", bad, got)
		}
	}
}

func TestEncryptedDNSPortPolicy(t *testing.T) {
	strictBlob := buildPrivacyPolicyFixture(t, nil, 3)
	strict, err := loadPrivacyPolicy(bytes.NewReader(strictBlob))
	if err != nil {
		t.Fatalf("load strict policy: %v", err)
	}
	balancedBlob := buildPrivacyPolicyFixture(t, nil, 2)
	balanced, err := loadPrivacyPolicy(bytes.NewReader(balancedBlob))
	if err != nil {
		t.Fatalf("load balanced policy: %v", err)
	}
	tcpDoT := parsedPacket{Protocol: protoTCP, HasPorts: true, DstPort: 853}
	udpDoQ := parsedPacket{Protocol: protoUDP, HasPorts: true, DstPort: 853}
	https := parsedPacket{Protocol: protoTCP, HasPorts: true, DstPort: 443}
	if got := strict.encryptedDNSAction(tcpDoT); got != privacyBlock {
		t.Fatalf("strict DoT should block, got %v", got)
	}
	if got := strict.encryptedDNSAction(udpDoQ); got != privacyBlock {
		t.Fatalf("strict DoQ should block, got %v", got)
	}
	if got := balanced.encryptedDNSAction(tcpDoT); got != privacyObserve {
		t.Fatalf("balanced DoT should observe, got %v", got)
	}
	if got := strict.encryptedDNSAction(https); got != privacyAllow {
		t.Fatalf("generic HTTPS must not be blocked as DoH, got %v", got)
	}
}
