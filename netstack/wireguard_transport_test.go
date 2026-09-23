package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	wgconn "golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

const (
	testWGPrivate = "0101010101010101010101010101010101010101010101010101010101010101"
	testWGPublic  = "0202020202020202020202020202020202020202020202020202020202020202"
)

func validWireGuardTestUAPI() []byte {
	return []byte("private_key=" + testWGPrivate + "\n" +
		"replace_peers=true\n" +
		"public_key=" + testWGPublic + "\n" +
		"endpoint=203.0.113.10:51820\n" +
		"persistent_keepalive_interval=25\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=0.0.0.0/0\n\n")
}

func TestValidateWireGuardUAPIAcceptsFullTunnel(t *testing.T) {
	raw := validWireGuardTestUAPI()
	normalized, err := validateWireGuardUAPI(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(normalized)
	if !bytes.Equal(raw, normalized) {
		t.Fatalf("normalization changed canonical UAPI: %q", normalized)
	}
}

func TestValidateWireGuardUAPIAcceptsDualStackFullTunnel(t *testing.T) {
	raw := bytes.Replace(validWireGuardTestUAPI(), []byte("allowed_ip=0.0.0.0/0\n"), []byte("allowed_ip=0.0.0.0/0\nallowed_ip=::/0\n"), 1)
	normalized, err := validateWireGuardUAPI(raw)
	if err != nil {
		t.Fatal(err)
	}
	clear(normalized)
}

func TestValidateWireGuardUAPIRejectsPartialTunnel(t *testing.T) {
	raw := bytes.Replace(validWireGuardTestUAPI(), []byte("allowed_ip=0.0.0.0/0"), []byte("allowed_ip=10.0.0.0/8"), 1)
	if _, err := validateWireGuardUAPI(raw); err == nil || !strings.Contains(err.Error(), "full-tunnel") {
		t.Fatalf("partial tunnel accepted: %v", err)
	}
}

func TestValidateWireGuardUAPIRejectsTrailingDataAfterTerminator(t *testing.T) {
	raw := append(validWireGuardTestUAPI(), []byte("allowed_ip=::/0\n")...)
	if _, err := validateWireGuardUAPI(raw); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing UAPI accepted: %v", err)
	}
}

func TestValidateWireGuardUAPIRejectsUnknownKey(t *testing.T) {
	raw := bytes.Replace(validWireGuardTestUAPI(), []byte("replace_peers=true\n"), []byte("replace_peers=true\nfwmark=1\n"), 1)
	if _, err := validateWireGuardUAPI(raw); err == nil {
		t.Fatal("unknown UAPI key accepted")
	}
}

func TestLoadWireGuardConfigRejectsOversize(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "wireguard-config-*.uapi")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	oversized := bytes.Repeat([]byte{'x'}, maxWireGuardConfigBytes+1)
	if _, err := file.Write(oversized); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWireGuardConfig(file); err == nil {
		t.Fatal("oversized WireGuard config accepted")
	}
}

func TestWireGuardTunRejectsOversizePeerPacketBeforeAndroid(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readEnd.Close()
	writer := newTunWriter(writeEnd)
	telemetry := newTelemetry(io.Discard)
	tracker := newPacketFlowTracker(telemetry)
	tun, err := newWireGuardTun(1280, writer, tracker)
	if err != nil {
		tracker.close()
		telemetry.close()
		writer.close()
		t.Fatal(err)
	}
	defer func() {
		_ = tun.Close()
		tracker.close()
		telemetry.close()
		writer.close()
	}()

	oversize := make([]byte, 1281)
	oversize[0] = 0x45
	if written, err := tun.Write([][]byte{oversize}, 0); err == nil || written != 0 {
		t.Fatalf("oversize peer packet admitted: written=%d err=%v", written, err)
	}
}

func TestPacketFlowTrackerRejectsUnsolicitedIngress(t *testing.T) {
	telemetry := newTelemetry(io.Discard)
	tracker := newPacketFlowTracker(telemetry)
	defer func() {
		tracker.close()
		telemetry.close()
	}()

	response := buildUDPPacket(4, netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("10.77.0.2"), 53, 42311, []byte("response"))
	if tracker.handleInbound(response) {
		t.Fatal("unsolicited WireGuard ingress was admitted")
	}

	request := buildUDPPacket(4, netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("198.51.100.7"), 42311, 53, []byte("request"))
	parsed, err := parsePacket(request)
	if err != nil {
		t.Fatal(err)
	}
	if !tracker.handleOutbound(parsed, policyMatch{Action: actionAllow}, request) {
		t.Fatal("outbound flow registration failed")
	}
	if !tracker.handleInbound(response) {
		t.Fatal("response for tracked flow was rejected")
	}
}

func TestValidateWireGuardUAPIRejectsUnsafeEndpointAndDuplicateKeepalive(t *testing.T) {
	unsafe := bytes.Replace(validWireGuardTestUAPI(), []byte("endpoint=203.0.113.10:51820"), []byte("endpoint=127.0.0.1:51820"), 1)
	if _, err := validateWireGuardUAPI(unsafe); err == nil || !strings.Contains(err.Error(), "endpoint invalid") {
		t.Fatalf("unsafe endpoint accepted: %v", err)
	}

	duplicate := bytes.Replace(
		validWireGuardTestUAPI(),
		[]byte("persistent_keepalive_interval=25\n"),
		[]byte("persistent_keepalive_interval=25\npersistent_keepalive_interval=25\n"),
		1,
	)
	if _, err := validateWireGuardUAPI(duplicate); err == nil || !strings.Contains(err.Error(), "keepalive duplicated") {
		t.Fatalf("duplicate keepalive accepted: %v", err)
	}
}

func TestValidateWireGuardUAPIRejectsPrivatePublicKeyCollision(t *testing.T) {
	raw := bytes.Replace(validWireGuardTestUAPI(), []byte("public_key="+testWGPublic), []byte("public_key="+testWGPrivate), 1)
	if _, err := validateWireGuardUAPI(raw); err == nil || !strings.Contains(err.Error(), "key collision") {
		t.Fatalf("private/public key collision accepted: %v", err)
	}
}

type wireGuardIntegrationTun struct {
	mtu       int
	outbound  chan []byte
	decrypted chan []byte
	events    chan wgtun.Event
	done      chan struct{}
	closeOnce sync.Once
}

func newWireGuardIntegrationTun(mtu int) *wireGuardIntegrationTun {
	return &wireGuardIntegrationTun{
		mtu:       mtu,
		outbound:  make(chan []byte, 8),
		decrypted: make(chan []byte, 8),
		events:    make(chan wgtun.Event, 1),
		done:      make(chan struct{}),
	}
}

func (t *wireGuardIntegrationTun) File() *os.File { return nil }

func (t *wireGuardIntegrationTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) || offset < 0 {
		return 0, io.ErrShortBuffer
	}
	select {
	case <-t.done:
		return 0, os.ErrClosed
	case packet := <-t.outbound:
		if offset > len(bufs[0]) || len(packet) > len(bufs[0])-offset {
			return 0, io.ErrShortBuffer
		}
		copy(bufs[0][offset:], packet)
		sizes[0] = len(packet)
		return 1, nil
	}
}

func (t *wireGuardIntegrationTun) Write(bufs [][]byte, offset int) (int, error) {
	written := 0
	for _, buf := range bufs {
		if offset < 0 || offset > len(buf) {
			return written, io.ErrShortBuffer
		}
		packet := append([]byte(nil), buf[offset:]...)
		select {
		case <-t.done:
			return written, os.ErrClosed
		case t.decrypted <- packet:
			written++
		default:
			return written, io.ErrShortBuffer
		}
	}
	return written, nil
}

func (t *wireGuardIntegrationTun) MTU() (int, error)          { return t.mtu, nil }
func (t *wireGuardIntegrationTun) Name() (string, error)      { return "gedefense-wg-test", nil }
func (t *wireGuardIntegrationTun) Events() <-chan wgtun.Event { return t.events }
func (t *wireGuardIntegrationTun) BatchSize() int             { return 8 }
func (t *wireGuardIntegrationTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.done)
		close(t.events)
	})
	return nil
}

func wireGuardPublicHex(t *testing.T, privateHex string) string {
	t.Helper()
	privateKey, err := hex.DecodeString(privateHex)
	if err != nil || len(privateKey) != 32 {
		t.Fatalf("invalid test private key: %v", err)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	clear(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(publicKey)
}

func wireGuardListenPort(t *testing.T, device *wgdevice.Device) uint16 {
	t.Helper()
	var status bytes.Buffer
	if err := device.IpcGetOperation(&status); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(status.String(), "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil || port == 0 {
				t.Fatalf("invalid WireGuard listen port %q", value)
			}
			return uint16(port)
		}
	}
	t.Fatalf("WireGuard listen port missing: %q", status.String())
	return 0
}

func testNonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addrs {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			continue
		}
		addr := prefix.Addr().Unmap()
		if addr.Is4() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsUnspecified() {
			return addr.String()
		}
	}
	t.Skip("no non-loopback IPv4 address available for encrypted WireGuard integration test")
	return ""
}

func TestWireGuardTransportEncryptedUDPRoundTrip(t *testing.T) {
	const serverPrivate = "0303030303030303030303030303030303030303030303030303030303030303"
	clientPublic := wireGuardPublicHex(t, testWGPrivate)
	serverPublic := wireGuardPublicHex(t, serverPrivate)

	serverTun := newWireGuardIntegrationTun(1280)
	serverDevice := wgdevice.NewDevice(serverTun, wgconn.NewDefaultBind(), &wgdevice.Logger{Verbosef: wgdevice.DiscardLogf, Errorf: wgdevice.DiscardLogf})
	defer serverDevice.Close()
	serverConfig := []byte("private_key=" + serverPrivate + "\n" +
		"listen_port=0\n" +
		"replace_peers=true\n" +
		"public_key=" + clientPublic + "\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=10.77.0.2/32\n\n")
	if err := serverDevice.IpcSetOperation(bytes.NewReader(serverConfig)); err != nil {
		t.Fatal(err)
	}
	if err := serverDevice.Up(); err != nil {
		t.Fatal(err)
	}
	serverPort := wireGuardListenPort(t, serverDevice)

	testEndpoint := testNonLoopbackIPv4(t)
	clientConfig := []byte("private_key=" + testWGPrivate + "\n" +
		"replace_peers=true\n" +
		"public_key=" + serverPublic + "\n" +
		"endpoint=" + testEndpoint + ":" + strconv.Itoa(int(serverPort)) + "\n" +
		"persistent_keepalive_interval=0\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=0.0.0.0/0\n\n")

	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readEnd.Close()
	writer := newTunWriter(writeEnd)
	telemetry := newTelemetry(io.Discard)
	client, err := newWireGuardTransportWithBind(clientConfig, 1280, writer, telemetry, wgconn.NewDefaultBind())
	clear(clientConfig)
	if err != nil {
		writer.close()
		telemetry.close()
		t.Fatal(err)
	}
	defer func() {
		client.close()
		writer.close()
		telemetry.close()
	}()

	request := buildUDPPacket(4, netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("10.77.0.1"), 42311, 53, []byte("gedefense-wireguard-request"))
	parsed, err := parsePacket(request)
	if err != nil {
		t.Fatal(err)
	}
	if !client.send(request, parsed, policyMatch{Action: actionAllow}) {
		t.Fatal("client WireGuard enqueue failed")
	}

	select {
	case got := <-serverTun.decrypted:
		if !bytes.Equal(got, request) {
			t.Fatalf("server plaintext mismatch: got %x want %x", got, request)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive decrypted WireGuard packet")
	}

	response := buildUDPPacket(4, netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr("10.77.0.2"), 53, 42311, []byte("gedefense-wireguard-response"))
	select {
	case serverTun.outbound <- response:
	case <-time.After(time.Second):
		t.Fatal("server outbound TUN queue blocked")
	}

	got := make([]byte, len(response))
	readResult := make(chan error, 1)
	go func() {
		_, readErr := io.ReadFull(readEnd, got)
		readResult <- readErr
	}()
	select {
	case err := <-readResult:
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, response) {
			t.Fatalf("client plaintext mismatch: got %x want %x", got, response)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not receive decrypted WireGuard response")
	}
}

type fakeProtectedBind struct {
	opened       bool
	closed       bool
	fd4          int
	fd6          int
	panic4       bool
	panic6       bool
	receiveCount int
}

func (b *fakeProtectedBind) Open(port uint16) ([]wgconn.ReceiveFunc, uint16, error) {
	b.opened = true
	count := b.receiveCount
	if count == 0 {
		count = 2
	}
	receivers := make([]wgconn.ReceiveFunc, count)
	for i := range receivers {
		receivers[i] = func([][]byte, []int, []wgconn.Endpoint) (int, error) { return 0, nil }
	}
	return receivers, port + 1, nil
}
func (b *fakeProtectedBind) Close() error                                  { b.closed = true; return nil }
func (b *fakeProtectedBind) SetMark(uint32) error                          { return nil }
func (b *fakeProtectedBind) Send([][]byte, wgconn.Endpoint) error          { return nil }
func (b *fakeProtectedBind) ParseEndpoint(string) (wgconn.Endpoint, error) { return nil, nil }
func (b *fakeProtectedBind) BatchSize() int                                { return 1 }
func (b *fakeProtectedBind) PeekLookAtSocketFd4() (int, error) {
	if b.panic4 {
		panic("ipv4 socket unavailable")
	}
	return b.fd4, nil
}
func (b *fakeProtectedBind) PeekLookAtSocketFd6() (int, error) {
	if b.panic6 {
		panic("ipv6 socket unavailable")
	}
	return b.fd6, nil
}

func TestProtectedWireGuardBindProtectsBothSocketsBeforeOpenReturns(t *testing.T) {
	inner := &fakeProtectedBind{fd4: 41, fd6: 42}
	called := false
	bind, err := newProtectedWireGuardBind(inner, func(fds []int) error {
		if !inner.opened {
			t.Fatal("socket protector called before inner bind opened")
		}
		if len(fds) != 2 || fds[0] != 41 || fds[1] != 42 {
			t.Fatalf("unexpected socket fds: %v", fds)
		}
		called = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := bind.Open(51820)
	if err != nil {
		t.Fatal(err)
	}
	if !called || port != 51821 || inner.closed {
		t.Fatalf("protected bind invariant failed: called=%v port=%d closed=%v", called, port, inner.closed)
	}
	if _, _, err := bind.Open(51820); err == nil {
		t.Fatal("protected WireGuard bind unexpectedly allowed a second socket open")
	}
}

func TestProtectedWireGuardBindFailsClosedWhenAndroidRejectsSocket(t *testing.T) {
	inner := &fakeProtectedBind{fd4: 51, fd6: 52}
	bind, err := newProtectedWireGuardBind(inner, func([]int) error { return errors.New("protect denied") })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bind.Open(0); err == nil {
		t.Fatal("socket protection failure was accepted")
	}
	if !inner.closed {
		t.Fatal("unprotected WireGuard bind was not closed")
	}
}

func TestProtectedWireGuardBindFailsClosedWhenUpstreamFDLookupPanics(t *testing.T) {
	inner := &fakeProtectedBind{fd4: 61, fd6: 62, panic6: true}
	bind, err := newProtectedWireGuardBind(inner, func([]int) error {
		t.Fatal("socket protector must not run after fd lookup panic")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bind.Open(0); err == nil || !strings.Contains(err.Error(), "ipv6 socket unavailable") {
		t.Fatalf("upstream fd panic was not converted into fail-closed error: %v", err)
	}
	if !inner.closed {
		t.Fatal("WireGuard bind was not closed after upstream fd lookup panic")
	}
}

func TestProtectedWireGuardBindProtectsSingleAvailableFamily(t *testing.T) {
	inner := &fakeProtectedBind{fd4: 71, fd6: 72, panic6: true, receiveCount: 1}
	called := false
	bind, err := newProtectedWireGuardBind(inner, func(fds []int) error {
		if len(fds) != 1 || fds[0] != 71 {
			t.Fatalf("unexpected single-family socket fds: %v", fds)
		}
		called = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	if !called || inner.closed {
		t.Fatalf("single-family protected bind invariant failed: called=%v closed=%v", called, inner.closed)
	}
}

func TestProtectedWireGuardBindRejectsInconsistentSingleFamily(t *testing.T) {
	inner := &fakeProtectedBind{fd4: 81, fd6: 82, receiveCount: 1}
	bind, err := newProtectedWireGuardBind(inner, func([]int) error {
		t.Fatal("socket protector must not run for inconsistent bind")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bind.Open(0); err == nil || !strings.Contains(err.Error(), "single receive family") {
		t.Fatalf("inconsistent bind was not rejected: %v", err)
	}
	if !inner.closed {
		t.Fatal("inconsistent WireGuard bind was not closed")
	}
}
