package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"sync"

	wgconn "golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
)

type egressMode uint8

const (
	egressDirect egressMode = iota
	egressWireGuard
	egressWireGuardStrict
)

const (
	maxWireGuardConfigBytes = 16 * 1024
	maxWireGuardAllowedIPs  = 64
)

type wireGuardTransport struct {
	device    *wgdevice.Device
	tun       *wireGuardTun
	tracker   *packetFlowTracker
	closeOnce sync.Once
}

func newWireGuardTransport(config []byte, mtu int, writer *tunWriter, telemetry *telemetry, protector wireGuardSocketProtector) (*wireGuardTransport, error) {
	bind, err := newProtectedWireGuardBind(wgconn.NewDefaultBind(), protector)
	if err != nil {
		return nil, err
	}
	return newWireGuardTransportWithBind(config, mtu, writer, telemetry, bind)
}

func newWireGuardTransportWithBind(config []byte, mtu int, writer *tunWriter, telemetry *telemetry, bind wgconn.Bind) (*wireGuardTransport, error) {
	if bind == nil {
		return nil, errors.New("wireguard bind missing")
	}
	normalized, err := validateWireGuardUAPI(config)
	if err != nil {
		return nil, err
	}
	defer clear(normalized)
	tracker := newPacketFlowTracker(telemetry)
	tun, err := newWireGuardTun(mtu, writer, tracker)
	if err != nil {
		tracker.close()
		return nil, err
	}
	logger := &wgdevice.Logger{Verbosef: wgdevice.DiscardLogf, Errorf: wgdevice.DiscardLogf}
	dev := wgdevice.NewDevice(tun, bind, logger)
	if err := dev.IpcSetOperation(bytes.NewReader(normalized)); err != nil {
		dev.Close()
		tracker.close()
		return nil, fmt.Errorf("wireguard config rejected: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		tracker.close()
		return nil, fmt.Errorf("wireguard up failed: %w", err)
	}
	return &wireGuardTransport{device: dev, tun: tun, tracker: tracker}, nil
}

func (w *wireGuardTransport) send(packet []byte, parsed parsedPacket, match policyMatch) bool {
	if w == nil || w.tun == nil {
		return false
	}
	if !w.tracker.handleOutbound(parsed, match, packet) {
		return false
	}
	return w.tun.enqueue(packet)
}

func (w *wireGuardTransport) close() {
	if w == nil {
		return
	}
	w.closeOnce.Do(func() {
		if w.device != nil {
			w.device.Close()
		} else if w.tun != nil {
			_ = w.tun.Close()
		}
		if w.tracker != nil {
			w.tracker.close()
		}
	})
}

func loadWireGuardConfig(file *os.File) ([]byte, error) {
	if file == nil {
		return nil, errors.New("wireguard config fd missing")
	}
	limited := io.LimitReader(file, maxWireGuardConfigBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > maxWireGuardConfigBytes {
		return nil, errors.New("wireguard config size invalid")
	}
	normalized, err := validateWireGuardUAPI(raw)
	clear(raw)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

func validateWireGuardUAPI(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxWireGuardConfigBytes || bytes.IndexByte(raw, 0) >= 0 || bytes.Contains(raw, []byte{'\r'}) {
		return nil, errors.New("wireguard config encoding invalid")
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), 4096)

	var privateKey, publicKey [64]byte
	privateKeySeen := false
	publicKeySeen := false
	endpointSeen := false
	var presharedSeen bool
	var keepaliveSeen bool
	var replacePeers, replaceAllowed bool
	allowedCount := 0
	fullV4 := false
	lineCount := 0
	terminated := false
	out := bytes.NewBuffer(make([]byte, 0, len(raw)+1))
	defer func() {
		clear(privateKey[:])
		clear(publicKey[:])
		clear(out.Bytes())
	}()

	for scanner.Scan() {
		lineCount++
		if lineCount > 128 {
			return nil, errors.New("wireguard config line limit exceeded")
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			terminated = true
			continue
		}
		if terminated {
			return nil, errors.New("wireguard config trailing data invalid")
		}
		split := bytes.IndexByte(line, '=')
		if split <= 0 || split == len(line)-1 {
			return nil, errors.New("wireguard config line invalid")
		}
		key, value := line[:split], line[split+1:]
		switch string(key) {
		case "private_key":
			if privateKeySeen || !validWireGuardHexKeyBytes(value, false) {
				return nil, errors.New("wireguard private key invalid")
			}
			copy(privateKey[:], value)
			privateKeySeen = true
		case "replace_peers":
			if replacePeers || !bytes.Equal(value, []byte("true")) {
				return nil, errors.New("wireguard replace_peers invalid")
			}
			replacePeers = true
		case "public_key":
			if publicKeySeen || !validWireGuardHexKeyBytes(value, false) {
				return nil, errors.New("wireguard public key invalid")
			}
			copy(publicKey[:], value)
			publicKeySeen = true
		case "preshared_key":
			if presharedSeen || !validWireGuardHexKeyBytes(value, true) {
				return nil, errors.New("wireguard preshared key invalid")
			}
			presharedSeen = true
		case "endpoint":
			if endpointSeen {
				return nil, errors.New("wireguard endpoint duplicated")
			}
			ap, err := netip.ParseAddrPort(string(value))
			if err != nil || !validWireGuardEndpoint(ap) {
				return nil, errors.New("wireguard endpoint invalid")
			}
			endpointSeen = true
		case "persistent_keepalive_interval":
			if keepaliveSeen {
				return nil, errors.New("wireguard keepalive duplicated")
			}
			keepaliveSeen = true
			n, err := strconv.ParseUint(string(value), 10, 16)
			if err != nil || n > 65535 {
				return nil, errors.New("wireguard keepalive invalid")
			}
		case "replace_allowed_ips":
			if replaceAllowed || !bytes.Equal(value, []byte("true")) {
				return nil, errors.New("wireguard replace_allowed_ips invalid")
			}
			replaceAllowed = true
		case "allowed_ip":
			allowedCount++
			if allowedCount > maxWireGuardAllowedIPs {
				return nil, errors.New("wireguard allowed-ip limit exceeded")
			}
			prefix, err := netip.ParsePrefix(string(value))
			if err != nil || !prefix.IsValid() || prefix != prefix.Masked() {
				return nil, errors.New("wireguard allowed ip invalid")
			}
			if bytes.Equal(value, []byte("0.0.0.0/0")) {
				fullV4 = true
			}
		default:
			return nil, errors.New("wireguard config key not allowed")
		}
		_, _ = out.Write(key)
		_ = out.WriteByte('=')
		_, _ = out.Write(value)
		_ = out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !privateKeySeen || !publicKeySeen || !endpointSeen || !keepaliveSeen || !replacePeers || !replaceAllowed || allowedCount == 0 || !fullV4 {
		return nil, errors.New("wireguard config incomplete or not full-tunnel")
	}
	if bytes.Equal(privateKey[:], publicKey[:]) {
		return nil, errors.New("wireguard private/public key collision")
	}
	_ = out.WriteByte('\n')
	normalized := append([]byte(nil), out.Bytes()...)
	return normalized, nil
}

func validWireGuardEndpoint(endpoint netip.AddrPort) bool {
	addr := endpoint.Addr()
	return addr.IsValid() && endpoint.Port() != 0 && !addr.IsUnspecified() && !addr.IsLoopback() &&
		!addr.IsMulticast() && !addr.IsLinkLocalUnicast()
}

func validWireGuardHexKeyBytes(value []byte, allowZero bool) bool {
	if len(value) != 64 {
		return false
	}
	nonZero := false
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
		if c != '0' {
			nonZero = true
		}
	}
	return allowZero || nonZero
}
