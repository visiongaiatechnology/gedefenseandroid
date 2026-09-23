//go:build android || gdandroidhelper

package main

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

const (
	helperProtocolVersion        = byte(5)
	helperProtocolV4             = byte(4)
	helperProtocolV3             = byte(3)
	helperProtocolV2             = byte(2)
	helperProtocolLegacy         = byte(1)
	helperInitBaseSize           = 40
	helperInitSize               = 44
	helperAckSize                = 8
	helperProtectFrameSize       = 8
	helperTokenBytes             = 32
	helperMaxControlBytes        = 2
	helperMaxProtectFDs          = 2
	helperStartupTimeout         = 10 * time.Second
	helperProtectResponseTimeout = 5 * time.Second
)

var (
	helperInitMagic       = [4]byte{'G', 'D', 'V', '2'}
	helperAckMagic        = [4]byte{'G', 'D', 'A', '2'}
	helperProtectMagic    = [4]byte{'G', 'D', 'P', '2'}
	helperProtectAckMagic = [4]byte{'G', 'D', 'R', '2'}
)

func runHelperMain(args []string) int {
	cfg, ok := parseHelperArgs(args)
	if !ok {
		return 64
	}
	_ = os.Remove(cfg.socketPath)
	addr := &net.UnixAddr{Name: cfg.socketPath, Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return 65
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(cfg.socketPath)
	}()
	if err := os.Chmod(cfg.socketPath, 0o600); err != nil {
		return 66
	}
	if err := listener.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		return 67
	}
	conn, err := listener.AcceptUnix()
	if err != nil {
		return 68
	}
	_ = listener.Close()
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(helperStartupTimeout)); err != nil {
		return 69
	}

	init, fds, err := receiveInit(conn)
	if err != nil {
		closeRawFDs(fds)
		return 70
	}
	if subtle.ConstantTimeCompare(init.token[:], cfg.token[:]) != 1 {
		closeRawFDs(fds)
		return 71
	}
	expectedFDs := 3
	switch init.version {
	case helperProtocolVersion:
		expectedFDs = 5 // TUN, telemetry, threat policy, privacy policy, package-egress gate.
	case helperProtocolV4:
		expectedFDs = 4 // TUN, telemetry, threat policy, privacy policy.
	}
	if init.egressMode != egressDirect {
		expectedFDs++
	}
	if len(fds) != expectedFDs {
		closeRawFDs(fds)
		return 72
	}

	policyFile := os.NewFile(uintptr(fds[2]), "gedefense-policy")
	if policyFile == nil {
		closeRawFDs(fds[:2])
		_ = syscall.Close(fds[2])
		return 73
	}
	policy, err := loadPolicy(policyFile)
	_ = policyFile.Close()
	if err != nil {
		closeRawFDs(fds[:2])
		_ = writeAck(conn, 74)
		return 74
	}
	var privacy *privacyPolicy
	var packageGate *packageEgressGate
	wireGuardFDIndex := 3
	if init.version == helperProtocolVersion || init.version == helperProtocolV4 {
		privacyFile := os.NewFile(uintptr(fds[3]), "gedefense-privacy-policy")
		if privacyFile == nil {
			closeRawFDs(fds[:2])
			_ = syscall.Close(fds[3])
			_ = writeAck(conn, 79)
			return 79
		}
		privacy, err = loadPrivacyPolicy(privacyFile)
		_ = privacyFile.Close()
		if err != nil {
			closeRawFDs(fds[:2])
			_ = writeAck(conn, 79)
			return 79
		}
		wireGuardFDIndex = 4
	}
	if init.version == helperProtocolVersion {
		packageGate, err = newPackageEgressGate(fds[4], init.packageGateEnabled)
		if err != nil {
			closeRawFDs(fds[:2])
			_ = writeAck(conn, 80)
			return 80
		}
		wireGuardFDIndex = 5
	}
	var wireGuardConfig []byte
	if init.egressMode != egressDirect {
		configFile := os.NewFile(uintptr(fds[wireGuardFDIndex]), "gedefense-wireguard-config")
		if configFile == nil {
			closeRawFDs(fds[:2])
			_ = syscall.Close(fds[wireGuardFDIndex])
			_ = writeAck(conn, 78)
			return 78
		}
		wireGuardConfig, err = loadWireGuardConfig(configFile)
		_ = configFile.Close()
		if err != nil {
			closeRawFDs(fds[:2])
			_ = writeAck(conn, 78)
			return 78
		}
	}
	setUnderlyingNetworkHandle(0)
	setPowerConstrained(init.powerConstrained)
	setTelemetryDetailed(init.telemetryDetailed)
	var wireGuardProtector wireGuardSocketProtector
	if init.egressMode != egressDirect {
		wireGuardProtector = func(socketFDs []int) error {
			return requestAndroidSocketProtection(conn, socketFDs)
		}
	}
	e, err := newEngine(fds[0], fds[1], policy, privacy, packageGate, init.egressMode, init.tunMTU, wireGuardConfig, wireGuardProtector)
	clear(wireGuardConfig)
	if err != nil {
		// newEngine takes ownership of TUN/telemetry; packageGate is closed by the engine on
		// post-construction failures and explicitly here if construction failed before ownership.
		if packageGate != nil {
			packageGate.close()
		}
		_ = writeAck(conn, 75)
		return 75
	}
	if err := writeAck(conn, 0); err != nil {
		e.close()
		return 76
	}
	_ = conn.SetReadDeadline(time.Time{})

	done := make(chan struct{})
	go func() {
		e.run()
		close(done)
	}()

	control := make(chan helperControl, 4)
	go readControls(conn, control)
	for {
		select {
		case <-done:
			setPowerConstrained(false)
			setTelemetryDetailed(false)
			return 0
		case command, open := <-control:
			if !open {
				e.close()
				<-done
				setPowerConstrained(false)
				setTelemetryDetailed(false)
				return 0
			}
			switch command.kind {
			case 'P':
				setPowerConstrained(command.value != 0)
				e.powerStateChanged()
			case 'V':
				setTelemetryDetailed(command.value != 0)
				e.powerStateChanged()
			case 'Q':
				e.setPackageGateEnabled(command.value != 0)
			case 'S':
				e.close()
				<-done
				setPowerConstrained(false)
				setTelemetryDetailed(false)
				return 0
			default:
				e.close()
				<-done
				setPowerConstrained(false)
				setTelemetryDetailed(false)
				return 77
			}
		}
	}
}

type helperConfig struct {
	socketPath string
	token      [helperTokenBytes]byte
}

type helperInit struct {
	version            byte
	token              [helperTokenBytes]byte
	powerConstrained   bool
	telemetryDetailed  bool
	egressMode         egressMode
	tunMTU             int
	packageGateEnabled bool
}

type helperControl struct {
	kind  byte
	value byte
}

func parseHelperArgs(args []string) (helperConfig, bool) {
	if len(args) != 4 || args[0] != "--control" || args[2] != "--token" {
		return helperConfig{}, false
	}
	path := args[1]
	if path == "" || len(path) > 96 || path[0] != '/' {
		return helperConfig{}, false
	}
	decoded, err := hex.DecodeString(args[3])
	if err != nil || len(decoded) != helperTokenBytes {
		return helperConfig{}, false
	}
	var token [helperTokenBytes]byte
	copy(token[:], decoded)
	return helperConfig{socketPath: path, token: token}, true
}

func receiveInit(conn *net.UnixConn) (helperInit, []int, error) {
	buf := make([]byte, helperInitSize)
	oob := make([]byte, syscall.CmsgSpace(6*4))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return helperInit{}, nil, err
	}
	if n <= 0 {
		return helperInit{}, nil, io.ErrUnexpectedEOF
	}
	fds, err := parseReceivedFDs(oob[:oobn])
	if err != nil {
		return helperInit{}, nil, err
	}
	if n < helperInitBaseSize {
		read, readErr := io.ReadFull(conn, buf[n:helperInitBaseSize])
		n += read
		if readErr != nil {
			return helperInit{}, fds, readErr
		}
	}
	if buf[0] != helperInitMagic[0] || buf[1] != helperInitMagic[1] || buf[2] != helperInitMagic[2] || buf[3] != helperInitMagic[3] {
		return helperInit{}, fds, errors.New("invalid helper init frame")
	}
	version := buf[4]
	if version != helperProtocolVersion && version != helperProtocolV4 && version != helperProtocolV3 && version != helperProtocolV2 && version != helperProtocolLegacy {
		return helperInit{}, fds, errors.New("unsupported helper protocol version")
	}
	expectedSize := helperInitBaseSize
	if version == helperProtocolVersion || version == helperProtocolV4 || version == helperProtocolV3 {
		expectedSize = helperInitSize
	}
	if n < expectedSize {
		read, readErr := io.ReadFull(conn, buf[n:expectedSize])
		n += read
		if readErr != nil {
			return helperInit{}, fds, readErr
		}
	}
	if n != expectedSize {
		return helperInit{}, fds, errors.New("helper init frame size invalid")
	}
	if buf[5]&^byte(1) != 0 || buf[6]&^byte(1) != 0 {
		return helperInit{}, fds, errors.New("invalid helper mode bytes")
	}
	mode := egressDirect
	if version == helperProtocolVersion || version == helperProtocolV4 || version == helperProtocolV3 || version == helperProtocolV2 {
		mode = egressMode(buf[7])
		if mode > egressWireGuardStrict {
			return helperInit{}, fds, errors.New("invalid egress mode")
		}
	} else if buf[7] != 0 {
		return helperInit{}, fds, errors.New("legacy egress mode invalid")
	}
	tunMTU := fullFlowMTU
	packageGateEnabled := false
	if version == helperProtocolVersion || version == helperProtocolV4 || version == helperProtocolV3 {
		if version == helperProtocolVersion {
			if buf[42]&^byte(1) != 0 || buf[43] != 0 {
				return helperInit{}, fds, errors.New("helper init package-gate bytes invalid")
			}
			packageGateEnabled = buf[42]&1 != 0
		} else if buf[42] != 0 || buf[43] != 0 {
			return helperInit{}, fds, errors.New("helper init reserved bytes invalid")
		}
		tunMTU = int(buf[40])<<8 | int(buf[41])
		if tunMTU < minWireGuardMTU || tunMTU > maxWireGuardMTU {
			return helperInit{}, fds, errors.New("helper tun mtu invalid")
		}
	}
	var token [helperTokenBytes]byte
	copy(token[:], buf[8:40])
	return helperInit{
		version:            version,
		token:              token,
		powerConstrained:   buf[5]&1 != 0,
		telemetryDetailed:  buf[6]&1 != 0,
		egressMode:         mode,
		tunMTU:             tunMTU,
		packageGateEnabled: packageGateEnabled,
	}, fds, nil
}

func parseReceivedFDs(oob []byte) ([]int, error) {
	messages, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	fds := make([]int, 0, 6)
	for _, message := range messages {
		rights, rightsErr := syscall.ParseUnixRights(&message)
		if rightsErr != nil {
			closeRawFDs(fds)
			return nil, rightsErr
		}
		fds = append(fds, rights...)
		if len(fds) > 6 {
			closeRawFDs(fds)
			return nil, errors.New("too many file descriptors")
		}
	}
	return fds, nil
}

func requestAndroidSocketProtection(conn *net.UnixConn, fds []int) error {
	if conn == nil || len(fds) == 0 || len(fds) > helperMaxProtectFDs {
		return errors.New("invalid socket protection request")
	}
	for _, fd := range fds {
		if fd < 0 {
			return errors.New("invalid socket protection fd")
		}
	}
	frame := [helperProtectFrameSize]byte{
		helperProtectMagic[0], helperProtectMagic[1], helperProtectMagic[2], helperProtectMagic[3],
		byte(len(fds)), 0, 0, 0,
	}
	oob := syscall.UnixRights(fds...)
	n, oobn, err := conn.WriteMsgUnix(frame[:], oob, nil)
	if err != nil {
		return fmt.Errorf("send socket protection request: %w", err)
	}
	if oobn != len(oob) {
		return errors.New("socket protection ancillary write incomplete")
	}
	if n < len(frame) {
		for n < len(frame) {
			written, writeErr := conn.Write(frame[n:])
			if writeErr != nil {
				return fmt.Errorf("complete socket protection request: %w", writeErr)
			}
			if written <= 0 {
				return io.ErrUnexpectedEOF
			}
			n += written
		}
	}

	// The helper startup deadline is an absolute wall-clock timestamp, not a rolling
	// per-read budget. Policy parsing and WireGuard construction happen between the
	// initial control read and this Android round-trip, so give this second read its
	// own bounded window instead of consuming whatever remains of startup time.
	if err := conn.SetReadDeadline(time.Now().Add(helperProtectResponseTimeout)); err != nil {
		return fmt.Errorf("set socket protection response deadline: %w", err)
	}

	var ack [helperProtectFrameSize]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		return fmt.Errorf("read socket protection response: %w", err)
	}
	if ack[0] != helperProtectAckMagic[0] || ack[1] != helperProtectAckMagic[1] ||
		ack[2] != helperProtectAckMagic[2] || ack[3] != helperProtectAckMagic[3] {
		return errors.New("socket protection response magic invalid")
	}
	status := uint32(ack[4])<<24 | uint32(ack[5])<<16 | uint32(ack[6])<<8 | uint32(ack[7])
	if status != 0 {
		return errors.New("android rejected wireguard socket protection")
	}
	return nil
}

func writeAck(conn *net.UnixConn, status uint32) error {
	frame := [helperAckSize]byte{helperAckMagic[0], helperAckMagic[1], helperAckMagic[2], helperAckMagic[3]}
	frame[4] = byte(status >> 24)
	frame[5] = byte(status >> 16)
	frame[6] = byte(status >> 8)
	frame[7] = byte(status)
	for written := 0; written < len(frame); {
		n, err := conn.Write(frame[written:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrUnexpectedEOF
		}
		written += n
	}
	return nil
}

func readControls(conn *net.UnixConn, out chan<- helperControl) {
	defer close(out)
	frame := make([]byte, helperMaxControlBytes)
	for {
		if _, err := io.ReadFull(conn, frame); err != nil {
			return
		}
		command := helperControl{kind: frame[0], value: frame[1]}
		select {
		case out <- command:
		default:
			return
		}
	}
}

func closeRawFDs(fds []int) {
	for _, fd := range fds {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
	}
}
