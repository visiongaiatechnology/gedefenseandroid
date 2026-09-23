//go:build gdandroidhelper

package main

import (
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestHelperArgsRequireExactTokenAndPrivateSocketPath(t *testing.T) {
	token := make([]byte, helperTokenBytes)
	for i := range token {
		token[i] = byte(i + 1)
	}
	encoded := hex.EncodeToString(token)
	cfg, ok := parseHelperArgs([]string{"--control", "/data/user/0/test/cache/gdv2.sock", "--token", encoded})
	if !ok || cfg.socketPath == "" || cfg.token[0] != 1 || cfg.token[31] != 32 {
		t.Fatal("valid helper args rejected")
	}
	bad := []struct {
		name string
		args []string
	}{
		{"relative socket", []string{"--control", "relative.sock", "--token", encoded}},
		{"short token", []string{"--control", "/tmp/gdv2.sock", "--token", "aa"}},
		{"extra arg", []string{"--control", "/tmp/gdv2.sock", "--token", encoded, "extra"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, accepted := parseHelperArgs(tc.args); accepted {
				t.Fatal("invalid helper args accepted")
			}
		})
	}
}

func TestHelperInitCarriesExactlyThreeDescriptors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gdv2.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	token := [helperTokenBytes]byte{}
	for i := range token {
		token[i] = byte(0x80 + i)
	}
	result := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		init, fds, err := receiveInit(conn)
		if err == nil {
			defer closeRawFDs(fds)
			if len(fds) != 3 || init.token != token || !init.powerConstrained || init.tunMTU != fullFlowMTU {
				err = syscall.EINVAL
			}
		}
		result <- err
	}()

	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	files := make([]*os.File, 0, 3)
	for i := 0; i < 3; i++ {
		file, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		files = append(files, file)
	}
	frame := make([]byte, helperInitSize)
	copy(frame[:4], helperInitMagic[:])
	frame[4] = helperProtocolVersion
	frame[5] = 1
	copy(frame[8:40], token[:])
	frame[40] = byte(fullFlowMTU >> 8)
	frame[41] = byte(fullFlowMTU & 0xff)
	oob := syscall.UnixRights(int(files[0].Fd()), int(files[1].Fd()), int(files[2].Fd()))
	if _, _, err := client.WriteMsgUnix(frame, oob, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestHelperInitCarriesFourDescriptorsForWireGuard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gdv2-wg.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	token := [helperTokenBytes]byte{}
	for i := range token {
		token[i] = byte(0x20 + i)
	}
	result := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		init, fds, err := receiveInit(conn)
		if err == nil {
			defer closeRawFDs(fds)
			if len(fds) != 4 || init.token != token || init.egressMode != egressWireGuard || init.tunMTU != 1380 {
				err = syscall.EINVAL
			}
		}
		result <- err
	}()

	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	files := make([]*os.File, 0, 4)
	for i := 0; i < 4; i++ {
		file, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		files = append(files, file)
	}
	frame := make([]byte, helperInitSize)
	copy(frame[:4], helperInitMagic[:])
	frame[4] = helperProtocolVersion
	frame[7] = byte(egressWireGuard)
	copy(frame[8:40], token[:])
	frame[40] = byte(1380 >> 8)
	frame[41] = byte(1380 & 0xff)
	oob := syscall.UnixRights(int(files[0].Fd()), int(files[1].Fd()), int(files[2].Fd()), int(files[3].Fd()))
	if _, _, err := client.WriteMsgUnix(frame, oob, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestHelperProtocolV2DefaultsMTU(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gdv2-compat.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	token := [helperTokenBytes]byte{}
	for i := range token {
		token[i] = byte(0x40 + i)
	}
	result := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			result <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		init, fds, receiveErr := receiveInit(conn)
		if receiveErr == nil {
			defer closeRawFDs(fds)
			if len(fds) != 3 || init.token != token || init.egressMode != egressDirect || init.tunMTU != fullFlowMTU {
				receiveErr = syscall.EINVAL
			}
		}
		result <- receiveErr
	}()

	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	files := make([]*os.File, 0, 3)
	for i := 0; i < 3; i++ {
		file, openErr := os.Open(os.DevNull)
		if openErr != nil {
			t.Fatal(openErr)
		}
		defer file.Close()
		files = append(files, file)
	}
	frame := make([]byte, helperInitBaseSize)
	copy(frame[:4], helperInitMagic[:])
	frame[4] = helperProtocolV2
	copy(frame[8:40], token[:])
	oob := syscall.UnixRights(int(files[0].Fd()), int(files[1].Fd()), int(files[2].Fd()))
	if _, _, err := client.WriteMsgUnix(frame, oob, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestWireGuardSocketProtectionTransfersFDsAndRequiresAck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gdv2-protect.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverResult := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		files := make([]*os.File, 0, 2)
		for i := 0; i < 2; i++ {
			file, openErr := os.Open(os.DevNull)
			if openErr != nil {
				serverResult <- openErr
				return
			}
			defer file.Close()
			files = append(files, file)
		}
		serverResult <- requestAndroidSocketProtection(conn, []int{int(files[0].Fd()), int(files[1].Fd())})
	}()

	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))

	frame := make([]byte, helperProtectFrameSize)
	oob := make([]byte, syscall.CmsgSpace(helperMaxProtectFDs*4))
	n, oobn, _, _, err := client.ReadMsgUnix(frame, oob)
	if err != nil {
		t.Fatal(err)
	}
	if n != helperProtectFrameSize || frame[0] != 'G' || frame[1] != 'D' || frame[2] != 'P' || frame[3] != '2' || frame[4] != 2 {
		t.Fatalf("invalid protection frame: n=%d frame=%v", n, frame)
	}
	received, err := parseReceivedFDs(oob[:oobn])
	if err != nil {
		t.Fatal(err)
	}
	if len(received) != 2 {
		closeRawFDs(received)
		t.Fatalf("expected 2 socket descriptors, got %d", len(received))
	}
	closeRawFDs(received)

	ack := []byte{'G', 'D', 'R', '2', 0, 0, 0, 0}
	if _, err := client.Write(ack); err != nil {
		t.Fatal(err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestWireGuardSocketProtectionRearmsStaleReadDeadline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gdv2-protect-deadline.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverResult := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer conn.Close()
		if deadlineErr := conn.SetReadDeadline(time.Now().Add(-time.Second)); deadlineErr != nil {
			serverResult <- deadlineErr
			return
		}
		file, openErr := os.Open(os.DevNull)
		if openErr != nil {
			serverResult <- openErr
			return
		}
		defer file.Close()
		serverResult <- requestAndroidSocketProtection(conn, []int{int(file.Fd())})
	}()

	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))

	frame := make([]byte, helperProtectFrameSize)
	oob := make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := client.ReadMsgUnix(frame, oob)
	if err != nil {
		t.Fatal(err)
	}
	received, err := parseReceivedFDs(oob[:oobn])
	if err != nil {
		t.Fatal(err)
	}
	closeRawFDs(received)
	if _, err := client.Write([]byte{'G', 'D', 'R', '2', 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("stale startup read deadline was not re-armed: %v", err)
	}
}

func TestWireGuardSocketProtectionRejectsNegativeAck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gdv2-protect-reject.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverResult := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		file, openErr := os.Open(os.DevNull)
		if openErr != nil {
			serverResult <- openErr
			return
		}
		defer file.Close()
		serverResult <- requestAndroidSocketProtection(conn, []int{int(file.Fd())})
	}()

	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	frame := make([]byte, helperProtectFrameSize)
	oob := make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := client.ReadMsgUnix(frame, oob)
	if err != nil {
		t.Fatal(err)
	}
	received, err := parseReceivedFDs(oob[:oobn])
	if err != nil {
		t.Fatal(err)
	}
	closeRawFDs(received)
	if _, err := client.Write([]byte{'G', 'D', 'R', '2', 0, 0, 0, 1}); err != nil {
		t.Fatal(err)
	}
	if err := <-serverResult; err == nil {
		t.Fatal("negative Android socket-protection acknowledgement was accepted")
	}
}

func TestHelperProtocolV3RejectsInvalidMTUAndReservedBytes(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]byte)
	}{
		{
			name: "mtu_below_minimum",
			mutate: func(frame []byte) {
				frame[40] = byte((minWireGuardMTU - 1) >> 8)
				frame[41] = byte((minWireGuardMTU - 1) & 0xff)
			},
		},
		{
			name: "mtu_above_maximum",
			mutate: func(frame []byte) {
				frame[40] = byte((maxWireGuardMTU + 1) >> 8)
				frame[41] = byte((maxWireGuardMTU + 1) & 0xff)
			},
		},
		{
			name:   "reserved_byte_42",
			mutate: func(frame []byte) { frame[42] = 1 },
		},
		{
			name:   "reserved_byte_43",
			mutate: func(frame []byte) { frame[43] = 1 },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "gdv3-reject.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			result := make(chan error, 1)
			go func() {
				conn, acceptErr := listener.AcceptUnix()
				if acceptErr != nil {
					result <- acceptErr
					return
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, fds, receiveErr := receiveInit(conn)
				closeRawFDs(fds)
				result <- receiveErr
			}()

			client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			files := make([]*os.File, 0, 3)
			for i := 0; i < 3; i++ {
				file, openErr := os.Open(os.DevNull)
				if openErr != nil {
					t.Fatal(openErr)
				}
				defer file.Close()
				files = append(files, file)
			}

			frame := make([]byte, helperInitSize)
			copy(frame[:4], helperInitMagic[:])
			frame[4] = helperProtocolV4
			frame[40] = byte(fullFlowMTU >> 8)
			frame[41] = byte(fullFlowMTU & 0xff)
			tc.mutate(frame)
			oob := syscall.UnixRights(int(files[0].Fd()), int(files[1].Fd()), int(files[2].Fd()))
			if _, _, err := client.WriteMsgUnix(frame, oob, nil); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err == nil {
				t.Fatal("invalid v3 helper init was accepted")
			}
		})
	}
}

func TestParseReceivedFDsAcceptsSixAndRejectsSeven(t *testing.T) {
	files := make([]*os.File, 0, 7)
	for i := 0; i < 7; i++ {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		files = append(files, f)
	}
	six := syscall.UnixRights(
		int(files[0].Fd()), int(files[1].Fd()), int(files[2].Fd()),
		int(files[3].Fd()), int(files[4].Fd()), int(files[5].Fd()),
	)
	received, err := parseReceivedFDs(six)
	if err != nil {
		t.Fatalf("six descriptor v5 WireGuard init was rejected: %v", err)
	}
	if len(received) != 6 {
		closeRawFDs(received)
		t.Fatalf("expected six descriptors, got %d", len(received))
	}
	closeRawFDs(received)

	seven := syscall.UnixRights(
		int(files[0].Fd()), int(files[1].Fd()), int(files[2].Fd()),
		int(files[3].Fd()), int(files[4].Fd()), int(files[5].Fd()), int(files[6].Fd()),
	)
	if received, err = parseReceivedFDs(seven); err == nil {
		closeRawFDs(received)
		t.Fatal("seven descriptors were accepted")
	}
}

func TestHelperProtocolV5CarriesPackageGateFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gdv5-gate.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	result := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			result <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		init, fds, receiveErr := receiveInit(conn)
		closeRawFDs(fds)
		if receiveErr == nil && (!init.packageGateEnabled || init.version != helperProtocolVersion || init.tunMTU != fullFlowMTU) {
			receiveErr = syscall.EINVAL
		}
		result <- receiveErr
	}()

	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	files := make([]*os.File, 0, 5)
	for i := 0; i < 5; i++ {
		file, openErr := os.Open(os.DevNull)
		if openErr != nil {
			t.Fatal(openErr)
		}
		defer file.Close()
		files = append(files, file)
	}
	frame := make([]byte, helperInitSize)
	copy(frame[:4], helperInitMagic[:])
	frame[4] = helperProtocolVersion
	frame[40] = byte(fullFlowMTU >> 8)
	frame[41] = byte(fullFlowMTU & 0xff)
	frame[42] = 1
	oob := syscall.UnixRights(int(files[0].Fd()), int(files[1].Fd()), int(files[2].Fd()), int(files[3].Fd()), int(files[4].Fd()))
	if _, _, err := client.WriteMsgUnix(frame, oob, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestHelperProtocolV5RejectsInvalidPackageGateBits(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(frame []byte) { frame[42] = 2 },
		func(frame []byte) { frame[43] = 1 },
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "gdv5-gate-reject.sock")
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			conn, acceptErr := listener.AcceptUnix()
			if acceptErr != nil {
				result <- acceptErr
				return
			}
			defer conn.Close()
			_, fds, receiveErr := receiveInit(conn)
			closeRawFDs(fds)
			result <- receiveErr
		}()
		client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			listener.Close()
			t.Fatal(err)
		}
		files := make([]*os.File, 0, 5)
		for i := 0; i < 5; i++ {
			file, openErr := os.Open(os.DevNull)
			if openErr != nil {
				client.Close()
				listener.Close()
				t.Fatal(openErr)
			}
			defer file.Close()
			files = append(files, file)
		}
		frame := make([]byte, helperInitSize)
		copy(frame[:4], helperInitMagic[:])
		frame[4] = helperProtocolVersion
		frame[40] = byte(fullFlowMTU >> 8)
		frame[41] = byte(fullFlowMTU & 0xff)
		mutate(frame)
		oob := syscall.UnixRights(int(files[0].Fd()), int(files[1].Fd()), int(files[2].Fd()), int(files[3].Fd()), int(files[4].Fd()))
		if _, _, err := client.WriteMsgUnix(frame, oob, nil); err != nil {
			client.Close()
			listener.Close()
			t.Fatal(err)
		}
		if err := <-result; err == nil {
			client.Close()
			listener.Close()
			t.Fatal("invalid v5 package-gate bits accepted")
		}
		client.Close()
		listener.Close()
	}
}
