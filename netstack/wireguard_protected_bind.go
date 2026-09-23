package main

import (
	"errors"
	"fmt"
	"sync"

	wgconn "golang.zx2c4.com/wireguard/conn"
)

type wireGuardSocketProtector func([]int) error

// protectedWireGuardBind wraps the official wireguard-go UDP bind and does not
// return from Open until Android's VpnService has protected every UDP socket.
// This closes the recursion window that would otherwise exist in a full-tunnel
// VpnService: no peer routine can use the sockets before the protection ACK.
type protectedWireGuardBind struct {
	inner     wgconn.Bind
	protector wireGuardSocketProtector
	mu        sync.Mutex
	opened    bool
}

func newProtectedWireGuardBind(inner wgconn.Bind, protector wireGuardSocketProtector) (wgconn.Bind, error) {
	if inner == nil {
		return nil, errors.New("wireguard bind missing")
	}
	if protector == nil {
		return nil, errors.New("wireguard socket protector missing")
	}
	if _, ok := inner.(wgconn.PeekLookAtSocketFd); !ok {
		return nil, errors.New("wireguard bind does not expose android socket fds")
	}
	return &protectedWireGuardBind{inner: inner, protector: protector}, nil
}

func (b *protectedWireGuardBind) Open(port uint16) ([]wgconn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.opened {
		return nil, 0, errors.New("wireguard protected bind reopen rejected")
	}
	receivers, actualPort, err := b.inner.Open(port)
	if err != nil {
		return nil, 0, err
	}
	fail := func(cause error) ([]wgconn.ReceiveFunc, uint16, error) {
		closeErr := b.inner.Close()
		if closeErr != nil {
			return nil, 0, errors.Join(cause, fmt.Errorf("close unprotected wireguard bind: %w", closeErr))
		}
		return nil, 0, cause
	}

	peeker := b.inner.(wgconn.PeekLookAtSocketFd)
	fds, err := wireGuardSocketFDs(receivers, peeker)
	if err != nil {
		return fail(err)
	}
	if err := b.protector(fds); err != nil {
		return fail(fmt.Errorf("wireguard socket protection failed: %w", err))
	}
	b.opened = true
	return receivers, actualPort, nil
}

func wireGuardSocketFDs(receivers []wgconn.ReceiveFunc, peeker wgconn.PeekLookAtSocketFd) ([]int, error) {
	if len(receivers) < 1 || len(receivers) > 2 {
		return nil, fmt.Errorf("wireguard receive family count invalid: %d", len(receivers))
	}
	fd4, err4 := safePeekWireGuardSocket("ipv4", peeker.PeekLookAtSocketFd4)
	fd6, err6 := safePeekWireGuardSocket("ipv6", peeker.PeekLookAtSocketFd6)

	if len(receivers) == 2 {
		if err4 != nil {
			return nil, err4
		}
		if err6 != nil {
			return nil, err6
		}
		if fd4 == fd6 {
			return nil, errors.New("wireguard socket fd collision")
		}
		return []int{fd4, fd6}, nil
	}

	// wireguard-go may legally expose only one receive family when the kernel
	// returns EAFNOSUPPORT for the other family. Accept that only if exactly one
	// socket FD is actually present. This preserves fail-closed behavior for an
	// inconsistent bind while allowing IPv4-only or IPv6-only kernels.
	switch {
	case err4 == nil && err6 != nil:
		return []int{fd4}, nil
	case err4 != nil && err6 == nil:
		return []int{fd6}, nil
	case err4 == nil && err6 == nil:
		return nil, errors.New("wireguard single receive family exposed two socket fds")
	default:
		return nil, errors.Join(err4, err6)
	}
}

func safePeekWireGuardSocket(family string, peek func() (int, error)) (fd int, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			fd = -1
			err = fmt.Errorf("wireguard %s socket unavailable: upstream fd lookup panicked", family)
		}
	}()
	fd, err = peek()
	if err != nil {
		return -1, fmt.Errorf("wireguard %s socket unavailable: %w", family, err)
	}
	if fd < 0 {
		return -1, fmt.Errorf("wireguard %s socket unavailable: invalid socket fd", family)
	}
	return fd, nil
}

func (b *protectedWireGuardBind) Close() error { return b.inner.Close() }

func (b *protectedWireGuardBind) SetMark(mark uint32) error { return b.inner.SetMark(mark) }

func (b *protectedWireGuardBind) Send(bufs [][]byte, endpoint wgconn.Endpoint) error {
	return b.inner.Send(bufs, endpoint)
}

func (b *protectedWireGuardBind) ParseEndpoint(endpoint string) (wgconn.Endpoint, error) {
	return b.inner.ParseEndpoint(endpoint)
}

func (b *protectedWireGuardBind) BatchSize() int { return b.inner.BatchSize() }
