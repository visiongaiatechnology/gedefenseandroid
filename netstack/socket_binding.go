package main

import (
	"sync/atomic"
	"syscall"
)

var underlyingNetworkHandle atomic.Uint64

func setUnderlyingNetworkHandle(handle uint64) { underlyingNetworkHandle.Store(handle) }

func controlSocketForUnderlyingNetwork(_ string, _ string, raw syscall.RawConn) error {
	handle := underlyingNetworkHandle.Load()
	if handle == 0 {
		return nil
	}
	var bindErr error
	if err := raw.Control(func(fd uintptr) { bindErr = bindSocketToUnderlying(fd, handle) }); err != nil {
		return err
	}
	return bindErr
}
