//go:build android && cgo && gdnetworkbinder

package main

/*
#cgo LDFLAGS: -landroid
#include <android/multinetwork.h>
*/
import "C"

import (
	"fmt"
	"syscall"
)

func bindSocketToUnderlying(fd uintptr, handle uint64) error {
	rc := C.android_setsocknetwork(C.net_handle_t(handle), C.int(fd))
	if rc == 0 {
		return nil
	}
	return fmt.Errorf("android_setsocknetwork failed: %w", syscall.Errno(-rc))
}
