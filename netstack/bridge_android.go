//go:build android && cgo && gdlegacyjni

package main

/*
#include <stdint.h>
typedef void* JNIEnvPtr;
typedef void* JObjectPtr;
typedef int32_t jint;
typedef int64_t jlong;
typedef uint8_t jboolean;
*/
import "C"

import (
	"os"
	"sync"
)

var bridgeState struct {
	sync.Mutex
	engine *engine
}

//export Java_de_visiongaia_gedefense_mobile_NativeGaiaNet_nativeStart
func Java_de_visiongaia_gedefense_mobile_NativeGaiaNet_nativeStart(env C.JNIEnvPtr, clazz C.JObjectPtr, tunFD C.jint, telemetryFD C.jint, policyFD C.jint, networkHandle C.jlong) C.jint {
	bridgeState.Lock()
	defer bridgeState.Unlock()
	if bridgeState.engine != nil {
		return -2
	}
	setUnderlyingNetworkHandle(uint64(networkHandle))
	setPowerConstrained(false)
	setTelemetryDetailed(false)
	closeDetached := func(fd C.jint, name string) {
		f := os.NewFile(uintptr(fd), name)
		if f != nil {
			_ = f.Close()
		}
	}
	pf := os.NewFile(uintptr(policyFD), "gedefense-policy")
	if pf == nil {
		closeDetached(tunFD, "gedefense-tun")
		closeDetached(telemetryFD, "gedefense-telemetry")
		return -3
	}
	policy, err := loadPolicy(pf)
	_ = pf.Close()
	if err != nil {
		closeDetached(tunFD, "gedefense-tun")
		closeDetached(telemetryFD, "gedefense-telemetry")
		return -4
	}
	e, err := newEngine(int(tunFD), int(telemetryFD), policy, nil, nil, egressDirect, fullFlowMTU, nil, nil)
	if err != nil {
		return -5
	}
	bridgeState.engine = e
	go func() {
		e.run()
		bridgeState.Lock()
		if bridgeState.engine == e {
			bridgeState.engine = nil
		}
		bridgeState.Unlock()
	}()
	return 0
}

//export Java_de_visiongaia_gedefense_mobile_NativeGaiaNet_nativeStop
func Java_de_visiongaia_gedefense_mobile_NativeGaiaNet_nativeStop(env C.JNIEnvPtr, clazz C.JObjectPtr) C.jint {
	bridgeState.Lock()
	e := bridgeState.engine
	bridgeState.engine = nil
	bridgeState.Unlock()
	if e == nil {
		return 0
	}
	e.close()
	setUnderlyingNetworkHandle(0)
	setPowerConstrained(false)
	setTelemetryDetailed(false)
	return 0
}

//export Java_de_visiongaia_gedefense_mobile_NativeGaiaNet_nativeSetPowerConstrained
func Java_de_visiongaia_gedefense_mobile_NativeGaiaNet_nativeSetPowerConstrained(env C.JNIEnvPtr, clazz C.JObjectPtr, constrained C.jboolean) {
	setPowerConstrained(constrained != 0)
	bridgeState.Lock()
	e := bridgeState.engine
	bridgeState.Unlock()
	if e != nil {
		e.powerStateChanged()
	}
}

//export Java_de_visiongaia_gedefense_mobile_NativeGaiaNet_nativeSetTelemetryDetailed
func Java_de_visiongaia_gedefense_mobile_NativeGaiaNet_nativeSetTelemetryDetailed(env C.JNIEnvPtr, clazz C.JObjectPtr, detailed C.jboolean) {
	setTelemetryDetailed(detailed != 0)
	bridgeState.Lock()
	e := bridgeState.engine
	bridgeState.Unlock()
	if e != nil {
		e.powerStateChanged()
	}
}

//export Java_de_visiongaia_gedefense_mobile_NativeGaiaNet_nativeApiVersion
func Java_de_visiongaia_gedefense_mobile_NativeGaiaNet_nativeApiVersion(env C.JNIEnvPtr, clazz C.JObjectPtr) C.jint {
	return 2
}
