package main

import "sync/atomic"

var nativeFlowID atomic.Uint64

func nextNativeFlowID() uint64 {
	id := nativeFlowID.Add(1)
	if id == 0 {
		// The wrap-around horizon is practically unreachable. Avoid 0 because it is
		// reserved as "not a flow" on the Kotlin telemetry side.
		id = nativeFlowID.Add(1)
	}
	return id
}
