//go:build (android && !gdnetworkbinder) || (!android && gdandroidhelper)

package main

// The pure-Go Android helper is restarted by the Android VPN service whenever the selected
// physical underlay changes. Per-socket Network.bindSocket/android_setsocknetwork requires cgo;
// keeping this implementation a no-op is intentional and explicit rather than pretending the
// helper has a binding primitive it cannot call without the Android NDK.
func bindSocketToUnderlying(_ uintptr, _ uint64) error { return nil }
