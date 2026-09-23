module golang.zx2c4.com/wireguard

go 1.23.1

// GeDefense vendored runtime graph for Android/Linux. The unmodified upstream
// module metadata is retained as go.mod.upstream. Wintun, gVisor, btree and
// x/time are upstream Windows/test-only graph entries and are not runtime
// dependencies of the process-isolated Android/Linux helper.
require (
	golang.org/x/crypto v0.37.0
	golang.org/x/net v0.39.0
	golang.org/x/sys v0.32.0
)
