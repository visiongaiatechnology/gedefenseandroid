module visiongaia.dev/gedefense/mobile/netstack

go 1.26.0

toolchain go1.26.8

require golang.zx2c4.com/wireguard v0.0.20250522

require (
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
)

replace golang.org/x/crypto => ../third_party/go/x-crypto

replace golang.org/x/net => ../third_party/go/x-net

replace golang.org/x/sys => ../third_party/go/x-sys

replace golang.org/x/term => ../third_party/go/x-term

replace golang.org/x/text => ../third_party/go/x-text

replace golang.zx2c4.com/wireguard => ../third_party/go/wireguard-go
