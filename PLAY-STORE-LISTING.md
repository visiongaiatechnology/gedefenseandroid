# Google Play Listing Draft

**App name:** GeDefense Mobile

## Short description

Local-first Android network protection, threat intelligence, XDR and security scanning.

## Full description

GeDefense Mobile is an open-source Android security platform built around local-first protection and explicit user control.

Its protection stack combines a local Android VPN firewall, the in-repository GaiaNet network engine, threat-intelligence correlation, package and signer monitoring, behavioral security signals, device-integrity checks and an optional shared-storage malware scanner. Security events are correlated locally into an XDR/EDR incident view instead of being sent to an analytics cloud.

### Local network protection

GeDefense uses Android's VPN interface as a local security boundary. It is not a location-changing consumer VPN. The application does not perform TLS man-in-the-middle interception and does not upload a browsing or traffic history to VisionGaiaTechnology.

### Transparent permissions

The first-run assistant explains each protection layer and classifies setup capabilities as core, recommended, optional or enterprise. Optional scanner, usage-access and coarse-location permissions remain optional for baseline VPN protection.

### Device Security Scanner

The optional scanner can inspect user-accessible shared storage and installed application metadata using bounded, read-only analysis. Android private application sandboxes are not bypassed.

### XDR and evidence

GeDefense correlates network, package, integrity, threat-intelligence, behavioral and hardening signals locally. Diagnostic bundles are exported only when requested and use a privacy-bounded aggregate profile.

### TITAN managed-device mode

Advanced managed-device controls are available when Android confirms the required Device Administrator or Device Owner role. These capabilities are intended for deliberately managed devices and are not silently enabled.

### Open and auditable

The source repository documents architecture, threat model, network egress, privacy boundaries, build/toolchain information and security reporting. GaiaNet helpers are reproducibly checked against their in-repository source during release verification.

GeDefense Mobile is currently a beta security product. Real-world protection depends on Android/OEM behavior, device configuration, granted capabilities and the quality/freshness of available threat intelligence. No security product can guarantee detection or prevention of every attack.
