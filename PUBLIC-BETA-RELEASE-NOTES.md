# GeDefense Mobile 0.28.0-beta1 — Public Beta Release Notes

`0.28.0-beta1` / VC59 is a focused stability and metrics release addressing Full Flow session metrics attribution and cold boot setup wizard state retention.

## Update experience

The post-update screen now uses the same spacing, safe-area and content-rail rules as the rest of GeDefense. The version indicator is compact, status and feature cards have clearer hierarchy, and the primary action is anchored in a dedicated bottom action area.

When **Threats aktualisieren & Schutz aktivieren** is pressed, GeDefense immediately shows an in-button loading indicator and security-refresh progress while Threat Intelligence synchronization, policy refresh and protection activation are running. The action remains disabled during the transaction so repeated taps cannot start overlapping update work. The update notice is still acknowledged only after the existing transactional protection checks succeed.

## WireGuard import

WireGuard profile import now supports three equivalent input paths that all end in the same bounded parser and validator:

- pasted configuration text, with normalization for common clipboard/BOM/line-ending artifacts;
- Android document import with a provider-compatible wildcard MIME surface so `.conf` files are visible even when an OEM file manager does not label them as `text/plain`;
- local QR-code scanning.

The QR path is completely local. GeDefense vendors pinned ZXing Android Embedded `4.3.0` and ZXing Core `3.5.3` artifacts in the repository and does not use Google Play Services, ML Kit, cloud decoding or an external scanner application.

Security semantics are unchanged: unsupported or unsafe wg-quick directives remain rejected, profile size is bounded, key/address/endpoint validation remains strict, and all three import methods share the same parser instead of maintaining separate acceptance rules.

This remains a public-beta build and should continue to be validated across Xiaomi/HyperOS, Pixel, Samsung/One UI and other Android OEM variants before critical production use.
