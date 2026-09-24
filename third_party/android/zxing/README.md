# Vendored Android QR scanner dependencies

GeDefense Mobile vendors the following Apache-2.0 components for the local-only WireGuard QR import path:

- `com.journeyapps:zxing-android-embedded:4.3.0`
- `com.google.zxing:core:3.5.3`

The artifacts are stored in-tree so release builds do not need to fetch QR runtime code from Maven repositories. `SHA256SUMS.txt` pins the exact reviewed artifacts. The scanner runs inside the GeDefense process/application boundary and the decoded WireGuard configuration is passed directly to the existing bounded parser; it is not sent to Google Play Services or to an external scanner application.

Upstream metadata is retained as the matching POM files. License: Apache-2.0, copied in `LICENSE-Apache-2.0.txt`.
