# Community Release Guide

GeDefense should earn trust through evidence rather than security superlatives.

## What to publish with every public beta

- signed APK for direct testers;
- signed AAB for Play distribution where applicable;
- matching source archive;
- SHA-256 checksums;
- release lint report;
- public release notes;
- architecture, threat model, privacy, egress and supply-chain documentation;
- exact known limitations and a clear request for compatibility reports.

## Recommended GitHub repository presentation

Pin the following paths near the top of the README: `SECURITY.md`, `PRIVACY.md`, `THREAT-MODEL.md`, `NETWORK-EGRESS.md`, `BUILD-RUNBOOK.md`, `CONTRIBUTING.md` and `SUPPORT.md`.

Use GitHub private vulnerability reporting for suspected vulnerabilities. Public issues are appropriate for reproducible non-sensitive bugs and feature discussion; they are not an acceptable place for private device evidence, keys, captured traffic or personal data.

## Useful community reports

Prioritize reports that contain Android version, OEM/ROM, model family, GeDefense version, protection mode, whether Always-on/Lockdown is enabled, the exact visible error/reason code and sanitized reproduction steps.

Compatibility evidence is more valuable than synthetic star counts. Do not incentivize reviews, vulnerability disclosure or security claims.
