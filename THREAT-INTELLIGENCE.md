# Threat Intelligence Policy

## Core rule

A feed is evidence, not authority. Its authority class is compiled into GeDefense and cannot be supplied by downloaded content.

| Feed | Semantics | Enforcement | Minimum refresh | Maximum active age |
|---|---|---|---:|---:|
| abuse.ch Feodo Tracker | active botnet C2 | ROUTE_BLOCK | 15 min | 6 h |
| Spamhaus DROP IPv4 | rogue/high-confidence network blocks | ROUTE_BLOCK | 24 h | 72 h |
| Spamhaus DROP IPv6 | rogue/high-confidence network blocks | ROUTE_BLOCK | 24 h | 72 h |
| CINS Army | hostile/scanner observations | CORRELATE_ONLY | 6 h | 48 h |
| blocklist.de | recent attacking hosts | CORRELATE_ONLY | 1 h | 48 h |
| Emerging Threats | aggregated block-IP intelligence | CORRELATE_ONLY | 6 h | 48 h |
| IPsum | multi-source reputation; score >= 3 | CORRELATE_ONLY | 6 h | 48 h |
| FireHOL Level 1 | high-confidence Level 1 public network blocks | ROUTE_BLOCK | 6 h | 48 h |
| Tor exit nodes | anonymizer context | ANNOTATE_ONLY | 6 h | 24 h |

The maximum active age is a GeDefense safety bound. An expired generation is retained on disk for rollback/diagnosis but is excluded from the runtime index until a fresh valid generation is available.

## Spamhaus modernization

The historical VGT list contained separate DROP and eDROP text feeds. eDROP was merged into DROP in 2024. GeDefense Mobile therefore uses the current Spamhaus JSON DROP IPv4 and DROP IPv6 datasets instead of pretending the removed eDROP feed still exists.

GeDefense gives Spamhaus attribution in the application. The application intentionally fetches DROP no more frequently than once per 24 hours, comfortably below the upstream warning against excessive polling.

## Feed ingestion gates

Every source is subjected to:

1. immutable compile-time HTTPS URL;
2. no proxy;
3. no automatic redirects;
4. maximum two same-host HTTPS redirects;
5. fixed connect/read timeouts;
6. maximum body size;
7. maximum line size;
8. parser-specific syntax handling;
9. numeric IP/CIDR parsing only;
10. rejection of non-public or dangerous broad prefixes;
11. maximum entry count;
12. anomalous-shrink rejection for established feeds;
13. SHA-256 content hash;
14. HMAC-authenticated local metadata;
15. generation commit and disk re-verification before use;
16. freshness check before inclusion in the active index.

HTML responses are rejected to avoid accidentally treating captive portals or web error pages as intelligence data.

## Cache model

Cache files are generation-based. There is no mutable active pointer.

```text
feedid-<generation>.feed
feedid-<generation>.meta
```

Metadata contains the feed URL, fetch time, size, parsed-record count, SHA-256 and generation ID, authenticated with a dedicated Android-Keystore HMAC key.

A generation becomes usable only if both files exist and verify. A crash between the two atomic renames produces an ignored orphan, not a partially trusted update.

## Source attribution / terms

GeDefense does not redistribute downloaded datasets inside the source release. It downloads them from their upstream locations at runtime. The UI displays attribution and upstream terms remain applicable.

Notable upstream handling:

- Feodo Tracker: abuse.ch attribution; current active C2 feed.
- Spamhaus DROP/DROPv6: explicit Spamhaus Project credit retained in product UI/documentation.
- Emerging Threats: copyright/license notice remains upstream; GeDefense fetches rather than bundles the dataset.
- IPsum: fetched from `stamparm/ipsum`; GeDefense uses score >= 3 only for correlation.
- FireHOL Level 1: treated as block-authoritative only after GeDefense rejects private, CGNAT, link-local, multicast, documentation and other non-public prefixes; the direct upstream Level 1 file is fetched rather than the slower GitHub mirror.
- Tor exit nodes: fetched from the Tor Project bulk exit list; context only, never automatically treated as malicious.


## Threat Policy Self-Test

`0.27.8-beta.7 / VC56` includes a deterministic diagnostics self-test for the **loaded threat-policy snapshot**. The test deliberately performs **no network egress** and never contacts a threat-listed address.

While Full Flow is `FULL_GUARDED`, Android selects a real `ROUTE_BLOCK` route from the immutable `ThreatIndex` that is also supplied to GaiaNet. It then:

1. resolves the selected address through the production Kotlin `ThreatIndex.match()` path;
2. verifies that at least one matched feed has blocking authority;
3. verifies that the matched address remains covered by the compiled route set;
4. serializes the same immutable index through `ThreatPolicyBinary`, the exact GDTI writer used during GaiaNet startup; and
5. validates the GDTI ABI-v2 header, record count and `fullPolicySha256` fingerprint locally.

The self-test does **not** increment real block counters, create synthetic threat XDR/Evidence records, open a socket, mutate the active transport, or claim to validate third-party-app/TUN capture. This is intentional: GeDefense's own UID is excluded from Direct Full Flow to prevent its native upstream sockets from recursively entering the VPN. Real TUN capture and packet enforcement therefore remain a separate device-level validation boundary.

A PASS means the active Android-side policy/index/route/serialization chain is coherent. If a real app flow is still not blocked or counted, investigation should move to Android VPN capture/routing, OEM behavior or runtime telemetry rather than treating the dataset as unverified.
