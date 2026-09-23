# ASN Evidence Snapshot

## Purpose

GeDefense Mobile uses ASN information only to enrich local forensic Evidence. ASN is not a reputation verdict and has no enforcement authority. The fixed classification is `evidence_only`.

## Provenance

- Upstream dataset: `IPtoASN`
- Distributor/snapshot path: `sapics/ip-location-db` / `iptoasn-asn`
- License: Public Domain Dedication and License 1.0 (`PDDL-1.0`)
- IPv4 source: `iptoasn-asn-ipv4.csv`
- IPv6 source: `iptoasn-asn-ipv6.csv`
- Integrity source: matching published `.sha256` release assets

The runtime manifest stores source identity, upstream identity, license ID, fetch timestamp, IPv4/IPv6 source SHA-256 values, compiled IPv4/IPv6 index SHA-256 values, organization-index SHA-256 and the `evidence_only` marker. The manifest and active-generation pointer are HMAC-SHA-256 authenticated with a dedicated Android-Keystore key domain.

## Local format

The CSV snapshots are parsed with bounded row/line limits and must be sorted and non-overlapping. IPv4 and IPv6 ranges are compiled separately into fixed-width big-endian records. Organizations are normalized into a bounded UTF-8 dictionary shared by both families. ASN 0 rows are validated for ordering but omitted because they represent unattributed/unannounced space rather than useful ASN evidence.

Lookups are memory-mapped O(log n) binary searches. They never issue a network request. Private/non-public addresses are rejected before lookup.

## Publication and rollback

A refresh follows:

```text
checksum fetch -> source fetch -> SHA-256 verify -> bounded compile -> fsync
-> HMAC manifest -> staged verification -> atomic generation move
-> authenticated pointer swap -> reopen/verify -> old-generation cleanup
```

Any failure before completion leaves the current generation untouched. If publication verification fails after the pointer changes, the prior authenticated pointer is restored. Startup may recover the newest valid authenticated generation inside the app-private storage jail.

## Privacy and authority boundary

Whole public datasets are refreshed periodically over HTTPS. Observed destination IPs are never appended to those requests and no ASN query API exists. A successful flow-time match may append a local `network.asn` Evidence event with AS number, organization, app attribution, IP family, snapshot time, source/license and family-specific source hash. The raw destination IP is intentionally absent from that ASN event.

There is deliberately no ASN block/allow API and no ASN-to-XDR ingest call. A future reputation system would require a separate explicit authority model and release review rather than silently reusing this evidence channel.
