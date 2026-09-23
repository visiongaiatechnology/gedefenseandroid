# Network Egress Inventory

GeDefense has no VGT telemetry or analytics backend. Application-originated network egress is limited to security dataset retrieval and one explicit external support action.

## Automatic / scheduled dataset retrieval

| Purpose | Host | Path family | Data sent by GeDefense |
|---|---|---|---|
| Feodo C2 intelligence | `feodotracker.abuse.ch` | `/downloads/ipblocklist.txt` | Standard HTTPS request only |
| Spamhaus DROP v4/v6 | `www.spamhaus.org` | `/drop/*.json` | Standard HTTPS request only |
| CINS Army | `cinsscore.com` | `/list/ci-badguys.txt` | Standard HTTPS request only |
| blocklist.de | `lists.blocklist.de` | `/lists/all.txt` | Standard HTTPS request only |
| Emerging Threats | `rules.emergingthreats.net` | `/fwrules/emerging-Block-IPs.txt` | Standard HTTPS request only |
| IPsum | `raw.githubusercontent.com` | `/stamparm/ipsum/...` | Standard HTTPS request only |
| FireHOL Level 1 | `iplists.firehol.org` | `/files/firehol_level1.netset` | Standard HTTPS request only |
| Tor exits | `check.torproject.org` | `/torbulkexitlist` | Standard HTTPS request only |
| Country dataset | `github.com` | `sapics/ip-location-db` release assets | Standard HTTPS request only |
| ASN evidence dataset | `github.com`, `release-assets.githubusercontent.com`, `objects.githubusercontent.com` | `sapics/ip-location-db` IPtoASN IPv4/IPv6 release + SHA-256 assets | Whole-dataset HTTPS refresh only; bounded redirects; no observed IP in request |

GeDefense does **not** append observed destination IPs, DNS history, package names, scanner findings, device identifiers or XDR incidents to these requests. The remote hosts can still observe ordinary transport metadata such as the public source IP of the HTTPS connection.


## Telemetry Shield is not network egress

Telemetry Shield is enforced only in Full Flow; Selective mode does not claim system-wide telemetry filtering. It uses only the Privacy Intelligence snapshot packaged in the signed APK plus locally observed DNS/flow metadata. It performs no tracker/telemetry lookup against VGT, Sophos or any third-party API at runtime. Updating that snapshot is a source/release operation subject to provenance, license and release-audit review, not an automatic device-side API dependency.

## Explicit user action

`paypal.me` is opened only when the user explicitly selects the external Support VGT action. The request is handled by the user's browser/application, not by a payment SDK embedded in GeDefense.

## Invariant

Any future network destination must be documented here, assigned a purpose, bounded in code, use HTTPS, and pass the release egress audit before shipping.


## Encrypted DNS control

In Full Flow, Telemetry Shield classifies captured destination port 853 as encrypted DNS without decrypting payloads. Conservative/Balanced observe these flows; Strict blocks them before Direct or WireGuard egress. Known documented public-resolver bootstrap domains can also be locally observed/blocked through the signed Privacy Intelligence registry. HTTPS/443 remains ordinary HTTPS unless another explicit local rule identifies the endpoint; GeDefense does not perform TLS MITM and does not claim universal DoH/ECH detection.
