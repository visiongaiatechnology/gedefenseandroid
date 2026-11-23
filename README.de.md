<p align="center"><img src="docs/assets/gedefense-logo.png" alt="GeDefense Mobile" width="150" /></p>
<h1 align="center">GeDefense Mobile</h1>
<p align="center"><strong>Lokale Android-Endpoint-Security, Netzwerkabwehr und XDR.</strong><br>Entwickelt von VisionGaiaTechnology für Umgebungen, in denen Sicherheitstelemetrie auf dem Gerät bleiben soll.</p>
<p align="center"><a href="README.md">English</a> · <a href="README.de.md"><strong>Deutsch</strong></a> · <a href="README.ru.md">Русский</a> · <a href="README.zh-CN.md">简体中文</a></p>
<p align="center">
<img alt="Version" src="https://img.shields.io/badge/Version-0.31.0-D8A928?style=flat-square" />
<img alt="VersionCode" src="https://img.shields.io/badge/VersionCode-62-64748B?style=flat-square" />
<img alt="Android" src="https://img.shields.io/badge/Android-10%2B%20(API%2029%2B)-3DDC84?style=flat-square&logo=android&logoColor=white" />
<img alt="Go" src="https://img.shields.io/badge/Go-1.26.8-00ADD8?style=flat-square&logo=go&logoColor=white" />
<img alt="Privacy" src="https://img.shields.io/badge/Datenschutz-local--first-06B6D4?style=flat-square" />
<img alt="License" src="https://img.shields.io/badge/Lizenz-AGPL--3.0--or--later-2563EB?style=flat-square" />
</p>

> [!NOTE]
> **Installations- und Update-Hinweis für Version 0.31.0 (`VC 62`):**
> Geräte mit bereits installiertem `0.28.0-beta1` (`VC 59`), `0.28.0-beta2` (`VC 60`) oder `0.30.0` (`VC 61`) können direkt per Update aktualisiert werden (identischer Signaturschlüssel). Nur Installationen vor `0.28.0` erfordern weiterhin eine vorherige Deinstallation (`Deinstallieren -> Neuinstallation`).

> [!IMPORTANT]
> GeDefense Mobile ist aktuell ein **Public-Beta-/Pre-Production-Security-Kandidat**. Die automatisierten Release-Gates sind umfangreich; OEM-Verhalten, VPN-Lifecycle und Update-/Migrationspfade müssen vor Hochrisiko-Produktiveinsatz weiterhin auf realen Geräten geprüft werden.

## Was ist GeDefense?

GeDefense Mobile ist eine native Android-Sicherheitsplattform, die einen lokalen VPN-Enforcement-Pfad, Endpoint-Telemetrie, EDR/XDR-Korrelation, Threat Intelligence, App-Risikobewertung, verschlüsselte Evidenz und optionale Android-Device-Owner-Steuerung verbindet.

Die Architektur ist konsequent **local-first**: Sicherheitsentscheidungen erfolgen auf dem Endgerät. GeDefense benötigt kein VGT-Cloudkonto und lädt keine Paket-Payloads, Paketlisten, Scan-Artefakte oder XDR-Evidenz zu einem VGT-Backend hoch. Optionale Threat-/ASN-Aktualisierungen werden als begrenzte und validierte Dateninputs geladen, nicht als Cloud-Verdict-Dienst.

### Kernfunktionen

| Bereich | Funktion |
| --- | --- |
| Netzwerkschutz | Full Flow `VpnService`, Direct-L4-Egress, Selective Routing und WireGuard-L3-Transport |
| Threat Intelligence | Lokal kompilierte Threat-Policy, gebündelter Offline-GeoIP-Seed (IPv4/IPv6) und Offline-Lookups |
| Telemetry Shield | 626 auditierte Lokalregeln (`MALICIOUS_TELEMETRY` in Conservative/Balanced/Strict scharf, 34 `ESSENTIAL_*`-Schutzausnahmen, DNS-NXDOMAIN mit 120s RFC-2308-SOA-Negative-Cache, TLS/QUIC-SNI-Blocking & XDR-Retry-Storm-Erkennung) ohne TLS-MITM |
| Encrypted-DNS Control | 19 verifizierte DoH-/DoT-Bootstrap-Domains + Port-853 DoT-/DoQ-Kontrolle in strikten Profilen ohne Root-CA |
| EDR / XDR | Lokale Korrelation aus Package-, Verhalten-, Netzwerk-, Integritäts- und Hardening-Evidenz |
| InstallGuard | Pre-Egress FlowGate sowie begrenzter Fast-/Deep-Scan frisch installierter Apps |
| Malwareanalyse | Lokale App-/Package-Analyse und begrenztes Scannen freigegebener Speicherbereiche |
| Secure Telemetry Vault | Domänengetrennte AES-256-GCM-Speicherung mit authentifizierten Snapshots und update-stabiler Key-Kustodie |
| Evidence | Verschlüsseltes, authentifiziertes lokales Evidence Ledger mit begrenzter Recovery-Semantik |
| Resilience | Begrenzte Selbstreparatur, Health Checks und Fail-Closed-Degradierung |
| TITAN | Optionaler Device-Owner-Policy-Pfad für Managed-Device-Härtung und Lockdown |
| Diagnostics | Nur vom Nutzer gestartetes Aggregate-Only-Support-Bundle plus Threat-Policy-Selbsttest ohne Netzwerkzugriff |

## Datenschutz und Telemetry Shield

Der zentrale Datenschutzgedanke ist nicht nur, dass **GeDefense selbst keine zentrale Telemetrie benötigt**. Der Telemetry Shield kann zusätzlich bekannte Tracking-, Advertising-, Analytics- und optionale Geräte-Telemetrie anderer Apps auf Netzwerk-/Policy-Ebene blockieren. GeDefense führt dabei bewusst **keine TLS-Interception** durch. Wenn eine App Funktionsdaten und Telemetrie innerhalb desselben verschlüsselten First-Party-Endpunkts mischt, behauptet GeDefense nicht, den Inhalt ohne MITM auseinanderhalten zu können.

Siehe [`PRIVACY.md`](PRIVACY.md), [`NETWORK-EGRESS.md`](docs/security/NETWORK-EGRESS.md) und [`SECURE-TELEMETRY-VAULT.md`](docs/security/SECURE-TELEMETRY-VAULT.md).

## Architektur

```text
Android UI / Control Plane (Kotlin)
        |
        | authentifizierter Unix-Domain-Control-Channel
        | SCM_RIGHTS Descriptor Transfer
        v
GaiaNet V2 Data Plane (Go, separater Prozess)
        |
        +-- Threat Policy / Telemetry Shield / Package Gate
        +-- Direct L4 Transport
        `-- WireGuard L3 Transport
                |
                v
          Physisches Netzwerk
```

Der Android-Host besitzt Lifecycle, Policy, Keystore-Zugriff und UI-State. GaiaNet wird als separater Prozess aus dem Native-Library-Verzeichnis gestartet und erhält nur die für den aktiven Transportpfad erforderlichen, begrenzten File-Deskriptoren und Konfigurationsdaten. Im Paket-Hot-Path gibt es kein JNI.

Aktuell gepinnt: **Go 1.26.8**, Kotlin 1.9.24, Gradle 8.7, JDK 17, Android API 36 und NDK r27c. Details: [`TOOLCHAINS.lock`](TOOLCHAINS.lock), [`SUPPLY-CHAIN.md`](docs/security/SUPPLY-CHAIN.md).

## Sicherheitsmodell

Wichtige Invarianten:

- Fail-Closed bei kritischen Integritäts-, VPN- und Evidence-Fehlern;
- kein TLS-MITM als Standardpfad;
- kein dynamisches Code-Loading und kein WebView-Sicherheitsplane;
- begrenzte Queues, Parser, Scans, Retries und Hintergrundarbeit;
- kein pauschaler WireGuard-UID-Bypass, nur exakte Upstream-Sockets werden geschützt/gebunden;
- getrennte Schlüsselbereiche für persistente Security-Daten;
- update-stabile Verschlüsselung, nicht aus APK-Hash oder Versionsnummer abgeleitet;
- crash-sichere authentifizierte Veröffentlichung (`stage -> fsync -> verify -> atomic replace -> directory fsync`);
- explizite Trust Boundaries zwischen Android-Host, GaiaNet, externen Datensätzen und Plattformdiensten.

Vor sensiblen Deployments: [`SECURITY.md`](SECURITY.md), [`THREAT-MODEL.md`](docs/security/THREAT-MODEL.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), [`SUPPLY-CHAIN.md`](docs/security/SUPPLY-CHAIN.md).

## Schutzmodi

- **Selective**: nur Policy-ausgewählte Threat-Präfixe werden in den Schutzpfad geroutet.
- **Full Flow / Direct**: Geräteverkehr läuft durch GaiaNet, freigegebener Traffic verlässt das Gerät über direkte Kernel-Sockets.
- **WireGuard**: Full Flow über den eingebetteten `wireguard-go`-L3-Transport.
- **Strict / Lockdown**: für Android Always-on/Lockdown und Fail-Closed bei nicht verfügbarem sicheren Transport.

## Build

Benötigt werden JDK 17, Gradle 8.7, Android Platform/Build Tools 36, NDK `27.2.12479018` und Go 1.26.8.

`:app` enthält exakt **zwei gepinnte, lokal vendorte Apache-2.0-QR-Scanner-Artefakte** (ZXing Android Embedded + ZXing Core) für den lokalen WireGuard-QR-Import; `:core` bleibt frei von externen Android-Runtime-Bibliotheken. GaiaNet verwendet einen kleinen, gepinnten und lokal vendorten Go-Dependency-Satz.

Kompletter Readiness-Lauf:

```bash
bash tools/release-readiness.sh
```

Exakter Offline-/Repro-Build: [`BUILD-RUNBOOK.md`](docs/release/BUILD-RUNBOOK.md).

## Architektur-Dossier

| Sprache | PDF |
| --- | --- |
| Deutsch (Original) | [`Master Architecture - DE`](docs/datasheets/GeDefense-Mobile-Master-Architecture-DE.pdf) |
| English | [`Master Architecture - EN`](docs/datasheets/GeDefense-Mobile-Master-Architecture-EN.pdf) |
| Русский | [`Master Architecture - RU`](docs/datasheets/GeDefense-Mobile-Master-Architecture-RU.pdf) |
| 简体中文 | [`Master Architecture - ZH-CN`](docs/datasheets/GeDefense-Mobile-Master-Architecture-ZH-CN.pdf) |

## Neueste Änderungen / Changelog

### Version 0.31.0 (VersionCode 62) — Kuratierter 626-Regel Telemetry Shield, Malicious Telemetry & Anti-Retry-Storm-Schutz
* **626-Regel Privacy Intelligence Core:** Ausbau von [`privacy_intelligence_v1.tsv`](app/src/main/assets/privacy_intelligence_v1.tsv) von 27 auf 626 lizenzgeprüfte Regeln (OEM-Telemetrie für Xiaomi/HyperOS, Samsung, Huawei, Oppo/ColorOS/HeyTap, Vivo, Motorola; Analytics, Ads, Attribution, Crash/Diagnostics) inklusive **34 `ESSENTIAL_*`-Schutzausnahmen** (FCM-Push, Captive-Portal, Play Integrity, OEM-OTA/Cloud/IoT) und **19 verifizierten `ENCRYPTED_DNS`-Bootstrap-Hosts** (`CONSERVATIVE`: 262 aktive Block-Regeln, `BALANCED`: 417, `STRICT`: 584).
* **Konsequente Abwehr bösartiger Telemetrie (`MALICIOUS_TELEMETRY`):** Neue Kategorie mit 30 Regeln für Firmware-Spyware (Adups/AdSunflower/AdFuture), getarntes Dark AdTech ohne Webpräsenz (`lazybumblebee.com`, `qa-analytics.com`, Bigo-Cluster), Supply-Chain-vorbelastete SDKs (`websdk.appsflyer.com`), AppMetrica, ByteDance `mssdk` und Session-Replay-Tracker — greift bereits im Standardprofil `CONSERVATIVE` sowie `BALANCED`/`STRICT` und eskaliert im `XdrEngine` mit `XdrSeverity.HIGH`.
* **Anti-Retry-Storm & Stage-2-Compiler:** RFC-2308-Negative-Cache-`SOA` (`120s` TTL) in `netstack/dns.go` gegen SDK-Retry-Stürme, Sliding-Window-`TelemetryRetryStormTracker` (`privacy.retry_storm`) in `FullFlowAnalytics`/`XdrEngine` sowie deterministischer Feed-Compiler [`tools/privacy_feed_compiler.py`](tools/privacy_feed_compiler.py).

### Highlights seit `0.28.0-beta1` (`0.28.0-beta2` VC 60 & `0.30.0` VC 61)
* **Offline GeoIP-Seed (`0.30.0` / VC 61):** Gebündelte IPv4- (329.323 Ranges) und IPv6-Tabellen (13.860 Ranges) aus GeDefense Linux inkl. `::ffff:`-Normalisierung und `"ZZ"`-Backfill für sofortige Länderauflösung ab Kaltstart.
* **Kompakte Glass-Notification & LAN/Sentinel-Härtung (`0.30.0` / VC 61):** Optimierte 2-Zeilen-Statuskarte (Grün bei Normalbetrieb, Rot nur bei echten XDR-Vorfällen/Quarantäne/Integritätsfehlern), VPN-bereinigte `selectLanNetwork()`-Erkennung, ephemerer mDNS-Fallback und Interface-Rebind in `PortSentinel`.
* **Datenfluss-Atlas & passives TLS/QUIC-SNI (`0.28.0-beta1` / VC 59):** Zero-MITM TLS/QUIC-SNI-Inspektion im Direct- und WireGuard-Pfad, 7-Tage-Verlaufsfenster und App-basierte Smart-Firewall.

> Der vollständige Versionsverlauf aller Builds befindet sich in [`CHANGELOG.md`](CHANGELOG.md).

## Dokumentation

[`ARCHITECTURE.md`](ARCHITECTURE.md) · [`SECURITY.md`](SECURITY.md) · [`THREAT-MODEL.md`](docs/security/THREAT-MODEL.md) · [`PRIVACY.md`](PRIVACY.md) · [`NETWORK-EGRESS.md`](docs/security/NETWORK-EGRESS.md) · [`SECURE-TELEMETRY-VAULT.md`](docs/security/SECURE-TELEMETRY-VAULT.md) · [`THREAT-INTELLIGENCE.md`](docs/security/THREAT-INTELLIGENCE.md) · [`ASN-EVIDENCE.md`](docs/security/ASN-EVIDENCE.md) · [`SUPPLY-CHAIN.md`](docs/security/SUPPLY-CHAIN.md) · [`SBOM.cdx.json`](SBOM.cdx.json) · [`RELEASE-CHECKLIST.md`](docs/release/RELEASE-CHECKLIST.md)

## Sicherheitsmeldungen

Bitte keine ausnutzbaren Schwachstellen oder sensitiven Gerätedaten in öffentliche Issues schreiben.

**Security-Kontakt:** [security@visiongaia.de](mailto:security@visiongaia.de)

Wenn verfügbar, GitHub Private Vulnerability Reporting verwenden.

## Lizenz

GNU Affero General Public License v3.0 oder neuer (**AGPL-3.0-or-later**), siehe [`LICENSE`](LICENSE).

---
<p align="center"><strong>VisionGaiaTechnology</strong><br>Experimental sovereign security & software engineering.</p>
