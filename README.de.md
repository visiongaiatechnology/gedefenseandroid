<p align="center"><img src="docs/assets/gedefense-logo.png" alt="GeDefense Mobile" width="150" /></p>
<h1 align="center">GeDefense Mobile</h1>
<p align="center"><strong>Lokale Android-Endpoint-Security, Netzwerkabwehr und XDR.</strong><br>Entwickelt von VisionGaiaTechnology für Umgebungen, in denen Sicherheitstelemetrie auf dem Gerät bleiben soll.</p>
<p align="center"><a href="README.md">English</a> · <a href="README.de.md"><strong>Deutsch</strong></a> · <a href="README.ru.md">Русский</a> · <a href="README.zh-CN.md">简体中文</a></p>
<p align="center">
<img alt="Version" src="https://img.shields.io/badge/Version-0.27.8--beta.6-D8A928?style=flat-square" />
<img alt="Android" src="https://img.shields.io/badge/Android-10%2B%20(API%2029%2B)-3DDC84?style=flat-square&logo=android&logoColor=white" />
<img alt="Go" src="https://img.shields.io/badge/Go-1.26.8-00ADD8?style=flat-square&logo=go&logoColor=white" />
<img alt="Privacy" src="https://img.shields.io/badge/Datenschutz-local--first-06B6D4?style=flat-square" />
<img alt="License" src="https://img.shields.io/badge/Lizenz-AGPL--3.0--or--later-2563EB?style=flat-square" />
</p>

> [!IMPORTANT]
> GeDefense Mobile ist aktuell ein **Public-Beta-/Pre-Production-Security-Kandidat**. Die automatisierten Release-Gates sind umfangreich; OEM-Verhalten, VPN-Lifecycle und Update-/Migrationspfade müssen vor Hochrisiko-Produktiveinsatz weiterhin auf realen Geräten geprüft werden.

## Was ist GeDefense?

GeDefense Mobile ist eine native Android-Sicherheitsplattform, die einen lokalen VPN-Enforcement-Pfad, Endpoint-Telemetrie, EDR/XDR-Korrelation, Threat Intelligence, App-Risikobewertung, verschlüsselte Evidenz und optionale Android-Device-Owner-Steuerung verbindet.

Die Architektur ist konsequent **local-first**: Sicherheitsentscheidungen erfolgen auf dem Endgerät. GeDefense benötigt kein VGT-Cloudkonto und lädt keine Paket-Payloads, Paketlisten, Scan-Artefakte oder XDR-Evidenz zu einem VGT-Backend hoch. Optionale Threat-/ASN-Aktualisierungen werden als begrenzte und validierte Dateninputs geladen, nicht als Cloud-Verdict-Dienst.

### Kernfunktionen

| Bereich | Funktion |
| --- | --- |
| Netzwerkschutz | Full Flow `VpnService`, Direct-L4-Egress, Selective Routing und WireGuard-L3-Transport |
| Threat Intelligence | Lokal kompilierte Threat-Policy mit deterministischer Feed-Autorität und Offline-Lookups |
| Telemetry Shield | Lokales Blockieren bekannter Advertising-, Analytics- und optionaler Geräte-Telemetrie ohne TLS-MITM |
| Encrypted-DNS Control | DoT-/DoQ-Kontrolle in strikten Profilen ohne manipulierte Root-CA |
| EDR / XDR | Lokale Korrelation aus Package-, Verhalten-, Netzwerk-, Integritäts- und Hardening-Evidenz |
| InstallGuard | Pre-Egress FlowGate sowie begrenzter Fast-/Deep-Scan frisch installierter Apps |
| Malwareanalyse | Lokale App-/Package-Analyse und begrenztes Scannen freigegebener Speicherbereiche |
| Secure Telemetry Vault | Domänengetrennte AES-256-GCM-Speicherung mit authentifizierten Snapshots und update-stabiler Key-Kustodie |
| Evidence | Verschlüsseltes, authentifiziertes lokales Evidence Ledger mit begrenzter Recovery-Semantik |
| Resilience | Begrenzte Selbstreparatur, Health Checks und Fail-Closed-Degradierung |
| TITAN | Optionaler Device-Owner-Policy-Pfad für Managed-Device-Härtung und Lockdown |
| Diagnostics | Nur vom Nutzer gestartetes Aggregate-Only-Support-Bundle, kein automatischer Upload |

## Datenschutz und Telemetry Shield

Der zentrale Datenschutzgedanke ist nicht nur, dass **GeDefense selbst keine zentrale Telemetrie benötigt**. Der Telemetry Shield kann zusätzlich bekannte Tracking-, Advertising-, Analytics- und optionale Geräte-Telemetrie anderer Apps auf Netzwerk-/Policy-Ebene blockieren. GeDefense führt dabei bewusst **keine TLS-Interception** durch. Wenn eine App Funktionsdaten und Telemetrie innerhalb desselben verschlüsselten First-Party-Endpunkts mischt, behauptet GeDefense nicht, den Inhalt ohne MITM auseinanderhalten zu können.

Siehe [`PRIVACY.md`](PRIVACY.md), [`NETWORK-EGRESS.md`](NETWORK-EGRESS.md) und [`SECURE-TELEMETRY-VAULT.md`](SECURE-TELEMETRY-VAULT.md).

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

Aktuell gepinnt: **Go 1.26.8**, Kotlin 1.9.24, Gradle 8.7, JDK 17, Android API 36 und NDK r27c. Details: [`TOOLCHAINS.lock`](TOOLCHAINS.lock), [`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md).

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

Vor sensiblen Deployments: [`SECURITY.md`](SECURITY.md), [`THREAT-MODEL.md`](THREAT-MODEL.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), [`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md).

## Schutzmodi

- **Selective**: nur Policy-ausgewählte Threat-Präfixe werden in den Schutzpfad geroutet.
- **Full Flow / Direct**: Geräteverkehr läuft durch GaiaNet, freigegebener Traffic verlässt das Gerät über direkte Kernel-Sockets.
- **WireGuard**: Full Flow über den eingebetteten `wireguard-go`-L3-Transport.
- **Strict / Lockdown**: für Android Always-on/Lockdown und Fail-Closed bei nicht verfügbarem sicheren Transport.

## Build

Benötigt werden JDK 17, Gradle 8.7, Android Platform/Build Tools 36, NDK `27.2.12479018` und Go 1.26.8.

`app` und `core` besitzen **keine externen Android-Runtime-Bibliotheken**. GaiaNet verwendet einen kleinen, gepinnten und lokal vendorten Go-Dependency-Satz.

Kompletter Readiness-Lauf:

```bash
bash tools/release-readiness.sh
```

Exakter Offline-/Repro-Build: [`BUILD-RUNBOOK.md`](BUILD-RUNBOOK.md).

## Architektur-Dossier

| Sprache | PDF |
| --- | --- |
| Deutsch (Original) | [`Master Architecture - DE`](docs/datasheets/GeDefense-Mobile-Master-Architecture-DE.pdf) |
| English | [`Master Architecture - EN`](docs/datasheets/GeDefense-Mobile-Master-Architecture-EN.pdf) |
| Русский | [`Master Architecture - RU`](docs/datasheets/GeDefense-Mobile-Master-Architecture-RU.pdf) |
| 简体中文 | [`Master Architecture - ZH-CN`](docs/datasheets/GeDefense-Mobile-Master-Architecture-ZH-CN.pdf) |

> Das Dossier dokumentiert die VC55-Architekturbaseline. Innerhalb desselben VersionCodes wurden danach weitere Härtungen vorgenommen. Für den aktuellen Implementierungsstand gelten `TOOLCHAINS.lock`, `SECURITY.md`, `CHANGELOG.md` und der Quellcode als maßgeblich.

## Dokumentation

[`ARCHITECTURE.md`](ARCHITECTURE.md) · [`SECURITY.md`](SECURITY.md) · [`THREAT-MODEL.md`](THREAT-MODEL.md) · [`PRIVACY.md`](PRIVACY.md) · [`NETWORK-EGRESS.md`](NETWORK-EGRESS.md) · [`SECURE-TELEMETRY-VAULT.md`](SECURE-TELEMETRY-VAULT.md) · [`THREAT-INTELLIGENCE.md`](THREAT-INTELLIGENCE.md) · [`ASN-EVIDENCE.md`](ASN-EVIDENCE.md) · [`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md) · [`SBOM.cdx.json`](SBOM.cdx.json) · [`RELEASE-CHECKLIST.md`](RELEASE-CHECKLIST.md)

## Sicherheitsmeldungen

Bitte keine ausnutzbaren Schwachstellen oder sensitiven Gerätedaten in öffentliche Issues schreiben.

**Security-Kontakt:** [security@visiongaia.de](mailto:security@visiongaia.de)

Wenn verfügbar, GitHub Private Vulnerability Reporting verwenden.

## Lizenz

GNU Affero General Public License v3.0 oder neuer (**AGPL-3.0-or-later**), siehe [`LICENSE`](LICENSE).

---
<p align="center"><strong>VisionGaiaTechnology</strong><br>Experimental sovereign security & software engineering.</p>
