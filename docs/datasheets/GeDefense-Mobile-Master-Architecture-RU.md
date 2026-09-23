# GeDefense Mobile
## Master Architecture Datasheet + Technical Master Map

**Архитектура · Безопасность · Supply Chain · Runtime · UI · Карта модулей**

- **Release baseline:** 0.27.8-beta.6
- **VersionCode:** 55 · VC55-KeyLifecycle-FINAL
- **Дата анализа:** 2026-09-23
- **Организация:** VisionGaiaTechnology (VGT)
- **Язык оригинала:** немецкий
- **Издание:** русский перевод с переразметкой

> **Примечание к переводу.** Это издание переводит и компактно переразмечает содержательную часть исходного 86-страничного немецкого master dossier. Технические идентификаторы, пути файлов, названия протоколов и ссылки на исходники сохраняются. Немецкий документ фиксирует baseline VC55 и поэтому содержит исторические упоминания, например Go 1.23.x и соответствующее число файлов. Текущее состояние репозитория может включать последующее hardening в том же VersionCode. Для фактической текущей реализации приоритет имеют `TOOLCHAINS.lock`, `SECURITY.md`, `CHANGELOG.md` и исходный код.

---

# Содержание

## Часть I · Архитектурный паспорт
A. Executive Architecture Summary · B. Идентичность продукта и назначение · C. Функциональный охват · D. Архитектурная модель · E. Архитектура компонентов · F. Внутренние зависимости · G. Third-Party Dependencies / Supply Chain · H. Сводка зависимостей · I. Языки и стек · J. Метрики кода · K. Архитектура безопасности · L. Trust Model · M. Threat Model · N. Криптография · O. Аутентификация и авторизация · P. Архитектура данных · Q. Потоки данных · R. Сетевая архитектура · S. Интеграция с ОС · T. Процессы/потоки/concurrency · U. Ошибки и устойчивость · V. Обновления и релизы · W. Build/Supply Chain Security · X. Приватность и телеметрия · Y. Logging/Audit/Evidence · Z. Производительность · AA. Масштабирование и лимиты · AB. Конфигурация и профили · AC. Интерфейсы и API · AD. Форматы и протоколы · AE. Тестирование · AF. Adversarial Security Testing · AG. Качество · AH. Архитектурные инварианты · AI. Security invariants · AJ. Внешняя инфраструктура · AK. Offline · AL. Attack Surface · AM. Hardening · AN. Secrets · AO. Привилегии · AP. Совместимость · AQ. Packaging · AR. Лицензирование · AS. Документация · AT. Ограничения · AU. Технический долг · AV. Остаточные риски · AW. Сильные стороны · AX. Границы · AY. Матрица зрелости · AZ. Factsheet.

## Часть II · Architecture & Technical Master Map
1. Глобальное дерево архитектуры · 2. Привязка файлов · 3. Документация модулей · 4. Dashboard подробно · 5. UI Architecture · 6. API Architecture · 7. Data Flows · 8. Shared/Core Files · 9. Архитектурные связи · 10. Ссылки на файлы · 11. Архитектурные наблюдения.

---

# Часть I · Архитектурный паспорт

## A. Executive Architecture Summary

### Техническая сводка

| Атрибут | Значение / статус | Основание |
| --- | --- | --- |
| Продукт | GeDefense Mobile | Android resources |
| Внутреннее имя | VGT-GeDefense-Mobile | `settings.gradle.kts` |
| Категория | On-device endpoint protection (EDR/XDR), mobile firewall, zero-trust network shield | архитектурная документация |
| Назначение | автономная, не зависящая от облака защита сети, угроз и устройства Android | security/manifest |
| Версия | 0.27.8-beta.6 | `VERSION` |
| VersionCode | 55 | `VERSION_CODE` |
| Канал | Public Beta / Pre-Production Security Candidate | release docs |
| Платформа | Android API 29-36 | Gradle |
| ABI | arm64-v8a, x86_64 | toolchain/build |
| ELF alignment | >=16 KiB (`0x4000`) PT_LOAD | native gate |
| Архитектура | Kotlin-host + изолированный Go netstack | `ARCHITECTURE.md` |
| Модель безопасности | local-first, least privilege, fail-closed, non-MITM | security docs |
| Сеть | один `VpnService`, Direct L4 или WireGuard L3 | transport source |
| Хранилище | 12 криптографически разделённых vault-доменов в `noBackupFilesDir` | vault docs |
| At-rest crypto | AES-256-GCM, 96-bit nonce, 128-bit tag, AAD, HMAC-SHA-256 | core crypto |
| Ключи | стабильный для установки AndroidKeyStore HMAC root `vgt.gedefense.mobile.vault.root-prf.v1` | `PersistentVaultKeys.kt` |
| Transit | WireGuard Noise IKpsk2 / ChaCha20-Poly1305 / Curve25519 / BLAKE2s | vendored WireGuard |
| Подписи | ECDSA P-256 + опционально ML-DSA-87 | artifact signer |
| Update model | атомарная однонаправленная миграция поколений, независимая от APK hash | key lifecycle |
| Android runtime dependencies | 0 внешних библиотек в `:app`/`:core` | Gradle |

### Что представляет собой система

GeDefense Mobile - локальная Android-платформа endpoint-защиты, объединяющая XDR, поведенческий сетевой анализ, пакетную фильтрацию, offline threat detection и криптографически защищённые доказательства без обязательного облачного анализа и центральной телеметрии.

Главная задача - уменьшить непрозрачность мобильной ОС для пользователя и ограничить скрытый data exfiltration, tracking, вредоносные соединения приложений и C2. GeDefense не ломает TLS ради универсального payload inspection; решения принимаются локально на основании метаданных, состояния устройства, локальных индексов угроз и независимых evidence-сигналов.

Система использует строгую двухпроцессную модель. Kotlin-host владеет UI, lifecycle, policy и Android Keystore. Отдельный процесс **GaiaNet V2** на Go обрабатывает L3/L4 пакеты. Связь идёт через приватный Unix-domain socket с передачей файловых дескрипторов `SCM_RIGHTS`, без JNI в packet hot path.

Сетевой слой поддерживает прямой egress через kernel sockets и встроенный `wireguard-go` L3 tunnel. В WireGuard-режиме отсутствует blanket UID bypass: Android получает и `protect()` только точные UDP transport sockets туннеля.

Secure Telemetry Vault разделяет постоянные security-данные на независимые криптографические домены. VC55 отделяет key custody от APK/version identity, чтобы обычное обновление не требовало re-keying.

## B. Идентичность продукта и назначение

- продукт: GeDefense Mobile;
- семейство: VisionGaiaTechnology Security & Defense Systems;
- класс: mobile endpoint protection / EDR / XDR / firewall / network defense;
- основное назначение: автономная защита мобильного трафика, блокирование вредоносных endpoint-ов, оценка приложений, hardening Android;
- дополнительные возможности: Network Discovery, Port Sentinel, TITAN Device Owner, локальное Evidence Ledger;
- поддержка: API 29-36+;
- режим эксплуатации: standalone/local-first;
- привилегии: обычное приложение; Device Owner - только опционально;
- UI: native Android Views, без WebView security plane;
- внешняя инфраструктура: обязательного VGT backend нет; разрешены опциональные публичные security/ASN updates.

### Обещания продукта

1. **Data sovereignty:** security telemetry/evidence не отправляются в VGT для облачного анализа.
2. **Deterministic security:** lookup и block decisions локальны и ограничены по ресурсам.
3. **Fail-closed integrity:** критичная поломка не превращается в незаметный fail-open.
4. **Update resilience:** обновление приложения не должно само по себе уничтожать ключи или создавать ложный tamper alarm.

### Явные non-goals

Нет TLS interception, cloud antivirus upload, гарантии против полного kernel/root compromise, on-device VM для исполнения malware и скрытой универсальной деинсталляции приложений без Device Owner.

## C. Функциональный охват

### Network / Policy

- GaiaNet V2 L3/L4 engine;
- Direct Egress;
- embedded WireGuard L3;
- Strict/Lockdown без fallback, когда policy требует туннель;
- Full Flow через TUN;
- Selective routing для уменьшенного blast radius.

### Security engines

- локальный Threat Intelligence Engine с явной feed authority;
- InstallGuard FlowGate и Fast/Deep Scan;
- Telemetry Shield;
- Encrypted-DNS Control (DoT/DoQ port 853) без MITM;
- App Risk Scanner и bounded Storage Malware Scanner;
- Network Discovery и Port Sentinel.

### Data / Evidence / Admin

- 12-доменный Secure Telemetry Vault;
- Evidence Ledger v3;
- Hybrid Artifact Signer;
- Resilience Supervisor;
- TITAN Device Owner;
- локальный ASN Evidence Repository;
- aggregate-only diagnostics.

## D. Архитектурная модель

```text
Presentation / UI
   -> Kotlin Application Control Plane
   -> authenticated Unix IPC + SCM_RIGHTS
   -> GaiaNet V2 Go Data Plane
   -> TUN / Direct sockets / WireGuard / physical network
```

UI читает immutable snapshots и не владеет ключами/packet buffers. Kotlin-host сериализует security-sensitive mutations, изолирует Keystore operations и выполняет recovery. IPC использует app-private socket и случайный 32-byte token. GaiaNet не имеет Android Context/JVM и получает только ограниченные дескрипторы и policy material.

## E. Архитектура компонентов

| Компонент | Ответственность | Trust | Critical |
| --- | --- | --- | --- |
| `GeDefenseVpnService` | VPN lifecycle, TUN, underlay, protect | host | да |
| `NativeGaiaNet` | process lifecycle, token handshake, FD transfer | host | да |
| GaiaNet Engine | IP/TCP/UDP, flows, forwarding | isolated | да |
| WireGuard transport | L3 tunnel, peers, rekey | isolated | да |
| Package Egress Gate | quarantine allow/drop | isolated | да |
| Secure Telemetry Vault | authenticated encryption | host crypto | да |
| PersistentVaultKeys | stable KEK/DEK custody | host crypto | да |
| Evidence Ledger | authenticated journal | host storage | да |
| InstallGuard | staged app scanning | host scanner | да |
| Resilience Supervisor | trust-preserving recovery | host maintenance | да |
| ThreatIndex | O(log n) threat match | read-only | да |
| TelemetryShield | tracking/telemetry policy | read-only | средняя |
| TITAN Manager | Device Owner hardening | admin | да |

## F. Внутренние зависимости

```text
app
├─ core (pure Kotlin domain/security)
└─ netstack (separate Go helper)

tools/ = audit/build verification
```

Циклических module dependencies нет. `:core` не зависит от Android и тестируется на JVM; `netstack` - отдельный Go module `visiongaia.dev/gedefense/mobile/netstack`.

## G. Third-Party Dependencies / Supply Chain

Android `app` и `core` не используют внешние runtime libraries. Go subsystem хранит upstream source локально под `third_party/go/` и связывает его через `replace`.

| Dependency | Version | Назначение | License |
| --- | --- | --- | --- |
| wireguard-go | 0.0.20250522 | WireGuard / Noise / peers | MIT |
| x/crypto | v0.37.0 | crypto primitives | BSD-3 |
| x/net | v0.39.0 | network helpers | BSD-3 |
| x/sys | v0.32.0 | Unix/Linux primitives | BSD-3 |
| x/term | v0.31.0 | auxiliary | BSD-3 |
| x/text | v0.24.0 | Unicode/config | BSD-3 |

Исходный dossier фиксирует AGP 8.5.2, Kotlin 1.9.24, Gradle 8.7, JDK 17, Go 1.23.x, NDK r27c. **Текущий публичный source tree использует Go 1.26.8**, что отражено в `TOOLCHAINS.lock`.

Go build может работать с `GOPROXY=off` и `GOSUMDB=off`. `SOURCE-MANIFEST.sha256` связывает snapshot исходников. Нулевой внешний Android runtime dependency surface уменьшает Maven supply-chain risk.

## H. Dependency Summary

Android runtime: 0 внешних библиотек. Go runtime: малый pinned/vendored набор. Dynamic code/module loading не используется. Build toolchain записан и проверяется отдельно.

## I. Языки и стек

Kotlin реализует Android control plane; Go - GaiaNet data plane; Python и shell/PowerShell - security/release gates. Большая часть общего LOC в dossier приходится на vendored Go source. `.so` у GaiaNet - способ упаковки executable в `nativeLibraryDir`, а не JNI library.

## J. Метрики кода

Исходный dossier насчитывает около 1.56M physical LOC вместе с vendored code. Наибольшие first-party файлы: `GeDefenseVpnService.kt`, `AppRuntime.kt`, `AppRiskScanner.kt`, `XdrEngine.kt`, `XdrActivity.kt`, `NetworkDiscoveryScanner.kt`. Руководство предпочитает <=500 LOC для stateless orchestrators; крупные lifecycle/state owners документированы отдельно.

## K. Архитектура безопасности

1. Confidentiality: AES-256-GCM для локального security state.
2. Integrity: HMAC и криптографическая верификация входных security datasets.
3. Availability: bounded memory/queues/flows/scans.
4. Authenticity: hashes/signatures для внешних и экспортируемых artifacts.
5. Least privilege: разделение host/data plane; GaiaNet не имеет Keystore доступа.

## L. Trust Model

Untrusted: hostile packets, third-party apps, external feeds, shared storage, непроверенные IPC данные. Trusted/TCB: Android platform в пределах threat model, KeyStore/KeyMint/StrongBox, GeDefense host и проверенные core algorithms. GaiaNet намеренно получает ограниченную authority.

## M. Threat Model

Учитываются malware apps, C2, transport attacker, malformed packets, resource exhaustion, tampered local storage, malicious update, crypto-provider failure и hostile external files. Митигируются quarantine/FlowGate, ThreatIndex, WireGuard, bounded reassembly, fuzzing, authenticated storage, package signature verification и fail-closed provider handling.

Не полностью покрываются: kernel/root compromise, физические атаки за пределами Android policy, неизвестный DoH over HTTPS/ECH и полный replay валидного filesystem image без trusted monotonic counter.

## N. Криптография

At rest: AES-256-GCM, 96-bit nonce, 128-bit tag, AAD binding, HMAC-SHA-256 snapshot authentication. Root custody - non-exportable AndroidKeyStore HMAC key. Random per-domain roots хранятся только wrapped; HKDF subkeys живут кратковременно. Generation/version migration явная.

Transit: WireGuard Noise IKpsk2 / ChaCha20-Poly1305 / Curve25519. Export signatures: ECDSA P-256 и условно ML-DSA-87 при реальной поддержке Android/KeyMint.

## O. Аутентификация и авторизация

VPN требует Android user consent и отдельное product disclosure. Helper startup использует fresh 32-byte token. TITAN actions требуют фактического Device Owner/Admin state. Managed CA installation ограничена по размеру/формату и требует явного подтверждения fingerprint.

## P. Архитектура данных

Sensitive state хранится в `noBackupFilesDir`, разнесён по независимым domains: XDR, evidence, scanner, behavior, firewall, WireGuard profile, package baseline, LAN history, Port Sentinel, TITAN policy и др. Android backup/device transfer для security stores отключён.

## Q. Потоки данных

```text
App traffic -> TUN -> GaiaNet -> threat/privacy/package policy
           -> allow/drop -> Direct or WireGuard -> network
```

```text
Security event -> XDR correlation -> encrypted local store/Evidence
               -> optional user-requested signed export
```

```text
HTTPS feed -> bounded parser -> canonical ThreatIndex
           -> authenticated atomic cache -> immutable GaiaNet policy
```

## R. Сетевая архитектура

Один владелец `VpnService`. Direct-mode использует protected kernel sockets. WireGuard-mode использует embedded userspace L3. Upstream UDP FDs передаются Android для точного `VpnService.protect()`/network binding. Blanket UID bypass запрещён.

## S. Интеграция с ОС

Используются `VpnService`, `ConnectivityManager`, `PackageManager`, `DevicePolicyManager`, `JobScheduler`, SAF, Android KeyStore/KeyMint. Blocking work не выполняется напрямую в UI callbacks.

## T. Process / Thread / Concurrency

UI thread - только presentation/lifecycle coordination. `gedefense-control` сериализует transport/security mutations. Expensive operations идут в bounded pools. Go flows/queues имеют лимиты, race tests обязательны. Unbounded queues в security path считаются недопустимыми.

## U. Ошибки и устойчивость

Критичные crypto/integrity/transport failures fail closed. Невалидный новый threat feed не уничтожает last-known-good state. Resilience Supervisor проверяет vaults, baselines и helper health, но не имеет права стирать evidence, снимать quarantine или превращать failed integrity в success ради «зелёного» статуса.

## V. Update / Release Architecture

VC55 отделяет persistent encryption custody от APK identity. Root создаётся один раз на установку и не строится из APK hash/version/source manifest. Исторические поколения читаются/аутентифицируются, мигрируются в памяти, новая версия публикуется crash-safe и только затем старое состояние выводится из активного использования.

## W. Build / Supply Chain Security

Source manifest, vendored Go, pinned toolchain, R8/minification, 16 KiB ELF alignment, native reproducibility и SBOM/release audits входят в shipping model.

## X. Приватность и телеметрия

В продукте нет Firebase Crashlytics, Sentry, Bugsnag, advertising/analytics SDK. Network observations используются локально. Диагностический export инициирует пользователь и работает в aggregate-only режиме без package identities, IP/domain/path/payload detail.

Telemetry Shield отдельно блокирует известную third-party telemetry там, где это можно определить на policy/network layer, без TLS interception.

## Y. Logging / Audit / Evidence

Evidence Ledger v3 использует encrypted records и HMAC continuity. Экспорт может подписываться detached signatures. Это tamper-evidence, а не обещание защиты от полностью контролирующего ядро атакующего.

## Z. Performance

Packet hot path ограничивает allocations/buffers; threat lookup использует компактные структуры. Blocking control-plane work уходит с main thread. UI может снижать декоративный FPS, не ослабляя security policy/evidence processing.

## AA. Capacity Limits

В исходном dossier указаны: 1 MiB unacked TCP per flow, 32 MiB global downstream buffer, 64 dial workers, 1,024 UDP flows, TCP idle 10 min / 90 sec constrained, UDP idle 90/30 sec, Fast Verdict 1.75 sec, Deep Scan 25 sec, LAN sweep 254 hosts, WireGuard import 16 KiB / 128 lines. Превышение всегда приводит к bounded/reject/recycle behavior.

## AB. Профили

Telemetry Shield: OFF, CONSERVATIVE, BALANCED, STRICT. Strict может блокировать DoT/DoQ port 853. Secure defaults: `allowBackup=false`, `usesCleartextTraffic=false`, network security config и quarantine нового/неизвестного приложения до bounded verdict.

## AC. Interfaces / APIs

Helper Protocol v5 на Unix socket, versioned framing, MTU negotiation, строгое число FD по режиму. WireGuard UAPI внутренний. Публичного HTTP/REST/RPC server нет.

## AD. Форматы и протоколы

`VGTVLT01` - AEAD vault, `VGTPVK01` - wrapped keysets, `GDTI-v2` - threat prefix index, JSON - signed exports/diagnostics, local PDDL/IPtoASN indexes, WireGuard Noise over UDP.

## AE. Testing / Verification

Отдельные harnesses покрывают core crypto/data structures, vault/key lifecycle, Privacy Shield, WireGuard, InstallGuard, resilience, startup/main-thread, i18n, source manifest, artifact validation и Go flow logic. Компиляция сама по себе не считается доказательством готовности.

## AF. Adversarial Security Testing

Проверяются bit flips/AAD mismatch, malformed packets, fuzzing, Go `-race`, descriptor/socket bypass conditions и fail-closed negative paths.

## AG. Качество

Host/core/netstack разделены. Исторические crypto generations существуют только как migration-only paths. Shared algorithms сосредоточены в `:core`. Dummy/TODO production paths не считаются допустимыми.

## AH. Архитектурные инварианты

Нет JNI hot path; один VPN owner; нет blocking network/file/crypto на main looper; ThreatIndex immutable до atomic replacement.

## AI. Security invariants

Нет secrets в обычных логах/preferences; sensitive buffers очищаются где возможно; crypto failure fail closed; normal path non-MITM; whole-UID WireGuard bypass запрещён.

## AJ. Внешняя инфраструктура

Mandatory VGT backend отсутствует. Public threat feeds опциональны. Их недоступность не переводит protection в fail-open: используется last-known-good local state.

## AK. Offline

Threat indexes, ASN, baselines и evidence локальны. Firewall/packet filter/Telemetry Shield/quarantine/scanner остаются доступны без постоянного backend connection.

## AL. Attack Surface

TUN packets ограничиваются memory-safe parser/fragment limits; IPC защищён private path/token/framing; critical Activities не экспортируются; backup отключён; external storage scanner read-only/bounded; update integrity опирается на Android package signature + signer drift evidence.

## AM. Hardening

PIE/NX/RELRO expectations, >=16 KiB ELF alignment, R8/minification, `usesCleartextTraffic=false`, detached evidence signatures.

## AN. Secrets Management

AndroidKeyStore HMAC root PRF; random 256-bit domain roots wrapped под KEK; transient HKDF subkeys; non-exportable keys и hardware backing там, где платформа надёжно поддерживает primitive.

## AO. Privilege Model

Обычный режим - unprivileged app UID. Go helper получает только explicit descriptors. TITAN Device Owner добавляет Android-managed Always-on/lockdown, restrictions и suspension в пределах DPC API.

## AP. Compatibility

Android API 29+, target/compile 36, arm64-v8a и x86_64. Особое внимание OEM background limits (HyperOS, OneUI).

## AQ. Packaging

Signed/minified APK + AAB. Dynamic code loading из Интернета отсутствует. Native helper строится из source и сравнивается с packaged bytes.

## AR. Лицензирование

Немецкий dossier был создан до окончательного решения по публичной лицензии и упоминает proprietary VGT license. **Публичный репозиторий этого пакета использует AGPL-3.0-or-later**, и именно `LICENSE` репозитория является действующим для данного source tree. Vendored upstream сохраняет MIT/BSD/Public-Domain terms.

## AS. Documentation Status

Architecture/security/threat/vault/transport/build/test/release задокументированы в Markdown и audit scripts. Dossier - snapshot baseline, а не замена current source evidence.

## AT. Ограничения

Android timing `PACKAGE_ADDED`; отсутствие TLS payload visibility по design; отсутствие universal monotonic anti-rollback hardware counter.

## AU. Технический долг

Большие Android lifecycle owners, подготовка offline AGP cache, размер локальных ASN assets.

## AV. Остаточные риски

Kernel/root compromise, unknown DoH/443+ECH, OEM Keystore provider defects и временный fail-closed stop при недоступном hardware crypto provider.

## AW. Сильные стороны

Zero third-party Android runtime libs, process isolation, no JNI hot path, update-stable key custody, hybrid signature readiness, fail-closed networking и extensive automated gates.

## AX. Границы

Security зависит от integrity Android/Keystore. Нет математической защиты от полностью контролируемого разблокированного устройства на уровне kernel. Нет TLS DPI.

## AY. Матрица зрелости

Architecture/crypto/storage оцениваются как release-hardened; networking/WireGuard/OEM требуют real-device matrix. Supply chain и reproducibility являются shipping properties.

## AZ. Factsheet

**GeDefense Mobile · 0.27.8-beta.6 / VC55 · Android 10+ · Kotlin host + Go GaiaNet · 0 external Android runtime libraries · AES-256-GCM + HMAC-SHA-256 · AndroidKeyStore root PRF · Direct L4 / WireGuard L3 · local-first / non-MITM · optional TITAN Device Owner · pinned/reproducible build gates.**

---

# Часть II · Architecture & Technical Master Map

## 1. Глобальное дерево

```text
GeDefense Mobile
├─ Presentation/UI
├─ Kotlin Application Control Plane
│  ├─ AppRuntime / State / UI snapshots
│  ├─ GeDefenseVpnService / NativeGaiaNet
│  ├─ Secure Vault / Evidence / XDR / InstallGuard / Resilience
│  └─ Android platform adapters
├─ Pure Kotlin Core
│  ├─ AEAD / authenticated snapshots / evidence
│  ├─ threat/privacy/route/ASN structures
│  └─ bounded parsers/recovery policies
└─ GaiaNet V2 Go Data Plane
   ├─ IP/TCP/UDP
   ├─ threat/privacy/package policy
   ├─ IPC/FD handling
   └─ Direct + WireGuard transport
```

## 2. Привязка файлов

### UI

`DashboardScreen.kt`, `ThreatScreen.kt`, `ProtectionHubScreen.kt`, `AnalysisHubScreen.kt`, `SystemHubScreen.kt`, `FirewallActivity.kt`, `WireGuardActivity.kt`, `PrivacyActivity.kt`, `ScannerActivity.kt`, `XdrActivity.kt`, `HardeningActivity.kt`, `BehaviorActivity.kt`, `NetworkDiscoveryActivity.kt`, `PortSentinelActivity.kt`, `TitanActivity.kt`, `EvidenceScreen.kt`, `DiagnosticsActivity.kt`, `SupportVgtActivity.kt`, `SetupWizardActivity.kt`, `VpnDisclosureActivity.kt`.

Reusable visuals: `CyberBackgroundView.kt`, `ShieldPulseView.kt`, `VgtActionTile.kt`, `VgtIconView.kt`, `VgtProgressView.kt`, `TitanCoreView.kt`, `ScannerRadarView.kt`, `TrafficWorldMapView.kt`.

### Control plane

Lifecycle/state: `GeDefenseApplication.kt`, `AppRuntime.kt`, `RuntimeState.kt`, `UiSnapshot.kt`, bounded executors/schedulers. Network: `GeDefenseVpnService.kt`, `NativeGaiaNet.kt`, `ConnectionOwner.kt`, `PackageEgressGate.kt`. Stores: firewall, WireGuard, XDR, behavior/package baselines, malware analysis, approvals, network discovery, Port Sentinel, TITAN, scanner, VPN disclosure, evidence, Threat/ASN/Geo/Privacy repositories.

### Data plane

Core files: `engine.go`, `packet.go`, `reassembly.go`, `limits.go`, TCP/UDP managers, DNS, `policy.go`, `privacy_policy.go`, `package_egress_gate.go`, helper/bridge/socket-binding files and WireGuard transport/tun/protected-bind/flow tracking.

### Crypto/core

Host: `SecureTelemetryVault.kt`, `PersistentVaultKeys.kt`, migration derivators, `AndroidSecrets.kt`, `AndroidKeystoreGate.kt`, `HybridArtifactSigner.kt`. Pure JVM: `AeadVaultEnvelope.kt`, `AuthenticatedSnapshotStore.kt`, `BoundedSecretKeyCrypto.kt`, `EvidenceLedger.kt`. Shared deterministic algorithms: ThreatIndex, parsers, IP prefixes, Privacy Intelligence, ASN, mDNS/DNS codec, LAN planner/evaluator, Port Sentinel classifier, certificate validator, recovery budget.

## 3. Модули

### Host & Runtime
Асинхронный bootstrap, dependency/state root, serialized mutations и platform lifecycle.

### Network/VPN
Единственный владелец `VpnService`, TUN, routes, handover, exact-socket protection и helper supervision.

### GaiaNet
Изолированный memory-safe packet engine, bounded state и Direct/WireGuard egress.

### Threat Intelligence
Bounded downloads, canonical parsing, compact index, authenticated atomic publication, immutable runtime policy.

### Secure Vault
Per-domain random keysets, stable root PRF, AES-GCM, HMAC, explicit migration, backup exclusion.

### XDR/EDR
Локальная корреляция независимых signals с explainable score и network quarantine.

### InstallGuard/Scanner
Pre-egress gating, Fast/Deep scanning, package signer/capability checks, non-authoritative caches.

### Telemetry Shield
Локальная privacy policy без TLS break; профили и encrypted-DNS controls.

### Discovery / Port Sentinel
Bounded LAN discovery и passive decoy evidence без payload retention.

### TITAN
Optional Device Owner hardening/lockdown/suspension, explicit validation для managed CA и destructive policy.

### Resilience
Trust-preserving repair: нельзя стирать evidence, снимать quarantine или маскировать integrity failure.

### Diagnostics
Aggregate-only manual export через SAF.

### Setup
Объясняет VPN/privacy model, получает consent, помогает с настройками и запускает initial protection baseline. В текущем source Telemetry Shield вынесен в onboarding как важная privacy capability.

## 4. Dashboard

Cockpit показывает protection/Threat Intelligence/blocked/session/analysis state из `UiSnapshot`. Threat screen управляет локальными feeds. Protection Hub открывает firewall/WireGuard/privacy/scanner/discovery/Port Sentinel. Analysis Hub ведёт к XDR/behavior/hardening/evidence. System Hub - TITAN, diagnostics, setup/support.

Firewall rules хранятся encrypted и синхронизируются с enforcement. WireGuard import bounded и активируется только после exact-socket Android protect/bind handshake. Privacy screen меняет Telemetry Shield profile. Scanner uses bounded workers/quarantine. XDR explorer decrypts local incidents и показывает correlation rationale.

## 5. UI Architecture

Native Android Views, тёмный glass/cyber visual system, reusable VGT controls, adaptive rendering. UI не делает direct disk/network work и получает cached immutable state. Destructive/privileged actions требуют явного подтверждения.

## 6. API Architecture

Public HTTP API отсутствует. Используются Kotlin internal APIs, Android platform APIs и versioned Unix-socket helper protocol. Все boundary inputs проверяются по version/size/schema/FD count/token.

## 7. Data Flows

`PACKAGE_ADDED -> InstallGuard -> quarantine/FlowGate -> Deep Scan -> XDR/Evidence -> verified release/block`.

`DNS/flow metadata -> Privacy profile -> allow/block -> bounded event -> XDR/Evidence`.

`Integrity observation -> baseline validation -> authenticated state -> XDR/Evidence on degradation`.

## 8. Shared/Core Files

`:core` содержит deterministic security/data primitives: AEAD, authenticated snapshots, evidence chaining, threat/IP/route/privacy/ASN structures, bounded DNS parsing, LAN behavior, Port Sentinel classification и recovery budgets. `AppRuntime`, `GeDefenseVpnService` и `NativeGaiaNet` - центральные ownership points host plane.

## 9. Архитектурные связи

```text
UI -> AppRuntime/VPN/Resilience -> Vault/Evidence/InstallGuard
   -> authenticated IPC -> GaiaNet -> Direct/WireGuard -> Network
```

KeyStore остаётся на host-side. MainActivity предоставляет пять hub-ов: Dashboard, Threat, Protection, Analysis, System.

## 10. Ключевые file references

Bootstrap: `AppRuntime.kt`, `StartupActivity.kt`; TUN: `GeDefenseVpnService.kt`, `NativeGaiaNet.kt`; SCM_RIGHTS: `NativeGaiaNet.kt`, `helper_main_process.go`; WireGuard exact-socket protection: `wireguard_protected_bind.go`; key lifecycle: `PersistentVaultKeys.kt`, `AndroidSecrets.kt`; AEAD: `AeadVaultEnvelope.kt`; InstallGuard: `InstallGuard.kt`, `package_egress_gate.go`; encrypted DNS: `privacy_policy.go`, `PrivacyIntelligence.kt`; signatures: `HybridArtifactSigner.kt`; recovery: `ResilienceSupervisor.kt`, `RecoveryAttemptBudget.kt`.

## 11. Архитектурные наблюдения

Исходный dossier отметил `MoreScreen.kt` и `SecurityScreen.kt` как исторические UI без active callers; `settings.gradle.kts.orig` как лишний backup; `helper_main_stub.go` как корректный build-tag stub; historical crypto derivators как migration-only; experimental cgo socket binders как неактивные в обычном production path. GitHub-ready пакет удаляет `settings.gradle.kts.orig` и внутренние handoff-файлы.

---

# Конец русского издания

Для security decisions всегда сверяйтесь с текущим исходным кодом, `SECURITY.md`, `THREAT-MODEL.md`, `TOOLCHAINS.lock`, release gates и фактическим signed artifact.
