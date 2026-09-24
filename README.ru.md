<p align="center"><img src="docs/assets/gedefense-logo.png" alt="GeDefense Mobile" width="150" /></p>
<h1 align="center">GeDefense Mobile</h1>
<p align="center"><strong>Локальная защита Android-устройств, сетевой трафик и XDR.</strong><br>Проект VisionGaiaTechnology для сред, где телеметрия безопасности должна оставаться на устройстве.</p>
<p align="center"><a href="README.md">English</a> · <a href="README.de.md">Deutsch</a> · <a href="README.ru.md"><strong>Русский</strong></a> · <a href="README.zh-CN.md">简体中文</a></p>
<p align="center">
<img alt="Version" src="https://img.shields.io/badge/version-0.27.8--beta.9-D8A928?style=flat-square" />
<img alt="VersionCode" src="https://img.shields.io/badge/VersionCode-58-64748B?style=flat-square" />
<img alt="Android" src="https://img.shields.io/badge/Android-10%2B%20(API%2029%2B)-3DDC84?style=flat-square&logo=android&logoColor=white" />
<img alt="Go" src="https://img.shields.io/badge/Go-1.26.8-00ADD8?style=flat-square&logo=go&logoColor=white" />
<img alt="Privacy" src="https://img.shields.io/badge/privacy-local--first-06B6D4?style=flat-square" />
<img alt="License" src="https://img.shields.io/badge/license-AGPL--3.0--or--later-2563EB?style=flat-square" />
</p>

> [!IMPORTANT]
> GeDefense Mobile сейчас является **публичной beta / pre-production security candidate**. Автоматические release-gates уже строгие, но поведение OEM, жизненный цикл VPN и пути обновления/миграции необходимо дополнительно проверять на реальных устройствах перед использованием в критичных средах.

## Что такое GeDefense

GeDefense Mobile - нативная платформа безопасности Android, объединяющая локальный VPN enforcement plane, endpoint-телеметрию, EDR/XDR-корреляцию, Threat Intelligence, анализ риска приложений, зашифрованные доказательства и опциональное управление Android Device Owner.

Архитектура изначально **local-first**: решения безопасности принимаются на самом устройстве. Для работы не нужен аккаунт VGT Cloud; пакетные payload-данные, список приложений, результаты сканирования и XDR evidence не отправляются на VGT backend. Опциональные обновления Threat/ASN загружаются как ограниченные и проверяемые наборы данных, а не как облачный verdict-сервис.

### Основные возможности

| Область | Возможность |
| --- | --- |
| Сетевая защита | Full Flow `VpnService`, прямой L4 egress, Selective Routing и WireGuard L3 |
| Threat Intelligence | Локальная скомпилированная политика угроз с детерминированной ролью источников и offline lookup |
| Telemetry Shield | Локальная фильтрация известных advertising/analytics/optional-device-telemetry endpoints без TLS MITM |
| Encrypted DNS | Контроль DoT/DoQ в строгих профилях без установки MITM root CA |
| EDR / XDR | Локальная корреляция package, behavior, network, integrity и hardening evidence |
| InstallGuard | Pre-egress FlowGate и ограниченные Fast/Deep проверки новых приложений |
| Malware analysis | Локальный анализ пакетов и ограниченное сканирование разрешённых областей общего хранилища |
| Secure Telemetry Vault | Разделённое по доменам AES-256-GCM хранение, аутентифицированные snapshots и update-stable key custody |
| Evidence | Локальный зашифрованный и аутентифицированный журнал с ограниченным recovery |
| Resilience | Ограниченное восстановление, health checks и fail-closed деградация |
| TITAN | Опциональная Device Owner policy plane для hardening и lockdown |
| Диагностика | Aggregate-only пакет поддержки только с ручным экспортом плюс самотест политики угроз без сетевого выхода |

## Privacy и Telemetry Shield

Смысл модели приватности не только в том, что **сама GeDefense не требует централизованной телеметрии**. Telemetry Shield также может блокировать известные tracking-, advertising-, analytics- и optional-device-telemetry endpoints других приложений на сетевом/policy уровне. GeDefense сознательно **не перехватывает TLS**. Если приложение смешивает функциональный трафик и телеметрию в одном зашифрованном first-party endpoint, продукт не делает вид, что может надёжно разделить содержимое без MITM.

См. [`PRIVACY.md`](PRIVACY.md), [`NETWORK-EGRESS.md`](NETWORK-EGRESS.md), [`SECURE-TELEMETRY-VAULT.md`](SECURE-TELEMETRY-VAULT.md).

## Архитектура

```text
Android UI / Control Plane (Kotlin)
        |
        | authenticated Unix-domain control channel
        | SCM_RIGHTS descriptor transfer
        v
GaiaNet V2 Data Plane (Go, отдельный процесс)
        |
        +-- Threat Policy / Telemetry Shield / Package Gate
        +-- Direct L4 Transport
        `-- WireGuard L3 Transport
                |
                v
          Physical Network
```

Android-host управляет lifecycle, policy, Keystore и UI state. GaiaNet запускается как отдельный процесс из native-library directory APK и получает только ограниченные файловые дескрипторы/конфигурацию, необходимые выбранному transport path. JNI в packet hot path не используется.

Текущий закреплённый toolchain: **Go 1.26.8**, Kotlin 1.9.24, Gradle 8.7, JDK 17, Android API 36, NDK r27c. См. [`TOOLCHAINS.lock`](TOOLCHAINS.lock), [`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md).

## Модель безопасности

Ключевые инварианты:

- fail-closed при критичных ошибках integrity, VPN и Evidence;
- без TLS MITM по умолчанию;
- без dynamic code loading и WebView security plane;
- ограниченные queues, parsers, scans, retries и background work;
- без глобального UID-bypass для WireGuard: исключаются только точные upstream transport sockets;
- независимые key domains для persistent security state;
- update-stable encryption custody, не зависящая от APK hash/versionCode;
- crash-safe authenticated publication: `stage -> fsync -> verify -> atomic replace -> directory fsync`;
- явные trust boundaries между Android host, GaiaNet, внешними datasets и Android platform services.

Перед использованием в чувствительной среде прочитайте [`SECURITY.md`](SECURITY.md), [`THREAT-MODEL.md`](THREAT-MODEL.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), [`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md).

## Режимы защиты

- **Selective** - в защитный тракт направляются только выбранные policy threat-prefixes.
- **Full Flow / Direct** - трафик проходит через GaiaNet, разрешённые соединения выходят через прямые kernel sockets.
- **WireGuard** - Full Flow через встроенный `wireguard-go` L3 transport.
- **Strict / Lockdown** - для Android Always-on/Lockdown с fail-closed при недоступном защищённом транспорте.

## Сборка

Требуются JDK 17, Gradle 8.7, Android Platform/Build Tools 36, NDK `27.2.12479018`, Go 1.26.8.

`:app` содержит ровно **два закреплённых локально vendored Apache-2.0 артефакта QR-сканера** (ZXing Android Embedded + ZXing Core) для локального импорта WireGuard по QR; `:core` остаётся без сторонних Android runtime libraries. GaiaNet использует небольшой закреплённый vendored-набор Go dependencies.

Полная проверка readiness:

```bash
bash tools/release-readiness.sh
```

Точная offline/reproducible процедура: [`BUILD-RUNBOOK.md`](BUILD-RUNBOOK.md).

## Архитектурный dossier

| Язык | PDF |
| --- | --- |
| Deutsch (оригинал) | [`Master Architecture - DE`](docs/datasheets/GeDefense-Mobile-Master-Architecture-DE.pdf) |
| English | [`Master Architecture - EN`](docs/datasheets/GeDefense-Mobile-Master-Architecture-EN.pdf) |
| Русский | [`Master Architecture - RU`](docs/datasheets/GeDefense-Mobile-Master-Architecture-RU.pdf) |
| 简体中文 | [`Master Architecture - ZH-CN`](docs/datasheets/GeDefense-Mobile-Master-Architecture-ZH-CN.pdf) |

> Dossier фиксирует архитектурную baseline VC55. Текущий исходный код имеет версию **0.27.8-beta.9 / VC58** и дополнительно включает укрепление непрерывности OEM-HMAC, самотест политики угроз без сетевого выхода, обновлённый транзакционный экран после обновления и тройной импорт профилей WireGuard (текст, файл и локальный QR-скан). Самотест проверяет загруженный `ThreatIndex`, полномочия блокировки, покрытие маршрутом и тот же сериализатор GDTI, который используется при запуске GaiaNet; перехват трафика сторонних приложений через TUN остаётся отдельной проверкой на реальном устройстве. Для актуального состояния приоритет имеют `TOOLCHAINS.lock`, `SECURITY.md`, `CHANGELOG.md` и исходный код.

## Документация

[`ARCHITECTURE.md`](ARCHITECTURE.md) · [`SECURITY.md`](SECURITY.md) · [`THREAT-MODEL.md`](THREAT-MODEL.md) · [`PRIVACY.md`](PRIVACY.md) · [`NETWORK-EGRESS.md`](NETWORK-EGRESS.md) · [`SECURE-TELEMETRY-VAULT.md`](SECURE-TELEMETRY-VAULT.md) · [`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md) · [`SBOM.cdx.json`](SBOM.cdx.json) · [`RELEASE-CHECKLIST.md`](RELEASE-CHECKLIST.md)

## Сообщения об уязвимостях

Не публикуйте exploitable vulnerabilities или чувствительные данные устройства в открытых issues.

**Security contact:** [security@visiongaia.de](mailto:security@visiongaia.de)

Используйте GitHub Private Vulnerability Reporting, если оно включено.

## Лицензия

GNU Affero General Public License v3.0 or later (**AGPL-3.0-or-later**), см. [`LICENSE`](LICENSE).

---
<p align="center"><strong>VisionGaiaTechnology</strong><br>Experimental sovereign security & software engineering.</p>
