# GeDefense Mobile architecture dossiers

The architecture dossier is published in four repository languages.

| Language | PDF | Source / translation text |
| --- | --- | --- |
| Deutsch | [German original](GeDefense-Mobile-Master-Architecture-DE.pdf) | Original 86-page VC55 baseline dossier |
| English | [English PDF](GeDefense-Mobile-Master-Architecture-EN.pdf) | [English Markdown](GeDefense-Mobile-Master-Architecture-EN.md) |
| Русский | [Русская PDF-версия](GeDefense-Mobile-Master-Architecture-RU.pdf) | [Русский Markdown](GeDefense-Mobile-Master-Architecture-RU.md) |
| 简体中文 | [简体中文 PDF](GeDefense-Mobile-Master-Architecture-ZH-CN.pdf) | [简体中文 Markdown](GeDefense-Mobile-Master-Architecture-ZH-CN.md) |

## Baseline and current-source note

The German PDF is the supplied **VC55 architecture baseline** and is preserved unchanged. The translated editions preserve the substantive architecture, security, supply-chain, runtime, UI and module-map material in reflowed form while keeping technical identifiers, paths and protocol names intact.

The baseline dossier predates some hardening performed later under the same `0.27.8-beta.6` / VC55 line. In particular, the current repository pins **Go 1.26.8** and includes later OEM-HMAC recovery hardening. For the current implementation, the source tree plus [`../../TOOLCHAINS.lock`](../../TOOLCHAINS.lock), [`../../SECURITY.md`](../../SECURITY.md), [`../../CHANGELOG.md`](../../CHANGELOG.md) and [`../../SUPPLY-CHAIN.md`](../../SUPPLY-CHAIN.md) are authoritative.

The German baseline also contains licensing language that predates publication of this source repository. The repository [`LICENSE`](../../LICENSE) is authoritative for the source distributed here: **AGPL-3.0-or-later**.

## Translation policy

The translated editions are human-readable translations/reflows of the supplied German technical dossier. They are provided for accessibility, not as a substitute for current source-level verification. Security decisions should always be checked against the exact release source and release gates being deployed.
