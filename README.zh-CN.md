<p align="center"><img src="docs/assets/gedefense-logo.png" alt="GeDefense Mobile" width="150" /></p>
<h1 align="center">GeDefense Mobile</h1>
<p align="center"><strong>本地优先的 Android 终端安全、网络防御与 XDR。</strong><br>由 VisionGaiaTechnology 构建，面向希望安全遥测尽可能留在设备本地的环境。</p>
<p align="center"><a href="README.md">English</a> · <a href="README.de.md">Deutsch</a> · <a href="README.ru.md">Русский</a> · <a href="README.zh-CN.md"><strong>简体中文</strong></a></p>
<p align="center">
<img alt="Version" src="https://img.shields.io/badge/version-0.27.8--beta.9-D8A928?style=flat-square" />
<img alt="VersionCode" src="https://img.shields.io/badge/VersionCode-58-64748B?style=flat-square" />
<img alt="Android" src="https://img.shields.io/badge/Android-10%2B%20(API%2029%2B)-3DDC84?style=flat-square&logo=android&logoColor=white" />
<img alt="Go" src="https://img.shields.io/badge/Go-1.26.8-00ADD8?style=flat-square&logo=go&logoColor=white" />
<img alt="Privacy" src="https://img.shields.io/badge/privacy-local--first-06B6D4?style=flat-square" />
<img alt="License" src="https://img.shields.io/badge/license-AGPL--3.0--or--later-2563EB?style=flat-square" />
</p>

> [!IMPORTANT]
> GeDefense Mobile 目前属于**公开测试版 / 预生产安全候选版本**。自动化发布门槛已经非常严格，但在高风险生产环境部署之前，仍应在真实设备上验证 OEM 行为、VPN 生命周期以及更新/迁移路径。

## GeDefense 是什么

GeDefense Mobile 是一套原生 Android 安全平台，将本地 VPN enforcement plane、终端遥测、EDR/XDR 关联、Threat Intelligence、应用风险分析、加密证据以及可选的 Android Device Owner 控制整合在一起。

架构坚持 **local-first**：安全决策在设备本地完成。GeDefense 不要求 VGT 云账户，也不会把数据包 payload、应用清单、扫描产物或 XDR evidence 上传到 VGT 后端。可选的 Threat/ASN 更新只是受限制并经过验证的数据输入，而不是云端 verdict 服务。

### 核心能力

| 领域 | 能力 |
| --- | --- |
| 网络保护 | Full Flow `VpnService`、Direct L4 egress、Selective Routing、WireGuard L3 transport |
| Threat Intelligence | 本地编译的威胁策略、确定性的 feed authority、离线查询 |
| Telemetry Shield | 无 TLS MITM 的本地 advertising / analytics / optional device telemetry endpoint 过滤 |
| Encrypted DNS | 严格配置下的 DoT/DoQ 控制，不安装 MITM Root CA |
| EDR / XDR | 本地关联 package、behavior、network、integrity、hardening evidence |
| InstallGuard | Pre-egress FlowGate，以及对新安装应用的有界 Fast/Deep 扫描 |
| Malware analysis | 本地应用/包分析以及对获准共享存储区域的有界扫描 |
| Secure Telemetry Vault | 分域 AES-256-GCM 存储、认证 snapshot、可跨更新保持的密钥托管 |
| Evidence | 加密、认证、本地 evidence ledger 与有界恢复语义 |
| Resilience | 有界自愈、健康检查、fail-closed 降级 |
| TITAN | 可选 Device Owner policy plane，用于受管设备加固与 lockdown |
| 诊断 | 仅手动导出的 aggregate-only 支持包，以及不产生网络外发的威胁策略自检 |

## 隐私与 Telemetry Shield

隐私模型不仅意味着 **GeDefense 自身不依赖集中式遥测**。Telemetry Shield 还可以在网络/策略层阻止其他应用中已知的 tracking、advertising、analytics 和可选设备遥测 endpoint。GeDefense 明确**不进行 TLS 拦截**。如果应用把业务流量与遥测混在同一个加密 first-party endpoint 内，GeDefense 不会假装在不做 MITM 的情况下仍能可靠区分 payload 内容。

参阅 [`PRIVACY.md`](PRIVACY.md)、[`NETWORK-EGRESS.md`](NETWORK-EGRESS.md)、[`SECURE-TELEMETRY-VAULT.md`](SECURE-TELEMETRY-VAULT.md)。

## 架构概览

```text
Android UI / Control Plane (Kotlin)
        |
        | authenticated Unix-domain control channel
        | SCM_RIGHTS descriptor transfer
        v
GaiaNet V2 Data Plane (Go，独立进程)
        |
        +-- Threat Policy / Telemetry Shield / Package Gate
        +-- Direct L4 Transport
        `-- WireGuard L3 Transport
                |
                v
          Physical Network
```

Android host 负责 lifecycle、policy、Keystore 访问与 UI state。GaiaNet 从 APK native-library 目录作为独立进程启动，只接收当前 transport path 所需的有界文件描述符和配置。数据包 hot path 不通过 JNI 加载。

当前固定 toolchain：**Go 1.26.8**、Kotlin 1.9.24、Gradle 8.7、JDK 17、Android API 36、NDK r27c。详见 [`TOOLCHAINS.lock`](TOOLCHAINS.lock)、[`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md)。

## 安全模型

关键不变量：

- 对关键 integrity、VPN、Evidence 故障执行 fail-closed；
- 默认不做 TLS MITM；
- 不使用动态代码加载，也不把 WebView 作为安全控制面；
- queue、parser、scan、retry 与后台工作都有资源上限；
- WireGuard 不允许整个 UID 绕过 VPN，只对精确 upstream transport socket 执行 protect/bind；
- 持久安全状态使用独立 key domain；
- 加密密钥托管可跨更新保持，不从 APK hash 或版本号派生；
- crash-safe authenticated publication：`stage -> fsync -> verify -> atomic replace -> directory fsync`；
- Android host、GaiaNet、外部数据集与 Android 平台服务之间存在明确 trust boundary。

敏感环境部署前请阅读 [`SECURITY.md`](SECURITY.md)、[`THREAT-MODEL.md`](THREAT-MODEL.md)、[`ARCHITECTURE.md`](ARCHITECTURE.md)、[`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md)。

## 保护模式

- **Selective**：仅将 policy 选中的 threat prefix 路由到保护路径。
- **Full Flow / Direct**：设备流量经过 GaiaNet，获准流量通过直接 kernel socket 发出。
- **WireGuard**：Full Flow 通过内置 `wireguard-go` L3 transport。
- **Strict / Lockdown**：面向 Android Always-on/Lockdown；安全 transport 不可用时保持 fail-closed。

## 构建

需要 JDK 17、Gradle 8.7、Android Platform/Build Tools 36、NDK `27.2.12479018`、Go 1.26.8。

`:app` 仅包含**两个固定版本、仓库内 vendored 的 Apache-2.0 二维码扫描构件**（ZXing Android Embedded + ZXing Core），用于本地 WireGuard 二维码导入；`:core` 的 Android 第三方 runtime library 数量仍为 0。GaiaNet 使用少量固定版本、仓库内 vendored 的 Go dependencies。

完整 readiness gate：

```bash
bash tools/release-readiness.sh
```

精确的离线/可复现构建流程见 [`BUILD-RUNBOOK.md`](BUILD-RUNBOOK.md)。

## 架构 Dossier

| 语言 | PDF |
| --- | --- |
| Deutsch（原版） | [`Master Architecture - DE`](docs/datasheets/GeDefense-Mobile-Master-Architecture-DE.pdf) |
| English | [`Master Architecture - EN`](docs/datasheets/GeDefense-Mobile-Master-Architecture-EN.pdf) |
| Русский | [`Master Architecture - RU`](docs/datasheets/GeDefense-Mobile-Master-Architecture-RU.pdf) |
| 简体中文 | [`Master Architecture - ZH-CN`](docs/datasheets/GeDefense-Mobile-Master-Architecture-ZH-CN.pdf) |

> Dossier 记录 VC55 架构 baseline。当前源码版本为 **0.27.8-beta.9 / VC58**，并新增了 OEM-HMAC 恢复连续性加固、不产生网络外发的威胁策略自检、重新设计的事务型更新界面以及三种 WireGuard 导入方式（文本、文件与本地二维码扫描）。该自检验证已加载的 `ThreatIndex`、阻断权限、路由覆盖以及启动 GaiaNet 所用的同一 GDTI 序列化路径；第三方应用的 TUN 捕获仍需在真实设备上单独验证。当前实现状态应优先参考 `TOOLCHAINS.lock`、`SECURITY.md`、`CHANGELOG.md` 与源码。

## 文档

[`ARCHITECTURE.md`](ARCHITECTURE.md) · [`SECURITY.md`](SECURITY.md) · [`THREAT-MODEL.md`](THREAT-MODEL.md) · [`PRIVACY.md`](PRIVACY.md) · [`NETWORK-EGRESS.md`](NETWORK-EGRESS.md) · [`SECURE-TELEMETRY-VAULT.md`](SECURE-TELEMETRY-VAULT.md) · [`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md) · [`SBOM.cdx.json`](SBOM.cdx.json) · [`RELEASE-CHECKLIST.md`](RELEASE-CHECKLIST.md)

## 漏洞报告

请不要在公开 issue 中披露可利用漏洞或敏感设备证据。

**Security contact：** [security@visiongaia.de](mailto:security@visiongaia.de)

如已启用，请优先使用 GitHub Private Vulnerability Reporting。

## 许可证

GNU Affero General Public License v3.0 or later（**AGPL-3.0-or-later**），见 [`LICENSE`](LICENSE)。

---
<p align="center"><strong>VisionGaiaTechnology</strong><br>Experimental sovereign security & software engineering.</p>
