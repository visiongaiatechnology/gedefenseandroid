# GeDefense Mobile
## Master Architecture Datasheet + Technical Master Map

**架构 · 安全 · Supply Chain · Runtime · UI · 模块地图**

- **Release baseline：** 0.27.8-beta.6
- **VersionCode：** 55 · VC55-KeyLifecycle-FINAL
- **分析日期：** 2026-09-23
- **组织：** VisionGaiaTechnology (VGT)
- **原始语言：** 德语
- **版本：** 简体中文翻译/重排版

> **翻译说明。** 本文将原始 86 页德语 Master Architecture Dossier 的实质内容翻译并重新排版为更紧凑的中文版本。技术标识符、文件路径、协议名称和源码引用保持原样。德语原版记录的是 VC55 architecture baseline，因此包含 Go 1.23.x 以及当时源码文件数量等历史信息。同一个 VersionCode 下的当前仓库可能已经继续 hardening。当前实现事实以 `TOOLCHAINS.lock`、`SECURITY.md`、`CHANGELOG.md` 和源码本身为准。

---

# 目录

## 第一部分 · Architecture Datasheet
A. Executive Architecture Summary · B. 产品身份与系统目的 · C. 功能范围 · D. 架构模型 · E. 组件架构 · F. 内部依赖 · G. Third-Party Dependencies / Supply Chain · H. 依赖摘要 · I. 语言与技术栈 · J. 代码指标 · K. 安全架构 · L. Trust Model · M. Threat Model · N. 密码学 · O. 身份验证与授权 · P. 数据架构 · Q. 数据流 · R. 网络架构 · S. OS/平台集成 · T. 进程/线程/并发 · U. 错误与韧性 · V. 更新/发布架构 · W. Build/Supply-Chain Security · X. 隐私与遥测 · Y. Logging/Audit/Evidence · Z. 性能架构 · AA. 容量与限制 · AB. 配置与 Profile · AC. 接口/API · AD. 文件格式/协议 · AE. 测试/验证 · AF. 对抗性安全测试 · AG. 质量/维护性 · AH. 架构规则 · AI. 安全不变量 · AJ. 外部服务 · AK. 离线能力 · AL. Attack Surface · AM. Hardening · AN. Secrets · AO. 权限模型 · AP. 兼容性 · AQ. Packaging · AR. 许可证 · AS. 文档状态 · AT. 已知限制 · AU. 技术债 · AV. 剩余风险 · AW. 架构优势 · AX. 架构边界 · AY. 成熟度 · AZ. Factsheet。

## 第二部分 · Architecture & Technical Master Map
1. 全局架构树 · 2. 文件到架构映射 · 3. 模块文档 · 4. Dashboard 详细说明 · 5. UI Architecture · 6. API Architecture · 7. Data Flows · 8. Shared/Core Files · 9. 架构关系 · 10. 文件引用 · 11. 架构观察。

---

# 第一部分 · Architecture Datasheet

## A. Executive Architecture Summary

### 技术事实总览

| 项目 | 值 / 状态 | 证据 |
| --- | --- | --- |
| 产品 | GeDefense Mobile | Android resources |
| 内部名称 | VGT-GeDefense-Mobile | `settings.gradle.kts` |
| 类别 | On-device endpoint protection (EDR/XDR)、mobile firewall、zero-trust network shield | architecture docs |
| 主要用途 | Android 上完全自治、非云依赖的网络/威胁/设备保护 | security/manifest |
| 版本 | 0.27.8-beta.6 | `VERSION` |
| VersionCode | 55 | `VERSION_CODE` |
| 渠道 | Public Beta / Pre-Production Security Candidate | release docs |
| Android | API 29-36 | Gradle |
| ABI | arm64-v8a、x86_64 | build/toolchain |
| ELF alignment | 两个 ABI 均 >=16 KiB (`0x4000`) PT_LOAD | native gate |
| 架构 | Kotlin host + 独立 Go netstack | architecture docs |
| 安全模型 | zero-trust local-first、least privilege、fail-closed、non-MITM | security docs |
| 网络模型 | 单一 `VpnService` owner，Direct L4 或 WireGuard L3 | transport source |
| 本地存储 | `noBackupFilesDir` 中 12 个密码学隔离 vault domain | vault docs |
| At-rest crypto | AES-256-GCM、96-bit nonce、128-bit tag、AAD、HMAC-SHA-256 | core crypto |
| Key custody | 安装级稳定 AndroidKeyStore HMAC root `vgt.gedefense.mobile.vault.root-prf.v1` | `PersistentVaultKeys.kt` |
| Transit | WireGuard Noise IKpsk2 / ChaCha20-Poly1305 / Curve25519 / BLAKE2s | vendored WireGuard |
| 签名 | ECDSA P-256 + 条件式 ML-DSA-87 | artifact signer |
| Update model | vault generation 单向原子迁移；加密密钥托管不依赖 APK hash | key lifecycle |
| Android runtime dependencies | `:app`/`:core` 外部库为 0 | Gradle |

### 系统是什么

GeDefense Mobile 是一套完全本地工作的 Android endpoint security 平台，将 XDR、行为网络分析、packet filtering、offline threat detection 与密码学保护的 evidence 结合起来，不依赖强制云分析或中心化遥测。

产品目标是减少移动操作系统对用户的不透明性，并限制隐藏 data exfiltration、tracking、恶意应用通信和 C2。GeDefense 不通过破坏 TLS 来换取通用 payload inspection，而是基于本地网络元数据、设备状态、本地 Threat Intelligence 以及相互独立的 evidence 信号做决策。

系统采用严格的双进程设计：Kotlin Android host 负责 UI、lifecycle、policy 和 Android Keystore；独立 Go 进程 **GaiaNet V2** 处理 L3/L4 packet。两者通过私有 Unix-domain socket 和 `SCM_RIGHTS` 传递 file descriptor，packet hot path 不经过 JNI。

网络层同时支持 Direct kernel-socket egress 与内置 `wireguard-go` L3 tunnel。WireGuard 模式没有整个 UID 的 bypass；只有精确的 upstream UDP transport socket 会交给 Android 执行 `VpnService.protect()`/network binding。

Secure Telemetry Vault 将持久 security state 分成独立密码学 domain。VC55 把 key custody 与 APK/version identity 分离，使正常更新不再天然要求 re-keying。

## B. 产品身份与系统目的

- 产品：GeDefense Mobile；
- 产品族：VisionGaiaTechnology Security & Defense Systems；
- 类别：mobile endpoint protection / EDR / XDR / firewall / network defense；
- 主要用途：移动流量保护、恶意 endpoint 阻断、应用风险识别、Android hardening；
- 辅助能力：Network Discovery、Port Sentinel、TITAN Device Owner、Evidence Ledger；
- 支持 Android API 29-36+；
- 运行模型：standalone / local-first；
- 默认为普通应用权限，Device Owner 仅可选；
- 原生 Android View UI，不使用 WebView 作为安全平面；
- 没有强制 VGT backend，可选下载公共 threat/ASN dataset。

### 核心承诺

1. **数据主权：** security telemetry/evidence 不发送到 VGT 云进行判定。
2. **确定性安全：** threat lookup/block decision 在本地、有资源上限地完成。
3. **Fail-closed integrity：** critical subsystem failure 不会悄悄转成 unprotected mode。
4. **更新韧性：** app update 不应天然造成 key loss 或错误 tamper detection。

### 明确的 Non-goals

不做 TLS interception；不做 cloud antivirus file upload；不声称可抵抗完整 kernel/root compromise；不在设备 VM 中执行未知 malware；没有 Device Owner 时不做隐蔽的通用 app uninstall。

## C. 功能范围

### Network / Policy

- GaiaNet V2 L3/L4 engine；
- Direct Egress；
- embedded WireGuard L3；
- Strict/Lockdown；
- Full Flow TUN；
- Selective routing。

### Security engines

- 本地 Threat Intelligence Engine，feed authority 明确；
- InstallGuard FlowGate + Fast/Deep Scan；
- Telemetry Shield；
- 非 MITM Encrypted-DNS Control（DoT/DoQ 853）；
- App Risk Scanner / bounded Storage Malware Scanner；
- Network Discovery / Port Sentinel。

### Data / Evidence / Admin

- 12-domain Secure Telemetry Vault；
- Evidence Ledger v3；
- Hybrid Artifact Signer；
- Resilience Supervisor；
- 可选 TITAN Device Owner；
- 本地 ASN Evidence；
- aggregate-only diagnostics。

## D. 架构模型

```text
Presentation / UI
  -> Kotlin Application Control Plane
  -> authenticated Unix IPC + SCM_RIGHTS
  -> GaiaNet V2 Go Data Plane
  -> TUN / Direct / WireGuard / physical network
```

UI 只渲染 immutable snapshot，不持有 key 或 packet buffer。Kotlin host 串行化 security-sensitive mutation、包装 Keystore operation 并执行 recovery。IPC 位于 app-private socket，通过随机 32-byte token 认证。GaiaNet 没有 Android Context/JVM，只获得明确传递的 FD 与 policy material。

## E. 组件架构

| 组件 | 责任 | Trust | Critical |
| --- | --- | --- | --- |
| `GeDefenseVpnService` | VPN lifecycle、TUN、underlay、protect | host | 是 |
| `NativeGaiaNet` | helper lifecycle、token handshake、FD transfer | host | 是 |
| GaiaNet Engine | IP/TCP/UDP、flow、forwarding | isolated | 是 |
| WireGuard transport | L3 tunnel、peer、rekey | isolated | 是 |
| Package Egress Gate | quarantine allow/drop | isolated | 是 |
| Secure Telemetry Vault | authenticated encryption | host crypto | 是 |
| PersistentVaultKeys | stable KEK/DEK custody | host crypto | 是 |
| Evidence Ledger | authenticated journal | host storage | 是 |
| InstallGuard | staged app scanning | host scanner | 是 |
| Resilience Supervisor | trust-preserving recovery | maintenance | 是 |
| ThreatIndex | O(log n) threat match | read-only | 是 |
| TelemetryShield | tracking/telemetry policy | read-only | 中 |
| TITAN Manager | Device Owner hardening | admin | 是 |

## F. 内部依赖

```text
app
├─ core (pure Kotlin domain/security)
└─ netstack (separate Go helper)

tools/ = build/security verification
```

无循环 module dependency。`:core` 不依赖 Android，可在 JVM 测试；`netstack` 是独立 Go module `visiongaia.dev/gedefense/mobile/netstack`。

## G. Third-Party Dependencies / Supply Chain

Android `app`/`core` 没有外部 runtime library。Go subsystem 把依赖源码 vendored 到 `third_party/go/`，通过 local `replace` 固定。

| Dependency | Version | 用途 | License |
| --- | --- | --- | --- |
| wireguard-go | 0.0.20250522 | WireGuard/Noise/peers | MIT |
| x/crypto | v0.37.0 | crypto primitives | BSD-3 |
| x/net | v0.39.0 | network helpers | BSD-3 |
| x/sys | v0.32.0 | Unix/Linux primitives | BSD-3 |
| x/term | v0.31.0 | auxiliary | BSD-3 |
| x/text | v0.24.0 | Unicode/config | BSD-3 |

原 dossier 记录 AGP 8.5.2、Kotlin 1.9.24、Gradle 8.7、JDK 17、Go 1.23.x、NDK r27c；**当前 repository 已固定 Go 1.26.8**，以 `TOOLCHAINS.lock` 为准。

Vendored Go build 可使用 `GOPROXY=off`/`GOSUMDB=off`。`SOURCE-MANIFEST.sha256` 绑定 source snapshot。Android runtime dependency surface 为 0，显著减少 Maven supply-chain 风险。

## H. 依赖摘要

Android runtime 外部依赖为 0；Go 只使用小型 pinned/vendored set；不动态加载第三方 module；build toolchain 明确记录。

## I. 语言与技术栈

Kotlin = Android control plane；Go = GaiaNet data plane；Python + shell/PowerShell = security/release gates。Dossier 总 LOC 很大主要因为 vendored Go source。`libgedefense_gaianet_v2.so` 的 `.so` 后缀用于 Android native extraction，它实际作为 executable child process 运行，不是 JNI hot-path library。

## J. 代码指标

Dossier 记录约 1.56M physical LOC（含 vendored code）。最大的 first-party 文件包括 `GeDefenseVpnService.kt`、`AppRuntime.kt`、`AppRiskScanner.kt`、`XdrEngine.kt`、`XdrActivity.kt`、`NetworkDiscoveryScanner.kt`。内部准则对 stateless orchestrator 倾向 <=500 LOC，大型 lifecycle/state owner 为有说明的例外。

## K. 安全架构

1. Confidentiality：AES-256-GCM 保护本地 security state。
2. Integrity：HMAC 与 cryptographic validation 保护持久状态和 threat input。
3. Availability：memory/queue/flow/scan 均受限。
4. Authenticity：外部数据和 export artifact 使用 hash/signature。
5. Least privilege：host 与 GaiaNet 分进程，GaiaNet 无 Keystore 权限。

## L. Trust Model

不可信：hostile packet、third-party app、external feed、shared storage、未认证 IPC。TCB：Android platform（在 threat model 范围内）、KeyStore/KeyMint/StrongBox、GeDefense host、已验证 core algorithms。GaiaNet 的权限被刻意限制。

## M. Threat Model

考虑 malware app、C2、transport attacker、malformed packet、resource exhaustion、本地状态篡改、恶意 update、crypto-provider failure、hostile external files。使用 FlowGate/quarantine、ThreatIndex、WireGuard、bounded parser/reassembly、fuzzing、authenticated storage、Android signature verification、fail-closed provider handling 等缓解。

不完全覆盖：kernel/root compromise、Android policy 之外的物理攻击、unknown DoH over HTTPS/ECH、完整旧 filesystem image replay。

## N. 密码学

At rest：AES-256-GCM、96-bit nonce、128-bit tag、AAD binding、HMAC-SHA-256。Root custody：non-exportable AndroidKeyStore HMAC key。每个 domain 使用随机 root seed 并 wrapped 存储；HKDF subkey 临时派生；generation migration 显式管理。

Transit：WireGuard Noise IKpsk2 / ChaCha20-Poly1305 / Curve25519。Export signature：ECDSA P-256；若 Android/KeyMint 确实提供则增加 ML-DSA-87。

## O. 身份验证与授权

VPN 需要 Android `VpnService.prepare()` consent 和产品级 disclosure。Helper startup 使用 fresh 32-byte token。TITAN action 必须由真实 Device Owner/Admin state 授权。Managed CA installation 有严格大小/证书/CA/keyUsage 校验与显式 fingerprint 确认。

## P. 数据架构

Sensitive durable state 位于 `noBackupFilesDir`，并分成 XDR、evidence、scanner、behavior、firewall、WireGuard、package baseline、LAN history、Port Sentinel、TITAN 等独立 domain。Android backup/device transfer 对这些 security store 禁用。

## Q. 数据流

```text
App traffic -> TUN -> GaiaNet -> threat/privacy/package policy
           -> allow/drop -> Direct or WireGuard -> network
```

```text
Security event -> XDR -> encrypted local store/Evidence
               -> optional user-requested signed export
```

```text
HTTPS feed -> bounded parser -> canonical ThreatIndex
           -> authenticated atomic cache -> immutable GaiaNet policy
```

## R. 网络架构

GeDefense 独占一个 `VpnService`。Direct 模式使用 protected kernel socket；WireGuard 模式使用 embedded userspace L3。Upstream UDP FD 由 Android 精确执行 `VpnService.protect()`/network bind。禁止 blanket UID bypass。

## S. OS/平台集成

使用 `VpnService`、`ConnectivityManager`、`PackageManager`、`DevicePolicyManager`、`JobScheduler`、SAF、Android KeyStore/KeyMint。阻塞任务不直接放进 UI callback。

## T. Process / Thread / Concurrency

Main/UI thread 只做 presentation/lifecycle coordination；`gedefense-control` 串行化 transport/security mutation；扫描/下载/平台调用使用 bounded pool；Go flow/queue 有上限并接受 race test。Security path 不接受 unbounded queue。

## U. 错误处理与韧性

关键 crypto/integrity/transport failure = fail-closed。无效的新 threat feed 不会覆盖 last-known-good。Resilience Supervisor 只能做 trust-preserving repair，不得为了“恢复绿色状态”清空 evidence、解除 quarantine 或把 failed integrity 改成 success。

## V. 更新与发布架构

VC55 将 encryption custody 与 APK identity 分离。Root 每次安装创建一次，不从 APK hash/version/source manifest 派生。历史 generation 经认证读取、内存迁移、crash-safe 发布新 generation，然后才退休旧状态。

## W. Build / Supply Chain Security

Source manifest、vendored Go、pinned toolchain、R8/minification、16 KiB ELF alignment、native reproducibility、SBOM/release audit 都属于 shipping model。

## X. 隐私与遥测

产品不含 Firebase Crashlytics、Sentry、Bugsnag、advertising/analytics SDK。Network observation 用于本地 protection/evidence。诊断仅由用户主动导出，aggregate-only 模式移除 package identity、IP/domain/path/payload detail。

Telemetry Shield 是另一层：在可通过 network/policy 识别的情况下阻止已知 third-party telemetry，但不解密 TLS。

## Y. Logging / Audit / Evidence

Evidence Ledger v3 使用 encrypted record + HMAC continuity。Export 可附 detached signature。目标是 tamper evidence，而不是宣称对已控制 kernel 的攻击者不可见。

## Z. 性能

Packet hot path 使用 bounded/fixed buffer 和紧凑 threat lookup。Blocking control work 离开 main thread。UI 可以降低装饰动画 FPS，但不得因此降低 policy/evidence enforcement。

## AA. 容量与限制

原 dossier 记录：1 MiB unacked TCP per flow、32 MiB global downstream buffer、64 dial worker、1,024 UDP flow、TCP idle 10 min/90 sec constrained、UDP 90/30 sec、Fast Verdict 1.75 sec、Deep Scan 25 sec、LAN 254 host、WireGuard import 16 KiB/128 lines。超过限制时进行 reject/drop/recycle，而不是无界增长。

## AB. Profile

Telemetry Shield：OFF、CONSERVATIVE、BALANCED、STRICT。Strict 可阻断 DoT/DoQ port 853。Secure defaults：`allowBackup=false`、`usesCleartextTraffic=false`、network security config、新应用在 verdict 前进入 quarantine/gate。

## AC. 接口/API

Helper Protocol v5：Unix socket、versioned framing、MTU negotiation、按模式精确 FD count。WireGuard UAPI 仅内部使用。GeDefense 不暴露 public HTTP/REST/RPC server。

## AD. 文件格式/协议

`VGTVLT01` = AEAD vault；`VGTPVK01` = wrapped keyset；`GDTI-v2` = threat prefix index；JSON = detached signatures/diagnostics；local PDDL/IPtoASN；WireGuard Noise over UDP。

## AE. 测试/验证

专用 harness 覆盖 core crypto/data、vault/key lifecycle、Privacy Shield、WireGuard、InstallGuard、resilience、startup/main-thread、i18n、source manifest、artifact validation、Go packet/flow。仅编译成功不等同于 release-ready。

## AF. 对抗性安全测试

包含 ciphertext bit flip、AAD mismatch、malformed packet、fuzzing、Go `-race`、socket bypass negative tests 以及 fail-closed 路径。

## AG. 质量/维护性

Host/core/netstack 边界明确；历史 crypto generation 仅为 migration；共享 deterministic algorithm 放在 `:core`；production dummy/TODO 不被视为完成。

## AH. 架构规则

无 JNI packet hot path；只有一个 VPN owner；main looper 不执行 blocking network/file/crypto；ThreatIndex 运行时 immutable，更新需 atomic replace。

## AI. 安全不变量

普通 log/preference 中不出现 secret；尽可能 zeroize sensitive buffer；key failure fail closed；默认 non-MITM；禁止 whole-UID WireGuard bypass。

## AJ. 外部服务

无 mandatory VGT backend。Public threat feed 只是可选更新来源；feed outage 时继续 last-known-good local protection。

## AK. 离线能力

Threat index、ASN、baseline、evidence 均本地。Firewall、packet filter、Telemetry Shield、quarantine、scanner 不依赖持续 backend connection。

## AL. Attack Surface

TUN：memory-safe parser/fragment limit/fuzzing；IPC：private path/token/framing；Android intent：关键 component 不导出；backup：关闭；shared storage：read-only bounded scanner；update：Android package signature + signer drift evidence。

## AM. Hardening

PIE/NX/RELRO expectations、>=16 KiB ELF alignment、R8/minification、`usesCleartextTraffic=false`、detached evidence signature。

## AN. Secrets

AndroidKeyStore HMAC root PRF；随机 256-bit domain root 仅 wrapped 存储；临时 HKDF subkey；non-exportable hardware key，平台可靠支持时使用硬件 backing/StrongBox。

## AO. 权限模型

正常模式为普通 app UID；Go helper 只获明确 FD/capability。TITAN Device Owner 增加 Android-managed Always-on/lockdown、restriction、package suspension 等 DPC 能力。

## AP. 兼容性

Android API 29+，target/compile 36，arm64-v8a、x86_64。特别关注 HyperOS/OneUI 等激进后台策略。

## AQ. Packaging

Signed/minified APK + AAB。不从 Internet 动态加载代码。Native helper 从 source 构建并与 packaged bytes 比较。

## AR. 许可证

德语原 dossier 编写于公共仓库许可证最终确定之前，因此写有 proprietary VGT license。**本 GitHub-ready 公共 source tree 的有效许可证是 `AGPL-3.0-or-later`**，以仓库 `LICENSE` 为准。Vendored upstream 保留 MIT/BSD/Public Domain 条款。

## AS. 文档状态

Architecture/security/threat/vault/transport/build/test/release 均有 Markdown 与 machine-verifiable audit。Dossier 是 VC55 snapshot，不取代当前 source evidence。

## AT. 已知限制

Android `PACKAGE_ADDED` timing；non-MITM 导致 TLS payload 不可见；没有通用 trusted monotonic anti-rollback counter。

## AU. 技术债

大型 Android lifecycle owner、offline AGP cache 准备、ASN 本地 asset 大小。

## AV. 剩余风险

Kernel/root compromise、unknown DoH 443/ECH、OEM Keystore provider defect 导致临时 fail-closed protection stop。

## AW. 架构优势

Android runtime third-party library 为 0；process isolation；no JNI hot path；update-stable key custody；hybrid signature readiness；fail-closed networking；大量自动化 gate。

## AX. 架构边界

依赖 Android/KeyStore 完整性；无法对已经获得 kernel 控制的解锁设备提供数学不可攻破保证；不做 TLS DPI。

## AY. 成熟度

Architecture/crypto/storage 为 release-hardened；network/WireGuard/OEM 仍需要 real-device matrix；supply chain 和 reproducibility 被视为正式 shipping property。

## AZ. Factsheet

**GeDefense Mobile · 0.27.8-beta.6 / VC55 · Android 10+ · Kotlin host + Go GaiaNet · Android external runtime libs = 0 · AES-256-GCM + HMAC-SHA-256 · AndroidKeyStore root PRF · Direct L4 / WireGuard L3 · local-first / non-MITM · optional TITAN Device Owner · pinned/reproducible release gates.**

---

# 第二部分 · Architecture & Technical Master Map

## 1. 全局架构树

```text
GeDefense Mobile
├─ Presentation/UI
├─ Kotlin Application Control Plane
│  ├─ AppRuntime / State / UiSnapshot
│  ├─ GeDefenseVpnService / NativeGaiaNet
│  ├─ Vault / Evidence / XDR / InstallGuard / Resilience
│  └─ Android platform adapters
├─ Pure Kotlin Core
│  ├─ AEAD / authenticated snapshots / evidence
│  ├─ threat/privacy/route/ASN structures
│  └─ bounded parser/recovery policy
└─ GaiaNet V2 Go Data Plane
   ├─ IP/TCP/UDP
   ├─ threat/privacy/package policy
   ├─ IPC/FD handling
   └─ Direct + WireGuard transport
```

## 2. 文件到架构映射

### UI

核心页面：`DashboardScreen.kt`、`ThreatScreen.kt`、`ProtectionHubScreen.kt`、`AnalysisHubScreen.kt`、`SystemHubScreen.kt`、`FirewallActivity.kt`、`WireGuardActivity.kt`、`PrivacyActivity.kt`、`ScannerActivity.kt`、`XdrActivity.kt`、`HardeningActivity.kt`、`BehaviorActivity.kt`、`NetworkDiscoveryActivity.kt`、`PortSentinelActivity.kt`、`TitanActivity.kt`、`EvidenceScreen.kt`、`DiagnosticsActivity.kt`、`SupportVgtActivity.kt`、`SetupWizardActivity.kt`、`VpnDisclosureActivity.kt`。

可复用 visuals：`CyberBackgroundView.kt`、`ShieldPulseView.kt`、`VgtActionTile.kt`、`VgtIconView.kt`、`VgtProgressView.kt`、`TitanCoreView.kt`、`ScannerRadarView.kt`、`TrafficWorldMapView.kt`。

### Control Plane

Lifecycle/state：`GeDefenseApplication.kt`、`AppRuntime.kt`、`RuntimeState.kt`、`UiSnapshot.kt` 及 bounded executors。Network：`GeDefenseVpnService.kt`、`NativeGaiaNet.kt`、`ConnectionOwner.kt`、`PackageEgressGate.kt`。Stores 覆盖 firewall、WireGuard、XDR、behavior/package baseline、malware analysis、approval、network discovery、Port Sentinel、TITAN、scanner、VPN disclosure、evidence、Threat/ASN/Geo/Privacy repositories。

### Go Data Plane

`engine.go`、`packet.go`、`reassembly.go`、`limits.go`、TCP/UDP managers、DNS、`policy.go`、`privacy_policy.go`、`package_egress_gate.go`、helper/bridge/socket binding 与 WireGuard transport/tun/protected-bind/flow tracker。

### Crypto/Core

Host：`SecureTelemetryVault.kt`、`PersistentVaultKeys.kt`、migration derivators、`AndroidSecrets.kt`、`AndroidKeystoreGate.kt`、`HybridArtifactSigner.kt`。Pure JVM：`AeadVaultEnvelope.kt`、`AuthenticatedSnapshotStore.kt`、`BoundedSecretKeyCrypto.kt`、`EvidenceLedger.kt`。Shared：ThreatIndex、IP/route/privacy/ASN、mDNS/DNS codec、LAN behavior、Port Sentinel classifier、certificate validator、recovery budget。

## 3. 模块文档

### Host & Runtime
异步 bootstrap、state/dependency root、serialized mutation、platform lifecycle。

### Network & VPN
单一 `VpnService` owner、TUN/routes/handover、exact-socket protection、helper supervision。

### GaiaNet
独立 memory-safe packet engine、bounded state、Direct/WireGuard egress。

### Threat Intelligence
Bounded download -> canonical parser -> compact index -> authenticated atomic publish -> immutable runtime policy。

### Secure Vault
Per-domain random keyset、stable root PRF、AES-GCM、HMAC、explicit migration、backup exclusion。

### XDR/EDR
本地关联多个独立 signal，产生 explainable incident；网络隔离优先于 destructive action。

### InstallGuard/Scanner
Pre-egress gate、Fast/Deep scan、signer/capability checks、non-authoritative cache。

### Telemetry Shield
无 TLS break 的本地 privacy policy 与 encrypted-DNS control。

### Network Discovery / Port Sentinel
Bounded LAN visibility、passive decoy evidence、不保留 payload。

### TITAN
Optional Device Owner hardening/lockdown/suspension；managed CA 与 destructive policy 需要显式确认。

### Resilience
只允许 trust-preserving repair，不能清空 evidence、解除 quarantine 或把 integrity failure 伪装成 success。

### Diagnostics
通过 SAF 由用户主动导出 aggregate-only support bundle。

### Setup
解释 VPN/privacy model、获得 consent、引导系统设置并建立初始保护 baseline。当前 source 已把 Telemetry Shield 作为 onboarding 的重要 privacy capability。

## 4. Dashboard 详细说明

Cockpit 从 `UiSnapshot` 读取 protection、Threat Intelligence、blocked/session、analysis 状态。Threat screen 管理本地 feed。Protection Hub 导航 firewall/WireGuard/privacy/scanner/discovery/Port Sentinel。Analysis Hub 进入 XDR/behavior/hardening/evidence。System Hub 提供 TITAN、diagnostics、setup/support。

Firewall policy 加密持久化并与 enforcement 原子同步。WireGuard import 有大小限制，并且只有 exact-socket Android protect/bind handshake 完成后才激活。Privacy screen 控制 Telemetry Shield profile。Scanner 使用 bounded worker 与 quarantine。XDR Explorer 解密本地 incident 并解释 correlation。

## 5. UI Architecture

原生 Android View、dark glass/cyber 视觉系统、可复用 VGT controls、adaptive rendering。UI 不直接做 disk/network I/O，而读取 immutable cached state。Destructive/privileged action 需要明确确认。

## 6. API Architecture

无 public HTTP API。内部接口由 Kotlin service、Android platform API 与 versioned Unix-socket helper protocol 构成。所有 boundary input 在使用前检查 version/size/schema/FD count/token。

## 7. Data Flows

`PACKAGE_ADDED -> InstallGuard -> quarantine/FlowGate -> Deep Scan -> XDR/Evidence -> verified release/block`。

`DNS/flow metadata -> Privacy profile -> allow/block -> bounded event -> XDR/Evidence`。

`Integrity observation -> baseline verify -> authenticated local state -> XDR/Evidence on degradation`。

## 8. Shared/Core Files

`:core` 持有 deterministic security/data primitive：AEAD、authenticated snapshot、evidence chain、threat/IP/route/privacy/ASN structure、bounded DNS parser、LAN behavior、Port Sentinel classification、recovery budget。`AppRuntime`、`GeDefenseVpnService`、`NativeGaiaNet` 是 host plane 的关键 ownership point。

## 9. 架构关系

```text
UI -> AppRuntime/VPN/Resilience -> Vault/Evidence/InstallGuard
   -> authenticated IPC -> GaiaNet -> Direct/WireGuard -> Network
```

KeyStore 始终留在 host-side。MainActivity 组织 Dashboard、Threat、Protection、Analysis、System 五个主 hub。

## 10. 关键文件引用

Bootstrap：`AppRuntime.kt`、`StartupActivity.kt`；TUN：`GeDefenseVpnService.kt`、`NativeGaiaNet.kt`；SCM_RIGHTS：`NativeGaiaNet.kt`、`helper_main_process.go`；WireGuard socket protection：`wireguard_protected_bind.go`；key lifecycle：`PersistentVaultKeys.kt`、`AndroidSecrets.kt`；AEAD：`AeadVaultEnvelope.kt`；InstallGuard：`InstallGuard.kt`、`package_egress_gate.go`；DoT/DoQ：`privacy_policy.go`、`PrivacyIntelligence.kt`；hybrid signatures：`HybridArtifactSigner.kt`；recovery：`ResilienceSupervisor.kt`、`RecoveryAttemptBudget.kt`。

## 11. 架构观察

原 dossier 将 `MoreScreen.kt`、`SecurityScreen.kt` 标为无 active caller 的历史 UI；`settings.gradle.kts.orig` 是应删除的 backup；`helper_main_stub.go` 是正确的 non-Android build-tag stub；旧 crypto derivator 仅服务 migration；experimental cgo socket binder 不属于普通 production packet path。本 GitHub-ready 目录已移除 `settings.gradle.kts.orig` 和内部 handoff 文件。

---

# 中文翻译版结束

进行安全决策时，请始终以当前源码、`SECURITY.md`、`THREAT-MODEL.md`、`TOOLCHAINS.lock`、release gates 与实际部署的 signed artifact 为最终依据。
