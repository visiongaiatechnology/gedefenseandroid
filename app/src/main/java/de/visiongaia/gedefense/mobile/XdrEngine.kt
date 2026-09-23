package de.visiongaia.gedefense.mobile

import android.content.Context
import de.visiongaia.gedefense.mobile.core.EvidenceEvent
import de.visiongaia.gedefense.mobile.core.EvidenceStore

class XdrEngine(
    context: Context,
    private val evidence: EvidenceStore,
    private val firewallPolicy: FirewallPolicyStore,
    private val networkDiscoveryStore: NetworkDiscoveryStore,
    private val portSentinelStore: PortSentinelStore,
    private val titan: TitanPolicyManager,
    private val approvals: AppApprovalStore,
    private val runtimeState: RuntimeState,
) {
    private val appContext = context.applicationContext
    private val store = XdrEventStore(appContext)
    private val baselines = PackageBaselineStore(appContext)

    fun initializePersistentState() {
        store.initialize()
        baselines.initialize()
        if (!store.integrityOk()) reportXdrPersistenceFailure(
            "store_integrity_degraded",
            IllegalStateException(store.integrityFailureReason() ?: "xdr_store_integrity_degraded"),
        )
    }

    fun snapshot(): XdrSnapshot {
        val raw = store.snapshot()
        val visible = raw.incidents.filter { incidentVisible(it, raw.events) }
        return raw.copy(
            incidents = visible,
            quarantinedPackages = firewallPolicy.quarantinedPackages(),
            packageBaselineIntegrityOk = baselines.integrityOk() && baselines.initialized(),
            firewallPolicyIntegrityOk = firewallPolicy.integrityOk(),
            networkDiscoveryIntegrityOk = networkDiscoveryStore.integrityOk(),
            portSentinelIntegrityOk = portSentinelStore.integrityOk(),
            titanPolicyIntegrityOk = titan.policyStore.integrityOk() && approvals.integrityOk(),
        )
    }

    fun reconcilePackages() {
        if (!store.integrityOk()) return
        if (!baselines.integrityOk()) {
            recordTrustStoreFailure("package-baseline", baselines.integrityFailureReason())
            return
        }
        baselines.reconcileAll().forEach(::ingestPackageChange)
        if (!baselines.integrityOk()) recordTrustStoreFailure("package-baseline", baselines.integrityFailureReason())
        if (!firewallPolicy.integrityOk()) recordTrustStoreFailure("firewall-policy", firewallPolicy.integrityFailureReason())
        pruneTrustedSignerEvents()
        pruneQuarantine()
    }

    fun handlePackageEvent(packageName: String, action: String, replacing: Boolean) {
        if (action.endsWith("PACKAGE_REMOVED") && replacing) return
        if (!store.integrityOk() || !baselines.integrityOk()) {
            if (!baselines.integrityOk()) recordTrustStoreFailure("package-baseline", baselines.integrityFailureReason())
            return
        }
        val removed = action.endsWith("PACKAGE_REMOVED")
        baselines.reconcilePackage(packageName, removed)?.let(::ingestPackageChange)
        if (!baselines.integrityOk()) recordTrustStoreFailure("package-baseline", baselines.integrityFailureReason())
        pruneQuarantine()
    }

    fun ingestInstallGuard(
        packageName: String,
        verdict: String,
        riskScore: Int,
        reasonCodes: List<String>,
        suspended: Boolean,
        networkQuarantined: Boolean,
        elapsedMs: Long,
    ) {
        val safeVerdict = verdict.trim().uppercase().take(32)
        val reasons = reasonCodes.asSequence().map { it.trim().take(96) }.filter { it.isNotEmpty() }.distinct().take(12).toList()
        val severity = when (safeVerdict) {
            "BLOCK" -> XdrSeverity.CRITICAL
            "REVIEW", "INCOMPLETE" -> XdrSeverity.HIGH
            else -> XdrSeverity.INFO
        }
        val points = when (safeVerdict) {
            "BLOCK" -> maxOf(75, riskScore.coerceIn(0, 100))
            "REVIEW" -> maxOf(42, riskScore.coerceIn(0, 100))
            "INCOMPLETE" -> 35
            else -> 0
        }
        emit(
            category = if (safeVerdict == "PASS" || safeVerdict == "FAST_PASS_DEEP_PENDING") XdrCategory.RESPONSE else XdrCategory.MALWARE,
            severity = severity,
            source = "install-guard",
            subject = packageName,
            title = "InstallGuard $safeVerdict",
            detail = "package=$packageName; verdict=$safeVerdict; risk=${riskScore.coerceIn(0, 100)}; suspended=$suspended; network_quarantine=$networkQuarantined; elapsed_ms=${elapsedMs.coerceAtLeast(0L)}; reasons=${reasons.joinToString(",")}",
            riskPoints = points,
            incidentKey = "install:$packageName",
            packageName = packageName,
            dedupeKey = "installguard:$packageName:$safeVerdict:${reasons.joinToString("|")}",
            dedupeMs = if (safeVerdict == "PASS" || safeVerdict == "FAST_PASS_DEEP_PENDING") 10L * 60L * 1000L else 60L * 60L * 1000L,
            detectorScore = riskScore.coerceIn(0, 100),
            forensicReasons = reasons.map { XdrForensicReason(it, if (safeVerdict == "BLOCK") 20 else 8) },
            forensicFacts = listOf(
                XdrForensicFact("install_guard_verdict", safeVerdict),
                XdrForensicFact("network_quarantined", networkQuarantined.toString()),
                XdrForensicFact("package_suspended", suspended.toString()),
                XdrForensicFact("scan_elapsed_ms", elapsedMs.coerceAtLeast(0L).toString()),
            ),
        )
    }

    fun ingestPrivacyDecision(
        owner: String,
        domain: String,
        action: String,
        category: String,
        confidence: String,
        ruleId: String,
    ) {
        val safeAction = action.trim().uppercase().take(16)
        if (safeAction != "BLOCK" && safeAction != "OBSERVE") return
        val safeDomain = domain.trim().lowercase().take(253)
        val safeCategory = category.trim().uppercase().take(48)
        val safeConfidence = confidence.trim().uppercase().take(16)
        val safeRule = ruleId.trim().take(96)
        val packageName = owner.substringBefore(',').takeIf { it.contains('.') && !it.startsWith("uid-") }
        emit(
            category = XdrCategory.NETWORK,
            severity = if (safeAction == "BLOCK") XdrSeverity.MEDIUM else XdrSeverity.INFO,
            source = "telemetry-shield",
            subject = packageName ?: owner.take(120),
            title = if (safeAction == "BLOCK") "Telemetry endpoint blocked" else "Telemetry endpoint observed",
            detail = "domain=$safeDomain; action=$safeAction; category=$safeCategory; confidence=$safeConfidence; rule=$safeRule",
            riskPoints = if (safeAction == "BLOCK") 12 else 0,
            incidentKey = packageName?.let { "app:$it" } ?: "privacy:${owner.take(120)}",
            packageName = packageName,
            dedupeKey = "privacy:$owner:$safeDomain:$safeAction:$safeRule",
            dedupeMs = 60L * 60L * 1000L,
            forensicFacts = listOf(
                XdrForensicFact("privacy_domain", safeDomain),
                XdrForensicFact("privacy_action", safeAction),
                XdrForensicFact("privacy_category", safeCategory),
                XdrForensicFact("privacy_confidence", safeConfidence),
                XdrForensicFact("privacy_rule", safeRule),
            ),
        )
    }

    fun ingestIntegrity(snapshot: IntegritySnapshot) {
        if (snapshot.ok) return
        val codes = snapshot.issues.joinToString(",") { it.code }.take(420)
        emit(
            category = XdrCategory.INTEGRITY,
            severity = XdrSeverity.CRITICAL,
            source = "integrity",
            subject = "GeDefense integrity",
            title = "Application integrity degraded",
            detail = "state=${snapshot.state}; issues=$codes",
            riskPoints = 90,
            incidentKey = "integrity:local",
            dedupeKey = "integrity:${snapshot.state}:$codes",
            dedupeMs = 30L * 60L * 1000L,
        )
    }

    fun ingestAppScan(snapshot: AppScanSnapshot) {
        if (snapshot.state != "COMPLETE") return
        snapshot.results
            .filter { maxOf(it.capabilityScore, it.heuristicScore) >= 20 || it.threatMatches.isNotEmpty() || it.approvalState == AppApprovalState.STALE }
            .take(48)
            .forEach { result ->
                val blocking = result.threatMatches.any { it.endsWith(":BLOCK") }
                val correlated = result.threatMatches.any { it.endsWith(":CORRELATE") }
                val staticContextScore = maxOf(result.capabilityScore, result.heuristicScore).coerceIn(0, 100)
                val points = when {
                    blocking -> 72
                    correlated -> 42
                    result.approvalState == AppApprovalState.APPROVED -> 4
                    result.approvalState == AppApprovalState.STALE -> 28
                    else -> (8 + staticContextScore / 4).coerceIn(8, 24)
                }
                val severity = when {
                    blocking -> XdrSeverity.CRITICAL
                    correlated -> XdrSeverity.HIGH
                    result.approvalState == AppApprovalState.STALE -> XdrSeverity.MEDIUM
                    points >= 20 -> XdrSeverity.MEDIUM
                    else -> XdrSeverity.LOW
                }
                val findings = result.findings.joinToString(",") { "${it.code}:${it.weight}" }.take(700)
                val reasons = result.findings.map { XdrForensicReason(code = it.code, points = it.weight) }
                val rawScannerScore = reasons.sumOf { it.points }.coerceIn(0, 100)
                val facts = buildList {
                    add(XdrForensicFact("package", result.packageName))
                    if (result.versionName.isNotBlank()) add(XdrForensicFact("version", result.versionName))
                    add(XdrForensicFact("installer", result.installer ?: "unknown"))
                    add(XdrForensicFact("risk_level", result.riskLevel.name))
                    add(XdrForensicFact("confidence", result.confidence.name))
                    add(XdrForensicFact("capability_score", result.capabilityScore.toString()))
                    add(XdrForensicFact("scanner_raw_score", rawScannerScore.toString()))
                    add(XdrForensicFact("effective_static_score", result.riskScore.toString()))
                    add(XdrForensicFact("approval_state", result.approvalState.name))
                    add(XdrForensicFact("analysis_mode", result.analysisMode))
                    result.signerSha256?.takeIf { it.isNotBlank() }?.let { add(XdrForensicFact("signer_sha256", it)) }
                    result.apkSha256?.takeIf { it.isNotBlank() }?.let { add(XdrForensicFact("apk_sha256", it)) }
                    if (result.threatMatches.isNotEmpty()) add(XdrForensicFact("threat_matches", result.threatMatches.joinToString(" | ").take(700)))
                }
                emit(
                    category = XdrCategory.MALWARE,
                    severity = severity,
                    source = "app-scanner",
                    subject = result.label,
                    title = when {
                        blocking -> "Threat-intelligence match in application"
                        correlated -> "Correlated application indicator"
                        result.approvalState == AppApprovalState.STALE -> "Approved application changed"
                        else -> "Application capability context"
                    },
                    detail = "package=${result.packageName}; capability_score=${result.capabilityScore}; effective_static_score=${result.riskScore}; approval=${result.approvalState}; confidence=${result.confidence}; analysis=${result.analysisMode}; findings=$findings; threat_matches=${result.threatMatches.size}",
                    riskPoints = points,
                    incidentKey = "app:${result.packageName}",
                    packageName = result.packageName,
                    dedupeKey = "appscan:${result.packageName}:${result.capabilityScore}:${result.approvalState}:$findings",
                    dedupeMs = 6L * 60L * 60L * 1000L,
                    detectorScore = rawScannerScore,
                    forensicReasons = reasons,
                    forensicFacts = facts,
                )
            }
    }

    fun ingestHardening(snapshot: HardeningSnapshot) {
        if (snapshot.checkedAtMillis <= 0L) return
        // Resolved posture findings must stop contributing to incidents immediately instead of
        // lingering for the seven-day event window. The authenticated event store remains the
        // source of truth; only events for a finding that now passes are removed.
        snapshot.findings.filter { it.status == HardeningStatus.PASS }.forEach { finding ->
            store.removeEvents("hardening:${finding.id}:", "hardening")
        }
        snapshot.findings.asSequence()
            .filter { it.status == HardeningStatus.FAIL || (it.status == HardeningStatus.REVIEW && it.severity >= HardeningSeverity.MEDIUM) }
            .take(16)
            .forEach { finding ->
                val severity = when (finding.severity) {
                    HardeningSeverity.CRITICAL -> XdrSeverity.CRITICAL
                    HardeningSeverity.HIGH -> XdrSeverity.HIGH
                    HardeningSeverity.MEDIUM -> XdrSeverity.MEDIUM
                    HardeningSeverity.LOW -> XdrSeverity.LOW
                    HardeningSeverity.INFO -> XdrSeverity.INFO
                }
                val risk = when (finding.severity) {
                    HardeningSeverity.CRITICAL -> 56
                    HardeningSeverity.HIGH -> 38
                    HardeningSeverity.MEDIUM -> 20
                    HardeningSeverity.LOW -> 8
                    HardeningSeverity.INFO -> 2
                }
                emit(
                    category = XdrCategory.SYSTEM,
                    severity = severity,
                    source = "hardening",
                    subject = "Local device posture",
                    title = finding.title,
                    detail = "status=${finding.status}; evidence=${finding.evidence}; remediation=${finding.remediation}".take(1100),
                    riskPoints = risk,
                    incidentKey = "system:hardening",
                    dedupeKey = "hardening:${finding.id}:${finding.status}:${finding.evidence}",
                    dedupeMs = 12L * 60L * 60L * 1000L,
                )
            }
    }

    fun ingestDeviceScan(snapshot: DeviceScanSnapshot) {
        if (snapshot.state != "COMPLETE") return
        ingestIntegrity(snapshot.integrity)
        ingestAppScan(snapshot.apps)
        snapshot.storage.results.filter { it.riskLevel == FileRiskLevel.HIGH || it.riskLevel == FileRiskLevel.SEVERE }.take(24).forEach { result ->
            val severe = result.riskLevel == FileRiskLevel.SEVERE
            emit(
                category = XdrCategory.MALWARE,
                severity = if (severe) XdrSeverity.CRITICAL else XdrSeverity.HIGH,
                source = "storage-scanner",
                subject = result.displayName,
                title = if (severe) "Severe file risk detected" else "High file risk detected",
                detail = "path=${result.path}; score=${result.riskScore}; kind=${result.kind}; threat_matches=${result.threatMatches.size}",
                riskPoints = if (severe) 68 else 45,
                incidentKey = "file:${result.sha256 ?: result.path}",
                dedupeKey = "filescan:${result.sha256 ?: result.path}:${result.riskScore}",
                dedupeMs = 6L * 60L * 60L * 1000L,
            )
        }
    }

    fun recordBehaviorAnomaly(anomaly: BehaviorAnomaly): Boolean = emit(
        category = XdrCategory.BEHAVIOR,
        severity = anomaly.severity,
        source = "behavior-engine",
        subject = anomaly.label.ifBlank { anomaly.packageName },
        title = anomaly.title,
        detail = "type=${anomaly.type}; package=${anomaly.packageName}; confidence=${anomaly.confidence}; baseline_observations=${anomaly.baselineObservations}; ${anomaly.detail}",
        riskPoints = behaviorRiskPoints(anomaly),
        incidentKey = "app:${anomaly.packageName}",
        packageName = anomaly.packageName,
        dedupeKey = "behavior:${anomaly.packageName}:${anomaly.type}:${anomaly.fingerprint}",
        dedupeMs = 30L * 60L * 1000L,
        detectorScore = anomaly.confidence,
        forensicReasons = listOf(XdrForensicReason("behavior_${anomaly.type.name.lowercase()}", anomaly.riskPoints, "confidence=${anomaly.confidence}")),
        forensicFacts = listOf(
            XdrForensicFact("behavior_type", anomaly.type.name),
            XdrForensicFact("behavior_confidence", anomaly.confidence.toString()),
            XdrForensicFact("baseline_observations", anomaly.baselineObservations.toString()),
        ),
    )

    private fun behaviorRiskPoints(anomaly: BehaviorAnomaly): Int {
        // Confidence modulates behavioral weight, but a high-confidence runtime anomaly remains an
        // independent signal. Low-confidence early-learning observations cannot dominate XDR.
        val confidence = anomaly.confidence.coerceIn(0, 100)
        val scaled = (anomaly.riskPoints * (60 + confidence)) / 160
        return scaled.coerceIn(8, anomaly.riskPoints.coerceIn(8, 100))
    }

    fun recordThreatBlock(owner: String, destination: String, protocol: Int, port: Int) {
        val packageName = owner.takeIf { it.contains('.') && !it.startsWith("uid-") }
        emit(
            category = XdrCategory.NETWORK,
            severity = XdrSeverity.HIGH,
            source = "gaianet",
            subject = packageName ?: owner,
            title = "Threat-intelligence network block",
            detail = "destination=${destination.take(160)}; protocol=$protocol; port=$port",
            riskPoints = 42,
            incidentKey = packageName?.let { "app:$it" } ?: "network:${owner.take(120)}",
            packageName = packageName,
            dedupeKey = "net:$owner:$destination:$protocol:$port",
            dedupeMs = 15L * 60L * 1000L,
        )
    }


    fun ingestNetworkDiscovery(snapshot: NetworkDiscoverySnapshot) {
        if (!snapshot.baselineIntegrityOk || !networkDiscoveryStore.integrityOk()) {
            recordNetworkDiscoveryIntegrityFailure(snapshot.baselineFailureReason ?: networkDiscoveryStore.integrityFailureReason())
            return
        }
        snapshot.networkBehaviorSignals.sorted().forEach { signal ->
            val severity = if (signal == "risk_surge") XdrSeverity.HIGH else XdrSeverity.MEDIUM
            val points = if (signal == "risk_surge") 38 else 24
            val title = if (signal == "risk_surge") "Local-network risk surge observed" else "Local-network device surge observed"
            emit(
                category = XdrCategory.NETWORK,
                severity = severity,
                source = "lan-behavior",
                subject = snapshot.localAddress,
                title = title,
                detail = "signal=$signal; devices=${snapshot.devices.size}; historical_devices=${snapshot.historicalDeviceCount}; elevated=${snapshot.elevatedDevices}; historical_elevated=${snapshot.historicalElevatedCount}; observations=${snapshot.networkBaselineObservations}",
                riskPoints = points,
                incidentKey = "lan:${snapshot.networkId}",
                dedupeKey = "lan-behavior:${snapshot.networkId}:$signal:${snapshot.devices.size}:${snapshot.elevatedDevices}",
                dedupeMs = 12L * 60L * 60L * 1000L,
            )
        }
        snapshot.devices.asSequence().take(512).forEach { device ->
            device.behaviorSignals.sorted().forEach { signal ->
                val severity = when (signal) {
                    "exposure_risk_spike" -> XdrSeverity.HIGH
                    "service_burst", "return_with_surface_drift" -> XdrSeverity.MEDIUM
                    else -> XdrSeverity.LOW
                }
                val points = when (severity) {
                    XdrSeverity.HIGH -> 40
                    XdrSeverity.MEDIUM -> 24
                    XdrSeverity.CRITICAL -> 60
                    XdrSeverity.LOW, XdrSeverity.INFO -> 8
                }
                val title = when (signal) {
                    "exposure_risk_spike" -> "Local device exposure risk spiked"
                    "service_burst" -> "Local device service burst observed"
                    "return_with_surface_drift" -> "Returning device changed its exposed surface"
                    else -> "Local device behavior changed"
                }
                emit(
                    category = XdrCategory.NETWORK,
                    severity = severity,
                    source = "lan-behavior",
                    subject = device.ipAddress,
                    title = title,
                    detail = "signal=$signal; role=${device.role}; risk=${device.riskScore}; historical_risk=${device.historicalRiskScore}; observations=${device.baselineObservations}; host=${device.hostname ?: "unavailable"}",
                    riskPoints = points,
                    incidentKey = "lan:${snapshot.networkId}:${device.stableId}",
                    dedupeKey = "lan-device-behavior:${snapshot.networkId}:${device.stableId}:$signal:${device.riskScore}",
                    dedupeMs = 12L * 60L * 60L * 1000L,
                )
            }
            if (device.newToBaseline) {
                emit(
                    category = XdrCategory.NETWORK, severity = XdrSeverity.LOW, source = "lan-discovery",
                    subject = device.ipAddress, title = "New device observed on local network",
                    detail = "role=${device.role}; identity=${device.identitySource}; host=${device.hostname ?: "unavailable"}; mac=${device.macAddress ?: "unavailable"}; active=${device.openServices.joinToString(",") { "${it.name}:${it.port}" }.take(300)}; advertised=${device.advertisedServices.joinToString(",") { it.serviceType }.take(300)}",
                    riskPoints = 10, incidentKey = "lan:${snapshot.networkId}:${device.stableId}",
                    dedupeKey = "lan-new:${snapshot.networkId}:${device.stableId}", dedupeMs = 24L * 60L * 60L * 1000L,
                )
            }
            if (device.changedBaselineAttributes.isNotEmpty()) {
                emit(
                    category = XdrCategory.NETWORK, severity = XdrSeverity.MEDIUM, source = "lan-baseline",
                    subject = device.ipAddress, title = "Local device identity drift observed",
                    detail = "changed=${device.changedBaselineAttributes.sorted().joinToString(",")}; identity=${device.identitySource}; host=${device.hostname ?: "unavailable"}; role=${device.role}",
                    riskPoints = 18, incidentKey = "lan:${snapshot.networkId}:${device.stableId}",
                    dedupeKey = "lan-identity:${snapshot.networkId}:${device.stableId}:${device.changedBaselineAttributes.sorted().joinToString("-")}",
                    dedupeMs = 24L * 60L * 60L * 1000L,
                )
            }
            val portsToReport = linkedSetOf<Int>().apply {
                addAll(device.newlyExposedPorts)
                device.openServices.asSequence().map { it.port }.filter { it in HIGH_RISK_LAN_PORTS }.forEach(::add)
            }
            portsToReport.sorted().forEach { port ->
                val severity = when (port) {
                    5555 -> XdrSeverity.CRITICAL
                    23, 3389, 5900 -> XdrSeverity.HIGH
                    21, 139, 445 -> XdrSeverity.MEDIUM
                    else -> XdrSeverity.LOW
                }
                val points = when (severity) {
                    XdrSeverity.CRITICAL -> 74
                    XdrSeverity.HIGH -> 46
                    XdrSeverity.MEDIUM -> 28
                    else -> 10
                }
                emit(
                    category = XdrCategory.NETWORK, severity = severity, source = "lan-discovery",
                    subject = device.ipAddress, title = "New local service exposure detected",
                    detail = "port=$port; role=${device.role}; mac=${device.macAddress ?: "unavailable"}; network=${snapshot.networkId.take(16)}",
                    riskPoints = points, incidentKey = "lan:${snapshot.networkId}:${device.stableId}",
                    dedupeKey = "lan-port:${snapshot.networkId}:${device.stableId}:$port", dedupeMs = 24L * 60L * 60L * 1000L,
                )
            }
            val advertisedToReport = linkedSetOf<String>().apply {
                addAll(device.newlyAdvertisedServiceTypes)
                device.advertisedServices.asSequence().map { it.serviceType }.filter { it in HIGH_RISK_DNS_SD_SERVICES }.forEach(::add)
            }
            advertisedToReport.sorted().forEach { serviceType ->
                val severity = when (serviceType) {
                    "_adb-tls-connect._tcp.local", "_adb-tls-pairing._tcp.local", "_telnet._tcp.local" -> XdrSeverity.HIGH
                    "_rdp._tcp.local", "_rfb._tcp.local" -> XdrSeverity.MEDIUM
                    "_smb._tcp.local", "_afpovertcp._tcp.local", "_ssh._tcp.local" -> XdrSeverity.LOW
                    else -> XdrSeverity.LOW
                }
                val points = when (severity) {
                    XdrSeverity.CRITICAL -> 70
                    XdrSeverity.HIGH -> 44
                    XdrSeverity.MEDIUM -> 24
                    XdrSeverity.LOW, XdrSeverity.INFO -> 8
                }
                val service = device.advertisedServices.firstOrNull { it.serviceType == serviceType }
                emit(
                    category = XdrCategory.NETWORK, severity = severity, source = "lan-mdns",
                    subject = device.ipAddress, title = "New local service advertisement detected",
                    detail = "service=$serviceType; port=${service?.port ?: 0}; host=${device.hostname ?: "unavailable"}; identity=${device.identitySource}; role=${device.role}",
                    riskPoints = points, incidentKey = "lan:${snapshot.networkId}:${device.stableId}",
                    dedupeKey = "lan-mdns:${snapshot.networkId}:${device.stableId}:$serviceType", dedupeMs = 24L * 60L * 60L * 1000L,
                )
            }
        }
    }

    fun recordPortSentinel(hit: PortSentinelHit) {
        val title = when (hit.eventCode) {
            "LAN_PORT_SCAN_DETECTED" -> "LAN port scan detected"
            "LAN_ADB_PROBE_DETECTED" -> "Wireless ADB probe detected"
            "LAN_TELNET_PROBE_DETECTED" -> "Telnet probe detected"
            "LAN_SOCKS_PROBE_DETECTED" -> "SOCKS proxy probe detected"
            "LAN_SSH_ALT_PROBE_DETECTED" -> "Alternate SSH probe detected"
            "LAN_WEB_PROXY_PROBE_DETECTED" -> "Web proxy probe detected"
            else -> "Network exposure connection attempt"
        }
        emit(
            category = XdrCategory.NETWORK, severity = hit.severity, source = "port-sentinel",
            subject = hit.sourceAddress, title = title,
            detail = "code=${hit.eventCode}; source=${hit.sourceAddress}:${hit.sourcePort}; target_port=${hit.targetPort}; protocol=${hit.protocol}; zone=${hit.sourceZone}; blocked=${hit.blockedSource}",
            riskPoints = hit.riskPoints, incidentKey = "network-sentinel:${hit.sourceAddress}",
            dedupeKey = "sentinel:${hit.sourceAddress}:${hit.eventCode}:${hit.targetPort}:${hit.protocol}",
            dedupeMs = if (hit.eventCode == "LAN_PORT_SCAN_DETECTED") 30_000L else 10_000L,
        )
    }

    fun recordPortSentinelIntegrityFailure(reason: String?) {
        recordTrustStoreFailure("port-sentinel", reason)
    }

    fun recordSentinelBlocklistChange(address: String, blocked: Boolean) {
        emit(
            category = XdrCategory.RESPONSE, severity = if (blocked) XdrSeverity.HIGH else XdrSeverity.INFO,
            source = "port-sentinel", subject = address,
            title = if (blocked) "Network source added to Sentinel denylist" else "Network source removed from Sentinel denylist",
            detail = "source=$address; denied=$blocked; scope=sentinel-network; system_kernel_firewall=false",
            riskPoints = if (blocked) 12 else 0, incidentKey = "network-sentinel:$address",
            dedupeKey = "sentinel-deny:$address:$blocked", dedupeMs = 2_000L,
        )
    }

    fun recordPortSentinelStoreReset() {
        emit(
            category = XdrCategory.RESPONSE, severity = XdrSeverity.HIGH, source = "trust-recovery",
            subject = "Port Sentinel state", title = "Port Sentinel state reset",
            detail = "Authenticated Sentinel history and local source denylist were explicitly reinitialized.",
            riskPoints = 8, incidentKey = "integrity:port-sentinel", dedupeKey = "port-sentinel-reset", dedupeMs = 5_000L,
        )
    }

    fun recordNetworkDiscoveryIntegrityFailure(reason: String?) {
        recordTrustStoreFailure("network-discovery", reason)
    }

    fun recordNetworkDiscoveryBaselineReset() {
        emit(
            category = XdrCategory.RESPONSE, severity = XdrSeverity.MEDIUM, source = "trust-recovery",
            subject = "Network discovery baseline", title = "Network discovery baseline reset",
            detail = "The authenticated local-network device baseline was explicitly reinitialized.",
            riskPoints = 4, incidentKey = "integrity:network-discovery",
            dedupeKey = "network-discovery-reset", dedupeMs = 5_000L,
        )
    }

    fun setQuarantined(packageName: String, quarantined: Boolean): Boolean {
        if (packageName.isBlank() || packageName == appContext.packageName || !firewallPolicy.integrityOk()) return false
        if (!firewallPolicy.setQuarantined(packageName, quarantined)) return false
        val nativeGateSynced = NativeGaiaNet.syncPackageEgressQuarantine(firewallPolicy.quarantinedPackages())
        val titanResult = titan.enforceQuarantine(packageName, quarantined)
        val titanDetail = when {
            titanResult.code == "DEVICE_OWNER_INACTIVE" -> "titan=inactive"
            titanResult.ok -> "titan=${titanResult.code.lowercase()}"
            else -> "titan_failed=${titanResult.code.lowercase()}"
        }
        val networkDetail = when {
            !quarantined -> "native_gate_sync=$nativeGateSynced"
            NativeGaiaNet.packageEgressGateActive() -> "full_flow_package_gate=active"
            nativeGateSynced -> "full_flow_package_gate=staged"
            else -> "full_flow_package_gate=recovery_required"
        }
        emit(
            category = XdrCategory.RESPONSE,
            severity = if (quarantined) XdrSeverity.HIGH else XdrSeverity.INFO,
            source = "response-engine",
            subject = packageName,
            title = if (quarantined && titanResult.code == "PACKAGE_SUSPENDED") "TITAN quarantine enforced" else if (quarantined) "Quarantine policy staged" else "Quarantine removed",
            detail = if (quarantined && titanResult.code == "PACKAGE_SUSPENDED") {
                "Package suspension is enforced by Android Device Owner; $networkDetail; $titanDetail."
            } else if (quarantined) {
                "Authenticated quarantine is persisted; active Full Flow enforces new-flow package egress through Android UID attribution; $networkDetail; $titanDetail."
            } else {
                "Quarantine policy was removed; $networkDetail; $titanDetail."
            },
            riskPoints = if (quarantined) 18 else 0,
            incidentKey = "app:$packageName",
            packageName = packageName,
            dedupeKey = "quarantine:$packageName:$quarantined:${titanResult.code}:$nativeGateSynced",
            dedupeMs = 5_000L,
        )
        return true
    }

    fun isQuarantined(packageName: String): Boolean = packageName in firewallPolicy.quarantinedPackages()

    fun recordResilienceFinding(
        component: String,
        state: String,
        action: String,
        repaired: Boolean,
        critical: Boolean,
    ) {
        val safeComponent = sanitizeResilienceCode(component, "component")
        val safeState = sanitizeResilienceCode(state, "state")
        val safeAction = sanitizeResilienceCode(action, "action")
        val severity = when {
            repaired -> XdrSeverity.INFO
            critical -> XdrSeverity.CRITICAL
            else -> XdrSeverity.MEDIUM
        }
        emit(
            category = if (repaired) XdrCategory.RESPONSE else XdrCategory.INTEGRITY,
            severity = severity,
            source = "resilience-supervisor",
            subject = safeComponent,
            title = if (repaired) "Self-healing repair completed" else "Self-healing requires attention",
            detail = "component=$safeComponent; state=$safeState; action=$safeAction; repaired=$repaired",
            riskPoints = when {
                repaired -> 0
                critical -> 86
                else -> 18
            },
            incidentKey = "resilience:$safeComponent",
            dedupeKey = "resilience:$safeComponent:$safeState:$safeAction:$repaired",
            dedupeMs = 5L * 60L * 1000L,
        )
    }

    fun recordPackageQuarantineBlock(owner: String, destination: String, protocol: Int, port: Int) {
        val packageName = owner.substringBefore(',').takeIf { it.contains('.') && !it.startsWith("uid-") && !it.startsWith("uid:") }
        emit(
            category = XdrCategory.RESPONSE,
            severity = XdrSeverity.HIGH,
            source = "package-egress-gate",
            subject = packageName ?: owner.take(120),
            title = "Quarantined application egress blocked",
            detail = "destination=${destination.take(80)}; protocol=$protocol; port=${port.coerceIn(0, 65535)}; owner=${owner.take(256)}",
            riskPoints = 20,
            incidentKey = packageName?.let { "app:$it" } ?: "network:package-egress-gate",
            packageName = packageName,
            dedupeKey = "package-egress:$owner:$destination:$protocol:$port",
            dedupeMs = 60_000L,
            forensicFacts = listOf(
                XdrForensicFact("package_egress_gate", "blocked"),
                XdrForensicFact("destination", destination.take(80)),
                XdrForensicFact("protocol", protocol.toString()),
                XdrForensicFact("port", port.coerceIn(0, 65535).toString()),
            ),
        )
    }

    fun recordTitanLightState(enabled: Boolean) {
        emit(
            category = XdrCategory.SYSTEM, severity = XdrSeverity.INFO, source = "titan-light",
            subject = "TITAN Light", title = if (enabled) "TITAN Light activated" else "TITAN Light disabled",
            detail = "legacy_device_admin=$enabled", riskPoints = 0, incidentKey = "system:titan-light",
            dedupeKey = "titan-light-state:$enabled", dedupeMs = 1_000L,
        )
    }

    fun recordTitanLightPasswordFailure(attempts: Int) {
        val points = when { attempts >= 8 -> 42; attempts >= 5 -> 30; else -> 16 }
        emit(
            category = XdrCategory.SYSTEM, severity = if (points >= 40) XdrSeverity.HIGH else XdrSeverity.MEDIUM, source = "titan-light",
            subject = "Device unlock", title = "Failed unlock attempt observed",
            detail = "failed_attempts=${attempts.coerceAtLeast(0)}", riskPoints = points, incidentKey = "system:titan-light-auth",
            dedupeKey = "titan-light-auth-failed:${attempts.coerceAtLeast(0)}", dedupeMs = 2_000L,
        )
    }

    fun recordTitanLightPasswordSuccess() {
        emit(
            category = XdrCategory.SYSTEM, severity = XdrSeverity.INFO, source = "titan-light",
            subject = "Device unlock", title = "Device unlock succeeded", detail = "unlock_success=true",
            riskPoints = 0, incidentKey = "system:titan-light-auth", dedupeKey = "titan-light-auth-success", dedupeMs = 5_000L,
        )
    }

    fun recordTitanPolicyChange(policy: String, code: String, detail: String = "") {
        emit(
            category = XdrCategory.RESPONSE, severity = XdrSeverity.MEDIUM, source = "titan-dpc",
            subject = "Device Owner policy", title = "TITAN policy changed",
            detail = "policy=${policy.take(120)}; result=${code.take(120)}; detail=${detail.take(220)}",
            riskPoints = 4, incidentKey = "system:titan",
            dedupeKey = "titan-policy:${policy.take(120)}:${code.take(120)}", dedupeMs = 2_000L,
        )
    }

    fun recordTitanPolicyFailure(policy: String, code: String, detail: String = "") {
        emit(
            category = XdrCategory.SYSTEM, severity = XdrSeverity.HIGH, source = "titan-dpc",
            subject = "Device Owner policy", title = "TITAN policy enforcement failed",
            detail = "policy=${policy.take(120)}; result=${code.take(120)}; detail=${detail.take(220)}",
            riskPoints = 28, incidentKey = "system:titan",
            dedupeKey = "titan-failure:${policy.take(120)}:${code.take(120)}", dedupeMs = 5_000L,
        )
    }

    fun recordTitanPackageRemoval(packageName: String, success: Boolean, status: Int, detail: String) {
        emit(
            category = XdrCategory.RESPONSE, severity = if (success) XdrSeverity.HIGH else XdrSeverity.MEDIUM, source = "titan-dpc",
            subject = packageName, title = if (success) "TITAN package removal completed" else "TITAN package removal failed",
            detail = "status=$status; detail=${detail.take(240)}", riskPoints = if (success) 8 else 12,
            incidentKey = "app:$packageName", packageName = packageName,
            dedupeKey = "titan-uninstall:$packageName:$success:$status", dedupeMs = 2_000L,
        )
    }

    fun recordAppApproval(packageName: String, approved: Boolean, signerSha256: String?) {
        emit(
            category = XdrCategory.RESPONSE,
            severity = XdrSeverity.INFO,
            source = "user-trust",
            subject = packageName,
            title = if (approved) "Application capability baseline approved" else "Application approval revoked",
            detail = "approved=$approved; signer=${signerSha256?.take(128) ?: "unknown"}",
            riskPoints = 0,
            incidentKey = "app:$packageName",
            packageName = packageName,
            dedupeKey = "approval:$packageName:$approved:${signerSha256?.take(32)}",
            dedupeMs = 1_000L,
        )
    }

    fun recoverXdrEventStore(): XdrEventStore.RecoveryArchive? {
        val recovered = store.recoverCorruptStore() ?: return null
        emit(
            category = XdrCategory.RESPONSE,
            severity = XdrSeverity.HIGH,
            source = "trust-recovery",
            subject = "XDR local event store",
            title = "Corrupt XDR store recovered",
            detail = if (recovered.fileName != null && recovered.sha256 != null) {
                "archive=${recovered.fileName}; sha256=${recovered.sha256}"
            } else {
                "Corrupt XDR state was reset after authentication failure; a forensic archive could not be retained."
            },
            riskPoints = 12,
            incidentKey = "integrity:xdr-store",
            dedupeKey = "xdr-store-recovered:${recovered.sha256 ?: "no-archive"}",
            dedupeMs = 0L,
        )
        return recovered
    }

    fun resetPackageBaseline(): Boolean {
        if (!baselines.resetTrustedBaseline()) return false
        emit(
            category = XdrCategory.RESPONSE, severity = XdrSeverity.MEDIUM, source = "trust-recovery",
            subject = "Package trust baseline", title = "Package baseline re-established",
            detail = "The package signer/permission baseline was explicitly rebuilt from the currently installed package state.",
            riskPoints = 6, incidentKey = "integrity:package-baseline", dedupeKey = "package-baseline-reset", dedupeMs = 5_000L,
        )
        return true
    }

    fun resetFirewallPolicy(): Boolean {
        if (!firewallPolicy.resetPolicy()) return false
        emit(
            category = XdrCategory.RESPONSE, severity = XdrSeverity.HIGH, source = "trust-recovery",
            subject = "Firewall policy", title = "Firewall policy reset",
            detail = "Authenticated firewall state was reinitialized with an empty allowlist and quarantine set. Lockdown therefore defaults to deny.",
            riskPoints = 10, incidentKey = "integrity:firewall-policy", dedupeKey = "firewall-policy-reset", dedupeMs = 5_000L,
        )
        return true
    }

    fun recordEmergencyLockdown() {
        emit(
            category = XdrCategory.RESPONSE, severity = XdrSeverity.HIGH, source = "response-engine",
            subject = "local-device", title = "Emergency Lockdown activated",
            detail = "Default-deny network policy requested from the XDR Security Center.", riskPoints = 12,
            incidentKey = "response:lockdown", dedupeKey = "response:lockdown", dedupeMs = 10_000L,
        )
    }

    private fun ingestPackageChange(change: PackageBaselineStore.Change) {
        val pkg = change.packageName
        when {
            change.old == null && change.current != null -> emit(
                XdrCategory.PACKAGE, XdrSeverity.LOW, "package-monitor", pkg,
                "New application installed", "version=${change.current.versionCode}", 8,
                "app:$pkg", pkg, "install:$pkg:${change.current.versionCode}", 60_000L,
            )
            change.old != null && change.current == null -> emit(
                XdrCategory.PACKAGE, XdrSeverity.INFO, "package-monitor", pkg,
                "Application removed", "last_version=${change.old.versionCode}", 0,
                "app:$pkg", pkg, "remove:$pkg:${change.old.versionCode}", 60_000L,
            )
            change.old != null && change.current != null -> emit(
                XdrCategory.PACKAGE, XdrSeverity.INFO, "package-monitor", pkg,
                "Application changed", "version=${change.old.versionCode}->${change.current.versionCode}", 2,
                "app:$pkg", pkg, "update:$pkg:${change.current.versionCode}", 60_000L,
            )
        }
        if (change.signerChanged) {
            // Replace any stale signer-only event before recording the new disposition. Legitimate
            // APK Signature Scheme v3 proof-of-rotation must not remain as a historic 100/100 alert.
            store.removeEvents("signer:$pkg:", "package-monitor")
            when {
                change.signerRotationTrusted -> emit(
                    XdrCategory.SIGNER, XdrSeverity.INFO, "package-monitor", pkg,
                    "Signing certificate rotation verified",
                    "Android reports a verified signing-certificate lineage containing the previous signer.", 0,
                    "app:$pkg", pkg, "signer:$pkg:${change.current?.signerSha256}:verified-rotation", 24L * 60L * 60L * 1000L,
                )
                change.signerChangeReviewOnly -> emit(
                    XdrCategory.SIGNER, XdrSeverity.MEDIUM, "package-monitor", pkg,
                    "System package signer transition",
                    "A system or updated-system package changed signer outside the legacy baseline. Treat as context and rely on package verification plus device integrity signals for escalation.", 14,
                    "app:$pkg", pkg, "signer:$pkg:${change.current?.signerSha256}:system-review", 24L * 60L * 60L * 1000L,
                )
                else -> emit(
                    XdrCategory.SIGNER, XdrSeverity.CRITICAL, "package-monitor", pkg,
                    "Signing certificate changed", "The package signer differs from the previous baseline without a verified rotation lineage.", 88,
                    "app:$pkg", pkg, "signer:$pkg:${change.current?.signerSha256}", 24L * 60L * 60L * 1000L,
                )
            }
        }
        val sensitiveRequested = change.newlyRequested.filterTo(linkedSetOf()) { it in SENSITIVE_PERMISSIONS }
        if (sensitiveRequested.isNotEmpty()) {
            val score = (18 + sensitiveRequested.size * 5).coerceAtMost(45)
            emit(
                XdrCategory.PERMISSION, if (score >= 35) XdrSeverity.HIGH else XdrSeverity.MEDIUM, "package-monitor", pkg,
                "Sensitive permission drift", "new_requested=${sensitiveRequested.joinToString(",").take(700)}", score,
                "app:$pkg", pkg, "permreq:$pkg:${sensitiveRequested.sorted().joinToString(",")}", 60L * 60L * 1000L,
            )
        }
        val sensitiveGranted = change.newlyGranted.filterTo(linkedSetOf()) { it in SENSITIVE_PERMISSIONS }
        if (sensitiveGranted.isNotEmpty()) {
            val score = (22 + sensitiveGranted.size * 6).coerceAtMost(50)
            emit(
                XdrCategory.PERMISSION, if (score >= 35) XdrSeverity.HIGH else XdrSeverity.MEDIUM, "package-monitor", pkg,
                "Sensitive permission granted", "new_granted=${sensitiveGranted.joinToString(",").take(700)}", score,
                "app:$pkg", pkg, "permgrant:$pkg:${sensitiveGranted.sorted().joinToString(",")}", 60L * 60L * 1000L,
            )
        }
        if (change.newCapabilities.isNotEmpty()) {
            val critical = change.newCapabilities.any { it in HIGH_RISK_CAPABILITIES }
            emit(
                XdrCategory.PERMISSION, if (critical) XdrSeverity.HIGH else XdrSeverity.MEDIUM, "package-monitor", pkg,
                "New privileged capability", "new_capabilities=${change.newCapabilities.sorted().joinToString(",")}",
                if (critical) 38 else 24, "app:$pkg", pkg,
                "cap:$pkg:${change.newCapabilities.sorted().joinToString(",")}", 60L * 60L * 1000L,
            )
        }
    }

    private fun pruneTrustedSignerEvents() {
        if (!store.integrityOk() || !baselines.integrityOk()) return
        val packages = store.snapshot(512).events.asSequence()
            .filter { it.source == "package-monitor" && it.category == XdrCategory.SIGNER }
            .mapNotNull { it.packageName }
            .distinct()
            .take(64)
            .toList()
        packages.forEach { pkg ->
            val context = baselines.currentSignerContext(pkg) ?: return@forEach
            if (context.verifiedRotationLineage || context.systemPackage) {
                store.removeEvents("signer:$pkg:", "package-monitor")
            }
        }
    }

    private fun incidentVisible(incident: XdrIncident, allEvents: List<XdrEvent>): Boolean {
        if (incident.score < INCIDENT_VISIBILITY_THRESHOLD) return false
        val pkg = incident.packageName ?: return true
        val events = allEvents.filter { it.incidentKey == incident.key }
        val approval = approvals.currentStatus(pkg)
        val approvedAt = approvals.approvedAt(pkg) ?: 0L
        val strongScanner = events.any { event ->
            event.source == "app-scanner" && event.forensicFacts.any { it.key == "threat_matches" && it.value.isNotBlank() }
        }
        val observed = events.any { event ->
            val afterApproval = approvedAt <= 0L || event.atMillis > approvedAt
            afterApproval && when (event.category) {
                XdrCategory.BEHAVIOR, XdrCategory.NETWORK, XdrCategory.SIGNER, XdrCategory.INTEGRITY -> event.riskPoints >= 20
                XdrCategory.PACKAGE, XdrCategory.PERMISSION -> event.severity == XdrSeverity.HIGH || event.severity == XdrSeverity.CRITICAL
                else -> false
            }
        }
        if (approval == AppApprovalState.APPROVED && !strongScanner && !observed) return false
        // Capability-only scanner context is intentionally retained in the authenticated event store
        // but does not become a user-facing incident until corroborated by independent evidence.
        val hasIndependentEvidence = events.any { it.source != "app-scanner" && it.category != XdrCategory.RESPONSE }
        return strongScanner || hasIndependentEvidence
    }

    private fun sanitizeResilienceCode(value: String, fallback: String): String {
        val cleaned = value.asSequence()
            .map { character -> if (character.isLetterOrDigit() || character == '-' || character == '_') character.lowercaseChar() else '_' }
            .joinToString("")
            .take(64)
        return cleaned.ifBlank { fallback }
    }

    private fun recordTrustStoreFailure(storeName: String, reason: String?) {
        emit(
            category = XdrCategory.INTEGRITY,
            severity = XdrSeverity.CRITICAL,
            source = "trust-store",
            subject = storeName,
            title = "Authenticated security state degraded",
            detail = "store=$storeName; reason=${reason?.take(160) ?: "unknown"}",
            riskPoints = 92,
            incidentKey = "integrity:$storeName",
            dedupeKey = "trust-store:$storeName:${reason?.take(80)}",
            dedupeMs = 30L * 60L * 1000L,
        )
    }

    private fun emit(
        category: XdrCategory,
        severity: XdrSeverity,
        source: String,
        subject: String,
        title: String,
        detail: String,
        riskPoints: Int,
        incidentKey: String,
        packageName: String? = null,
        dedupeKey: String = "",
        dedupeMs: Long = 0L,
        detectorScore: Int? = null,
        forensicReasons: List<XdrForensicReason> = emptyList(),
        forensicFacts: List<XdrForensicFact> = emptyList(),
    ): Boolean {
        if (!store.integrityOk()) return false
        if (dedupeMs > 0L && store.hasRecent(dedupeKey, dedupeMs)) return false
        val event = XdrEvent(
            id = store.newId(), atMillis = System.currentTimeMillis(), category = category,
            severity = severity, source = source, subject = subject.take(256), title = title.take(160),
            detail = detail.take(1200), riskPoints = riskPoints.coerceIn(0, 100), incidentKey = incidentKey.take(256),
            packageName = packageName?.take(256), dedupeKey = dedupeKey.take(300),
            detectorScore = detectorScore?.coerceIn(0, 100), forensicReasons = forensicReasons, forensicFacts = forensicFacts,
        )
        try {
            store.append(event)
        } catch (error: Exception) {
            reportXdrPersistenceFailure("event_write_failed", error)
            return false
        }
        try {
            evidence.append(EvidenceEvent("xdr.${category.name.lowercase()}", severity.name.lowercase(), event.subject,
                "title=${event.title}; risk=${event.riskPoints}; source=${event.source}; ${event.detail}".take(1900)))
        } catch (error: Exception) {
            reportEvidencePersistenceFailure(error)
        }
        return true
    }

    private fun reportXdrPersistenceFailure(code: String, error: Throwable) {
        try {
            runtimeState.recordXdrPersistenceFailure(code)
        } catch (stateError: RuntimeException) {
            RuntimeFailureLog.nonCritical("xdr-state-report", stateError)
        }
        RuntimeFailureLog.nonCritical("xdr-event-store", error)
    }

    private fun reportEvidencePersistenceFailure(error: Throwable) {
        try {
            runtimeState.recordEvidencePersistenceFailure(EvidenceWriteFailureClassifier.code(error))
        } catch (stateError: RuntimeException) {
            RuntimeFailureLog.nonCritical("xdr-evidence-state-report", stateError)
        }
        RuntimeFailureLog.nonCritical("xdr-evidence", error)
    }

    private fun pruneQuarantine() {
        if (!firewallPolicy.integrityOk()) return
        val installed = firewallPolicy.installedPackageNames() ?: return
        var changed = false
        firewallPolicy.quarantinedPackages().filterNot { it in installed }.forEach {
            if (firewallPolicy.setQuarantined(it, false)) changed = true
        }
        if (changed) NativeGaiaNet.syncPackageEgressQuarantine(firewallPolicy.quarantinedPackages())
    }

    companion object {
        private const val INCIDENT_VISIBILITY_THRESHOLD = 35
        private val SENSITIVE_PERMISSIONS = setOf(
            android.Manifest.permission.RECORD_AUDIO,
            android.Manifest.permission.CAMERA,
            android.Manifest.permission.ACCESS_FINE_LOCATION,
            android.Manifest.permission.READ_CONTACTS,
            android.Manifest.permission.WRITE_CONTACTS,
            android.Manifest.permission.READ_CALL_LOG,
            android.Manifest.permission.WRITE_CALL_LOG,
            android.Manifest.permission.READ_SMS,
            android.Manifest.permission.RECEIVE_SMS,
            android.Manifest.permission.SEND_SMS,
            android.Manifest.permission.REQUEST_INSTALL_PACKAGES,
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
        )
        private val HIGH_RISK_CAPABILITIES = setOf("ACCESSIBILITY_SERVICE", "DEVICE_ADMIN", "PACKAGE_INSTALLER", "OVERLAY")
        private val HIGH_RISK_LAN_PORTS = setOf(23, 3389, 5555, 5900)
        private val HIGH_RISK_DNS_SD_SERVICES = setOf(
            "_adb-tls-connect._tcp.local", "_adb-tls-pairing._tcp.local", "_telnet._tcp.local",
            "_rdp._tcp.local", "_rfb._tcp.local", "_smb._tcp.local", "_afpovertcp._tcp.local", "_ssh._tcp.local",
        )
    }
}
