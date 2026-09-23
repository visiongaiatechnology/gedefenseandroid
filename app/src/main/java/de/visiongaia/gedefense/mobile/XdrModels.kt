package de.visiongaia.gedefense.mobile

enum class XdrSeverity { INFO, LOW, MEDIUM, HIGH, CRITICAL }
enum class XdrCategory { PACKAGE, PERMISSION, SIGNER, NETWORK, BEHAVIOR, MALWARE, INTEGRITY, RESPONSE, SYSTEM }

data class XdrForensicReason(
    val code: String,
    val points: Int,
    val detail: String = "",
)

data class XdrForensicFact(
    val key: String,
    val value: String,
)

data class XdrEvent(
    val id: String,
    val atMillis: Long,
    val category: XdrCategory,
    val severity: XdrSeverity,
    val source: String,
    val subject: String,
    val title: String,
    val detail: String,
    val riskPoints: Int,
    val incidentKey: String,
    val packageName: String? = null,
    val dedupeKey: String = "",
    val detectorScore: Int? = null,
    val forensicReasons: List<XdrForensicReason> = emptyList(),
    val forensicFacts: List<XdrForensicFact> = emptyList(),
)

data class XdrIncident(
    val key: String,
    val subject: String,
    val packageName: String?,
    val score: Int,
    val severity: XdrSeverity,
    val eventCount: Int,
    val categories: Set<XdrCategory>,
    val firstSeenMillis: Long,
    val lastSeenMillis: Long,
    val summary: String,
)

data class XdrScoreBreakdown(
    val eventPoints: Int,
    val categoryBonus: Int,
    val criticalBonus: Int,
    val volumeBonus: Int,
    val unclampedScore: Int,
    val finalScore: Int,
    val countedEventIds: Set<String>,
)

data class XdrSnapshot(
    val generatedAtMillis: Long,
    val events: List<XdrEvent>,
    val incidents: List<XdrIncident>,
    val quarantinedPackages: Set<String>,
    val eventStoreIntegrityOk: Boolean,
    val packageBaselineIntegrityOk: Boolean,
    val firewallPolicyIntegrityOk: Boolean,
    val networkDiscoveryIntegrityOk: Boolean,
    val portSentinelIntegrityOk: Boolean,
    val titanPolicyIntegrityOk: Boolean,
) {
    val criticalIncidents: Int get() = incidents.count { it.severity == XdrSeverity.CRITICAL }
    val highIncidents: Int get() = incidents.count { it.severity == XdrSeverity.HIGH }
    val trustStoresHealthy: Boolean get() = eventStoreIntegrityOk && packageBaselineIntegrityOk && firewallPolicyIntegrityOk && networkDiscoveryIntegrityOk && portSentinelIntegrityOk && titanPolicyIntegrityOk
}

fun xdrScoreBreakdown(events: List<XdrEvent>): XdrScoreBreakdown {
    if (events.isEmpty()) return XdrScoreBreakdown(0, 0, 0, 0, 0, 0, emptySet())

    // Collapse recurring observations into independent signal families. A scanner capability finding
    // must never gain authority merely because the same scan ran repeatedly. RESPONSE events are
    // audit evidence and do not increase threat risk.
    val riskEvents = events.filter { it.category != XdrCategory.RESPONSE }
    val uniqueSignals = riskEvents.groupBy { event ->
        val family = signalFamily(event)
        // Scanner capability observations are one static-analysis signal regardless of how many
        // underlying permission rules fired. Other families retain a bounded subtype key so a
        // signer change and an install event are not collapsed into the same observation.
        when (family) {
            "static-analysis" -> family
            else -> "$family:${event.category}:${event.title}"
        }
    }.values.mapNotNull { group -> group.maxByOrNull { effectiveEventPoints(it) } }

    val counted = uniqueSignals
        .sortedByDescending(::effectiveEventPoints)
        .take(8)
    val eventPoints = counted.sumOf(::effectiveEventPoints)
    val independentFamilies = counted.mapTo(linkedSetOf()) { signalFamily(it) }.size
    val categories = counted.mapTo(linkedSetOf()) { it.category }
    val categoryBonus = (((categories.size - 1).coerceAtLeast(0)) * 4).coerceAtMost(16)
    val criticalBonus = if (counted.any { event ->
            ((event.source != "app-scanner" && event.severity == XdrSeverity.CRITICAL) || scannerHasStrongEvidence(event)) &&
                (independentFamilies >= 2 || effectiveEventPoints(event) >= 80)
        }) 8 else 0
    // Bonus reflects genuinely independent detector families, not multiple emitters from the same
    // subsystem. This avoids turning several network observations into fake multi-sensor certainty.
    val volumeBonus = when { independentFamilies >= 4 -> 8; independentFamilies >= 3 -> 6; independentFamilies >= 2 -> 3; else -> 0 }
    val raw = eventPoints + categoryBonus + criticalBonus + volumeBonus
    return XdrScoreBreakdown(
        eventPoints = eventPoints,
        categoryBonus = categoryBonus,
        criticalBonus = criticalBonus,
        volumeBonus = volumeBonus,
        unclampedScore = raw,
        finalScore = raw.coerceIn(0, 100),
        countedEventIds = counted.mapTo(linkedSetOf()) { it.id },
    )
}


private fun signalFamily(event: XdrEvent): String = when {
    event.source == "app-scanner" -> "static-analysis"
    event.source == "storage-scanner" -> "file-analysis"
    event.source == "behavior-engine" -> "behavior"
    event.source == "gaianet" -> "network-ti"
    event.source.startsWith("lan-") -> "lan-observation"
    event.source == "port-sentinel" -> "network-exposure"
    event.source == "package-monitor" && event.category == XdrCategory.SIGNER -> "package-signer"
    event.source == "package-monitor" -> "package-state"
    event.source == "integrity" || event.source == "trust-store" -> "integrity"
    event.source.startsWith("titan") -> "device-policy"
    else -> "${event.category.name.lowercase()}:${event.source}"
}

private fun effectiveEventPoints(event: XdrEvent): Int {
    if (event.category == XdrCategory.RESPONSE) return 0
    if (event.source != "app-scanner") return event.riskPoints.coerceIn(0, 100)
    if (scannerHasStrongEvidence(event)) return event.riskPoints.coerceIn(0, 100)
    // Capability-only scanner evidence is context. It helps corroborate an observed anomaly but can
    // never create a critical incident on its own.
    return event.riskPoints.coerceIn(0, 24)
}

private fun scannerHasStrongEvidence(event: XdrEvent): Boolean =
    event.source == "app-scanner" && event.forensicFacts.any { fact ->
        fact.key == "threat_matches" && fact.value.isNotBlank()
    }

fun xdrSeverityForScore(score: Int): XdrSeverity = when {
    score >= 80 -> XdrSeverity.CRITICAL
    score >= 60 -> XdrSeverity.HIGH
    score >= 35 -> XdrSeverity.MEDIUM
    score >= 15 -> XdrSeverity.LOW
    else -> XdrSeverity.INFO
}
