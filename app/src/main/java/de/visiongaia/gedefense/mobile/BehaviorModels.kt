package de.visiongaia.gedefense.mobile

enum class BehaviorAnomalyType {
    POTENTIAL_EXFILTRATION,
    TRAFFIC_SPIKE,
    EGRESS_RATIO_SHIFT,
    CONNECTION_FANOUT,
    NEW_DESTINATION_BURST,
    NEW_COUNTRY,
    OFF_HOURS_ACTIVITY,
}

data class BehaviorProfile(
    val packageName: String,
    val label: String,
    val observations: Int,
    val firstSeenMillis: Long,
    val lastSeenMillis: Long,
    val avgTxPerMinute: Long,
    val avgRxPerMinute: Long,
    val avgTotalPerMinute: Long,
    val peakTxPerMinute: Long,
    val peakTotalPerMinute: Long,
    val txDeviationPerMinute: Long,
    val totalDeviationPerMinute: Long,
    val avgUploadRatioPermille: Int,
    val avgFlowsPerMinute: Long,
    val flowDeviationPerMinute: Long,
    val avgDomainCardinality: Int,
    val avgCountryCardinality: Int,
    val knownDomains: Set<String>,
    val knownCountries: Set<String>,
    val pendingDomains: Map<String, Int>,
    val pendingCountries: Map<String, Int>,
    val hourHistogram: List<Int>,
    val anomalyCount: Int,
    val lastAnomalyAtMillis: Long,
) {
    val mature: Boolean get() = observations >= 5
    val learningConfidence: Int get() = (50 + observations.coerceAtMost(20) * 2).coerceIn(50, 90)
}

data class BehaviorAnomaly(
    val packageName: String,
    val label: String,
    val type: BehaviorAnomalyType,
    val severity: XdrSeverity,
    val riskPoints: Int,
    val confidence: Int,
    val baselineObservations: Int,
    val title: String,
    val detail: String,
    val fingerprint: String,
    val atMillis: Long,
)

data class BehaviorSnapshot(
    val generatedAtMillis: Long,
    val profiles: List<BehaviorProfile>,
    val autoQuarantineCritical: Boolean,
    val baselineIntegrityOk: Boolean,
) {
    val matureProfiles: Int get() = profiles.count { it.mature }
    val learningProfiles: Int get() = profiles.count { !it.mature }
    val anomalyCount: Int get() = profiles.sumOf { it.anomalyCount }
}
