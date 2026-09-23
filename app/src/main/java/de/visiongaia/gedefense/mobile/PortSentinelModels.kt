package de.visiongaia.gedefense.mobile

// STATUS: DIAMANT VGT SUPREME

enum class SentinelProtocol { TCP, UDP }

data class PortSentinelHit(
    val id: String,
    val atMillis: Long,
    val sourceAddress: String,
    val sourcePort: Int,
    val targetPort: Int,
    val protocol: SentinelProtocol,
    val sourceZone: String,
    val severity: XdrSeverity,
    val eventCode: String,
    val riskPoints: Int,
    val blockedSource: Boolean,
)

data class PortSentinelRuntimeState(
    val active: Boolean,
    val listenerCount: Int,
    val localAddresses: List<String>,
    val transport: String,
    val lastError: String? = null,
) {
    companion object { fun standby() = PortSentinelRuntimeState(false, 0, emptyList(), "NONE") }
}

data class PortSentinelSnapshot(
    val generatedAtMillis: Long,
    val runtime: PortSentinelRuntimeState,
    val hits: List<PortSentinelHit>,
    val blockedSources: Set<String>,
    val integrityOk: Boolean,
    val integrityFailureReason: String?,
) {
    val criticalHits: Int get() = hits.count { it.severity == XdrSeverity.CRITICAL }
    val uniqueSources: Int get() = hits.asSequence().map { it.sourceAddress }.distinct().count()
}
