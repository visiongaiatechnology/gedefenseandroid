package de.visiongaia.gedefense.mobile

/**
 * Process-local result of the threat-policy diagnostic.
 *
 * The test performs no network egress. While Full Flow is guarded it takes the same immutable
 * ThreatIndex used to build GaiaNet's active policy, selects a real ROUTE_BLOCK route, verifies
 * the production Kotlin matcher/block authority and route coverage, then serializes the index
 * through the exact GDTI policy writer used at GaiaNet startup and validates that header locally.
 *
 * This deliberately does not increment production block counters and does not claim to validate
 * third-party app/TUN capture. That boundary remains a separate real-device test.
 */
data class ThreatEnforcementSelfTestSnapshot(
    val state: String,
    val sequence: Int,
    val startedAtMillis: Long,
    val completedAtMillis: Long,
    val target: String?,
    val feeds: List<String>,
    val reason: String?,
) {
    companion object {
        fun idle() = ThreatEnforcementSelfTestSnapshot(
            state = "IDLE",
            sequence = 0,
            startedAtMillis = 0L,
            completedAtMillis = 0L,
            target = null,
            feeds = emptyList(),
            reason = null,
        )
    }
}
