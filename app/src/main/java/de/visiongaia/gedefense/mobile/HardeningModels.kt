package de.visiongaia.gedefense.mobile

enum class HardeningSeverity { INFO, LOW, MEDIUM, HIGH, CRITICAL }
enum class HardeningStatus { PASS, REVIEW, FAIL, UNKNOWN }
enum class HardeningCategory { LOCKSCREEN, PATCHING, PLATFORM, DEBUGGING, PRIVILEGED_ACCESS, NETWORK, ENCRYPTION }

data class HardeningFinding(
    val id: String,
    val category: HardeningCategory,
    val status: HardeningStatus,
    val severity: HardeningSeverity,
    val title: String,
    val summary: String,
    val evidence: String,
    val remediation: String,
    val pointsLost: Int,
    val settingsAction: String? = null,
)

data class HardeningSnapshot(
    val checkedAtMillis: Long,
    val score: Int,
    val findings: List<HardeningFinding>,
) {
    val failed: Int get() = findings.count { it.status == HardeningStatus.FAIL }
    val review: Int get() = findings.count { it.status == HardeningStatus.REVIEW }
    val critical: Int get() = findings.count { it.severity == HardeningSeverity.CRITICAL && it.status == HardeningStatus.FAIL }
    val high: Int get() = findings.count { it.severity == HardeningSeverity.HIGH && it.status == HardeningStatus.FAIL }
    val passed: Int get() = findings.count { it.status == HardeningStatus.PASS }

    companion object {
        fun pending() = HardeningSnapshot(0L, 0, emptyList())
    }
}
