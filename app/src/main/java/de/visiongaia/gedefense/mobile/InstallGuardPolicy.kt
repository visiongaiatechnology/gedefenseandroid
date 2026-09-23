package de.visiongaia.gedefense.mobile

// STATUS: PLATIN
enum class InstallFastRisk { LOW, REVIEW, HIGH, SEVERE }
enum class InstallFastVerdict { RELEASE_PENDING_DEEP, HOLD_FOR_DEEP, BLOCK }

data class InstallFastPolicyInput(
    val resultAvailable: Boolean,
    val blockThreat: Boolean,
    val correlateThreat: Boolean,
    val signerAvailable: Boolean,
    val signerContinuity: Boolean,
    val approvalStale: Boolean,
    val risk: InstallFastRisk,
)

/** Pure local policy for the stage-1 install/update verdict. */
object InstallGuardPolicy {
    fun fastVerdict(input: InstallFastPolicyInput): InstallFastVerdict {
        if (!input.resultAvailable) return InstallFastVerdict.HOLD_FOR_DEEP
        if (input.blockThreat || input.risk == InstallFastRisk.SEVERE) return InstallFastVerdict.BLOCK
        if (!input.signerAvailable || !input.signerContinuity || input.correlateThreat ||
            input.risk == InstallFastRisk.HIGH || input.risk == InstallFastRisk.REVIEW || input.approvalStale
        ) return InstallFastVerdict.HOLD_FOR_DEEP
        return InstallFastVerdict.RELEASE_PENDING_DEEP
    }
}
