package de.visiongaia.gedefense.mobile

enum class TitanTier { STANDARD, LIGHT, FULL }

data class TitanSnapshot(
    val isDeviceOwner: Boolean,
    val adminActive: Boolean,
    val policyStoreIntegrityOk: Boolean,
    val policyStoreFailureReason: String?,
    val alwaysOnVpn: Boolean,
    val alwaysOnLockdown: Boolean,
    val debuggingBlocked: Boolean,
    val unknownSourcesBlocked: Boolean,
    val safeBootBlocked: Boolean,
    val usbFileTransferBlocked: Boolean,
    val verifyAppsEnforced: Boolean,
    val highPasswordComplexityRequired: Boolean,
    val wipeAfterFailedAttempts: Int,
    val autoSuspendOnQuarantine: Boolean,
    val managedCaCount: Int,
    val maxTimeToLockMillis: Long = 0L,
    val platformQueryOk: Boolean = true,
    val platformFailureReason: String? = null,
) {
    val titanActive: Boolean get() = isDeviceOwner && adminActive
    val titanLightActive: Boolean get() = adminActive && !isDeviceOwner
    val tier: TitanTier get() = when { titanActive -> TitanTier.FULL; titanLightActive -> TitanTier.LIGHT; else -> TitanTier.STANDARD }
}

data class TitanActionResult(
    val ok: Boolean,
    val code: String,
    val detail: String = "",
    val changed: Boolean = false,
)


data class TitanCaCertificateInfo(
    val subject: String,
    val issuer: String,
    val sha256Fingerprint: String,
    val notAfterMillis: Long,
)
