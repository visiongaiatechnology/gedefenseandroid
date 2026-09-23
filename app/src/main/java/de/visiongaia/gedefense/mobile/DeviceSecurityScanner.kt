package de.visiongaia.gedefense.mobile

import de.visiongaia.gedefense.mobile.core.ThreatIndex

enum class DeviceScanPhase { IDLE, INTEGRITY, APPS, STORAGE, FINALIZING, COMPLETE, FAILED, CANCELLED }

data class DeviceScanProgress(
    val phase: DeviceScanPhase,
    val fraction: Float,
    val processed: Int,
    val total: Int,
    val current: String,
    val findings: Int,
)

data class DeviceScanSnapshot(
    val state: String,
    val startedAtMillis: Long,
    val completedAtMillis: Long,
    val progress: DeviceScanProgress,
    val integrity: IntegritySnapshot,
    val apps: AppScanSnapshot,
    val storage: StorageScanSnapshot,
) {
    companion object {
        fun idle() = DeviceScanSnapshot(
            state = "IDLE",
            startedAtMillis = 0L,
            completedAtMillis = 0L,
            progress = DeviceScanProgress(DeviceScanPhase.IDLE, 0f, 0, 0, "", 0),
            integrity = IntegritySnapshot.pending(),
            apps = AppScanSnapshot.idle(),
            storage = StorageScanSnapshot.idle(),
        )
    }
}

/**
 * Orchestrates the local scanner as four independent evidence phases. No phase can silently grant a
 * malware verdict: app/file heuristics are review signals, while integrity failure remains a hard
 * security condition for GeDefense itself.
 */
class DeviceSecurityScanner(
    private val integrity: IntegrityGuardian,
    private val apps: AppRiskScanner,
    private val storage: StorageMalwareScanner,
) {
    fun scan(
        index: ThreatIndex,
        cancelled: () -> Boolean,
        onProgress: (DeviceScanProgress) -> Unit,
    ): DeviceScanSnapshot {
        val started = System.currentTimeMillis()
        fun cancelledCheck() {
            if (cancelled() || Thread.currentThread().isInterrupted) throw InterruptedException("device scan cancelled")
        }
        return try {
            onProgress(DeviceScanProgress(DeviceScanPhase.INTEGRITY, 0.02f, 0, 1, "Integrity Guard", 0))
            cancelledCheck()
            val integrityResult = integrity.scan(cancelled)
            val integrityFindings = integrityResult.issues.size
            onProgress(DeviceScanProgress(DeviceScanPhase.INTEGRITY, 0.08f, 1, 1, "Integrity Guard", integrityFindings))

            cancelledCheck()
            // Publish the phase transition before entering AppRiskScanner.scan(). A concurrent
            // app-analysis must never make the UI look as though Integrity Guard itself is hung.
            onProgress(DeviceScanProgress(DeviceScanPhase.APPS, 0.10f, 0, 0, "", integrityFindings))
            val appResult = apps.scan(
                index = index,
                cancelled = cancelled,
                onProgress = { processed, total, label ->
                    val local = if (total <= 0) 0f else processed.toFloat() / total.toFloat()
                    onProgress(DeviceScanProgress(
                        DeviceScanPhase.APPS,
                        0.10f + (local * 0.47f),
                        processed,
                        total,
                        label,
                        integrityFindings,
                    ))
                },
            )
            val appFindings = appResult.results.count { it.riskLevel != AppRiskLevel.LOW }

            cancelledCheck()
            val storageResult = storage.scan(
                index = index,
                cancelled = cancelled,
                onProgress = { processed, total, current ->
                    val local = if (total <= 0) 0f else processed.toFloat() / total.toFloat()
                    onProgress(DeviceScanProgress(
                        DeviceScanPhase.STORAGE,
                        0.58f + (local * 0.36f),
                        processed,
                        total,
                        current,
                        integrityFindings + appFindings,
                    ))
                },
            )
            val fileFindings = storageResult.results.size

            cancelledCheck()
            onProgress(DeviceScanProgress(
                DeviceScanPhase.FINALIZING,
                0.97f,
                1,
                1,
                "Evidence correlation",
                integrityFindings + appFindings + fileFindings,
            ))
            val completed = System.currentTimeMillis()
            val finalProgress = DeviceScanProgress(
                DeviceScanPhase.COMPLETE,
                1f,
                1,
                1,
                "",
                integrityFindings + appFindings + fileFindings,
            )
            onProgress(finalProgress)
            DeviceScanSnapshot(
                state = "COMPLETE",
                startedAtMillis = started,
                completedAtMillis = completed,
                progress = finalProgress,
                integrity = integrityResult,
                apps = appResult,
                storage = storageResult,
            )
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            DeviceScanSnapshot(
                state = "CANCELLED",
                startedAtMillis = started,
                completedAtMillis = System.currentTimeMillis(),
                progress = DeviceScanProgress(DeviceScanPhase.CANCELLED, 0f, 0, 0, "", 0),
                integrity = IntegritySnapshot.pending(),
                apps = AppScanSnapshot.idle(),
                storage = StorageScanSnapshot.idle(),
            )
        } catch (_: Throwable) {
            DeviceScanSnapshot(
                state = "FAILED",
                startedAtMillis = started,
                completedAtMillis = System.currentTimeMillis(),
                progress = DeviceScanProgress(DeviceScanPhase.FAILED, 0f, 0, 0, "", 0),
                integrity = IntegritySnapshot.pending(),
                apps = AppScanSnapshot.idle(),
                storage = StorageScanSnapshot.idle(),
            )
        }
    }
}
