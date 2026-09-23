package de.visiongaia.gedefense.mobile

import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

// STATUS: PLATIN
/**
 * Hard wall-clock budgets for install/update protection.
 *
 * Fast verdicts and deep scans intentionally use separate fixed daemon pools so a stuck OEM
 * PackageManager/AppOps/Binder call in a deep inspection cannot starve new fast verdicts. Both
 * pools use a zero-capacity queue: saturation is surfaced as an explicit fail-closed condition,
 * never converted into an implicit clean verdict.
 *
 * Cancellation is best-effort because Binder implementations may ignore interruption. A timed-out
 * worker may therefore remain occupied, but the fixed pool bounds the blast radius.
 */
object BoundedInstallScanCall {
    const val FAST_TIMEOUT_MS = 1_750L
    const val DEEP_TIMEOUT_MS = 25_000L

    private val fastExecutor = executor("gedefense-install-fast", 4)
    private val deepExecutor = executor("gedefense-install-deep", 2)

    fun <T> fast(action: () -> T): T = call(
        executor = fastExecutor,
        timeoutMillis = FAST_TIMEOUT_MS,
        timeoutReason = "install_fast_timeout",
        capacityReason = "install_fast_capacity_exhausted",
        failureReason = "install_fast_failed",
        action = action,
    )

    fun <T> deep(action: () -> T): T = call(
        executor = deepExecutor,
        timeoutMillis = DEEP_TIMEOUT_MS,
        timeoutReason = "install_deep_timeout",
        capacityReason = "install_deep_capacity_exhausted",
        failureReason = "install_deep_failed",
        action = action,
    )

    private fun executor(name: String, workers: Int): ThreadPoolExecutor = ThreadPoolExecutor(
        workers,
        workers,
        0L,
        TimeUnit.MILLISECONDS,
        SynchronousQueue(),
        { runnable -> Thread(runnable, name).apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )

    private fun <T> call(
        executor: ThreadPoolExecutor,
        timeoutMillis: Long,
        timeoutReason: String,
        capacityReason: String,
        failureReason: String,
        action: () -> T,
    ): T {
        val future = try {
            executor.submit<T> { action() }
        } catch (error: RejectedExecutionException) {
            throw InstallScanUnavailableException(capacityReason, error)
        }
        return try {
            future.get(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (error: TimeoutException) {
            future.cancel(true)
            throw InstallScanUnavailableException(timeoutReason, error)
        } catch (error: InterruptedException) {
            future.cancel(true)
            Thread.currentThread().interrupt()
            throw InstallScanUnavailableException("install_scan_interrupted", error)
        } catch (error: java.util.concurrent.ExecutionException) {
            val cause = error.cause ?: error
            if (cause is InstallScanUnavailableException) throw cause
            throw InstallScanUnavailableException(failureReason, cause)
        }
    }
}

class InstallScanUnavailableException(
    val reasonCode: String,
    cause: Throwable? = null,
) : RuntimeException(reasonCode, cause)
