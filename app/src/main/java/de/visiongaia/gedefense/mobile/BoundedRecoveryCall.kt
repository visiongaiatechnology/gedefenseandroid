package de.visiongaia.gedefense.mobile

import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Bounds self-healing work that may touch Android providers, authenticated stores or filesystem
 * state. A stuck repair may occupy one daemon worker, but the fixed pool and zero-capacity queue
 * prevent unbounded repair storms or memory growth.
 */
object BoundedRecoveryCall {
    private const val WORKERS = 2
    const val DEFAULT_TIMEOUT_MS = 8_000L

    private val executor = ThreadPoolExecutor(
        WORKERS,
        WORKERS,
        0L,
        TimeUnit.MILLISECONDS,
        SynchronousQueue(),
        { runnable -> Thread(runnable, "gedefense-self-heal").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )

    fun <T> call(timeoutMillis: Long = DEFAULT_TIMEOUT_MS, action: () -> T): T {
        require(timeoutMillis in 250L..20_000L)
        val future = try {
            executor.submit<T> { action() }
        } catch (error: RejectedExecutionException) {
            throw RecoveryCallUnavailableException("self_heal_capacity_exhausted", error)
        }
        return try {
            future.get(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (error: TimeoutException) {
            future.cancel(true)
            throw RecoveryCallUnavailableException("self_heal_timeout", error)
        } catch (error: InterruptedException) {
            future.cancel(true)
            Thread.currentThread().interrupt()
            throw RecoveryCallUnavailableException("self_heal_interrupted", error)
        } catch (error: java.util.concurrent.ExecutionException) {
            val cause = error.cause ?: error
            if (cause is RuntimeException) throw cause
            throw RecoveryCallUnavailableException("self_heal_failed", cause)
        }
    }
}

class RecoveryCallUnavailableException(
    val reasonCode: String,
    cause: Throwable? = null,
) : RuntimeException(reasonCode, cause)
