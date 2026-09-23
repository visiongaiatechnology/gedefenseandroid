package de.visiongaia.gedefense.mobile

import android.os.Looper
import java.security.GeneralSecurityException
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock

// STATUS: PLATIN
/**
 * Process-wide fail-closed isolation boundary for AndroidKeyStore provider/Binder operations.
 *
 * OEM providers may block in native/Binder code instead of throwing. Calls therefore execute on a
 * single daemon worker with an operation deadline. A fair admission lock prevents unbounded queues
 * and, critically, keeps queue wait separate from provider execution time: a caller waiting behind
 * another legitimate Keystore operation cannot falsely trip the provider circuit breaker.
 *
 * After the first provider execution timeout the process circuit opens permanently. The stuck
 * daemon may remain inside vendor code, but no second worker is created and all later operations
 * fail immediately. Main-thread Keystore access is rejected rather than risking an ANR.
 */
object AndroidKeystoreGate {
    class UnavailableException internal constructor(
        val reasonCode: String,
        cause: Throwable? = null,
    ) : GeneralSecurityException(reasonCode, cause)

    private const val OPERATION_TIMEOUT_MILLIS = 5_000L
    private const val ADMISSION_TIMEOUT_MILLIS = 10_000L
    private val circuitOpen = AtomicBoolean(false)
    private val admission = ReentrantLock(true)
    private val executor = ThreadPoolExecutor(
        1,
        1,
        0L,
        TimeUnit.MILLISECONDS,
        SynchronousQueue(),
        { runnable -> Thread(runnable, "gedefense-keystore-gate").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )

    fun isAvailable(): Boolean = !circuitOpen.get()

    @Throws(Exception::class)
    fun <T> call(action: () -> T): T {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw UnavailableException("keystore_main_thread_forbidden")
        }
        if (circuitOpen.get()) throw UnavailableException("keystore_circuit_open")

        val admitted = try {
            admission.tryLock(ADMISSION_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw UnavailableException("keystore_admission_interrupted", error)
        }
        if (!admitted) throw UnavailableException("keystore_admission_timeout")

        try {
            if (circuitOpen.get()) throw UnavailableException("keystore_circuit_open")
            val future = try {
                executor.submit(Callable { action() })
            } catch (error: RejectedExecutionException) {
                throw UnavailableException("keystore_executor_unavailable", error)
            }
            return try {
                future.get(OPERATION_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
            } catch (error: TimeoutException) {
                if (circuitOpen.compareAndSet(false, true)) executor.shutdownNow()
                future.cancel(true)
                throw UnavailableException("keystore_operation_timeout", error)
            } catch (error: InterruptedException) {
                future.cancel(true)
                Thread.currentThread().interrupt()
                throw UnavailableException("keystore_operation_interrupted", error)
            } catch (error: ExecutionException) {
                val cause = error.cause
                when (cause) {
                    is RuntimeException -> throw cause
                    is Error -> throw cause
                    is Exception -> throw cause
                    else -> throw UnavailableException("keystore_operation_failed", error)
                }
            }
        } finally {
            admission.unlock()
        }
    }
}
