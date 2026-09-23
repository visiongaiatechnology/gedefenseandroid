package de.visiongaia.gedefense.mobile

import android.app.job.JobParameters
import android.app.job.JobService
import java.util.concurrent.FutureTask
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

// STATUS: PLATIN
/** Runs the local self-healing supervisor without requiring network access. */
class ResilienceJobService : JobService() {
    private val jobLock = Any()
    private val generation = AtomicLong(0)
    private val active = AtomicReference<FutureTask<Unit>?>(null)

    override fun onStartJob(params: JobParameters): Boolean = synchronized(jobLock) {
        if (active.get() != null) return@synchronized false

        val token = generation.incrementAndGet()
        val readinessGate = FutureTask<Unit> { }
        active.set(readinessGate)
        AppRuntime.executeWhenReady(this) { runtime ->
            if (runtime == null) {
                synchronized(jobLock) {
                    if (generation.get() == token) {
                        active.set(null)
                        jobFinished(params, true)
                    }
                }
                return@executeWhenReady
            }

            val task = FutureTask<Unit> {
                var reschedule = false
                try {
                    if (Thread.currentThread().isInterrupted || generation.get() != token) {
                        throw InterruptedException("resilience job cancelled")
                    }
                    val report = runtime.resilienceSupervisor.runOnce("periodic-job")
                    reschedule = report.skipped || report.findings.any {
                        it.disposition == ResilienceSupervisor.Disposition.RETRY_LATER
                    }
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    reschedule = true
                } catch (_: Throwable) {
                    reschedule = true
                } finally {
                    synchronized(jobLock) {
                        if (generation.get() == token) {
                            active.set(null)
                            runtime.notifyStateChanged()
                            jobFinished(params, reschedule)
                        }
                    }
                }
            }

            synchronized(jobLock) ready@{
                if (generation.get() != token || active.get() !== readinessGate) return@ready
                active.set(task)
                if (!runtime.executeBackground("resilience-job") { task.run() }) {
                    active.set(null)
                    jobFinished(params, true)
                }
            }
        }
        true
    }

    override fun onStopJob(params: JobParameters): Boolean = synchronized(jobLock) {
        generation.incrementAndGet()
        active.getAndSet(null)?.cancel(true)
        true
    }
}
