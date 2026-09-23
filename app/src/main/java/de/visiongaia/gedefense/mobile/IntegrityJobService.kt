package de.visiongaia.gedefense.mobile

import android.app.job.JobParameters
import android.app.job.JobService
import de.visiongaia.gedefense.mobile.core.EvidenceEvent
import java.util.concurrent.FutureTask
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

class IntegrityJobService : JobService() {
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
                if (Thread.currentThread().isInterrupted || generation.get() != token) throw InterruptedException("integrity job cancelled")
                val result = runtime.integrityGuardian.scan()
                if (Thread.currentThread().isInterrupted || generation.get() != token) throw InterruptedException("integrity job cancelled")
                runtime.integritySnapshot.set(result)
                try { runtime.xdr.ingestIntegrity(result) } catch (error: Throwable) { runtime.recordXdrFailure("integrity_job_ingest", error) }
                val hardening = runtime.hardeningScanner.scan()
                runtime.hardeningSnapshot.set(hardening)
                try { runtime.xdr.ingestHardening(hardening) } catch (error: Throwable) { runtime.recordXdrFailure("hardening_job_ingest", error) }
                try {
                    runtime.resilienceSupervisor.runOnce()
                } catch (error: Throwable) {
                    RuntimeFailureLog.nonCritical("integrity-job-resilience", error)
                    reschedule = true
                }
                if (!result.ok) {
                    try {
                        runtime.evidence.append(EvidenceEvent(
                            "integrity.failure",
                            "critical",
                            "local",
                            "state=${result.state} issues=${result.issues.joinToString(",") { it.code }.take(512)}",
                        ))
                    } catch (error: Throwable) {
                        runtime.recordEvidenceFailure("integrity_job", error)
                        reschedule = true
                    }
                    runtime.requestIntegrityFailClosed("integrity_job")
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                reschedule = true
            } catch (error: Throwable) {
                RuntimeFailureLog.nonCritical("integrity-job", error)
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
                if (!runtime.executeBackground("integrity-job") { task.run() }) {
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
