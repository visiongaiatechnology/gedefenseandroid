package de.visiongaia.gedefense.mobile

import android.app.job.JobParameters
import android.app.job.JobService
import android.content.Intent
import de.visiongaia.gedefense.mobile.core.EvidenceEvent
import java.util.concurrent.Future
import java.util.concurrent.FutureTask
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

class ThreatIntelJobService : JobService() {
    private val jobLock = Any()
    private val generation = AtomicLong(0)
    private val active = AtomicReference<Future<*>?>(null)

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
            var needsReschedule = false
            try {
                if (Thread.currentThread().isInterrupted || generation.get() != token) throw InterruptedException("job cancelled")
                val report = runtime.feeds.syncDue()
                if (Thread.currentThread().isInterrupted || generation.get() != token) throw InterruptedException("job cancelled")
                runtime.state.setFeedSync(report.atMillis)
                runtime.refreshFeedHealth()
                appendSyncEvidence(runtime, report)

                // Geo-country is a local analytics dataset, not an online lookup service. It shares
                // the periodic network job so Full Flow keeps country attribution fresh without a
                // second scheduler or any destination-IP disclosure. A failed geo refresh preserves
                // its last-known-good authenticated generation and requests a later retry.
                try {
                    val geo = runtime.geoCountry.syncDue()
                    appendGeoEvidence(runtime, geo)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw InterruptedException("job cancelled")
                } catch (t: Throwable) {
                    needsReschedule = true
                    try {
                        runtime.evidence.append(
                            EvidenceEvent(
                                "geo.sync",
                                "warning",
                                "local",
                                "geo refresh failed; last-known-good retained type=${t::class.java.simpleName.take(64)}",
                            ),
                        )
                    } catch (error: Throwable) { runtime.recordEvidenceFailure("geo_sync_failure", error) }
                }

                // ASN enrichment is likewise a whole-dataset local snapshot. It is evidence-only:
                // no destination IP is sent to an ASN API and no ASN result enters enforcement/XDR scoring.
                try {
                    val asn = runtime.asnEvidence.syncDue()
                    appendAsnEvidence(runtime, asn)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw InterruptedException("job cancelled")
                } catch (t: Throwable) {
                    needsReschedule = true
                    try {
                        runtime.evidence.append(
                            EvidenceEvent(
                                "asn.sync",
                                "warning",
                                "local",
                                "ASN refresh failed; last-known-good retained type=${t::class.java.simpleName.take(64)} evidence_only=true",
                            ),
                        )
                    } catch (error: Throwable) { runtime.recordEvidenceFailure("asn_sync_failure", error) }
                }

                if (runtime.state.isVpnActive()) {
                    try {
                        startService(
                            Intent(this, GeDefenseVpnService::class.java)
                                .setAction(GeDefenseVpnService.ACTION_REFRESH),
                        )
                    } catch (error: RuntimeException) {
                        RuntimeFailureLog.nonCritical("threat-intel-policy-refresh", error)
                        needsReschedule = true
                    }
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                needsReschedule = true
            } catch (t: Throwable) {
                needsReschedule = true
                try {
                    runtime.evidence.append(
                        EvidenceEvent(
                            "threatintel.sync",
                            "warning",
                            "local",
                            "background sync failed type=${t::class.java.simpleName.take(64)}",
                        ),
                    )
                } catch (error: Throwable) { runtime.recordEvidenceFailure("threatintel_sync_failure", error) }
            } finally {
                synchronized(jobLock) {
                    if (generation.get() == token) {
                        active.set(null)
                        runtime.notifyStateChanged()
                        jobFinished(params, needsReschedule)
                    }
                }
            }
            }
            synchronized(jobLock) ready@{
                if (generation.get() != token || active.get() !== readinessGate) return@ready
                active.set(task)
                if (!runtime.executeBackground("threat-intel-job") { task.run() }) {
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

    private fun appendGeoEvidence(runtime: AppRuntime, geo: GeoCountryState) {
        if (!geo.ready) return
        try {
            runtime.evidence.append(
                EvidenceEvent(
                    "geo.sync",
                    "info",
                    "local",
                    "authenticated local country generation ready records=${geo.v4Records + geo.v6Records} fetchedAt=${geo.fetchedAtMillis}",
                ),
            )
        } catch (error: Throwable) { runtime.recordEvidenceFailure("geo_sync_evidence", error) }
    }

    private fun appendAsnEvidence(runtime: AppRuntime, asn: AsnEvidenceState) {
        if (!asn.ready) return
        try {
            runtime.evidence.append(
                EvidenceEvent(
                    "asn.sync",
                    "info",
                    "local",
                    "authenticated local ASN generation ready records=${asn.v4Records + asn.v6Records} organizations=${asn.organizations} fetchedAt=${asn.fetchedAtMillis} upstream=${asn.upstreamId} source=${asn.sourceId} license=${asn.licenseId} v4_source_sha256=${asn.v4SourceSha256} v6_source_sha256=${asn.v6SourceSha256} v4_index_sha256=${asn.v4IndexSha256} v6_index_sha256=${asn.v6IndexSha256} org_index_sha256=${asn.organizationsSha256} evidence_only=true",
                ),
            )
        } catch (error: Throwable) { runtime.recordEvidenceFailure("asn_sync_evidence", error) }
    }

    private fun appendSyncEvidence(runtime: AppRuntime, report: SyncReport) {
        try {
            runtime.evidence.append(
                EvidenceEvent(
                    "threatintel.sync",
                    if (report.statuses.all { it.ok }) "info" else "warning",
                    "local",
                    "healthy=${report.statuses.count { it.ok }}/${report.statuses.size} indexed=${report.totalRecords} routes=${report.routePrefixes} candidates=${report.routeCandidates} overflow=${report.routeOverflow} routePolicy=${runtime.threatIndex.get().routePolicySha256} fullPolicy=${runtime.threatIndex.get().fullPolicySha256}",
                ),
            )
        } catch (error: Throwable) { runtime.recordEvidenceFailure("threatintel_sync_evidence", error) }
    }
}
