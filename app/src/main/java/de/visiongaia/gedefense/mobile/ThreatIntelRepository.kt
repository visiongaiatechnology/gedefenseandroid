package de.visiongaia.gedefense.mobile

import android.content.Context
import de.visiongaia.gedefense.mobile.core.EnforcementClass
import de.visiongaia.gedefense.mobile.core.FeedCommitResult
import de.visiongaia.gedefense.mobile.core.ThreatCacheStore
import de.visiongaia.gedefense.mobile.core.ThreatFeed
import de.visiongaia.gedefense.mobile.core.ThreatFeedCatalog
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import javax.crypto.SecretKey
import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.CancellationException
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock

data class FeedSyncStatus(
    val id: String,
    val ok: Boolean,
    val message: String,
    val records: Int = 0,
    val skipped: Boolean = false,
)


data class FeedSyncProgress(
    val completed: Int,
    val total: Int,
    val successful: Int,
    val lastFeedId: String,
    val lastFeedOk: Boolean,
)

data class SyncReport(
    val statuses: List<FeedSyncStatus>,
    val totalRecords: Int,
    val routePrefixes: Int,
    val routeCandidates: Int,
    val routeOverflow: Boolean,
    val atMillis: Long,
)

data class FeedHealthStatus(
    val id: String,
    val name: String,
    val available: Boolean,
    val fresh: Boolean,
    val records: Int,
    val fetchedAtMillis: Long,
    val enforcement: EnforcementClass,
)

class ThreatIntelRepository(
    context: Context,
    private val current: AtomicReference<ThreatIndex>,
    integrityKeyProvider: () -> SecretKey?,
) {
    private val root = File(context.filesDir, "threat-intel")
    private val store = ThreatCacheStore(root, null, integrityKeyProvider)
    private val syncLock = ReentrantLock()

    fun loadCachedSnapshot(): ThreatIndex = store.loadSnapshot().also { current.set(it) }

    @Throws(InterruptedException::class)
    fun syncDue(onProgress: ((FeedSyncProgress) -> Unit)? = null): SyncReport {
        syncLock.lockInterruptibly()
        try {
            throwIfInterrupted()
            val feeds = ThreatFeedCatalog.all
            val pool = BoundedExecutors.fixed(
                name = "gedefense-ti-download",
                threads = MAX_PARALLEL_DOWNLOADS,
                queueCapacity = feeds.size.coerceIn(1, 64),
            )
            val completion = ExecutorCompletionService<Pair<Int, FeedSyncStatus>>(pool)
            val futures = feeds.mapIndexed { index, feed ->
                completion.submit(Callable {
                    try {
                        index to syncOne(feed)
                    } catch (e: InterruptedException) {
                        Thread.currentThread().interrupt()
                        throw e
                    } catch (t: Throwable) {
                        index to FeedSyncStatus(feed.id, false, t.message ?: "sync failure")
                    }
                })
            }
            try {
                val ordered = arrayOfNulls<FeedSyncStatus>(feeds.size)
                var successful = 0
                repeat(feeds.size) { completedIndex ->
                    throwIfInterrupted()
                    val result = try {
                        completion.take().get()
                    } catch (e: InterruptedException) {
                        futures.forEach { it.cancel(true) }
                        Thread.currentThread().interrupt()
                        throw e
                    } catch (_: CancellationException) {
                        throw InterruptedException("threat-intel sync cancelled")
                    } catch (t: Throwable) {
                        futures.forEach { it.cancel(true) }
                        throw IllegalStateException("threat-intel worker failed", t.cause ?: t)
                    }
                    val (sourceIndex, status) = result
                    ordered[sourceIndex] = status
                    if (status.ok) successful++
                    emitProgress(
                        onProgress,
                        FeedSyncProgress(
                            completed = completedIndex + 1,
                            total = feeds.size,
                            successful = successful,
                            lastFeedId = status.id,
                            lastFeedOk = status.ok,
                        ),
                    )
                }
                throwIfInterrupted()
                val snapshot = store.loadSnapshot().also { current.set(it) }
                return SyncReport(
                    statuses = ordered.mapIndexed { index, status ->
                        status ?: FeedSyncStatus(feeds[index].id, false, "sync result unavailable")
                    },
                    totalRecords = snapshot.count,
                    routePrefixes = snapshot.routePrefixes.size,
                    routeCandidates = snapshot.routeCandidateCount,
                    routeOverflow = snapshot.routeOverflow,
                    atMillis = System.currentTimeMillis(),
                )
            } finally {
                futures.forEach { if (!it.isDone) it.cancel(true) }
                pool.shutdownNow()
            }
        } finally {
            syncLock.unlock()
        }
    }

    fun healthSnapshot(now: Long = System.currentTimeMillis()): List<FeedHealthStatus> =
        ThreatFeedCatalog.all.map { feed ->
            val info = store.latestInfo(feed, now)
            FeedHealthStatus(
                id = feed.id,
                name = feed.name,
                available = info != null,
                fresh = info?.fresh == true,
                records = info?.records ?: 0,
                fetchedAtMillis = info?.fetchedAt ?: 0L,
                enforcement = feed.enforcement,
            )
        }

    @Throws(InterruptedException::class)
    private fun syncOne(feed: ThreatFeed): FeedSyncStatus {
        throwIfInterrupted()
        val now = System.currentTimeMillis()
        val previous = store.latestInfo(feed, now)
        val minAge = Math.multiplyExact(feed.minRefreshMinutes, 60_000L)
        if (previous != null && now - previous.fetchedAt < minAge) {
            return FeedSyncStatus(feed.id, true, "rate-limited; cached data retained", previous.records, true)
        }

        val downloaded = try {
            FeedDownloader.download(feed, root)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw e
        } catch (t: Throwable) {
            return FeedSyncStatus(feed.id, false, t.message ?: "download failed")
        }

        throwIfInterrupted()
        return try {
            store.commit(feed, downloaded.file, downloaded.sha256, downloaded.bytes, now).toStatus(feed)
        } finally {
            downloaded.file.delete()
        }
    }

    private fun FeedCommitResult.toStatus(feed: ThreatFeed): FeedSyncStatus =
        FeedSyncStatus(feed.id, ok, message, records)

    private fun emitProgress(listener: ((FeedSyncProgress) -> Unit)?, progress: FeedSyncProgress) {
        if (listener == null) return
        try {
            listener(progress)
        } catch (_: RuntimeException) {
            // Progress observers have no authority over feed synchronization.
        }
    }

    private fun throwIfInterrupted() {
        if (Thread.currentThread().isInterrupted) throw InterruptedException("threat-intel sync interrupted")
    }

    companion object {
        private const val MAX_PARALLEL_DOWNLOADS = 3
    }
}
