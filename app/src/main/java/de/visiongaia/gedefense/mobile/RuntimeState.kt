package de.visiongaia.gedefense.mobile

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import de.visiongaia.gedefense.mobile.core.LedgerHealth
import de.visiongaia.gedefense.mobile.core.PrivacyProfile
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock

/**
 * Process-live runtime state with asynchronous, coalesced persistence.
 *
 * No SharedPreferences read/write is allowed on the caller thread. This class is constructed during
 * AppRuntime composition, including from startup-sensitive paths. Until the persisted snapshot has
 * loaded, conservative in-memory defaults are returned. Mutations made during loading win over old
 * disk state and are flushed after initialization completes.
 *
 * VPN activity itself is intentionally process-only: process death means there is no live VpnService
 * to trust, regardless of historical persistence.
 */
enum class ProtectionMode { SELECTIVE, FULL_FLOW_BETA, LOCKDOWN }

class RuntimeState(context: Context) {
    private val appContext = context.applicationContext
    private val live = AtomicReference(PersistedState())
    private val vpnActive = AtomicBoolean(false)
    private val transportPowerConstrained = AtomicBoolean(false)
    private val dirty = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
    private val persistenceReady = AtomicBoolean(false)
    private val persistenceLoadHealthy = AtomicBoolean(false)
    private val persistenceWriteHealthy = AtomicBoolean(true)
    private val persistenceReadyLatch = CountDownLatch(1)
    private val stateRevision = AtomicLong(0L)
    private val durableRevision = AtomicLong(0L)
    private val persistenceMonitor = Object()
    private val protectionConfigurationLock = ReentrantLock()
    private val flushRequested = AtomicBoolean(false)
    private val flushRunning = AtomicBoolean(false)
    private val executor = ThreadPoolExecutor(
        1,
        1,
        0L,
        TimeUnit.MILLISECONDS,
        ArrayBlockingQueue(2),
        { runnable -> Thread(runnable, "gedefense-runtime-state").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )

    init {
        scheduleInitialLoad()
    }

    fun isVpnActive(): Boolean = vpnActive.get()
    fun setVpnActive(value: Boolean) = vpnActive.set(value)
    fun transportPowerConstrained(): Boolean = transportPowerConstrained.get()
    fun setTransportPowerConstrained(value: Boolean) = transportPowerConstrained.set(value)

    fun lastVpnStatus(): String = live.get().vpnStatus
    fun lastVpnReason(): String? = live.get().vpnReason

    fun setVpnStatus(status: String, reason: String? = null) {
        val safeStatus = status.trim().take(120).ifBlank { "UNKNOWN" }
        val safeReason = reason?.trim()?.takeIf { it.isNotEmpty() }?.take(160)
        mutate(KEY_VPN_STATUS, KEY_VPN_REASON) { it.copy(vpnStatus = safeStatus, vpnReason = safeReason) }
    }

    fun lastFeedSync(): Long = live.get().feedSync
    fun setFeedSync(value: Long) = mutate(KEY_FEED_SYNC) { it.copy(feedSync = value.coerceAtLeast(0L)) }

    fun evidenceOk(): Boolean = live.get().evidenceOk
    fun evidenceReason(): String? = live.get().evidenceReason
    fun setEvidenceHealth(health: LedgerHealth) = mutate(KEY_EVIDENCE_OK, KEY_EVIDENCE_REASON) {
        it.copy(evidenceOk = health.ok, evidenceReason = health.reason?.take(240))
    }

    fun recordEvidencePersistenceFailure(code: String) = recordPersistenceFailure("evidence", code)
    fun recordXdrPersistenceFailure(code: String) = recordPersistenceFailure("xdr", code)

    fun evidencePersistenceFailureCount(): Long = live.get().evidencePersistenceFailures
    fun xdrPersistenceFailureCount(): Long = live.get().xdrPersistenceFailures
    fun lastEvidencePersistenceFailure(): String? = live.get().evidencePersistenceFailureCode
    fun lastXdrPersistenceFailure(): String? = live.get().xdrPersistenceFailureCode
    fun lastEvidencePersistenceFailureAtMillis(): Long = live.get().evidencePersistenceFailureAt
    fun lastXdrPersistenceFailureAtMillis(): Long = live.get().xdrPersistenceFailureAt

    fun protectionMode(): ProtectionMode = live.get().protectionMode

    private fun protectionConfigurationMutableState(): Boolean =
        !isVpnActive() && live.get().vpnStatus !in CONFIGURATION_LOCKED_VPN_STATES

    /**
     * Fast UI/read-side predicate. A concurrent configuration transaction also makes mutation
     * temporarily unavailable so callers never wait on Android's main thread for disk-backed
     * WireGuard profile work.
     */
    fun canMutateProtectionConfiguration(): Boolean =
        protectionConfigurationMutableState() && !protectionConfigurationLock.isLocked

    /**
     * Serializes all security-relevant protection configuration writes against VPN startup.
     * Callers must treat rejection as a normal busy/transition state and retry from the UI.
     */
    internal fun <T> withMutableProtectionConfiguration(block: () -> T): T {
        require(protectionConfigurationLock.tryLock()) { "protection configuration transaction busy" }
        return try {
            require(protectionConfigurationMutableState()) { "protection configuration cannot change while VPN is active or transitioning" }
            block()
        } finally {
            protectionConfigurationLock.unlock()
        }
    }

    /**
     * Service-only startup barrier. The control worker may wait briefly for an already-running
     * profile transaction, but the Android main thread never calls this method. Once STARTING is
     * visible, new configuration transactions are rejected until startup resolves.
     */
    fun beginProtectionStartTransition(timeoutMillis: Long): Boolean {
        require(timeoutMillis in 1L..5_000L) { "protection configuration freeze timeout outside allowed range" }
        val locked = try {
            protectionConfigurationLock.tryLock(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        if (!locked) return false
        return try {
            if (isVpnActive() || live.get().vpnStatus == "RECOVERING") return false
            if (live.get().vpnStatus != "STARTING") mutate(KEY_VPN_STATUS, KEY_VPN_REASON) {
                it.copy(vpnStatus = "STARTING", vpnReason = null)
            }
            true
        } finally {
            protectionConfigurationLock.unlock()
        }
    }

    fun setProtectionMode(mode: ProtectionMode) = withMutableProtectionConfiguration {
        mutate(KEY_PROTECTION_MODE) { it.copy(protectionMode = mode) }
    }

    /** Service-only coercion used when Android lockdown requires Full Flow during STARTING. */
    fun setProtectionModeForVpnStart(mode: ProtectionMode) {
        require(protectionConfigurationLock.tryLock()) { "protection configuration transaction busy during vpn startup" }
        try {
            require(!isVpnActive() && live.get().vpnStatus == "STARTING") { "vpn-start protection mode coercion outside startup" }
            mutate(KEY_PROTECTION_MODE) { it.copy(protectionMode = mode) }
        } finally {
            protectionConfigurationLock.unlock()
        }
    }

    fun wireGuardEgressMode(): WireGuardEgressMode = live.get().wireGuardEgressMode

    fun setWireGuardEgressMode(mode: WireGuardEgressMode) = withMutableProtectionConfiguration {
        mutate(KEY_WIREGUARD_EGRESS_MODE) { it.copy(wireGuardEgressMode = mode) }
    }

    fun privacyProfile(): PrivacyProfile = live.get().privacyProfile

    fun setPrivacyProfile(profile: PrivacyProfile) = withMutableProtectionConfiguration {
        mutate(KEY_PRIVACY_PROFILE) { it.copy(privacyProfile = profile) }
    }

    fun awaitPersistenceReady(timeoutMillis: Long): Boolean {
        require(timeoutMillis in 1L..30_000L) { "runtime state persistence timeout outside allowed range" }
        if (persistenceReady.get()) return persistenceLoadHealthy.get()
        return try {
            persistenceReadyLatch.await(timeoutMillis, TimeUnit.MILLISECONDS) && persistenceLoadHealthy.get()
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
    }

    /**
     * Waits until every RuntimeState mutation visible at call entry is durably committed.
     * This is used only by the serialized VPN control worker, never Android's main thread.
     */
    fun awaitDurableState(timeoutMillis: Long): Boolean {
        require(timeoutMillis in 1L..30_000L) { "runtime state durability timeout outside allowed range" }
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        val initialRemaining = TimeUnit.NANOSECONDS.toMillis((deadline - System.nanoTime()).coerceAtLeast(0L)).coerceAtLeast(1L)
        if (!awaitPersistenceReady(initialRemaining)) return false
        val targetRevision = stateRevision.get()
        requestFlush()
        while (true) {
            if (!persistenceLoadHealthy.get() || !persistenceWriteHealthy.get()) return false
            if (durableRevision.get() >= targetRevision) return true
            val remainingNanos = deadline - System.nanoTime()
            if (remainingNanos <= 0L) return false
            val waitMillis = TimeUnit.NANOSECONDS.toMillis(remainingNanos).coerceIn(1L, 250L)
            try {
                synchronized(persistenceMonitor) { persistenceMonitor.wait(waitMillis) }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return false
            }
        }
    }

    fun resilienceDesired(): Boolean = live.get().resilienceDesired
    fun setResilienceDesired(enabled: Boolean) = mutate(KEY_RESILIENCE_DESIRED) { it.copy(resilienceDesired = enabled) }

    fun platformAlwaysOn(): Boolean = live.get().platformAlwaysOn
    fun platformLockdown(): Boolean = live.get().platformLockdown
    fun platformPolicyObservedAtMillis(): Long = live.get().platformPolicyObservedAt

    fun recordPlatformVpnPolicy(alwaysOn: Boolean, lockdown: Boolean) = mutate(
        KEY_PLATFORM_ALWAYS_ON,
        KEY_PLATFORM_LOCKDOWN,
        KEY_PLATFORM_POLICY_AT,
    ) {
        it.copy(
            platformAlwaysOn = alwaysOn,
            platformLockdown = lockdown,
            platformPolicyObservedAt = System.currentTimeMillis(),
        )
    }

    fun recordVpnRecovery(reason: String) = mutate(KEY_RECOVERY_COUNT, KEY_RECOVERY_AT, KEY_RECOVERY_REASON) {
        it.copy(
            vpnRecoveryCount = increment(it.vpnRecoveryCount),
            vpnRecoveryAt = System.currentTimeMillis(),
            vpnRecoveryReason = reason.trim().take(120),
        )
    }

    fun vpnRecoveryCount(): Long = live.get().vpnRecoveryCount
    fun lastVpnRecoveryAtMillis(): Long = live.get().vpnRecoveryAt
    fun lastVpnRecoveryReason(): String? = live.get().vpnRecoveryReason

    fun recordResilienceSelfTestStarted() = mutate(KEY_SELF_TEST_STATUS, KEY_SELF_TEST_AT, KEY_SELF_TEST_DURATION) {
        it.copy(
            selfTestStatus = "RUNNING",
            selfTestAt = System.currentTimeMillis(),
            selfTestDuration = 0L,
        )
    }

    fun recordResilienceSelfTestResult(success: Boolean, durationMillis: Long) = mutate(
        KEY_SELF_TEST_STATUS,
        KEY_SELF_TEST_AT,
        KEY_SELF_TEST_DURATION,
    ) {
        it.copy(
            selfTestStatus = if (success) "PASS" else "FAIL",
            selfTestAt = System.currentTimeMillis(),
            selfTestDuration = durationMillis.coerceIn(0L, MAX_SELF_TEST_DURATION_MS),
        )
    }

    fun lastResilienceSelfTestStatus(): String? = live.get().selfTestStatus
    fun lastResilienceSelfTestAtMillis(): Long = live.get().selfTestAt
    fun lastResilienceSelfTestDurationMillis(): Long = live.get().selfTestDuration

    private fun recordPersistenceFailure(component: String, code: String) {
        require(component == "evidence" || component == "xdr") { "unsupported persistence component" }
        val safe = sanitizeCode(code)
        val now = System.currentTimeMillis()
        if (component == "evidence") {
            mutate(KEY_EVIDENCE_PERSIST_COUNT, KEY_EVIDENCE_PERSIST_CODE, KEY_EVIDENCE_PERSIST_AT) {
                it.copy(
                    evidencePersistenceFailures = increment(it.evidencePersistenceFailures),
                    evidencePersistenceFailureCode = safe,
                    evidencePersistenceFailureAt = now,
                )
            }
        } else {
            mutate(KEY_XDR_PERSIST_COUNT, KEY_XDR_PERSIST_CODE, KEY_XDR_PERSIST_AT) {
                it.copy(
                    xdrPersistenceFailures = increment(it.xdrPersistenceFailures),
                    xdrPersistenceFailureCode = safe,
                    xdrPersistenceFailureAt = now,
                )
            }
        }
    }

    private fun mutate(vararg keys: String, transform: (PersistedState) -> PersistedState) {
        keys.forEach(dirty::add)
        while (true) {
            val current = live.get()
            val next = transform(current)
            if (live.compareAndSet(current, next)) break
        }
        stateRevision.incrementAndGet()
        requestFlush()
    }

    private fun scheduleInitialLoad() {
        try {
            executor.execute {
                try {
                    val persisted = readPersistedState()
                    mergeLoadedState(persisted)
                    persistenceLoadHealthy.set(true)
                } catch (error: RuntimeException) {
                    persistenceLoadHealthy.set(false)
                    Log.w(LOG_TAG, "runtime_state_load_failed:" + error.javaClass.simpleName.take(48))
                } finally {
                    persistenceReady.set(true)
                    persistenceReadyLatch.countDown()
                    synchronized(persistenceMonitor) { persistenceMonitor.notifyAll() }
                    requestFlush()
                }
            }
        } catch (_: RejectedExecutionException) {
            persistenceLoadHealthy.set(false)
            persistenceReady.set(true)
            persistenceReadyLatch.countDown()
            synchronized(persistenceMonitor) { persistenceMonitor.notifyAll() }
            Log.w(LOG_TAG, "runtime_state_load_rejected")
        }
    }

    private fun <T : Enum<T>> readPersistedEnum(
        preferences: SharedPreferences,
        key: String,
        defaultValue: T,
        enumClass: Class<T>,
    ): T {
        if (!preferences.contains(key)) return defaultValue
        val raw = preferences.getString(key, null)
            ?: throw IllegalStateException("persisted security mode missing")
        return try {
            java.lang.Enum.valueOf(enumClass, raw)
        } catch (error: IllegalArgumentException) {
            throw IllegalStateException("persisted security mode invalid", error)
        }
    }

    private fun readPersistedState(): PersistedState {
        val preferences = appContext.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        val rawStatus = preferences.getString(KEY_VPN_STATUS, "OFF") ?: "OFF"
        val normalizedStatus = if (rawStatus in TRANSIENT_VPN_STATES) "OFF" else rawStatus.take(120)
        val normalizedReason = if (rawStatus in TRANSIENT_VPN_STATES) null else preferences.getString(KEY_VPN_REASON, null)?.take(160)
        val rawSelfTest = preferences.getString(KEY_SELF_TEST_STATUS, null)
        val rawSelfTestAt = preferences.getLong(KEY_SELF_TEST_AT, 0L).coerceAtLeast(0L)
        val selfTestWasRunning = rawSelfTest == "RUNNING"
        val selfTestElapsed = if (selfTestWasRunning && rawSelfTestAt > 0L) {
            (now - rawSelfTestAt).coerceIn(0L, MAX_SELF_TEST_DURATION_MS)
        } else {
            preferences.getLong(KEY_SELF_TEST_DURATION, 0L).coerceIn(0L, MAX_SELF_TEST_DURATION_MS)
        }
        // Absent keys are legitimate legacy/default state. A present but malformed security mode is
        // corruption, not a request to silently downgrade protection. Let the initial-load boundary
        // mark persistence unhealthy so VPN startup fails closed instead of falling back to DIRECT,
        // CONSERVATIVE or another less restrictive mode.
        val protectionMode = readPersistedEnum(
            preferences,
            KEY_PROTECTION_MODE,
            ProtectionMode.FULL_FLOW_BETA,
            ProtectionMode::class.java,
        )
        val wireGuardEgressMode = readPersistedEnum(
            preferences,
            KEY_WIREGUARD_EGRESS_MODE,
            WireGuardEgressMode.DIRECT,
            WireGuardEgressMode::class.java,
        )
        val privacyProfile = readPersistedEnum(
            preferences,
            KEY_PRIVACY_PROFILE,
            PrivacyProfile.CONSERVATIVE,
            PrivacyProfile::class.java,
        )

        return PersistedState(
            vpnStatus = normalizedStatus,
            vpnReason = normalizedReason,
            feedSync = preferences.getLong(KEY_FEED_SYNC, 0L).coerceAtLeast(0L),
            evidenceOk = preferences.getBoolean(KEY_EVIDENCE_OK, false),
            evidenceReason = preferences.getString(KEY_EVIDENCE_REASON, "evidence_initializing")?.take(240),
            evidencePersistenceFailures = preferences.getLong(KEY_EVIDENCE_PERSIST_COUNT, 0L).coerceAtLeast(0L),
            xdrPersistenceFailures = preferences.getLong(KEY_XDR_PERSIST_COUNT, 0L).coerceAtLeast(0L),
            evidencePersistenceFailureCode = preferences.getString(KEY_EVIDENCE_PERSIST_CODE, null)?.take(64),
            xdrPersistenceFailureCode = preferences.getString(KEY_XDR_PERSIST_CODE, null)?.take(64),
            evidencePersistenceFailureAt = preferences.getLong(KEY_EVIDENCE_PERSIST_AT, 0L).coerceAtLeast(0L),
            xdrPersistenceFailureAt = preferences.getLong(KEY_XDR_PERSIST_AT, 0L).coerceAtLeast(0L),
            protectionMode = protectionMode,
            wireGuardEgressMode = wireGuardEgressMode,
            privacyProfile = privacyProfile,
            resilienceDesired = preferences.getBoolean(KEY_RESILIENCE_DESIRED, false),
            platformAlwaysOn = preferences.getBoolean(KEY_PLATFORM_ALWAYS_ON, false),
            platformLockdown = preferences.getBoolean(KEY_PLATFORM_LOCKDOWN, false),
            platformPolicyObservedAt = preferences.getLong(KEY_PLATFORM_POLICY_AT, 0L).coerceAtLeast(0L),
            vpnRecoveryCount = preferences.getLong(KEY_RECOVERY_COUNT, 0L).coerceAtLeast(0L),
            vpnRecoveryAt = preferences.getLong(KEY_RECOVERY_AT, 0L).coerceAtLeast(0L),
            vpnRecoveryReason = preferences.getString(KEY_RECOVERY_REASON, null)?.take(120),
            selfTestStatus = if (selfTestWasRunning) "FAIL" else rawSelfTest?.take(16),
            selfTestAt = if (selfTestWasRunning) now else rawSelfTestAt,
            selfTestDuration = selfTestElapsed,
        )
    }

    private fun mergeLoadedState(persisted: PersistedState) {
        while (true) {
            val current = live.get()
            val next = PersistedState(
                vpnStatus = choose(KEY_VPN_STATUS, current.vpnStatus, persisted.vpnStatus),
                vpnReason = choose(KEY_VPN_REASON, current.vpnReason, persisted.vpnReason),
                feedSync = choose(KEY_FEED_SYNC, current.feedSync, persisted.feedSync),
                evidenceOk = choose(KEY_EVIDENCE_OK, current.evidenceOk, persisted.evidenceOk),
                evidenceReason = choose(KEY_EVIDENCE_REASON, current.evidenceReason, persisted.evidenceReason),
                evidencePersistenceFailures = choose(KEY_EVIDENCE_PERSIST_COUNT, current.evidencePersistenceFailures, persisted.evidencePersistenceFailures),
                xdrPersistenceFailures = choose(KEY_XDR_PERSIST_COUNT, current.xdrPersistenceFailures, persisted.xdrPersistenceFailures),
                evidencePersistenceFailureCode = choose(KEY_EVIDENCE_PERSIST_CODE, current.evidencePersistenceFailureCode, persisted.evidencePersistenceFailureCode),
                xdrPersistenceFailureCode = choose(KEY_XDR_PERSIST_CODE, current.xdrPersistenceFailureCode, persisted.xdrPersistenceFailureCode),
                evidencePersistenceFailureAt = choose(KEY_EVIDENCE_PERSIST_AT, current.evidencePersistenceFailureAt, persisted.evidencePersistenceFailureAt),
                xdrPersistenceFailureAt = choose(KEY_XDR_PERSIST_AT, current.xdrPersistenceFailureAt, persisted.xdrPersistenceFailureAt),
                protectionMode = choose(KEY_PROTECTION_MODE, current.protectionMode, persisted.protectionMode),
                wireGuardEgressMode = choose(KEY_WIREGUARD_EGRESS_MODE, current.wireGuardEgressMode, persisted.wireGuardEgressMode),
                privacyProfile = choose(KEY_PRIVACY_PROFILE, current.privacyProfile, persisted.privacyProfile),
                resilienceDesired = choose(KEY_RESILIENCE_DESIRED, current.resilienceDesired, persisted.resilienceDesired),
                platformAlwaysOn = choose(KEY_PLATFORM_ALWAYS_ON, current.platformAlwaysOn, persisted.platformAlwaysOn),
                platformLockdown = choose(KEY_PLATFORM_LOCKDOWN, current.platformLockdown, persisted.platformLockdown),
                platformPolicyObservedAt = choose(KEY_PLATFORM_POLICY_AT, current.platformPolicyObservedAt, persisted.platformPolicyObservedAt),
                vpnRecoveryCount = choose(KEY_RECOVERY_COUNT, current.vpnRecoveryCount, persisted.vpnRecoveryCount),
                vpnRecoveryAt = choose(KEY_RECOVERY_AT, current.vpnRecoveryAt, persisted.vpnRecoveryAt),
                vpnRecoveryReason = choose(KEY_RECOVERY_REASON, current.vpnRecoveryReason, persisted.vpnRecoveryReason),
                selfTestStatus = choose(KEY_SELF_TEST_STATUS, current.selfTestStatus, persisted.selfTestStatus),
                selfTestAt = choose(KEY_SELF_TEST_AT, current.selfTestAt, persisted.selfTestAt),
                selfTestDuration = choose(KEY_SELF_TEST_DURATION, current.selfTestDuration, persisted.selfTestDuration),
            )
            if (live.compareAndSet(current, next)) return
        }
    }

    private fun requestFlush() {
        if (!persistenceReady.get()) return
        flushRequested.set(true)
        if (!flushRunning.compareAndSet(false, true)) return
        try {
            executor.execute {
                try {
                    do {
                        flushRequested.set(false)
                        val (snapshot, revision) = stableSnapshot()
                        val ok = writePersistedState(snapshot)
                        persistenceWriteHealthy.set(ok)
                        if (ok) durableRevision.updateAndGet { current -> maxOf(current, revision) }
                        synchronized(persistenceMonitor) { persistenceMonitor.notifyAll() }
                    } while (flushRequested.get())
                } finally {
                    flushRunning.set(false)
                    synchronized(persistenceMonitor) { persistenceMonitor.notifyAll() }
                    if (flushRequested.get()) requestFlush()
                }
            }
        } catch (_: RejectedExecutionException) {
            persistenceWriteHealthy.set(false)
            flushRunning.set(false)
            synchronized(persistenceMonitor) { persistenceMonitor.notifyAll() }
            Log.w(LOG_TAG, "runtime_state_flush_rejected")
        }
    }

    private fun stableSnapshot(): Pair<PersistedState, Long> {
        while (true) {
            val before = stateRevision.get()
            val snapshot = live.get()
            val after = stateRevision.get()
            if (before == after) return snapshot to after
        }
    }

    // This method already runs exclusively on the bounded persistence worker. commit() is
    // intentional: RuntimeState must observe durable-write failure instead of losing it behind
    // SharedPreferences.apply()'s asynchronous, non-reporting write path.
    @SuppressLint("ApplySharedPref")
    private fun writePersistedState(state: PersistedState): Boolean {
        val preferences = appContext.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        val ok = try {
            preferences.edit()
                .putString(KEY_VPN_STATUS, state.vpnStatus)
                .applyOptionalString(KEY_VPN_REASON, state.vpnReason)
                .putLong(KEY_FEED_SYNC, state.feedSync)
                .putBoolean(KEY_EVIDENCE_OK, state.evidenceOk)
                .applyOptionalString(KEY_EVIDENCE_REASON, state.evidenceReason)
                .putLong(KEY_EVIDENCE_PERSIST_COUNT, state.evidencePersistenceFailures)
                .putLong(KEY_XDR_PERSIST_COUNT, state.xdrPersistenceFailures)
                .applyOptionalString(KEY_EVIDENCE_PERSIST_CODE, state.evidencePersistenceFailureCode)
                .applyOptionalString(KEY_XDR_PERSIST_CODE, state.xdrPersistenceFailureCode)
                .putLong(KEY_EVIDENCE_PERSIST_AT, state.evidencePersistenceFailureAt)
                .putLong(KEY_XDR_PERSIST_AT, state.xdrPersistenceFailureAt)
                .putString(KEY_PROTECTION_MODE, state.protectionMode.name)
                .putString(KEY_WIREGUARD_EGRESS_MODE, state.wireGuardEgressMode.name)
                .putString(KEY_PRIVACY_PROFILE, state.privacyProfile.name)
                .putBoolean(KEY_RESILIENCE_DESIRED, state.resilienceDesired)
                .putBoolean(KEY_PLATFORM_ALWAYS_ON, state.platformAlwaysOn)
                .putBoolean(KEY_PLATFORM_LOCKDOWN, state.platformLockdown)
                .putLong(KEY_PLATFORM_POLICY_AT, state.platformPolicyObservedAt)
                .putLong(KEY_RECOVERY_COUNT, state.vpnRecoveryCount)
                .putLong(KEY_RECOVERY_AT, state.vpnRecoveryAt)
                .applyOptionalString(KEY_RECOVERY_REASON, state.vpnRecoveryReason)
                .applyOptionalString(KEY_SELF_TEST_STATUS, state.selfTestStatus)
                .putLong(KEY_SELF_TEST_AT, state.selfTestAt)
                .putLong(KEY_SELF_TEST_DURATION, state.selfTestDuration)
                .remove("vpn_active")
                .commit()
        } catch (error: RuntimeException) {
            Log.w(LOG_TAG, "runtime_state_commit_exception:" + error.javaClass.simpleName.take(48))
            false
        }
        if (!ok) Log.w(LOG_TAG, "runtime_state_commit_failed")
        return ok
    }

    private fun android.content.SharedPreferences.Editor.applyOptionalString(
        key: String,
        value: String?,
    ): android.content.SharedPreferences.Editor = if (value == null) remove(key) else putString(key, value)

    private fun <T> choose(key: String, current: T, persisted: T): T = if (key in dirty) current else persisted

    private fun sanitizeCode(code: String): String {
        val out = StringBuilder(minOf(code.length, 64))
        var previousUnderscore = false
        for (char in code.trim().lowercase()) {
            if (out.length >= 64) break
            val normalized = if (char in 'a'..'z' || char in '0'..'9' || char == '_') char else '_'
            if (normalized == '_') {
                if (previousUnderscore || out.isEmpty()) continue
                previousUnderscore = true
            } else {
                previousUnderscore = false
            }
            out.append(normalized)
        }
        while (out.isNotEmpty() && out.last() == '_') out.setLength(out.length - 1)
        return out.toString().ifBlank { "write_failed" }
    }

    private fun increment(value: Long): Long = if (value == Long.MAX_VALUE) Long.MAX_VALUE else value + 1L

    private data class PersistedState(
        val vpnStatus: String = "OFF",
        val vpnReason: String? = null,
        val feedSync: Long = 0L,
        val evidenceOk: Boolean = false,
        val evidenceReason: String? = "evidence_initializing",
        val evidencePersistenceFailures: Long = 0L,
        val xdrPersistenceFailures: Long = 0L,
        val evidencePersistenceFailureCode: String? = null,
        val xdrPersistenceFailureCode: String? = null,
        val evidencePersistenceFailureAt: Long = 0L,
        val xdrPersistenceFailureAt: Long = 0L,
        val protectionMode: ProtectionMode = ProtectionMode.FULL_FLOW_BETA,
        val wireGuardEgressMode: WireGuardEgressMode = WireGuardEgressMode.DIRECT,
        val privacyProfile: PrivacyProfile = PrivacyProfile.CONSERVATIVE,
        val resilienceDesired: Boolean = false,
        val platformAlwaysOn: Boolean = false,
        val platformLockdown: Boolean = false,
        val platformPolicyObservedAt: Long = 0L,
        val vpnRecoveryCount: Long = 0L,
        val vpnRecoveryAt: Long = 0L,
        val vpnRecoveryReason: String? = null,
        val selfTestStatus: String? = null,
        val selfTestAt: Long = 0L,
        val selfTestDuration: Long = 0L,
    )

    companion object {
        private const val LOG_TAG = "GeDefenseRuntimeState"
        private const val PREFERENCES_NAME = "gedefense_runtime"
        private val TRANSIENT_VPN_STATES = setOf("GUARDED", "FULL_GUARDED", "LOCKDOWN_GUARDED", "STARTING", "RECOVERING")
        private val CONFIGURATION_LOCKED_VPN_STATES = setOf("STARTING", "RECOVERING")
        private const val MAX_SELF_TEST_DURATION_MS = 120_000L

        private const val KEY_VPN_STATUS = "vpn_status"
        private const val KEY_VPN_REASON = "vpn_reason"
        private const val KEY_FEED_SYNC = "feed_sync"
        private const val KEY_EVIDENCE_OK = "evidence_ok"
        private const val KEY_EVIDENCE_REASON = "evidence_reason"
        private const val KEY_EVIDENCE_PERSIST_COUNT = "persist_evidence_failures"
        private const val KEY_XDR_PERSIST_COUNT = "persist_xdr_failures"
        private const val KEY_EVIDENCE_PERSIST_CODE = "persist_evidence_failure_code"
        private const val KEY_XDR_PERSIST_CODE = "persist_xdr_failure_code"
        private const val KEY_EVIDENCE_PERSIST_AT = "persist_evidence_failure_at"
        private const val KEY_XDR_PERSIST_AT = "persist_xdr_failure_at"
        private const val KEY_PROTECTION_MODE = "protection_mode"
        private const val KEY_WIREGUARD_EGRESS_MODE = "wireguard_egress_mode"
        private const val KEY_PRIVACY_PROFILE = "privacy_profile"
        private const val KEY_RESILIENCE_DESIRED = "vpn_resilience_desired"
        private const val KEY_PLATFORM_ALWAYS_ON = "vpn_platform_always_on"
        private const val KEY_PLATFORM_LOCKDOWN = "vpn_platform_lockdown"
        private const val KEY_PLATFORM_POLICY_AT = "vpn_platform_policy_observed_at"
        private const val KEY_RECOVERY_COUNT = "vpn_recovery_count"
        private const val KEY_RECOVERY_AT = "vpn_recovery_at"
        private const val KEY_RECOVERY_REASON = "vpn_recovery_reason"
        private const val KEY_SELF_TEST_STATUS = "vpn_self_test_status"
        private const val KEY_SELF_TEST_AT = "vpn_self_test_at"
        private const val KEY_SELF_TEST_DURATION = "vpn_self_test_duration_ms"
    }
}
