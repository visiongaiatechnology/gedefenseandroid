package de.visiongaia.gedefense.mobile

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotState
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets

/**
 * Authenticated, crash-resistant Lockdown policy store.
 *
 * A corrupted policy fails closed: no package is implicitly allowed until the user explicitly
 * resets the policy. Quarantine and allowlist updates are committed in one authenticated snapshot
 * so they cannot diverge after a crash or concurrent response action.
 */
class FirewallPolicyStore(context: Context) {
    private val lock = Any()
    private val appContext = context.applicationContext
    private val pm = appContext.packageManager
    private val snapshotStore = SecureSnapshotStore(
        file = File(appContext.noBackupFilesDir, "firewall/policy.v2.bin"),
        hmacKey = null,
        domain = VaultDomain.FIREWALL_POLICY,
        schemaVersion = 2,
        maxPlaintextBytes = MAX_POLICY_BYTES,
        hmacKeyProvider = { SecureTelemetryVault.hotPathHmacKey(VaultDomain.FIREWALL_POLICY) },
        legacyHmacKeyProvider = { AndroidSecrets.hmacSha256OrNull("vgt.gedefense.mobile.firewall-policy.hmac.v2") },
    )

    @Volatile private var policyIntegrityOk = false
    @Volatile private var integrityReason: String? = "firewall_policy_initializing"
    private var allowedState = linkedSetOf<String>()
    private var quarantineState = linkedSetOf<String>()

    fun initialize() = loadOrMigrate()

    data class AppEntry(
        val packageName: String,
        val label: String,
        val systemApp: Boolean,
        val internetCapable: Boolean,
        val allowed: Boolean,
    )

    fun integrityOk(): Boolean = policyIntegrityOk
    fun integrityFailureReason(): String? = integrityReason

    fun allowedPackages(): Set<String> = synchronized(lock) {
        if (!policyIntegrityOk) return@synchronized emptySet()
        allowedState.asSequence()
            .filter { it != appContext.packageName && it !in quarantineState }
            .take(MAX_ALLOWED_PACKAGES)
            .toCollection(LinkedHashSet())
    }

    fun quarantinedPackages(): Set<String> = synchronized(lock) {
        if (!policyIntegrityOk) return@synchronized emptySet()
        quarantineState.take(MAX_QUARANTINED_PACKAGES).toCollection(LinkedHashSet())
    }

    fun hasQuarantinedPackages(): Boolean = synchronized(lock) { policyIntegrityOk && quarantineState.isNotEmpty() }

    fun isQuarantined(packageName: String): Boolean = synchronized(lock) {
        policyIntegrityOk && validPackageName(packageName) && packageName in quarantineState
    }

    fun setQuarantined(packageName: String, quarantined: Boolean): Boolean = synchronized(lock) {
        if (!policyIntegrityOk || !validPackageName(packageName) || packageName == appContext.packageName) return@synchronized false
        val nextAllowed = LinkedHashSet(allowedState)
        val nextQuarantine = LinkedHashSet(quarantineState)
        if (quarantined) {
            if (nextQuarantine.size >= MAX_QUARANTINED_PACKAGES && packageName !in nextQuarantine) return@synchronized false
            nextQuarantine += packageName
            nextAllowed -= packageName
        } else {
            nextQuarantine -= packageName
        }
        commit(nextAllowed, nextQuarantine)
    }

    fun installedPackageNames(): Set<String>? = try {
        val packages = if (Build.VERSION.SDK_INT >= 33) pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
        else { @Suppress("DEPRECATION") pm.getInstalledPackages(0) }
        packages.asSequence().map { it.packageName }.filter(::validPackageName).take(MAX_LISTED_PACKAGES * 2).toSet()
    } catch (_: RuntimeException) { null }

    fun setAllowed(packageName: String, allowed: Boolean): Boolean = synchronized(lock) {
        if (!policyIntegrityOk || !validPackageName(packageName) || packageName == appContext.packageName) return@synchronized false
        if (allowed && packageName in quarantineState) return@synchronized false
        val nextAllowed = LinkedHashSet(allowedState)
        if (allowed) {
            if (nextAllowed.size >= MAX_ALLOWED_PACKAGES && packageName !in nextAllowed) return@synchronized false
            nextAllowed += packageName
        } else {
            nextAllowed -= packageName
        }
        commit(nextAllowed, LinkedHashSet(quarantineState))
    }

    fun pruneMissingPackages(): Int = synchronized(lock) {
        if (!policyIntegrityOk || (allowedState.isEmpty() && quarantineState.isEmpty())) return@synchronized 0
        // One bounded PackageManager snapshot avoids interpreting a transient per-package Binder
        // failure as proof that an app vanished. No policy is pruned when inventory is unavailable.
        val installed = installedPackageNames() ?: return@synchronized 0
        val retainedAllowed = allowedState.filterTo(LinkedHashSet()) { it in installed }
        val retainedQuarantine = quarantineState.filterTo(LinkedHashSet()) { it in installed }
        if (retainedAllowed == allowedState && retainedQuarantine == quarantineState) return@synchronized 0
        val removed = (allowedState.size - retainedAllowed.size) + (quarantineState.size - retainedQuarantine.size)
        if (!commit(retainedAllowed, retainedQuarantine)) return@synchronized 0
        removed
    }

    fun resetPolicy(): Boolean = synchronized(lock) {
        val ok = writeState(emptySet(), emptySet())
        if (ok) {
            allowedState.clear()
            quarantineState.clear()
            policyIntegrityOk = true
            integrityReason = null
            legacyPrefs().edit().clear().apply()
        }
        ok
    }

    fun appEntries(): List<AppEntry> {
        pruneMissingPackages()
        val allowed = allowedPackages()
        val flags = PackageManager.GET_PERMISSIONS
        val packages = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(flags)
        }
        return packages.asSequence()
            .mapNotNull { pkg ->
                val app = pkg.applicationInfo ?: return@mapNotNull null
                if (pkg.packageName == appContext.packageName) return@mapNotNull null
                val requested = pkg.requestedPermissions?.toSet().orEmpty()
                val internet = Manifest.permission.INTERNET in requested
                if (!internet) return@mapNotNull null
                val system = app.flags and ApplicationInfo.FLAG_SYSTEM != 0 &&
                    app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP == 0
                val label = try { pm.getApplicationLabel(app).toString().take(140) }
                catch (_: RuntimeException) { pkg.packageName }
                AppEntry(pkg.packageName, label, system, internet, pkg.packageName in allowed)
            }
            .sortedWith(compareBy<AppEntry> { it.systemApp }.thenBy { it.label.lowercase() }.thenBy { it.packageName })
            .take(MAX_LISTED_PACKAGES)
            .toList()
    }

    private fun loadOrMigrate() = synchronized(lock) {
        val read = snapshotStore.read()
        when (read.state) {
                AuthenticatedSnapshotState.VALID -> {
                    val decoded = decode(read.payload ?: ByteArray(0))
                    if (decoded == null) {
                        failClosed("policy payload invalid")
                    } else {
                        allowedState = decoded.first
                        quarantineState = decoded.second
                        policyIntegrityOk = true
                        integrityReason = null
                        legacyPrefs().edit().clear().apply()
                    }
                }
                AuthenticatedSnapshotState.INVALID -> failClosed(read.reason ?: "policy authentication failed")
                AuthenticatedSnapshotState.ABSENT -> migrateLegacy()
        }
    }

    private fun migrateLegacy() {
        val allowed = legacyPrefs().getStringSet(LEGACY_KEY_ALLOWED, emptySet()).orEmpty()
            .asSequence().map(String::trim).filter(::validPackageName).filter { it != appContext.packageName }
            .take(MAX_ALLOWED_PACKAGES).toCollection(LinkedHashSet())
        val quarantine = legacyPrefs().getStringSet(LEGACY_KEY_QUARANTINED, emptySet()).orEmpty()
            .asSequence().map(String::trim).filter(::validPackageName).filter { it != appContext.packageName }
            .take(MAX_QUARANTINED_PACKAGES).toCollection(LinkedHashSet())
        allowed.removeAll(quarantine)
        if (!writeState(allowed, quarantine)) {
            failClosed("policy migration write failed")
            return
        }
        allowedState = allowed
        quarantineState = quarantine
        policyIntegrityOk = true
        integrityReason = null
        legacyPrefs().edit().clear().apply()
    }

    /** Legacy preferences are acquired only during explicit background migration. */
    private fun legacyPrefs() = appContext.getSharedPreferences(LEGACY_PREFS, Context.MODE_PRIVATE)

    private fun commit(nextAllowed: LinkedHashSet<String>, nextQuarantine: LinkedHashSet<String>): Boolean {
        nextAllowed.removeAll(nextQuarantine)
        if (!writeState(nextAllowed, nextQuarantine)) return false
        allowedState = nextAllowed
        quarantineState = nextQuarantine
        return true
    }

    private fun writeState(allowed: Set<String>, quarantine: Set<String>): Boolean {
        return try {
            val root = JSONObject()
                .put("version", 2)
                .put("allowed", JSONArray(allowed.sorted().take(MAX_ALLOWED_PACKAGES)))
                .put("quarantined", JSONArray(quarantine.sorted().take(MAX_QUARANTINED_PACKAGES)))
            val bytes = root.toString().toByteArray(StandardCharsets.UTF_8)
            if (bytes.size > MAX_POLICY_BYTES) false else { snapshotStore.write(bytes); true }
        } catch (_: Exception) { false }
    }

    private fun decode(payload: ByteArray): Pair<LinkedHashSet<String>, LinkedHashSet<String>>? {
        return try {
            if (payload.size > MAX_POLICY_BYTES) null
            else {
                val root = JSONObject(payload.toString(StandardCharsets.UTF_8))
                if (root.optInt("version") != 2) null
                else {
                    val allowed = jsonPackages(root.optJSONArray("allowed"), MAX_ALLOWED_PACKAGES)
                    val quarantine = jsonPackages(root.optJSONArray("quarantined"), MAX_QUARANTINED_PACKAGES)
                    allowed.removeAll(quarantine)
                    allowed to quarantine
                }
            }
        } catch (_: Exception) { null }
    }

    private fun jsonPackages(array: JSONArray?, limit: Int): LinkedHashSet<String> = linkedSetOf<String>().also { out ->
        if (array == null) return@also
        for (i in 0 until minOf(array.length(), limit)) {
            array.optString(i).trim().takeIf(::validPackageName)?.takeIf { it != appContext.packageName }?.let(out::add)
        }
    }

    private fun failClosed(reason: String) {
        allowedState.clear()
        quarantineState.clear()
        policyIntegrityOk = false
        integrityReason = reason.take(160)
    }

    private fun packageExists(packageName: String): Boolean = try {
        if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
        else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(packageName, 0)
        }
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    } catch (_: RuntimeException) {
        false
    }

    private fun validPackageName(value: String): Boolean = value.length in 3..256 &&
        value.contains('.') && value.none(Char::isWhitespace) && !value.startsWith(".") && !value.endsWith(".")

    companion object {
        private const val LEGACY_PREFS = "gedefense_firewall_policy"
        private const val LEGACY_KEY_ALLOWED = "allowed_packages"
        private const val LEGACY_KEY_QUARANTINED = "quarantined_packages"
        const val MAX_ALLOWED_PACKAGES = 512
        const val MAX_QUARANTINED_PACKAGES = 256
        private const val MAX_LISTED_PACKAGES = 1024
        private const val MAX_POLICY_BYTES = 256 * 1024
    }
}
