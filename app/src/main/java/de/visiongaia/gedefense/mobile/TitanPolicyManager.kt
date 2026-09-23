package de.visiongaia.gedefense.mobile

import android.app.PendingIntent
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Build
import android.os.UserManager
import de.visiongaia.gedefense.mobile.core.ManagedCaCertificateValidator
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference

class TitanPolicyManager(context: Context) {
    private val appContext = context.applicationContext
    private val dpm = appContext.getSystemService(DevicePolicyManager::class.java)
    private val admin = ComponentName(appContext, TitanDeviceAdminReceiver::class.java)
    val policyStore = TitanPolicyStore(appContext)
    private val cachedSnapshot = AtomicReference(unavailableSnapshot("titan_initializing"))
    private val suspendedPackages = ConcurrentHashMap<String, Boolean>()

    fun initialize() {
        policyStore.initialize()
        refreshSnapshot()
    }

    fun snapshot(): TitanSnapshot = cachedSnapshot.get()

    @Suppress("DEPRECATION")
    fun refreshSnapshot(): TitanSnapshot {
        val next = try {
            BoundedAndroidCall.call {
                val deviceOwner = dpm.isDeviceOwnerApp(appContext.packageName)
                val active = dpm.isAdminActive(admin)
                if (!active) {
                    return@call TitanSnapshot(
                        isDeviceOwner = deviceOwner,
                        adminActive = false,
                        policyStoreIntegrityOk = policyStore.integrityOk(),
                        policyStoreFailureReason = policyStore.integrityFailureReason(),
                        alwaysOnVpn = false,
                        alwaysOnLockdown = false,
                        debuggingBlocked = false,
                        unknownSourcesBlocked = false,
                        safeBootBlocked = false,
                        usbFileTransferBlocked = false,
                        verifyAppsEnforced = false,
                        highPasswordComplexityRequired = false,
                        wipeAfterFailedAttempts = 0,
                        autoSuspendOnQuarantine = policyStore.autoSuspendOnQuarantine(),
                        managedCaCount = 0,
                        maxTimeToLockMillis = 0L,
                        platformQueryOk = true,
                    )
                }

                if (!deviceOwner) {
                    val quality = dpm.getPasswordQuality(admin)
                    val wipeThreshold = dpm.getMaximumFailedPasswordsForWipe(admin)
                    val maxLock = dpm.getMaximumTimeToLock(admin)
                    return@call TitanSnapshot(
                        isDeviceOwner = false,
                        adminActive = true,
                        policyStoreIntegrityOk = policyStore.integrityOk(),
                        policyStoreFailureReason = policyStore.integrityFailureReason(),
                        alwaysOnVpn = false,
                        alwaysOnLockdown = false,
                        debuggingBlocked = false,
                        unknownSourcesBlocked = false,
                        safeBootBlocked = false,
                        usbFileTransferBlocked = false,
                        verifyAppsEnforced = false,
                        highPasswordComplexityRequired = quality >= DevicePolicyManager.PASSWORD_QUALITY_ALPHANUMERIC,
                        wipeAfterFailedAttempts = wipeThreshold,
                        autoSuspendOnQuarantine = false,
                        managedCaCount = 0,
                        maxTimeToLockMillis = maxLock,
                        platformQueryOk = true,
                    )
                }

                val restrictions = dpm.getUserRestrictions(admin)
                val alwaysOnPackage = dpm.getAlwaysOnVpnPackage(admin)
                val lockdown = dpm.isAlwaysOnVpnLockdownEnabled(admin)
                val highComplexity = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    dpm.requiredPasswordComplexity >= DevicePolicyManager.PASSWORD_COMPLEXITY_HIGH
                } else {
                    dpm.getPasswordQuality(admin) >= DevicePolicyManager.PASSWORD_QUALITY_ALPHANUMERIC
                }
                val wipeThreshold = dpm.getMaximumFailedPasswordsForWipe(admin)
                val maxLock = dpm.getMaximumTimeToLock(admin)
                TitanSnapshot(
                    isDeviceOwner = true,
                    adminActive = true,
                    policyStoreIntegrityOk = policyStore.integrityOk(),
                    policyStoreFailureReason = policyStore.integrityFailureReason(),
                    alwaysOnVpn = alwaysOnPackage == appContext.packageName,
                    alwaysOnLockdown = alwaysOnPackage == appContext.packageName && lockdown,
                    debuggingBlocked = restrictions.getBoolean(UserManager.DISALLOW_DEBUGGING_FEATURES, false),
                    unknownSourcesBlocked = restrictions.getBoolean(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES, false),
                    safeBootBlocked = restrictions.getBoolean(UserManager.DISALLOW_SAFE_BOOT, false),
                    usbFileTransferBlocked = restrictions.getBoolean(UserManager.DISALLOW_USB_FILE_TRANSFER, false),
                    verifyAppsEnforced = restrictions.getBoolean(UserManager.ENSURE_VERIFY_APPS, false),
                    highPasswordComplexityRequired = highComplexity,
                    wipeAfterFailedAttempts = wipeThreshold,
                    autoSuspendOnQuarantine = policyStore.autoSuspendOnQuarantine(),
                    managedCaCount = dpm.getInstalledCaCerts(admin).size,
                    maxTimeToLockMillis = maxLock,
                    platformQueryOk = true,
                )
            }
        } catch (error: PlatformCallUnavailableException) {
            unavailableSnapshot(error.reasonCode)
        } catch (_: RuntimeException) {
            unavailableSnapshot("titan_platform_failure")
        }
        cachedSnapshot.set(next)
        return next
    }

    fun refreshSuspendedPackages(packageNames: Collection<String>) {
        val targets = packageNames.asSequence()
            .filter { PACKAGE_PATTERN.matches(it) && it != appContext.packageName }
            .distinct()
            .take(MAX_SUSPENSION_REFRESH_PACKAGES)
            .toList()
        if (targets.isEmpty() || !snapshot().isDeviceOwner) return
        try {
            val refreshed = BoundedAndroidCall.call {
                if (!dpm.isDeviceOwnerApp(appContext.packageName)) return@call emptyMap<String, Boolean>()
                targets.associateWith { packageName ->
                    runCatching { dpm.isPackageSuspended(admin, packageName) }.getOrDefault(false)
                }
            }
            targets.forEach { packageName -> suspendedPackages[packageName] = refreshed[packageName] == true }
        } catch (_: RuntimeException) {
            // Existing cache remains authoritative for this process; no fail-open policy change occurs.
        }
    }

    fun isDeviceOwner(): Boolean = snapshot().isDeviceOwner
    fun isAdminActive(): Boolean = snapshot().adminActive
    fun isPackageSuspended(packageName: String): Boolean = suspendedPackages[packageName] == true

    fun setRestriction(key: String, enabled: Boolean): TitanActionResult {
        if (key !in ALLOWED_RESTRICTIONS) return TitanActionResult(false, "INVALID_RESTRICTION")
        return executePlatform("RESTRICTION_FAILED") {
            if (!dpm.isDeviceOwnerApp(appContext.packageName)) return@executePlatform TitanActionResult(false, "DEVICE_OWNER_REQUIRED")
            if (enabled) dpm.addUserRestriction(admin, key) else dpm.clearUserRestriction(admin, key)
            TitanActionResult(true, if (enabled) "RESTRICTION_ENABLED" else "RESTRICTION_DISABLED", key, changed = true)
        }
    }

    fun setAlwaysOnVpnLockdown(enabled: Boolean): TitanActionResult = executePlatform("ALWAYS_ON_FAILED") {
        if (!dpm.isDeviceOwnerApp(appContext.packageName)) return@executePlatform TitanActionResult(false, "DEVICE_OWNER_REQUIRED")
        if (enabled) dpm.setAlwaysOnVpnPackage(admin, appContext.packageName, true)
        else dpm.setAlwaysOnVpnPackage(admin, null, false)
        TitanActionResult(true, if (enabled) "ALWAYS_ON_ENABLED" else "ALWAYS_ON_DISABLED", changed = true)
    }

    @Suppress("DEPRECATION")
    fun setHighPasswordComplexity(enabled: Boolean): TitanActionResult = executePlatform("PASSWORD_POLICY_FAILED") {
        if (!dpm.isAdminActive(admin)) return@executePlatform TitanActionResult(false, "ADMIN_REQUIRED")
        if (dpm.isDeviceOwnerApp(appContext.packageName) && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            dpm.setRequiredPasswordComplexity(
                if (enabled) DevicePolicyManager.PASSWORD_COMPLEXITY_HIGH else DevicePolicyManager.PASSWORD_COMPLEXITY_NONE,
            )
        } else {
            dpm.setPasswordQuality(
                admin,
                if (enabled) DevicePolicyManager.PASSWORD_QUALITY_ALPHANUMERIC else DevicePolicyManager.PASSWORD_QUALITY_UNSPECIFIED,
            )
            dpm.setPasswordMinimumLength(admin, if (enabled) 8 else 0)
        }
        TitanActionResult(true, if (enabled) "PASSWORD_POLICY_ENABLED" else "PASSWORD_POLICY_DISABLED", changed = true)
    }

    fun setWipeThreshold(enabled: Boolean): TitanActionResult = executePlatform("WIPE_THRESHOLD_FAILED") {
        if (!dpm.isAdminActive(admin)) return@executePlatform TitanActionResult(false, "ADMIN_REQUIRED")
        dpm.setMaximumFailedPasswordsForWipe(admin, if (enabled) FAILED_PASSWORD_WIPE_THRESHOLD else 0)
        TitanActionResult(true, if (enabled) "WIPE_THRESHOLD_ENABLED" else "WIPE_THRESHOLD_DISABLED", changed = true)
    }

    fun lockDeviceNow(): TitanActionResult = executePlatform("DEVICE_LOCK_FAILED") {
        if (!dpm.isAdminActive(admin)) return@executePlatform TitanActionResult(false, "ADMIN_REQUIRED")
        dpm.lockNow()
        TitanActionResult(true, "DEVICE_LOCKED", changed = true)
    }

    fun setLightAutoLock(enabled: Boolean): TitanActionResult = executePlatform("AUTO_LOCK_FAILED") {
        if (!dpm.isAdminActive(admin)) return@executePlatform TitanActionResult(false, "ADMIN_REQUIRED")
        dpm.setMaximumTimeToLock(admin, if (enabled) TITAN_LIGHT_MAX_LOCK_MS else 0L)
        TitanActionResult(true, if (enabled) "AUTO_LOCK_ENABLED" else "AUTO_LOCK_DISABLED", changed = true)
    }

    fun setAutoSuspendOnQuarantine(enabled: Boolean): TitanActionResult {
        if (!snapshot().isDeviceOwner) return TitanActionResult(false, "DEVICE_OWNER_REQUIRED")
        if (!policyStore.integrityOk()) return TitanActionResult(false, "TITAN_POLICY_INVALID")
        if (!policyStore.setAutoSuspendOnQuarantine(enabled)) return TitanActionResult(false, "TITAN_POLICY_WRITE_FAILED")
        refreshSnapshot()
        return TitanActionResult(true, if (enabled) "AUTO_SUSPEND_ENABLED" else "AUTO_SUSPEND_DISABLED", changed = true)
    }

    fun enforceQuarantine(packageName: String, quarantine: Boolean): TitanActionResult {
        if (!snapshot().isDeviceOwner) return TitanActionResult(false, "DEVICE_OWNER_INACTIVE")
        if (quarantine && !policyStore.autoSuspendOnQuarantine()) return TitanActionResult(true, "NETWORK_ONLY_QUARANTINE")
        return setPackageSuspended(packageName, quarantine)
    }

    fun setPackageSuspended(packageName: String, suspended: Boolean): TitanActionResult {
        if (packageName == appContext.packageName || !PACKAGE_PATTERN.matches(packageName)) return TitanActionResult(false, "PROTECTED_PACKAGE")
        val result = executePlatform("PACKAGE_SUSPEND_FAILED") {
            if (!dpm.isDeviceOwnerApp(appContext.packageName)) return@executePlatform TitanActionResult(false, "DEVICE_OWNER_REQUIRED")
            if (suspended && isProtectedSystemPackageDirect(packageName)) return@executePlatform TitanActionResult(false, "SYSTEM_PACKAGE_NOT_SUSPENDED")
            val failed = dpm.setPackagesSuspended(admin, arrayOf(packageName), suspended)
            if (failed.isEmpty()) TitanActionResult(true, if (suspended) "PACKAGE_SUSPENDED" else "PACKAGE_UNSUSPENDED", changed = true)
            else TitanActionResult(false, "PACKAGE_SUSPEND_REJECTED")
        }
        if (result.ok) suspendedPackages[packageName] = suspended
        return result
    }

    fun uninstallUserPackage(packageName: String): TitanActionResult {
        if (packageName == appContext.packageName || !PACKAGE_PATTERN.matches(packageName)) return TitanActionResult(false, "PROTECTED_PACKAGE")
        return executePlatform("UNINSTALL_FAILED") {
            if (!dpm.isDeviceOwnerApp(appContext.packageName)) return@executePlatform TitanActionResult(false, "DEVICE_OWNER_REQUIRED")
            if (isProtectedSystemPackageDirect(packageName)) return@executePlatform TitanActionResult(false, "SYSTEM_PACKAGE_NOT_REMOVED")
            val nonce = ByteArray(16).also(UNINSTALL_RANDOM::nextBytes).let(::hex)
            val resultIntent = Intent(appContext, TitanPackageOperationReceiver::class.java)
                .setAction(TitanPackageOperationReceiver.ACTION_UNINSTALL_RESULT)
                .setData(
                    Uri.Builder()
                        .scheme(TitanPackageOperationReceiver.RESULT_SCHEME)
                        .authority(TitanPackageOperationReceiver.RESULT_AUTHORITY)
                        .appendPath(packageName)
                        .appendPath(nonce)
                        .build(),
                )
            val pending = PendingIntent.getBroadcast(
                appContext,
                UNINSTALL_RANDOM.nextInt(),
                resultIntent,
                PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_ONE_SHOT,
            )
            appContext.packageManager.packageInstaller.uninstall(packageName, pending.intentSender)
            TitanActionResult(true, "UNINSTALL_REQUESTED", changed = true)
        }
    }

    fun inspectCaCertificate(certBytes: ByteArray): TitanCaCertificateInfo? {
        val cert = ManagedCaCertificateValidator.inspect(certBytes) ?: return null
        return TitanCaCertificateInfo(
            subject = cert.subject,
            issuer = cert.issuer,
            sha256Fingerprint = cert.sha256Fingerprint,
            notAfterMillis = cert.notAfterMillis,
        )
    }

    fun installCaCertificate(certBytes: ByteArray): TitanActionResult {
        val cert = ManagedCaCertificateValidator.inspect(certBytes) ?: return TitanActionResult(false, "INVALID_CA_CERTIFICATE")
        return executePlatform("CA_CERT_INSTALL_FAILED") {
            if (!dpm.isDeviceOwnerApp(appContext.packageName)) return@executePlatform TitanActionResult(false, "DEVICE_OWNER_REQUIRED")
            if (dpm.installCaCert(admin, cert.encoded)) {
                TitanActionResult(true, "CA_CERT_INSTALLED", cert.subject.take(180), changed = true)
            } else {
                TitanActionResult(false, "CA_CERT_INSTALL_REJECTED")
            }
        }
    }

    private fun executePlatform(failureCode: String, action: () -> TitanActionResult): TitanActionResult {
        val result = try {
            BoundedAndroidCall.call(action = action)
        } catch (error: PlatformCallUnavailableException) {
            TitanActionResult(false, failureCode, error.reasonCode)
        } catch (_: RuntimeException) {
            TitanActionResult(false, failureCode, "platform_failure")
        }
        if (result.ok && result.changed) refreshSnapshot()
        return result
    }

    private fun unavailableSnapshot(reason: String): TitanSnapshot = TitanSnapshot(
        isDeviceOwner = false,
        adminActive = false,
        policyStoreIntegrityOk = false,
        policyStoreFailureReason = reason.take(96),
        alwaysOnVpn = false,
        alwaysOnLockdown = false,
        debuggingBlocked = false,
        unknownSourcesBlocked = false,
        safeBootBlocked = false,
        usbFileTransferBlocked = false,
        verifyAppsEnforced = false,
        highPasswordComplexityRequired = false,
        wipeAfterFailedAttempts = 0,
        autoSuspendOnQuarantine = false,
        managedCaCount = 0,
        maxTimeToLockMillis = 0L,
        platformQueryOk = false,
        platformFailureReason = reason.take(96),
    )

    private fun isProtectedSystemPackageDirect(packageName: String): Boolean = try {
        val info = appContext.packageManager.getApplicationInfo(packageName, 0)
        (info.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
    } catch (_: Exception) {
        true
    }

    companion object {
        private val UNINSTALL_RANDOM = SecureRandom()
        private val HEX = "0123456789abcdef".toCharArray()
        private const val MAX_SUSPENSION_REFRESH_PACKAGES = 64

        private fun hex(bytes: ByteArray): String {
            val out = CharArray(bytes.size * 2)
            var cursor = 0
            for (byte in bytes) {
                val value = byte.toInt() and 0xff
                out[cursor++] = HEX[value ushr 4]
                out[cursor++] = HEX[value and 0x0f]
            }
            return String(out)
        }

        const val FAILED_PASSWORD_WIPE_THRESHOLD = 10
        const val TITAN_LIGHT_MAX_LOCK_MS = 2L * 60L * 1000L
        const val MAX_CA_CERT_BYTES = ManagedCaCertificateValidator.MAX_BYTES
        const val ADB_COMPONENT = "de.visiongaia.gedefense.mobile/.TitanDeviceAdminReceiver"
        private val PACKAGE_PATTERN = Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+")
        private val ALLOWED_RESTRICTIONS = setOf(
            UserManager.DISALLOW_DEBUGGING_FEATURES,
            UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES,
            UserManager.DISALLOW_SAFE_BOOT,
            UserManager.DISALLOW_USB_FILE_TRANSFER,
            UserManager.ENSURE_VERIFY_APPS,
        )
    }
}
