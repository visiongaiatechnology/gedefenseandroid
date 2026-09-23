package de.visiongaia.gedefense.mobile

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.provider.Settings
import java.io.File
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit
import java.util.Locale

/**
 * Dependency-free Android hardening assessment. Every control must be observable locally; unknown
 * states are reported as UNKNOWN instead of being converted into a reassuring pass.
 */
class DeviceHardeningScanner(context: Context) {
    private val appContext = context.applicationContext
    private val resolver = appContext.contentResolver
    private val pm = appContext.packageManager

    fun scan(nowMillis: Long = System.currentTimeMillis()): HardeningSnapshot {
        val findings = ArrayList<HardeningFinding>(16)
        findings += screenLock()
        findings += securityPatch(nowMillis)
        findings += adb()
        findings += developerOptions()
        findings += selinux()
        findings += verifiedBoot()
        findings += rootIndicators()
        findings += storageEncryption()
        findings += privateDns()
        findings += accessibilityServices()
        findings += notificationListeners()
        findings += deviceAdmins()
        val score = (100 - findings.sumOf { it.pointsLost.coerceAtLeast(0) }).coerceIn(0, 100)
        return HardeningSnapshot(nowMillis, score, findings)
    }

    private fun screenLock(): HardeningFinding {
        val secure = runCatching { appContext.getSystemService(KeyguardManager::class.java)?.isDeviceSecure }.getOrNull()
        return when (secure) {
            true -> pass("screen_lock", HardeningCategory.LOCKSCREEN, "Secure screen lock", "A credential-protected lock screen is configured.", "KeyguardManager.isDeviceSecure=true")
            false -> fail("screen_lock", HardeningCategory.LOCKSCREEN, HardeningSeverity.CRITICAL, "Secure screen lock missing", "The device has no secure credential lock screen.", "KeyguardManager.isDeviceSecure=false", "Configure a PIN, password or strong biometric-backed device credential.", 25, Settings.ACTION_SECURITY_SETTINGS)
            null -> unknown("screen_lock", HardeningCategory.LOCKSCREEN, "Secure screen lock", "The device lock state could not be read through KeyguardManager.", "KeyguardManager.isDeviceSecure=unknown")
        }
    }

    private fun securityPatch(nowMillis: Long): HardeningFinding {
        val raw = Build.VERSION.SECURITY_PATCH.orEmpty().trim()
        val days = runCatching {
            val patch = LocalDate.parse(raw)
            val now = java.time.Instant.ofEpochMilli(nowMillis).atZone(ZoneOffset.UTC).toLocalDate()
            ChronoUnit.DAYS.between(patch, now).coerceAtLeast(0)
        }.getOrNull()
        return when {
            days == null -> unknown("security_patch", HardeningCategory.PATCHING, "Android security patch", "Patch age could not be determined.", "security_patch=${raw.ifBlank { "unknown" }}")
            days <= 90 -> pass("security_patch", HardeningCategory.PATCHING, "Android security patch", "Security patch level is recent.", "security_patch=$raw; age_days=$days")
            days <= 180 -> review("security_patch", HardeningCategory.PATCHING, HardeningSeverity.MEDIUM, "Security patch aging", "The Android security patch is more than 90 days old.", "security_patch=$raw; age_days=$days", "Install the latest system/security update offered by the device vendor.", 8, ACTION_SYSTEM_UPDATE_SETTINGS)
            else -> fail("security_patch", HardeningCategory.PATCHING, HardeningSeverity.HIGH, "Security patch outdated", "The Android security patch is more than 180 days old.", "security_patch=$raw; age_days=$days", "Install the latest system/security update. If the vendor no longer supplies patches, consider a supported device/OS.", 18, ACTION_SYSTEM_UPDATE_SETTINGS)
        }
    }

    private fun adb(): HardeningFinding {
        return when (val state = globalInt(Settings.Global.ADB_ENABLED)) {
            0 -> pass("adb", HardeningCategory.DEBUGGING, "USB/Wireless debugging", "ADB debugging is disabled.", "adb_enabled=0")
            1 -> fail("adb", HardeningCategory.DEBUGGING, HardeningSeverity.HIGH, "ADB debugging enabled", "Android Debug Bridge is enabled and expands the local attack surface.", "adb_enabled=1", "Disable USB/Wireless debugging when it is not actively required.", 14, Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
            else -> unknown("adb", HardeningCategory.DEBUGGING, "USB/Wireless debugging", "ADB state could not be read from Android global settings.", "adb_enabled=${state ?: "unknown"}")
        }
    }

    private fun developerOptions(): HardeningFinding {
        return when (val state = globalInt(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED)) {
            0 -> pass("developer_options", HardeningCategory.DEBUGGING, "Developer options", "Developer options are disabled.", "development_settings_enabled=0")
            1 -> review("developer_options", HardeningCategory.DEBUGGING, HardeningSeverity.LOW, "Developer options enabled", "Developer options are enabled. This is not inherently unsafe, but security-sensitive toggles should be reviewed.", "development_settings_enabled=1", "Disable developer options on production devices when they are not needed.", 3, Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
            else -> unknown("developer_options", HardeningCategory.DEBUGGING, "Developer options", "Developer-options state could not be read from Android global settings.", "development_settings_enabled=${state ?: "unknown"}")
        }
    }

    private fun selinux(): HardeningFinding {
        val value = runCatching { File("/sys/fs/selinux/enforce").takeIf(File::canRead)?.readText()?.trim() }.getOrNull()
        return when (value) {
            "1" -> pass("selinux", HardeningCategory.PLATFORM, "SELinux enforcement", "SELinux is enforcing mandatory access controls.", "selinux_enforce=1")
            "0" -> fail("selinux", HardeningCategory.PLATFORM, HardeningSeverity.CRITICAL, "SELinux permissive", "SELinux is not enforcing mandatory access controls.", "selinux_enforce=0", "Restore an enforcing, vendor-supported Android build.", 25)
            else -> unknown("selinux", HardeningCategory.PLATFORM, "SELinux enforcement", "SELinux state could not be read on this device.", "selinux_enforce=unknown")
        }
    }

    private fun verifiedBoot(): HardeningFinding {
        val cmdline = readSmallFile("/proc/cmdline", 32 * 1024) + " " + readSmallFile("/proc/bootconfig", 64 * 1024)
        val normalized = cmdline.lowercase(Locale.ROOT)
        val green = "verifiedbootstate=green" in normalized || "androidboot.verifiedbootstate=green" in normalized
        val orange = "verifiedbootstate=orange" in normalized || "androidboot.verifiedbootstate=orange" in normalized
        val unlocked = "flash.locked=0" in normalized || "androidboot.flash.locked=0" in normalized
        return when {
            unlocked || orange -> fail("verified_boot", HardeningCategory.PLATFORM, HardeningSeverity.HIGH, "Verified Boot / bootloader weakened", "Boot metadata indicates an unlocked or non-green verified boot state.", summarizeBoot(normalized), "Use a locked bootloader and a verified, trusted OS image where your threat model requires it.", 18)
            green -> pass("verified_boot", HardeningCategory.PLATFORM, "Verified Boot", "Boot metadata reports a green verified boot state.", summarizeBoot(normalized))
            Build.TAGS?.contains("test-keys") == true -> review("verified_boot", HardeningCategory.PLATFORM, HardeningSeverity.MEDIUM, "Non-production build tags", "The OS reports test-keys and should be reviewed.", "build_tags=${Build.TAGS}", "Prefer a production-signed, maintained Android build unless this is intentional.", 8)
            else -> unknown("verified_boot", HardeningCategory.PLATFORM, "Verified Boot", "Verified Boot state is not exposed to this app on this device.", "verified_boot=unknown")
        }
    }

    private fun rootIndicators(): HardeningFinding {
        val indicators = ROOT_PATHS.filter { runCatching { File(it).exists() }.getOrDefault(false) }.take(4)
        return if (indicators.isEmpty()) pass("root", HardeningCategory.PLATFORM, "Root indicators", "No common root-management binaries were found.", "common_su_paths=absent")
        else fail("root", HardeningCategory.PLATFORM, HardeningSeverity.HIGH, "Root indicators detected", "Common root-management binaries are present. Root may be intentional, but it weakens Android's application isolation model.", "paths=${indicators.joinToString(",")}", "Remove root access on devices that require a hardened production security posture, or explicitly accept the risk.", 18)
    }

    private fun storageEncryption(): HardeningFinding {
        val dpm = appContext.getSystemService(DevicePolicyManager::class.java)
        val status = runCatching { dpm?.storageEncryptionStatus }.getOrNull()
        return when (status) {
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE,
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER,
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY -> pass("encryption", HardeningCategory.ENCRYPTION, "Storage encryption", "Android reports active storage encryption.", "encryption_status=$status")
            DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE -> fail("encryption", HardeningCategory.ENCRYPTION, HardeningSeverity.CRITICAL, "Storage encryption inactive", "Device storage is reported as not encrypted.", "encryption_status=$status", "Enable device encryption or migrate to a supported Android device where file-based encryption is active by default.", 25, Settings.ACTION_SECURITY_SETTINGS)
            else -> unknown("encryption", HardeningCategory.ENCRYPTION, "Storage encryption", "Encryption status could not be confirmed through the public device-policy API.", "encryption_status=${status ?: "unknown"}")
        }
    }

    private fun privateDns(): HardeningFinding {
        val mode = globalString("private_dns_mode").lowercase(Locale.ROOT)
        val specifier = globalString("private_dns_specifier")
        return when (mode) {
            "hostname" -> pass("private_dns", HardeningCategory.NETWORK, "Private DNS", "Strict Private DNS is configured.", "mode=hostname; provider=${specifier.take(120)}")
            "opportunistic", "automatic" -> review("private_dns", HardeningCategory.NETWORK, HardeningSeverity.LOW, "Private DNS automatic", "Private DNS is opportunistic/automatic rather than pinned to a provider.", "mode=$mode", "Use a trusted strict Private DNS provider if it fits your network model, or rely on GeDefense DNS enforcement when available.", 2, ACTION_PRIVATE_DNS_SETTINGS)
            "off" -> review("private_dns", HardeningCategory.NETWORK, HardeningSeverity.MEDIUM, "Private DNS disabled", "System Private DNS is disabled.", "mode=off", "Enable Private DNS or use a trusted encrypted DNS path.", 5, ACTION_PRIVATE_DNS_SETTINGS)
            else -> unknown("private_dns", HardeningCategory.NETWORK, "Private DNS", "Private DNS state is not exposed consistently by this Android build.", "mode=${mode.ifBlank { "unknown" }}")
        }
    }

    private fun accessibilityServices(): HardeningFinding {
        val packages = componentPackages(secureString(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES))
            .filterNot { isSystemPackage(it) }
            .distinct()
        return if (packages.isEmpty()) pass("accessibility", HardeningCategory.PRIVILEGED_ACCESS, "Third-party accessibility services", "No third-party accessibility service is currently enabled.", "third_party_accessibility=0")
        else review("accessibility", HardeningCategory.PRIVILEGED_ACCESS, HardeningSeverity.HIGH, "Third-party accessibility access", "Accessibility services can observe UI content and perform actions on behalf of the user. Review every enabled service.", "packages=${packages.take(8).joinToString(",")}", "Disable accessibility access for apps that do not explicitly require it.", 8, Settings.ACTION_ACCESSIBILITY_SETTINGS)
    }

    private fun notificationListeners(): HardeningFinding {
        val packages = componentPackages(secureString("enabled_notification_listeners")).filterNot { isSystemPackage(it) }.distinct()
        return if (packages.isEmpty()) pass("notification_listeners", HardeningCategory.PRIVILEGED_ACCESS, "Notification access", "No third-party notification listener is currently enabled.", "third_party_notification_listeners=0")
        else review("notification_listeners", HardeningCategory.PRIVILEGED_ACCESS, HardeningSeverity.MEDIUM, "Third-party notification access", "Notification listeners can read notification content and should be explicitly trusted.", "packages=${packages.take(8).joinToString(",")}", "Revoke notification access from apps that do not need it.", 4, Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
    }

    private fun deviceAdmins(): HardeningFinding {
        val dpm = appContext.getSystemService(DevicePolicyManager::class.java)
            ?: return unknown("device_admin", HardeningCategory.PRIVILEGED_ACCESS, "Third-party device administrators", "DevicePolicyManager is unavailable on this device.", "device_admin=unknown")
        val active = try { dpm.activeAdmins.orEmpty().map(ComponentName::getPackageName).distinct() }
        catch (_: RuntimeException) { return unknown("device_admin", HardeningCategory.PRIVILEGED_ACCESS, "Third-party device administrators", "Active device administrators could not be queried.", "device_admin=unknown") }
        val selfActive = appContext.packageName in active
        val packages = active.filterNot { it == appContext.packageName || isSystemPackage(it) }
        return when {
            packages.isNotEmpty() -> review(
                "device_admin", HardeningCategory.PRIVILEGED_ACCESS, HardeningSeverity.HIGH,
                "Third-party device administrator",
                "Legacy device-admin privileges are powerful and should be granted only to explicitly trusted software.",
                "packages=${packages.take(8).joinToString(",")}; gedefense_admin=$selfActive",
                "Review and deactivate unneeded device administrators.", 8, Settings.ACTION_SECURITY_SETTINGS,
            )
            selfActive -> pass(
                "device_admin", HardeningCategory.PRIVILEGED_ACCESS, "GeDefense device administrator",
                "GeDefense TITAN Light is the only non-system legacy device administrator currently active.",
                "third_party_device_admins=0; gedefense_admin=1",
            )
            else -> pass(
                "device_admin", HardeningCategory.PRIVILEGED_ACCESS, "Third-party device administrators",
                "No third-party legacy device administrator is active.", "third_party_device_admins=0; gedefense_admin=0",
            )
        }
    }

    private fun pass(id: String, category: HardeningCategory, title: String, summary: String, evidence: String) =
        HardeningFinding(id, category, HardeningStatus.PASS, HardeningSeverity.INFO, title, summary, evidence, "", 0)

    private fun review(id: String, category: HardeningCategory, severity: HardeningSeverity, title: String, summary: String, evidence: String, remediation: String, points: Int, action: String? = null) =
        HardeningFinding(id, category, HardeningStatus.REVIEW, severity, title, summary, evidence, remediation, points, action)

    private fun fail(id: String, category: HardeningCategory, severity: HardeningSeverity, title: String, summary: String, evidence: String, remediation: String, points: Int, action: String? = null) =
        HardeningFinding(id, category, HardeningStatus.FAIL, severity, title, summary, evidence, remediation, points, action)

    private fun unknown(id: String, category: HardeningCategory, title: String, summary: String, evidence: String) =
        HardeningFinding(id, category, HardeningStatus.UNKNOWN, HardeningSeverity.INFO, title, summary, evidence, "", 0)

    private fun globalInt(key: String): Int? = runCatching { Settings.Global.getInt(resolver, key) }.getOrNull()
    private fun globalString(key: String): String = runCatching { Settings.Global.getString(resolver, key).orEmpty() }.getOrDefault("")
    private fun secureString(key: String): String = runCatching { Settings.Secure.getString(resolver, key).orEmpty() }.getOrDefault("")

    private fun componentPackages(raw: String): List<String> = raw.split(':').mapNotNull {
        ComponentName.unflattenFromString(it.trim())?.packageName?.takeIf(String::isNotBlank)
    }

    @Suppress("DEPRECATION")
    private fun isSystemPackage(packageName: String): Boolean = runCatching {
        val info = if (Build.VERSION.SDK_INT >= 33) pm.getApplicationInfo(packageName, android.content.pm.PackageManager.ApplicationInfoFlags.of(0))
        else pm.getApplicationInfo(packageName, 0)
        (info.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0 || (info.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
    }.getOrDefault(false)

    private fun readSmallFile(path: String, maxChars: Int): String = runCatching {
        val file = File(path)
        if (!file.isFile || !file.canRead() || file.length() > maxChars * 4L) "" else file.readText().take(maxChars)
    }.getOrDefault("")

    private fun summarizeBoot(value: String): String {
        val tokens = value.split(' ', '\n').filter {
            it.contains("verifiedbootstate") || it.contains("flash.locked") || it.contains("vbmeta.device_state")
        }.take(6)
        return if (tokens.isEmpty()) "boot_state=unknown" else tokens.joinToString(";").take(320)
    }

    companion object {
        private const val ACTION_SYSTEM_UPDATE_SETTINGS = "android.settings.SYSTEM_UPDATE_SETTINGS"
        private const val ACTION_PRIVATE_DNS_SETTINGS = "android.settings.PRIVATE_DNS_SETTINGS"
        private val ROOT_PATHS = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
            "/data/adb/magisk", "/data/adb/ksu", "/system/app/Superuser.apk",
        )
    }
}
