package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.UserManager
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.io.ByteArrayOutputStream
import java.text.DateFormat
import java.util.Date

class TitanActivity : Activity() {
    private lateinit var runtime: AppRuntime
    private lateinit var rootLayout: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runtime = RuntimeActivityEntry.requireReady(this) ?: return
        setContentView(buildRoot())
        render()
    }

    override fun onResume() {
        super.onResume()
        if (TitanVisualMode.refresh(this)) {
            recreate()
            return
        }
        if (::rootLayout.isInitialized) render()
        runtime.refreshTitanSnapshotAsync {
            runOnUiThread {
                if (!isFinishing && !isDestroyed && ::rootLayout.isInitialized) render()
            }
        }
    }

    private fun buildRoot(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))
        val scroll = ScrollView(this).apply { clipToPadding = false; overScrollMode = View.OVER_SCROLL_NEVER }
        VgtUiPerformance.bindScroll(scroll)
        rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(16), dp(18), dp(48))
        }
        scroll.addView(rootLayout, FrameLayout.LayoutParams(-1, -2))
        root.addView(scroll, FrameLayout.LayoutParams(-1, -1))
        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            rootLayout.setPadding(dp(18) + safe.left, dp(16) + safe.top, dp(18) + safe.right, dp(48) + safe.bottom)
            insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun render() {
        val snapshot = runtime.titan.snapshot()
        rootLayout.removeAllViews()
        rootLayout.addView(VgtUiComponents.screenHeader(this, getString(R.string.titan_title), getString(R.string.titan_subtitle)))
        gap(14)
        rootLayout.addView(statusCard(snapshot))
        gap(12)
        rootLayout.addView(commandDeck(snapshot))

        if (snapshot.titanLightActive) {
            gap(14)
            rootLayout.addView(titanLightProtectionCard(snapshot))
            gap(14)
            rootLayout.addView(capabilityCard(snapshot))
            gap(14)
            rootLayout.addView(provisioningCard())
            return
        }
        if (!snapshot.titanActive) {
            gap(14)
            rootLayout.addView(provisioningCard())
            gap(14)
            rootLayout.addView(capabilityCard(snapshot))
            return
        }

        gap(14)
        rootLayout.addView(capabilityCard(snapshot))
        gap(14)
        rootLayout.addView(networkEnforcementCard(snapshot))
        gap(14)
        rootLayout.addView(hardwareHardeningCard(snapshot))
        gap(14)
        rootLayout.addView(credentialCard(snapshot))
        gap(14)
        rootLayout.addView(trustAnchorsCard(snapshot))
        gap(14)
        rootLayout.addView(quarantineCard(snapshot))
    }

    private fun statusCard(snapshot: TitanSnapshot): View {
        val accent = when {
            !snapshot.policyStoreIntegrityOk -> GeDefenseUi.red
            snapshot.titanActive -> GeDefenseUi.gold
            snapshot.titanLightActive -> GeDefenseUi.cyan
            else -> GeDefenseUi.cyan
        }
        val title = when {
            !snapshot.policyStoreIntegrityOk -> getString(R.string.titan_state_degraded)
            snapshot.titanActive -> getString(R.string.titan_state_active)
            snapshot.titanLightActive -> getString(R.string.titan_light_state_active)
            else -> getString(R.string.titan_state_standard)
        }
        val body = when {
            !snapshot.policyStoreIntegrityOk -> getString(R.string.titan_store_failed, snapshot.policyStoreFailureReason ?: "unknown")
            snapshot.titanActive -> getString(R.string.titan_state_active_body)
            snapshot.titanLightActive -> getString(R.string.titan_light_state_body)
            else -> getString(R.string.titan_state_standard_body)
        }
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = GeDefenseUi.heroPanelBackground(this@TitanActivity, snapshot.titanActive || snapshot.titanLightActive)
            setPadding(dp(20), dp(20), dp(20), dp(20))
            addView(LinearLayout(this@TitanActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                val core = TitanCoreView(this@TitanActivity).apply { activeState = snapshot.titanActive || snapshot.titanLightActive }
                addView(core, LinearLayout.LayoutParams(dp(86), dp(86)))
                addView(LinearLayout(this@TitanActivity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(15), 0, 0, 0)
                    addView(GeDefenseUi.textView(this@TitanActivity, getString(R.string.titan_control_plane), 10.5f, accent, bold = true).apply {
                        letterSpacing = 0.14f
                        setAllCaps(true)
                    })
                    addView(GeDefenseUi.displayTextView(this@TitanActivity, title, 18.5f, GeDefenseUi.text).apply {
                        setPadding(0, dp(5), 0, dp(7))
                    })
                    addView(GeDefenseUi.pill(this@TitanActivity, getString(when { snapshot.titanActive -> R.string.titan_managed_online; snapshot.titanLightActive -> R.string.titan_light_mode; else -> R.string.titan_local_mode }), accent))
                }, LinearLayout.LayoutParams(0, -2, 1f))
            })
            addView(GeDefenseUi.textView(this@TitanActivity, body, 12.3f, GeDefenseUi.textMuted).apply {
                setLineSpacing(dp(2).toFloat(), 1.08f)
            }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(16) })
            if (snapshot.titanActive) {
                addView(GeDefenseUi.monoTextView(this@TitanActivity, getString(R.string.titan_managed_stamp), 10.2f, GeDefenseUi.cyan).apply {
                    letterSpacing = 0.07f
                    setPadding(0, dp(13), 0, 0)
                })
            }
            if (!snapshot.policyStoreIntegrityOk) {
                addView(GeDefenseUi.actionButton(this@TitanActivity, getString(R.string.titan_reset_local_policy), goldStyle = true) {
                    val accepted = runtime.executeBackground("titan-reset-local-policy") {
                        val ok = try { runtime.titan.policyStore.reset() } catch (_: RuntimeException) { false }
                        if (ok) runtime.titan.refreshSnapshot()
                        runOnUiThread {
                            if (isFinishing || isDestroyed) return@runOnUiThread
                            if (!ok) toast(R.string.titan_action_failed)
                            render()
                        }
                    }
                    if (!accepted) toast(R.string.titan_action_failed)
                }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(15) })
            }
        }
    }

    private fun provisioningCard(): View {
        val command = "adb shell dpm set-device-owner --user 0 ${TitanPolicyManager.ADB_COMPONENT}"
        val xiaomiDevice = Build.MANUFACTURER.contains("xiaomi", ignoreCase = true) ||
            Build.BRAND.contains("xiaomi", ignoreCase = true) || Build.BRAND.contains("redmi", ignoreCase = true) ||
            Build.BRAND.contains("poco", ignoreCase = true)
        return sectionCard(VgtIcon.POLICY, GeDefenseUi.gold, getString(R.string.titan_activation_title), listOf(
            GeDefenseUi.textView(this, getString(R.string.titan_activation_body), 12.2f, GeDefenseUi.textMuted),
            activationMethodCard(
                number = "01",
                title = getString(R.string.titan_qr_title),
                badge = getString(R.string.titan_recommended),
                body = getString(R.string.titan_qr_body),
                accent = GeDefenseUi.green,
            ),
            activationMethodCard(
                number = "02",
                title = getString(R.string.titan_adb_title),
                badge = getString(R.string.titan_manual),
                body = getString(R.string.titan_adb_requirements),
                accent = GeDefenseUi.cyan,
                extra = adbCommandWell(command),
                actionLabel = getString(R.string.titan_copy_adb),
                action = { copyToClipboard(command) },
            ),
            activationMethodCard(
                number = "03",
                title = getString(R.string.titan_xiaomi_title),
                badge = getString(if (xiaomiDevice) R.string.titan_xiaomi_detected else R.string.titan_xiaomi_oem),
                body = getString(R.string.titan_xiaomi_body),
                accent = GeDefenseUi.gold,
                extra = xiaomiProvisioningGuide(xiaomiDevice),
                actionLabel = getString(R.string.titan_open_android_settings),
                action = { try { startActivity(Intent(Settings.ACTION_SETTINGS)) } catch (_: RuntimeException) { toast(R.string.titan_action_failed) } },
            ),
        ))
    }


    private fun commandDeck(snapshot: TitanSnapshot): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = GeDefenseUi.glassPanelBackground(this@TitanActivity, accent = GeDefenseUi.gold, radius = 20)
        setPadding(dp(18), dp(17), dp(18), dp(17))
        addView(GeDefenseUi.textView(this@TitanActivity, getString(R.string.titan_command_deck), 10.4f, GeDefenseUi.goldSoft, bold = true).apply {
            letterSpacing = 0.13f
            setAllCaps(true)
        })
        addView(LinearLayout(this@TitanActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(commandTile(
                getString(R.string.titan_deck_dpc),
                getString(when { snapshot.titanActive -> R.string.titan_deck_owner; snapshot.titanLightActive -> R.string.titan_deck_light; else -> R.string.titan_deck_standard }),
                when { snapshot.titanActive -> GeDefenseUi.green; snapshot.titanLightActive -> GeDefenseUi.cyan; else -> GeDefenseUi.textDim },
            ), LinearLayout.LayoutParams(0, -2, 1f))
            addView(commandTile(
                getString(R.string.titan_deck_vpn),
                getString(if (snapshot.alwaysOnLockdown) R.string.titan_deck_locked else R.string.titan_deck_user),
                if (snapshot.alwaysOnLockdown) GeDefenseUi.green else GeDefenseUi.gold,
            ), LinearLayout.LayoutParams(0, -2, 1f).apply { marginStart = dp(8) })
            addView(commandTile(
                getString(R.string.titan_deck_xdr),
                getString(if (snapshot.titanActive && snapshot.autoSuspendOnQuarantine) R.string.titan_deck_os else R.string.titan_deck_network_only),
                if (snapshot.titanActive && snapshot.autoSuspendOnQuarantine) GeDefenseUi.green else GeDefenseUi.orange,
            ), LinearLayout.LayoutParams(0, -2, 1f).apply { marginStart = dp(8) })
        }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(11) })
    }

    private fun commandTile(label: String, value: String, accent: Int): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER
        background = GeDefenseUi.softPanelBackground(this@TitanActivity, radius = 13, accent = accent)
        setPadding(dp(10), dp(11), dp(10), dp(11))
        addView(GeDefenseUi.monoTextView(this@TitanActivity, label, 8.3f, GeDefenseUi.textDim).apply {
            gravity = Gravity.CENTER
            letterSpacing = 0.05f
            setAllCaps(true)
        })
        addView(GeDefenseUi.textView(this@TitanActivity, value, 10.4f, accent, bold = true).apply {
            gravity = Gravity.CENTER
            setPadding(0, dp(5), 0, 0)
            maxLines = 2
        })
    }

    private fun xiaomiProvisioningGuide(xiaomiDevice: Boolean): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(GeDefenseUi.monoTextView(this@TitanActivity, getString(R.string.titan_xiaomi_path), 10.4f, GeDefenseUi.goldSoft).apply {
            background = GeDefenseUi.softPanelBackground(this@TitanActivity, radius = 13, accent = GeDefenseUi.gold)
            setPadding(dp(12), dp(11), dp(12), dp(11))
        })
        addView(provisioningStep("1", getString(R.string.titan_xiaomi_step1_title), getString(R.string.titan_xiaomi_step1_body), GeDefenseUi.gold), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(9) })
        addView(provisioningStep("2", getString(R.string.titan_xiaomi_step2_title), getString(R.string.titan_xiaomi_step2_body), GeDefenseUi.cyan), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        addView(provisioningStep("3", getString(R.string.titan_xiaomi_step3_title), getString(R.string.titan_xiaomi_step3_body), GeDefenseUi.cyan), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        addView(provisioningStep("4", getString(R.string.titan_xiaomi_step4_title), getString(R.string.titan_xiaomi_step4_body), GeDefenseUi.green), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        if (xiaomiDevice) {
            addView(GeDefenseUi.pill(this@TitanActivity, getString(R.string.titan_xiaomi_detected_hint), GeDefenseUi.gold), LinearLayout.LayoutParams(-2, -2).apply { topMargin = dp(10) })
        }
    }

    private fun provisioningStep(number: String, title: String, body: String, accent: Int): View = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.TOP
        addView(GeDefenseUi.pill(this@TitanActivity, number, accent), LinearLayout.LayoutParams(-2, -2))
        addView(LinearLayout(this@TitanActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(10), 0, 0, 0)
            addView(GeDefenseUi.textView(this@TitanActivity, title, 11.7f, GeDefenseUi.text, bold = true))
            addView(GeDefenseUi.textView(this@TitanActivity, body, 10.9f, GeDefenseUi.textDim).apply {
                setPadding(0, dp(4), 0, 0)
                setLineSpacing(dp(1).toFloat(), 1.04f)
            })
        }, LinearLayout.LayoutParams(0, -2, 1f))
    }

    private fun activationMethodCard(
        number: String,
        title: String,
        badge: String,
        body: String,
        accent: Int,
        extra: View? = null,
        actionLabel: String? = null,
        action: (() -> Unit)? = null,
    ): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = GeDefenseUi.softPanelBackground(this@TitanActivity, radius = 16, accent = accent)
        setPadding(dp(16), dp(16), dp(16), dp(16))
        addView(LinearLayout(this@TitanActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(GeDefenseUi.monoTextView(this@TitanActivity, number, 11f, accent).apply {
                gravity = Gravity.CENTER
                minWidth = dp(34)
            })
            addView(GeDefenseUi.textView(this@TitanActivity, title, 13.2f, GeDefenseUi.text, bold = true), LinearLayout.LayoutParams(0, -2, 1f).apply { marginStart = dp(9) })
            addView(GeDefenseUi.pill(this@TitanActivity, badge, accent))
        })
        addView(GeDefenseUi.textView(this@TitanActivity, body, 11.6f, GeDefenseUi.textMuted).apply {
            setLineSpacing(dp(1).toFloat(), 1.06f)
        }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(11) })
        extra?.let { addView(it, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(11) }) }
        if (actionLabel != null && action != null) {
            addView(GeDefenseUi.actionButton(this@TitanActivity, actionLabel, goldStyle = accent == GeDefenseUi.gold, action = action), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(11) })
        }
    }

    private fun adbCommandWell(command: String): View = HorizontalScrollView(this).apply {
        isHorizontalScrollBarEnabled = false
        background = GeDefenseUi.softPanelBackground(this@TitanActivity, radius = 13, accent = GeDefenseUi.cyan)
        addView(GeDefenseUi.monoTextView(this@TitanActivity, command, 10.6f, GeDefenseUi.cyan).apply {
            setTextIsSelectable(true)
            setPadding(dp(12), dp(12), dp(12), dp(12))
        })
    }

    private fun capabilityCard(snapshot: TitanSnapshot): View = sectionCard(
        VgtIcon.INTELLIGENCE,
        when { snapshot.titanActive -> GeDefenseUi.green; snapshot.titanLightActive -> GeDefenseUi.cyan; else -> GeDefenseUi.textDim },
        getString(R.string.titan_capabilities_title),
        if (snapshot.titanLightActive) listOf(
            capabilityRow(R.string.titan_light_cap_lock, true, VgtIcon.SHIELD),
            capabilityRow(R.string.titan_light_cap_password, true, VgtIcon.POLICY),
            capabilityRow(R.string.titan_light_cap_login_watch, true, VgtIcon.ACTIVITY),
            capabilityRow(R.string.titan_light_cap_wipe, true, VgtIcon.ALERT),
            capabilityRow(R.string.titan_cap_always_on, false, VgtIcon.TRAFFIC),
        ) else listOf(
            capabilityRow(R.string.titan_cap_quarantine, snapshot.titanActive, VgtIcon.BLOCK),
            capabilityRow(R.string.titan_cap_always_on, snapshot.titanActive, VgtIcon.TRAFFIC),
            capabilityRow(R.string.titan_cap_restrictions, snapshot.titanActive, VgtIcon.INTEGRITY),
            capabilityRow(R.string.titan_cap_credentials, snapshot.titanActive, VgtIcon.POLICY),
            capabilityRow(R.string.titan_cap_uninstall, snapshot.titanActive, VgtIcon.SHIELD),
        ),
    )

    private fun titanLightProtectionCard(snapshot: TitanSnapshot): View = sectionCard(
        VgtIcon.SHIELD,
        GeDefenseUi.cyan,
        getString(R.string.titan_light_controls_title),
        listOf(
            GeDefenseUi.textView(this, getString(R.string.titan_light_controls_body), 11.4f, GeDefenseUi.textMuted),
            GeDefenseUi.actionButton(this, getString(R.string.titan_light_lock_now), goldStyle = true) {
                runTitanAction("titan-light-lock") { runtime.titan.lockDeviceNow() }
            },
            stateLine(R.string.titan_light_auto_lock_label, snapshot.maxTimeToLockMillis in 1..TitanPolicyManager.TITAN_LIGHT_MAX_LOCK_MS),
            GeDefenseUi.actionButton(this, getString(if (snapshot.maxTimeToLockMillis > 0L) R.string.titan_light_auto_lock_disable else R.string.titan_light_auto_lock_enable)) {
                runTitanAction("titan-light-auto-lock") { runtime.titan.setLightAutoLock(snapshot.maxTimeToLockMillis <= 0L) }
            },
            stateLine(R.string.titan_password_complexity, snapshot.highPasswordComplexityRequired),
            GeDefenseUi.actionButton(this, getString(if (snapshot.highPasswordComplexityRequired) R.string.titan_disable_high_complexity else R.string.titan_enable_high_complexity)) {
                runTitanAction("titan-light-password") { runtime.titan.setHighPasswordComplexity(!snapshot.highPasswordComplexityRequired) }
            },
            GeDefenseUi.textView(this, getString(R.string.titan_light_wipe_warning, TitanPolicyManager.FAILED_PASSWORD_WIPE_THRESHOLD), 10.5f, GeDefenseUi.orange),
            stateLine(R.string.titan_wipe_label, snapshot.wipeAfterFailedAttempts > 0),
            GeDefenseUi.actionButton(this, getString(if (snapshot.wipeAfterFailedAttempts > 0) R.string.titan_disable_wipe else R.string.titan_enable_wipe), goldStyle = false) {
                if (snapshot.wipeAfterFailedAttempts > 0) runTitanAction("titan-light-wipe") { runtime.titan.setWipeThreshold(false) } else confirmWipeThreshold()
            },
        ),
    )

    private fun networkEnforcementCard(snapshot: TitanSnapshot): View = sectionCard(
        VgtIcon.TRAFFIC,
        if (snapshot.alwaysOnLockdown) GeDefenseUi.green else GeDefenseUi.gold,
        getString(R.string.titan_network_title),
        listOf(
            stateLine(R.string.titan_always_on_label, snapshot.alwaysOnVpn && snapshot.alwaysOnLockdown),
            GeDefenseUi.textView(this, getString(R.string.titan_always_on_body), 11.6f, GeDefenseUi.textMuted),
            GeDefenseUi.actionButton(this, getString(if (snapshot.alwaysOnLockdown) R.string.titan_disable_always_on else R.string.titan_enable_always_on), goldStyle = !snapshot.alwaysOnLockdown) {
                toggleAlwaysOn(snapshot.alwaysOnLockdown)
            },
            stateLine(R.string.titan_auto_suspend_label, snapshot.autoSuspendOnQuarantine),
            GeDefenseUi.textView(this, getString(R.string.titan_auto_suspend_body), 11.6f, GeDefenseUi.textMuted),
            GeDefenseUi.actionButton(this, getString(if (snapshot.autoSuspendOnQuarantine) R.string.titan_disable_auto_suspend else R.string.titan_enable_auto_suspend)) {
                runTitanAction("auto-suspend") { runtime.titan.setAutoSuspendOnQuarantine(!snapshot.autoSuspendOnQuarantine) }
            },
        ),
    )

    private fun hardwareHardeningCard(snapshot: TitanSnapshot): View = sectionCard(
        VgtIcon.INTEGRITY,
        GeDefenseUi.cyan,
        getString(R.string.titan_hardware_title),
        listOf(
            restrictionControl(R.string.titan_adb_lock, R.string.titan_adb_lock_body, UserManager.DISALLOW_DEBUGGING_FEATURES, snapshot.debuggingBlocked),
            restrictionControl(R.string.titan_unknown_sources, R.string.titan_unknown_sources_body, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES, snapshot.unknownSourcesBlocked),
            restrictionControl(R.string.titan_safe_boot, R.string.titan_safe_boot_body, UserManager.DISALLOW_SAFE_BOOT, snapshot.safeBootBlocked),
            restrictionControl(R.string.titan_usb_transfer, R.string.titan_usb_transfer_body, UserManager.DISALLOW_USB_FILE_TRANSFER, snapshot.usbFileTransferBlocked),
            restrictionControl(R.string.titan_verify_apps, R.string.titan_verify_apps_body, UserManager.ENSURE_VERIFY_APPS, snapshot.verifyAppsEnforced),
        ),
    )

    private fun credentialCard(snapshot: TitanSnapshot): View = sectionCard(
        VgtIcon.POLICY,
        if (snapshot.highPasswordComplexityRequired) GeDefenseUi.green else GeDefenseUi.gold,
        getString(R.string.titan_credentials_title),
        listOf(
            stateLine(R.string.titan_password_complexity, snapshot.highPasswordComplexityRequired),
            GeDefenseUi.actionButton(this, getString(if (snapshot.highPasswordComplexityRequired) R.string.titan_disable_high_complexity else R.string.titan_enable_high_complexity)) {
                runTitanAction("password-policy") { runtime.titan.setHighPasswordComplexity(!snapshot.highPasswordComplexityRequired) }
            },
            GeDefenseUi.textView(this, getString(R.string.titan_wipe_body, TitanPolicyManager.FAILED_PASSWORD_WIPE_THRESHOLD), 11.6f, GeDefenseUi.textMuted),
            stateLine(R.string.titan_wipe_label, snapshot.wipeAfterFailedAttempts > 0),
            GeDefenseUi.actionButton(this, getString(if (snapshot.wipeAfterFailedAttempts > 0) R.string.titan_disable_wipe else R.string.titan_enable_wipe), goldStyle = snapshot.wipeAfterFailedAttempts == 0) {
                if (snapshot.wipeAfterFailedAttempts > 0) runTitanAction("wipe-threshold") { runtime.titan.setWipeThreshold(false) } else confirmWipeThreshold()
            },
        ),
    )

    private fun trustAnchorsCard(snapshot: TitanSnapshot): View = sectionCard(
        VgtIcon.POLICY,
        GeDefenseUi.cyan,
        getString(R.string.titan_trust_title),
        listOf(
            GeDefenseUi.textView(this, getString(R.string.titan_trust_body), 9f, GeDefenseUi.textMuted),
            GeDefenseUi.textView(this, getString(R.string.titan_trust_count, snapshot.managedCaCount), 9.3f, GeDefenseUi.text, bold = true),
            GeDefenseUi.actionButton(this, getString(R.string.titan_import_ca), goldStyle = true) { openCaCertificatePicker() },
        ),
    )

    @Suppress("DEPRECATION")
    private fun openCaCertificatePicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(
                Intent.EXTRA_MIME_TYPES,
                arrayOf("application/x-x509-ca-cert", "application/pkix-cert", "application/x-pem-file", "application/octet-stream"),
            )
        }
        startActivityForResult(intent, REQUEST_CA_CERTIFICATE)
    }

    @Deprecated("Platform callback retained intentionally because this module has zero AndroidX dependencies.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN_DISCLOSURE) {
            if (resultCode == RESULT_OK) toggleAlwaysOn(false)
            return
        }
        if (requestCode != REQUEST_CA_CERTIFICATE || resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        val bytes = readCertificateUri(uri)
        if (bytes == null) {
            toast(R.string.titan_ca_invalid)
            return
        }
        val info = runtime.titan.inspectCaCertificate(bytes)
        if (info == null) {
            toast(R.string.titan_ca_invalid)
            return
        }
        confirmCaInstall(bytes, info)
    }

    private fun readCertificateUri(uri: Uri): ByteArray? = try {
        contentResolver.openInputStream(uri)?.use { input ->
            val output = ByteArrayOutputStream(minOf(8192, TitanPolicyManager.MAX_CA_CERT_BYTES))
            val buffer = ByteArray(8192)
            var total = 0
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                total += read
                if (total > TitanPolicyManager.MAX_CA_CERT_BYTES) return null
                output.write(buffer, 0, read)
            }
            if (total == 0) null else output.toByteArray()
        }
    } catch (_: Exception) {
        null
    }

    private fun confirmCaInstall(bytes: ByteArray, info: TitanCaCertificateInfo) {
        val expiry = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(info.notAfterMillis))
        AlertDialog.Builder(this)
            .setTitle(R.string.titan_ca_confirm_title)
            .setMessage(
                getString(
                    R.string.titan_ca_confirm_body,
                    info.subject,
                    info.issuer,
                    expiry,
                    info.sha256Fingerprint,
                ),
            )
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.titan_ca_install) { _, _ ->
                runTitanAction("managed-ca-install") { runtime.titan.installCaCertificate(bytes) }
            }
            .show()
    }

    private fun quarantineCard(snapshot: TitanSnapshot): View {
        val quarantined = runtime.firewallPolicy.quarantinedPackages().sorted()
        val views = mutableListOf<View>()
        views += GeDefenseUi.textView(this, getString(R.string.titan_quarantine_body), 11.6f, GeDefenseUi.textMuted)
        if (quarantined.isEmpty()) {
            views += GeDefenseUi.textView(this, getString(R.string.titan_no_quarantine), 11.6f, GeDefenseUi.textDim)
        } else {
            quarantined.take(64).forEach { packageName -> views += quarantinedPackageRow(packageName, snapshot) }
        }
        return sectionCard(VgtIcon.BLOCK, GeDefenseUi.orange, getString(R.string.titan_quarantine_title), views)
    }

    private fun quarantinedPackageRow(packageName: String, snapshot: TitanSnapshot): View {
        val suspended = snapshot.titanActive && runtime.titan.isPackageSuspended(packageName)
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = GeDefenseUi.softPanelBackground(this@TitanActivity, radius = 15, accent = if (suspended) GeDefenseUi.red else GeDefenseUi.gold)
            setPadding(dp(14), dp(14), dp(14), dp(14))
            addView(LinearLayout(this@TitanActivity).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                addView(GeDefenseUi.monoTextView(this@TitanActivity, packageName, 10.2f, GeDefenseUi.text), LinearLayout.LayoutParams(0, -2, 1f))
                addView(GeDefenseUi.pill(this@TitanActivity, getString(if (suspended) R.string.titan_suspended else R.string.titan_network_only), if (suspended) GeDefenseUi.red else GeDefenseUi.gold))
            })
            if (snapshot.titanActive) {
                addView(GeDefenseUi.actionButton(this@TitanActivity, getString(if (suspended) R.string.titan_unsuspend else R.string.titan_suspend)) {
                    runTitanAction("package-suspension") { runtime.titan.setPackageSuspended(packageName, !suspended) }
                }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(7) })
                addView(GeDefenseUi.actionButton(this@TitanActivity, getString(R.string.titan_uninstall), goldStyle = false) {
                    confirmUninstall(packageName)
                }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(6) })
            }
        }
    }

    private fun restrictionControl(titleRes: Int, bodyRes: Int, key: String, enabled: Boolean): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = GeDefenseUi.softPanelBackground(this@TitanActivity, radius = 15, accent = if (enabled) GeDefenseUi.green else GeDefenseUi.cyan)
        setPadding(dp(14), dp(14), dp(14), dp(14))
        addView(GeDefenseUi.textView(this@TitanActivity, getString(titleRes), 12.3f, GeDefenseUi.text, bold = true))
        addView(GeDefenseUi.textView(this@TitanActivity, getString(bodyRes), 11.2f, GeDefenseUi.textDim).apply { setPadding(0, dp(6), 0, 0) })
        addView(GeDefenseUi.pill(this@TitanActivity, getString(if (enabled) R.string.titan_enforced else R.string.titan_not_enforced), if (enabled) GeDefenseUi.green else GeDefenseUi.gold), LinearLayout.LayoutParams(-2, -2).apply { topMargin = dp(9) })
        addView(GeDefenseUi.actionButton(this@TitanActivity, getString(if (enabled) R.string.titan_release_policy else R.string.titan_enforce_policy)) {
            runTitanAction("restriction:$key") { runtime.titan.setRestriction(key, !enabled) }
        }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(9) })
    }

    private fun stateLine(labelRes: Int, enabled: Boolean): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, dp(2), 0, dp(2))
        addView(GeDefenseUi.textView(this@TitanActivity, getString(labelRes), 11.7f, GeDefenseUi.textMuted, bold = true))
        addView(GeDefenseUi.pill(this@TitanActivity, getString(if (enabled) R.string.titan_enforced else R.string.titan_not_enforced), if (enabled) GeDefenseUi.green else GeDefenseUi.gold), LinearLayout.LayoutParams(-2, -2).apply { topMargin = dp(7) })
    }

    private fun capabilityRow(labelRes: Int, available: Boolean, icon: VgtIcon): View = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        background = GeDefenseUi.softPanelBackground(this@TitanActivity, radius = 14, accent = if (available) GeDefenseUi.green else GeDefenseUi.gold)
        setPadding(dp(13), dp(13), dp(13), dp(13))
        addView(VgtUiComponents.iconWell(this@TitanActivity, icon, if (available) GeDefenseUi.green else GeDefenseUi.gold, 34), LinearLayout.LayoutParams(dp(34), dp(34)))
        addView(LinearLayout(this@TitanActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(11), 0, 0, 0)
            addView(GeDefenseUi.textView(this@TitanActivity, getString(labelRes), 11.7f, GeDefenseUi.text, bold = true))
            addView(GeDefenseUi.pill(this@TitanActivity, getString(if (available) R.string.titan_enforced else R.string.titan_not_enforced), if (available) GeDefenseUi.green else GeDefenseUi.gold), LinearLayout.LayoutParams(-2, -2).apply { topMargin = dp(6) })
        }, LinearLayout.LayoutParams(0, -2, 1f))
    }

    private fun toggleAlwaysOn(currentlyEnabled: Boolean) {
        if (!currentlyEnabled) {
            if (!runtime.vpnDisclosure.isAccepted()) {
                startActivityForResult(Intent(this, VpnDisclosureActivity::class.java), REQUEST_VPN_DISCLOSURE)
                return
            }
            val ready = runtime.evidenceHealth.ok && runtime.integritySnapshot.get().ok && NativeGaiaNet.available && runtime.threatIndex.get().count > 0
            if (!ready) {
                toast(R.string.titan_always_on_not_ready)
                return
            }
            if (!runtime.state.canMutateProtectionConfiguration()) {
                toast(R.string.titan_always_on_not_ready)
                return
            }
            try {
                runtime.state.setProtectionMode(ProtectionMode.FULL_FLOW_BETA)
            } catch (_: IllegalArgumentException) {
                toast(R.string.titan_always_on_not_ready)
                return
            }
        }
        runTitanAction(
            policy = "always-on-vpn",
            onSuccessUi = {
                if (!currentlyEnabled) {
                    try { startForegroundService(Intent(this, GeDefenseVpnService::class.java).setAction(GeDefenseVpnService.ACTION_START)) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("titan-activity", error) }
                }
            },
        ) { runtime.titan.setAlwaysOnVpnLockdown(!currentlyEnabled) }
    }

    private fun confirmWipeThreshold() {
        AlertDialog.Builder(this)
            .setTitle(R.string.titan_wipe_confirm_title)
            .setMessage(getString(R.string.titan_wipe_confirm_body, TitanPolicyManager.FAILED_PASSWORD_WIPE_THRESHOLD))
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.titan_enable_wipe) { _, _ -> runTitanAction("wipe-threshold") { runtime.titan.setWipeThreshold(true) } }
            .show()
    }

    private fun confirmUninstall(packageName: String) {
        AlertDialog.Builder(this)
            .setTitle(R.string.titan_uninstall_confirm_title)
            .setMessage(getString(R.string.titan_uninstall_confirm_body, packageName))
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.titan_uninstall) { _, _ -> runTitanAction("uninstall:$packageName") { runtime.titan.uninstallUserPackage(packageName) } }
            .show()
    }

    private fun runTitanAction(
        policy: String,
        onSuccessUi: (() -> Unit)? = null,
        action: () -> TitanActionResult,
    ) {
        val accepted = runtime.executeBackground("titan-action") {
            val result = try {
                action()
            } catch (_: RuntimeException) {
                TitanActionResult(false, "PLATFORM_OPERATION_FAILED", "platform_unavailable")
            }
            runCatching {
                if (result.ok) runtime.xdr.recordTitanPolicyChange(policy, result.code, result.detail)
                else runtime.xdr.recordTitanPolicyFailure(policy, result.code, result.detail)
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                if (result.ok) {
                    onSuccessUi?.invoke()
                    toast(R.string.titan_action_ok)
                } else {
                    Toast.makeText(this, getString(R.string.titan_action_failed_detail, result.code, result.detail), Toast.LENGTH_LONG).show()
                }
                runtime.notifyStateChanged()
                render()
            }
        }
        if (!accepted) toast(R.string.titan_action_failed)
    }

    private fun copyToClipboard(text: String) {
        val clipboard = getSystemService(ClipboardManager::class.java)
        clipboard.setPrimaryClip(ClipData.newPlainText(getString(R.string.titan_adb_title), text))
        toast(R.string.titan_copied)
    }

    private fun sectionCard(icon: VgtIcon, accent: Int, title: String, views: List<View>): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = GeDefenseUi.glassPanelBackground(this@TitanActivity, accent = accent, radius = 22)
        setPadding(dp(20), dp(20), dp(20), dp(20))
        addView(LinearLayout(this@TitanActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(VgtUiComponents.iconWell(this@TitanActivity, icon, accent, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
            addView(GeDefenseUi.textView(this@TitanActivity, title, 12.2f, GeDefenseUi.goldSoft, bold = true).apply {
                letterSpacing = 0.11f
                setAllCaps(true)
            }, LinearLayout.LayoutParams(0, -2, 1f).apply { marginStart = dp(12) })
        })
        views.forEachIndexed { index, view ->
            if (view.visibility != View.GONE) addView(view, LinearLayout.LayoutParams(-1, -2).apply { topMargin = if (index == 0) dp(15) else dp(13) })
        }
    }

    private fun gap(dpValue: Int) = rootLayout.addView(View(this).apply { layoutParams = LinearLayout.LayoutParams(1, dp(dpValue)) })
    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
    private fun toast(res: Int) = Toast.makeText(this, getString(res), Toast.LENGTH_LONG).show()
    companion object {
        private const val REQUEST_CA_CERTIFICATE = 0x5443
        private const val REQUEST_VPN_DISCLOSURE = 0x5444
    }

}
