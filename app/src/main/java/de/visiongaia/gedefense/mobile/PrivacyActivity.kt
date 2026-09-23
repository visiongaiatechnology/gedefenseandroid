package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Toast
import de.visiongaia.gedefense.mobile.core.PrivacyProfile

// STATUS: DIAMANT VGT SUPREME
class PrivacyActivity : Activity() {
    private lateinit var runtime: AppRuntime

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        VgtWindowInsets.configureSystemBars(window)
        runtime = RuntimeActivityEntry.requireReady(this) ?: return
        setContentView(buildUi())
    }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))
        val scroll = ScrollView(this).apply {
            clipToPadding = false
            overScrollMode = View.OVER_SCROLL_NEVER
        }
        VgtUiPerformance.bindScroll(scroll)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(18), dp(22), dp(48))
        }
        scroll.addView(content, FrameLayout.LayoutParams(-1, -2))
        root.addView(scroll, FrameLayout.LayoutParams(-1, -1))

        content.addView(VgtUiComponents.screenHeader(this, getString(R.string.privacy_title), getString(R.string.privacy_subtitle)))
        gap(content, 14)
        content.addView(section(VgtIcon.SHIELD, GeDefenseUi.cyan, getString(R.string.privacy_local_title), getString(R.string.privacy_local_body)))
        gap(content, 12)
        content.addView(section(VgtIcon.INTELLIGENCE, GeDefenseUi.gold, getString(R.string.privacy_network_title), getString(R.string.privacy_network_body)))
        gap(content, 12)
        content.addView(telemetryShieldCard())
        gap(content, 12)
        content.addView(section(VgtIcon.SCANNER, GeDefenseUi.green, getString(R.string.privacy_scanner_title), getString(R.string.privacy_scanner_body)))
        gap(content, 12)
        content.addView(section(VgtIcon.POLICY, GeDefenseUi.cyan, getString(R.string.privacy_permissions_title), getString(R.string.privacy_permissions_body)))
        gap(content, 12)
        content.addView(section(VgtIcon.EVIDENCE, GeDefenseUi.green, getString(R.string.privacy_diagnostics_title), getString(R.string.privacy_diagnostics_body)))
        gap(content, 12)
        content.addView(section(VgtIcon.CLOUD, GeDefenseUi.gold, getString(R.string.privacy_network_services_title), getString(R.string.privacy_network_services_body)))
        gap(content, 12)
        content.addView(section(VgtIcon.SETTINGS, GeDefenseUi.textMuted, getString(R.string.privacy_retention_title), getString(R.string.privacy_retention_body)))
        gap(content, 12)
        content.addView(section(VgtIcon.EVIDENCE, GeDefenseUi.cyan, getString(R.string.privacy_vault_title), getString(R.string.privacy_vault_body)))
        gap(content, 14)

        val disclosure = runtime.vpnDisclosure.snapshot()
        val status = when {
            !disclosure.integrityOk -> getString(R.string.privacy_vpn_consent_invalid)
            disclosure.accepted -> getString(R.string.privacy_vpn_consent_accepted, GeDefenseUi.formatTime(this, disclosure.acceptedAtMillis))
            else -> getString(R.string.privacy_vpn_consent_missing)
        }
        content.addView(section(VgtIcon.SHIELD, if (disclosure.accepted) GeDefenseUi.green else GeDefenseUi.orange, getString(R.string.privacy_vpn_consent_title), status))
        gap(content, 10)
        if (disclosure.accepted) {
            content.addView(GeDefenseUi.actionButton(this, getString(R.string.privacy_vpn_consent_revoke), destructive = true) {
                revokeVpnConsent()
            })
            gap(content, 10)
        }
        content.addView(GeDefenseUi.actionButton(this, getString(R.string.privacy_review_vpn_disclosure), goldStyle = true) {
            startActivity(Intent(this, VpnDisclosureActivity::class.java))
        })

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            content.setPadding(
                dp(22) + safe.left,
                dp(18) + safe.top,
                dp(22) + safe.right,
                dp(48) + safe.bottom,
            )
            insets
        }
        root.post { root.requestApplyInsets() }

        return root
    }


    private fun telemetryShieldCard(): View = FrameLayout(this).apply {
        val active = runtime.state.privacyProfile()
        background = GeDefenseUi.glassPanelBackground(this@PrivacyActivity, accent = GeDefenseUi.cyan, radius = 18)
        addView(LinearLayout(this@PrivacyActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(LinearLayout(this@PrivacyActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(this@PrivacyActivity, VgtIcon.SHIELD, GeDefenseUi.cyan, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
                addView(LinearLayout(this@PrivacyActivity).apply {
                    orientation = LinearLayout.VERTICAL
                    addView(GeDefenseUi.textView(this@PrivacyActivity, getString(R.string.privacy_telemetry_shield_title), 13.2f, GeDefenseUi.text, bold = true))
                    addView(GeDefenseUi.textView(this@PrivacyActivity, getString(profileLabel(active)), 9.5f, GeDefenseUi.cyan, bold = true).apply {
                        setPadding(0, dp(3), 0, 0)
                    })
                }, LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(13) })
            })
            addView(GeDefenseUi.textView(this@PrivacyActivity, getString(R.string.privacy_telemetry_shield_body), 10.1f, GeDefenseUi.textMuted).apply {
                setPadding(0, dp(10), 0, 0)
                setLineSpacing(dp(2).toFloat(), 1f)
            })
            addView(GeDefenseUi.textView(this@PrivacyActivity, getString(R.string.privacy_telemetry_full_flow_only), 9.2f, GeDefenseUi.gold, bold = true).apply {
                setPadding(0, dp(8), 0, 0)
                setLineSpacing(dp(2).toFloat(), 1f)
            })
            addView(GeDefenseUi.textView(this@PrivacyActivity, getString(R.string.privacy_telemetry_encrypted_dns_note), 9.2f, GeDefenseUi.textDim).apply {
                setPadding(0, dp(7), 0, 0)
                setLineSpacing(dp(2).toFloat(), 1f)
            })
            addView(GeDefenseUi.actionButton(
                this@PrivacyActivity,
                getString(R.string.privacy_telemetry_profile_conservative),
                goldStyle = active == PrivacyProfile.CONSERVATIVE,
            ) { setPrivacyProfile(PrivacyProfile.CONSERVATIVE) }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })
            addView(GeDefenseUi.actionButton(
                this@PrivacyActivity,
                getString(R.string.privacy_telemetry_profile_balanced),
                goldStyle = active == PrivacyProfile.BALANCED,
            ) { setPrivacyProfile(PrivacyProfile.BALANCED) }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
            addView(GeDefenseUi.actionButton(
                this@PrivacyActivity,
                getString(R.string.privacy_telemetry_profile_strict),
                goldStyle = active == PrivacyProfile.STRICT,
            ) { setPrivacyProfile(PrivacyProfile.STRICT) }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
            addView(GeDefenseUi.actionButton(
                this@PrivacyActivity,
                getString(R.string.privacy_telemetry_profile_off),
                goldStyle = active == PrivacyProfile.OFF,
            ) { setPrivacyProfile(PrivacyProfile.OFF) }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
            addView(GeDefenseUi.textView(this@PrivacyActivity, getString(R.string.privacy_telemetry_restart_note), 9.2f, GeDefenseUi.textDim).apply {
                setPadding(0, dp(10), 0, 0)
            })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun setPrivacyProfile(profile: PrivacyProfile) {
        if (!runtime.state.canMutateProtectionConfiguration()) {
            Toast.makeText(this, R.string.privacy_telemetry_stop_first, Toast.LENGTH_LONG).show()
            return
        }
        try {
            runtime.state.setPrivacyProfile(profile)
        } catch (_: IllegalArgumentException) {
            Toast.makeText(this, R.string.privacy_telemetry_stop_first, Toast.LENGTH_LONG).show()
            return
        }
        runtime.notifyStateChanged()
        recreate()
    }

    private fun profileLabel(profile: PrivacyProfile): Int = when (profile) {
        PrivacyProfile.OFF -> R.string.privacy_telemetry_profile_off
        PrivacyProfile.CONSERVATIVE -> R.string.privacy_telemetry_profile_conservative
        PrivacyProfile.BALANCED -> R.string.privacy_telemetry_profile_balanced
        PrivacyProfile.STRICT -> R.string.privacy_telemetry_profile_strict
    }

    private fun revokeVpnConsent() {
        val accepted = runtime.executeBackground("vpn-disclosure-revoke") {
            val revoked = try { runtime.vpnDisclosure.revoke() } catch (_: RuntimeException) { false }
            val stopped = if (revoked) stopProtectionAfterConsentRevoke() else false
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                val message = when {
                    !revoked -> R.string.privacy_vpn_consent_revoke_failed
                    stopped -> R.string.privacy_vpn_consent_revoked
                    else -> R.string.privacy_vpn_consent_revoked_stop_unconfirmed
                }
                Toast.makeText(this, getString(message), Toast.LENGTH_LONG).show()
                recreate()
            }
        }
        if (!accepted) Toast.makeText(this, getString(R.string.privacy_vpn_consent_revoke_failed), Toast.LENGTH_LONG).show()
    }

    private fun stopProtectionAfterConsentRevoke(): Boolean {
        if (!runtime.state.isVpnActive()) return true
        try {
            startService(Intent(this, GeDefenseVpnService::class.java).setAction(GeDefenseVpnService.ACTION_STOP))
        } catch (_: RuntimeException) {
            // Fall through to the explicit service-stop fallback below. Consent is already revoked,
            // so a new protection start remains fail-closed even if this control delivery failed.
        }
        if (waitForVpnInactive(CONSENT_REVOKE_STOP_WAIT_MS)) return true
        try {
            stopService(Intent(this, GeDefenseVpnService::class.java))
        } catch (_: RuntimeException) {
            return false
        }
        return waitForVpnInactive(CONSENT_REVOKE_FORCE_STOP_WAIT_MS)
    }

    private fun waitForVpnInactive(timeoutMs: Long): Boolean {
        val deadline = android.os.SystemClock.elapsedRealtime() + timeoutMs
        while (runtime.state.isVpnActive() && android.os.SystemClock.elapsedRealtime() < deadline) {
            try {
                Thread.sleep(CONSENT_REVOKE_POLL_MS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return false
            }
        }
        return !runtime.state.isVpnActive()
    }

    private fun section(icon: VgtIcon, accent: Int, title: String, body: String): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@PrivacyActivity, accent = accent, radius = 18)
        addView(LinearLayout(this@PrivacyActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(LinearLayout(this@PrivacyActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(this@PrivacyActivity, icon, accent, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
                addView(GeDefenseUi.textView(this@PrivacyActivity, title, 13.2f, GeDefenseUi.text, bold = true), LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(13) })
            })
            addView(GeDefenseUi.textView(this@PrivacyActivity, body, 10.1f, GeDefenseUi.textMuted).apply {
                setPadding(0, dp(10), 0, 0)
                setLineSpacing(dp(2).toFloat(), 1f)
            })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun gap(parent: LinearLayout, value: Int) = parent.addView(View(this).apply {
        layoutParams = LinearLayout.LayoutParams(1, dp(value))
    })

    private fun dp(value: Int): Int = GeDefenseUi.dp(this, value)

    private companion object {
        const val CONSENT_REVOKE_STOP_WAIT_MS = 1_500L
        const val CONSENT_REVOKE_FORCE_STOP_WAIT_MS = 1_000L
        const val CONSENT_REVOKE_POLL_MS = 50L
    }
}
