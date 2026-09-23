package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicBoolean

// STATUS: DIAMANT VGT SUPREME
class WireGuardActivity : Activity() {
    private lateinit var runtime: AppRuntime
    private lateinit var rootLayout: LinearLayout
    private lateinit var modeBadge: TextView
    private lateinit var statusBadge: TextView
    private lateinit var summary: TextView
    private lateinit var directButton: TextView
    private lateinit var tunnelButton: TextView
    private lateinit var strictButton: TextView
    private lateinit var importButton: TextView
    private lateinit var clearButton: TextView
    private lateinit var configInput: EditText
    private val importRunning = AtomicBoolean(false)
    private val listener: () -> Unit = { runOnUiThread { if (!isFinishing && !isDestroyed) refresh() } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        VgtWindowInsets.configureSystemBars(window)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        runtime = RuntimeActivityEntry.requireReady(this) ?: return
        setContentView(buildUi())
        refresh()
    }

    override fun onStart() {
        super.onStart()
        runtime.addStateListener(listener)
        refresh()
    }

    override fun onStop() {
        runtime.removeStateListener(listener)
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    @Deprecated("Document picker result uses the platform Activity API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_IMPORT || resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        if (!runtime.state.canMutateProtectionConfiguration()) {
            Toast.makeText(this, R.string.wireguard_stop_first, Toast.LENGTH_LONG).show()
            return
        }
        if (!importRunning.compareAndSet(false, true)) return
        setImportBusy(true)
        val accepted = runtime.executeBackground("wireguard-import-file") {
            val text = try {
                contentResolver.openInputStream(uri)?.use(::readBoundedUtf8)
            } catch (_: Exception) {
                null
            }
            val result = if (text == null) WireGuardImportResult(false, "wireguard_file_read_failed") else runtime.wireGuard.importConfig(text)
            runOnUiThread {
                importRunning.set(false)
                setImportBusy(false)
                showImportResult(result)
                refresh()
            }
        }
        if (!accepted) {
            importRunning.set(false)
            setImportBusy(false)
            Toast.makeText(this, R.string.wireguard_runtime_busy, Toast.LENGTH_LONG).show()
        }
    }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))
        val scroll = ScrollView(this).apply { clipToPadding = false; overScrollMode = View.OVER_SCROLL_NEVER }
        VgtUiPerformance.bindScroll(scroll)
        rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(18), dp(22), dp(48))
        }
        scroll.addView(rootLayout, FrameLayout.LayoutParams(-1, -2))
        root.addView(scroll, FrameLayout.LayoutParams(-1, -1))

        rootLayout.addView(VgtUiComponents.screenHeader(this, getString(R.string.wireguard_title), getString(R.string.wireguard_subtitle)))
        gap(14)

        modeBadge = GeDefenseUi.pill(this, getString(R.string.wireguard_mode_direct), GeDefenseUi.cyan)
        statusBadge = GeDefenseUi.pill(this, getString(R.string.ui_waiting), GeDefenseUi.gold)
        summary = GeDefenseUi.textView(this, "", 10.4f, GeDefenseUi.textMuted)
        rootLayout.addView(statusCard())

        gap(12)
        directButton = GeDefenseUi.actionButton(this, getString(R.string.wireguard_mode_direct)) { setMode(WireGuardEgressMode.DIRECT) }
        tunnelButton = GeDefenseUi.actionButton(this, getString(R.string.wireguard_mode_tunnel)) { setMode(WireGuardEgressMode.WIREGUARD) }
        strictButton = GeDefenseUi.actionButton(this, getString(R.string.wireguard_mode_strict), goldStyle = true) { setMode(WireGuardEgressMode.WIREGUARD_STRICT) }
        rootLayout.addView(modeCard())

        gap(12)
        configInput = EditText(this).apply {
            hint = getString(R.string.wireguard_config_hint)
            minLines = 6
            maxLines = 12
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            imeOptions = EditorInfo.IME_FLAG_NO_EXTRACT_UI or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            setTextColor(GeDefenseUi.text)
            setHintTextColor(GeDefenseUi.textDim)
            background = GeDefenseUi.softPanelBackground(this@WireGuardActivity, 14, GeDefenseUi.cyan)
            setPadding(dp(14), dp(12), dp(14), dp(12))
        }
        importButton = GeDefenseUi.actionButton(this, getString(R.string.wireguard_import_paste), goldStyle = true) { importPastedConfig() }
        val fileButton = GeDefenseUi.actionButton(this, getString(R.string.wireguard_import_file)) { openConfigPicker() }
        clearButton = GeDefenseUi.actionButton(this, getString(R.string.wireguard_clear_profile)) { clearProfile() }
        rootLayout.addView(importCard(fileButton))

        gap(12)
        rootLayout.addView(FrameLayout(this).apply {
            background = GeDefenseUi.softPanelBackground(this@WireGuardActivity, 16, GeDefenseUi.gold)
            addView(LinearLayout(this@WireGuardActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(18), dp(15), dp(18), dp(15))
                addView(GeDefenseUi.textView(this@WireGuardActivity, getString(R.string.wireguard_security_title), 12.5f, GeDefenseUi.text, bold = true))
                addView(GeDefenseUi.textView(this@WireGuardActivity, getString(R.string.wireguard_security_body), 9.8f, GeDefenseUi.textDim).apply { setPadding(0, dp(8), 0, 0) })
                addView(GeDefenseUi.actionButton(this@WireGuardActivity, getString(R.string.wireguard_open_vpn_settings)) {
                    if (!runtime.setup.openVpnSettings(this@WireGuardActivity)) {
                        try { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("wire-guard-activity", error) }
                    }
                }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })
            }, FrameLayout.LayoutParams(-1, -2))
        })

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            rootLayout.setPadding(dp(22) + safe.left, dp(18) + safe.top, dp(22) + safe.right, dp(48) + safe.bottom)
            insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun statusCard(): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@WireGuardActivity, strong = true, accent = GeDefenseUi.cyan, radius = 20)
        addView(LinearLayout(this@WireGuardActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(LinearLayout(this@WireGuardActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(this@WireGuardActivity, VgtIcon.SHIELD, GeDefenseUi.cyan, 38), LinearLayout.LayoutParams(dp(38), dp(38)))
                addView(modeBadge, LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(12); rightMargin = dp(8) })
                addView(statusBadge)
            })
            addView(summary.apply { setPadding(0, dp(12), 0, 0) })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun modeCard(): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@WireGuardActivity, accent = GeDefenseUi.gold, radius = 18)
        addView(LinearLayout(this@WireGuardActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(GeDefenseUi.textView(this@WireGuardActivity, getString(R.string.wireguard_mode_title), 13.5f, GeDefenseUi.text, bold = true))
            addView(GeDefenseUi.textView(this@WireGuardActivity, getString(R.string.wireguard_mode_body), 9.8f, GeDefenseUi.textDim).apply { setPadding(0, dp(7), 0, 0) })
            addView(directButton, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(13) })
            addView(tunnelButton, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
            addView(strictButton, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun importCard(fileButton: TextView): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@WireGuardActivity, accent = GeDefenseUi.cyan, radius = 18)
        addView(LinearLayout(this@WireGuardActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(GeDefenseUi.textView(this@WireGuardActivity, getString(R.string.wireguard_profile_title), 13.5f, GeDefenseUi.text, bold = true))
            addView(GeDefenseUi.textView(this@WireGuardActivity, getString(R.string.wireguard_profile_body), 9.8f, GeDefenseUi.textDim).apply { setPadding(0, dp(7), 0, 0) })
            addView(configInput, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(13) })
            addView(importButton, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
            addView(fileButton, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
            addView(clearButton, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun refresh() {
        val mode = runtime.state.wireGuardEgressMode()
        val profile = runtime.wireGuard.status()
        val mutable = runtime.state.canMutateProtectionConfiguration()
        val killSwitch = runtime.state.platformLockdown() || runtime.titan.snapshot().alwaysOnLockdown
        val ready = profile.initialized && profile.integrityOk && profile.configured

        modeBadge.text = getString(when (mode) {
            WireGuardEgressMode.DIRECT -> R.string.wireguard_mode_direct
            WireGuardEgressMode.WIREGUARD -> R.string.wireguard_mode_tunnel
            WireGuardEgressMode.WIREGUARD_STRICT -> R.string.wireguard_mode_strict
        })
        modeBadge.setTextColor(if (mode == WireGuardEgressMode.WIREGUARD_STRICT) GeDefenseUi.gold else GeDefenseUi.cyan)
        statusBadge.text = getString(when {
            !profile.initialized -> R.string.ui_waiting
            !profile.integrityOk -> R.string.wireguard_state_integrity_failed
            !profile.configured -> R.string.wireguard_state_unconfigured
            mode == WireGuardEgressMode.WIREGUARD_STRICT && !killSwitch -> R.string.wireguard_state_lockdown_required
            else -> R.string.ui_ready
        })
        val statusColor = when {
            !profile.integrityOk -> GeDefenseUi.red
            ready && (mode != WireGuardEgressMode.WIREGUARD_STRICT || killSwitch) -> GeDefenseUi.green
            else -> GeDefenseUi.orange
        }
        statusBadge.setTextColor(statusColor)
        statusBadge.background = GeDefenseUi.badgeBackground(this, statusColor)
        summary.text = getString(
            R.string.wireguard_summary,
            profile.endpoint ?: getString(R.string.wireguard_not_configured),
            profile.addressCount,
            profile.allowedIpCount,
            profile.mtu,
            if (killSwitch) getString(R.string.always_on_enabled) else getString(R.string.always_on_disabled),
        )

        styleModeButton(directButton, mode == WireGuardEgressMode.DIRECT, mutable)
        styleModeButton(tunnelButton, mode == WireGuardEgressMode.WIREGUARD, mutable && ready)
        styleModeButton(strictButton, mode == WireGuardEgressMode.WIREGUARD_STRICT, mutable && ready)
        importButton.isEnabled = mutable && !importRunning.get()
        importButton.alpha = if (importButton.isEnabled) 1f else 0.45f
        configInput.isEnabled = mutable && !importRunning.get()
        clearButton.isEnabled = mutable && profile.configured && !importRunning.get()
        clearButton.alpha = if (clearButton.isEnabled) 1f else 0.45f
    }

    private fun setMode(mode: WireGuardEgressMode) {
        if (!runtime.state.canMutateProtectionConfiguration()) {
            Toast.makeText(this, R.string.wireguard_stop_first, Toast.LENGTH_LONG).show()
            return
        }
        if (mode != WireGuardEgressMode.DIRECT) {
            val status = runtime.wireGuard.status()
            if (!status.initialized || !status.integrityOk || !status.configured) {
                Toast.makeText(this, R.string.wireguard_profile_required, Toast.LENGTH_LONG).show()
                return
            }
        }
        try {
            runtime.state.setWireGuardEgressMode(mode)
        } catch (_: IllegalArgumentException) {
            Toast.makeText(this, R.string.wireguard_stop_first, Toast.LENGTH_LONG).show()
            refresh()
            return
        }
        runtime.notifyStateChanged()
        if (mode == WireGuardEgressMode.WIREGUARD_STRICT && !(runtime.state.platformLockdown() || runtime.titan.snapshot().alwaysOnLockdown)) {
            Toast.makeText(this, R.string.wireguard_strict_lockdown_hint, Toast.LENGTH_LONG).show()
        }
        refresh()
    }

    private fun importPastedConfig() {
        if (!runtime.state.canMutateProtectionConfiguration() || !importRunning.compareAndSet(false, true)) return
        val text = configInput.text?.toString().orEmpty()
        configInput.setText("")
        setImportBusy(true)
        val accepted = runtime.executeBackground("wireguard-import-paste") {
            val result = runtime.wireGuard.importConfig(text)
            runOnUiThread {
                importRunning.set(false)
                setImportBusy(false)
                showImportResult(result)
                refresh()
            }
        }
        if (!accepted) {
            importRunning.set(false)
            setImportBusy(false)
            Toast.makeText(this, R.string.wireguard_runtime_busy, Toast.LENGTH_LONG).show()
        }
    }

    private fun openConfigPicker() {
        if (!runtime.state.canMutateProtectionConfiguration()) {
            Toast.makeText(this, R.string.wireguard_stop_first, Toast.LENGTH_LONG).show()
            return
        }
        try {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "text/plain"
            }, REQUEST_IMPORT)
        } catch (_: RuntimeException) {
            Toast.makeText(this, R.string.wireguard_file_picker_failed, Toast.LENGTH_LONG).show()
        }
    }

    private fun clearProfile() {
        if (!runtime.state.canMutateProtectionConfiguration() || importRunning.get()) return
        val accepted = runtime.executeBackground("wireguard-clear-profile") {
            val ok = runtime.wireGuard.clearProfile()
            runOnUiThread {
                Toast.makeText(this, if (ok) R.string.wireguard_profile_cleared else R.string.wireguard_profile_clear_failed, Toast.LENGTH_LONG).show()
                runtime.notifyStateChanged()
                refresh()
            }
        }
        if (!accepted) Toast.makeText(this, R.string.wireguard_runtime_busy, Toast.LENGTH_LONG).show()
    }

    private fun showImportResult(result: WireGuardImportResult) {
        val message = if (result.ok) getString(R.string.wireguard_import_ok) else getString(R.string.wireguard_import_failed, result.reason ?: "invalid")
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        if (result.ok) runtime.notifyStateChanged()
    }

    private fun setImportBusy(busy: Boolean) {
        importButton.isEnabled = !busy
        importButton.alpha = if (busy) 0.45f else 1f
        configInput.isEnabled = !busy
    }

    private fun readBoundedUtf8(input: java.io.InputStream): String? {
        val bytes = ByteArray(MAX_CONFIG_BYTES + 1)
        var total = 0
        return try {
            while (total < bytes.size) {
                val count = input.read(bytes, total, bytes.size - total)
                if (count < 0) break
                if (count == 0) continue
                total += count
            }
            if (total == 0 || total > MAX_CONFIG_BYTES) return null
            val decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            decoder.decode(ByteBuffer.wrap(bytes, 0, total)).toString()
        } catch (_: CharacterCodingException) {
            null
        } finally {
            bytes.fill(0)
        }
    }

    private fun styleModeButton(button: TextView, selected: Boolean, enabled: Boolean) {
        button.isEnabled = enabled
        button.alpha = if (enabled) 1f else 0.45f
        button.background = if (selected) GeDefenseUi.goldButtonBackground(this) else GeDefenseUi.darkButtonBackground(this)
        button.setTextColor(if (selected) Color.rgb(18, 19, 20) else GeDefenseUi.text)
    }

    private fun gap(value: Int) = GeDefenseUi.addVerticalGap(rootLayout, this, value)
    private fun dp(value: Int) = GeDefenseUi.dp(this, value)

    companion object {
        private const val REQUEST_IMPORT = 9401
        private const val MAX_CONFIG_BYTES = 16 * 1024
    }
}
