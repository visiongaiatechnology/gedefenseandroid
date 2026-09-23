package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

class EvidenceScreen(
    private val activity: Activity,
    private val actions: UiActions,
) {
    val view: View
    private val rootLayout: LinearLayout
    private val policyStatus: TextView
    private val policyDetail: TextView
    private val threatIndexStatus: TextView
    private val threatIndexDetail: TextView
    private val evidenceStatus: TextView
    private val evidenceDetail: TextView
    private val syncStatus: TextView
    private val syncDetail: TextView
    private val integrityStatus: TextView
    private val integrityDetail: TextView
    private val verifyButton: TextView
    private val recoverButton: TextView

    init {
        val scroll = ScrollView(activity).apply { clipToPadding = false; overScrollMode = View.OVER_SCROLL_NEVER }
        rootLayout = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                GeDefenseUi.screenHorizontalPadding(activity),
                dp(16),
                GeDefenseUi.screenHorizontalPadding(activity),
                GeDefenseUi.scrollReservedBottomPadding(activity),
            )
        }
        val root = rootLayout
        scroll.addView(root, FrameLayout.LayoutParams(-1, -2))
        root.addView(VgtUiComponents.screenHeader(activity, activity.getString(R.string.ui_evidence_policy), activity.getString(R.string.ui_transparency_tagline)))
        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)

        policyStatus = statusText(); policyDetail = detailText()
        root.addView(infoCard(VgtIcon.POLICY, activity.getString(R.string.ui_policy_snapshot), policyStatus, policyDetail, GeDefenseUi.gold))
        threatIndexStatus = statusText(); threatIndexDetail = detailText()
        root.addView(infoCard(VgtIcon.INTELLIGENCE, activity.getString(R.string.threat_intel), threatIndexStatus, threatIndexDetail, GeDefenseUi.gold), spaced())
        evidenceStatus = statusText(); evidenceDetail = detailText()
        root.addView(infoCard(VgtIcon.EVIDENCE, activity.getString(R.string.evidence_ledger), evidenceStatus, evidenceDetail, GeDefenseUi.gold), spaced())
        syncStatus = statusText(); syncDetail = detailText()
        root.addView(infoCard(VgtIcon.CLOUD, activity.getString(R.string.ui_sync_status), syncStatus, syncDetail, GeDefenseUi.cyan), spaced())
        integrityStatus = statusText(); integrityDetail = detailText()
        root.addView(infoCard(VgtIcon.INTEGRITY, activity.getString(R.string.ui_system_integrity), integrityStatus, integrityDetail, GeDefenseUi.green), spaced())

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        verifyButton = GeDefenseUi.actionButton(activity, activity.getString(R.string.verify_evidence)) { actions.verifyEvidence() }
        recoverButton = GeDefenseUi.actionButton(activity, activity.getString(R.string.recover_evidence), destructive = true) { actions.recoverEvidence() }
        root.addView(verifyButton)
        root.addView(recoverButton, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        root.addView(FrameLayout(activity).apply {
            background = GeDefenseUi.glassPanelBackground(activity, strong = true, accent = GeDefenseUi.gold, radius = 18)
            val content = LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(dp(20), dp(18), dp(20), dp(18))
                addView(VgtUiComponents.iconWell(activity, VgtIcon.SHIELD, GeDefenseUi.gold, 40), LinearLayout.LayoutParams(dp(40), dp(40)))
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(14), 0, 0, 0)
                    addView(GeDefenseUi.textView(activity, activity.getString(R.string.ui_safer_internet), 12f, GeDefenseUi.gold, bold = true).apply { letterSpacing = 0.07f })
                    addView(GeDefenseUi.textView(activity, activity.getString(R.string.ui_evidence_footer), 10.5f, GeDefenseUi.textMuted).apply { setPadding(0, dp(5), 0, 0) })
                }, LinearLayout.LayoutParams(0, -2, 1f))
            }
            addView(content, FrameLayout.LayoutParams(-1, -2))
        })
        view = scroll
    }

    fun setBottomPadding(bottomPx: Int) {
        rootLayout.setPadding(rootLayout.paddingLeft, rootLayout.paddingTop, rootLayout.paddingRight, bottomPx)
    }

    fun setVerifying(verifying: Boolean) {
        verifyButton.isEnabled = !verifying
        verifyButton.alpha = if (verifying) 0.55f else 1f
        verifyButton.text = activity.getString(if (verifying) R.string.verifying else R.string.verify_evidence)
    }

    fun update(snapshot: UiSnapshot) {
        val fullFlow = snapshot.protectionMode == ProtectionMode.FULL_FLOW_BETA
        val policyHealthy = if (fullFlow) snapshot.indexedPrefixes > 0 && snapshot.nativeFullFlowAvailable else !snapshot.routeOverflow && snapshot.compactedRoutes > 0
        policyStatus.text = when {
            !policyHealthy -> activity.getString(R.string.ui_policy_attention)
            snapshot.vpnActive && snapshot.vpnStatus in setOf("GUARDED", "FULL_GUARDED") -> activity.getString(R.string.ui_enforced_ready)
            else -> activity.getString(R.string.ui_ready)
        }
        policyStatus.setTextColor(if (policyHealthy) GeDefenseUi.green else GeDefenseUi.red)
        policyDetail.text = if (fullFlow) {
            activity.getString(R.string.ui_full_policy_detail, snapshot.indexedPrefixes, snapshot.fullPolicySha256.take(16))
        } else {
            activity.getString(R.string.ui_policy_detail, snapshot.compactedRoutes, snapshot.routeCandidates, snapshot.routePolicySha256.take(16))
        }

        threatIndexStatus.text = activity.getString(R.string.ui_indexed_prefixes, snapshot.indexedPrefixes)
        val indexHealthy = snapshot.indexedPrefixes > 0 && (fullFlow || !snapshot.routeOverflow)
        threatIndexStatus.setTextColor(if (indexHealthy) GeDefenseUi.green else GeDefenseUi.red)
        threatIndexDetail.text = if (!fullFlow && snapshot.routeOverflow) activity.getString(R.string.status_route_overflow)
        else activity.getString(R.string.ui_threat_index_detail, snapshot.routeBlockFeeds)

        evidenceStatus.text = if (snapshot.evidenceOk) activity.getString(R.string.ui_verified_stored) else activity.getString(R.string.ui_integrity_failure)
        evidenceStatus.setTextColor(if (snapshot.evidenceOk) GeDefenseUi.green else GeDefenseUi.red)
        evidenceDetail.text = if (snapshot.evidenceOk) activity.getString(R.string.evidence_ok, snapshot.evidenceRecords)
        else activity.getString(R.string.evidence_bad, snapshot.evidenceInvalidLine ?: 0L, snapshot.evidenceReason ?: "unknown")

        val allFeedsHealthy = snapshot.healthyFeeds == snapshot.feeds.size && snapshot.feeds.isNotEmpty()
        syncStatus.text = activity.getString(if (allFeedsHealthy) R.string.ui_synchronized else R.string.ui_partial_sync)
        syncStatus.setTextColor(if (allFeedsHealthy) GeDefenseUi.green else GeDefenseUi.orange)
        syncDetail.text = activity.getString(R.string.ui_last_sync_detail, GeDefenseUi.formatTime(activity, snapshot.lastFeedSync), snapshot.healthyFeeds, snapshot.feeds.size)

        val integrityOk = snapshot.evidenceOk && snapshot.integrity.ok && policyHealthy && snapshot.vpnStatus != "POLICY_INVARIANT_FAILED"
        integrityStatus.text = activity.getString(if (integrityOk) R.string.ui_all_systems_secure else R.string.ui_attention_required)
        integrityStatus.setTextColor(if (integrityOk) GeDefenseUi.green else GeDefenseUi.red)
        integrityDetail.text = snapshot.vpnReason?.let { activity.getString(R.string.status_reason, it) } ?: activity.getString(R.string.ui_no_tampering)
        recoverButton.visibility = if (snapshot.evidenceOk) View.GONE else View.VISIBLE
    }

    private fun infoCard(icon: VgtIcon, title: String, status: TextView, detail: TextView, accent: Int): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, accent = accent, radius = 18)
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(VgtUiComponents.iconWell(activity, icon, accent, 40), LinearLayout.LayoutParams(dp(40), dp(40)))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(14), 0, 0, 0)
                addView(GeDefenseUi.textView(activity, title, 13.5f, GeDefenseUi.text, bold = true))
                addView(status.apply { setPadding(0, dp(5), 0, 0) })
                addView(detail.apply { setPadding(0, dp(4), 0, 0) })
            }, LinearLayout.LayoutParams(0, -2, 1f))
        }
        addView(content, FrameLayout.LayoutParams(-1, -2))
    }

    private fun statusText() = GeDefenseUi.textView(activity, "", 12.5f, GeDefenseUi.green, bold = true)
    private fun detailText() = GeDefenseUi.textView(activity, "", 10.2f, GeDefenseUi.textMuted)
    private fun spaced() = LinearLayout.LayoutParams(-1, -2).apply { topMargin = GeDefenseUi.cardGap(activity) }
    private fun gap(parent: LinearLayout, value: Int) = GeDefenseUi.addVerticalGap(parent, activity, value)
    private fun dp(value: Int) = GeDefenseUi.dp(activity, value)
}
