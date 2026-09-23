package de.visiongaia.gedefense.mobile

// STATUS: DIAMANT VGT SUPREME

enum class SetupWizardStep(
    val titleRes: Int,
    val subtitleRes: Int,
) {
    WELCOME(R.string.setup_page_welcome_title, R.string.setup_page_welcome_subtitle),
    PROTECTION_MODEL(R.string.setup_page_model_title, R.string.setup_page_model_subtitle),
    LOCAL_VPN(R.string.setup_page_vpn_title, R.string.setup_page_vpn_subtitle),
    XDR_INTELLIGENCE(R.string.setup_page_xdr_title, R.string.setup_page_xdr_subtitle),
    RELIABILITY(R.string.setup_page_reliability_title, R.string.setup_page_reliability_subtitle),
    STORAGE_SCANNER(R.string.setup_page_scanner_title, R.string.setup_page_scanner_subtitle),
    VISIBILITY(R.string.setup_page_visibility_title, R.string.setup_page_visibility_subtitle),
    TITAN(R.string.setup_page_titan_title, R.string.setup_page_titan_subtitle),
    PRIVACY(R.string.setup_page_privacy_title, R.string.setup_page_privacy_subtitle),
    INITIAL_SYNC(R.string.setup_page_initial_sync_title, R.string.setup_page_initial_sync_subtitle),
    SUMMARY(R.string.setup_page_summary_title, R.string.setup_page_summary_subtitle),
}

enum class SetupRequirementLevel {
    CORE,
    RECOMMENDED,
    OPTIONAL,
    ENTERPRISE,
}
