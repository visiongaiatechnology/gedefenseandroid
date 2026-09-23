package de.visiongaia.gedefense.mobile

// STATUS: DIAMANT VGT SUPREME

enum class InitialSetupFeedSyncPhase {
    IDLE,
    SYNCING,
    READY,
    FAILED,
}

data class InitialSetupFeedSyncState(
    val phase: InitialSetupFeedSyncPhase = InitialSetupFeedSyncPhase.IDLE,
    val completedFeeds: Int = 0,
    val totalFeeds: Int = 0,
    val successfulFeeds: Int = 0,
    val totalRecords: Int = 0,
    val lastFeedId: String = "",
    val failureCode: String? = null,
) {
    val progress: Float
        get() = when {
            phase == InitialSetupFeedSyncPhase.READY -> 1f
            totalFeeds <= 0 -> 0f
            else -> (completedFeeds.toFloat() / totalFeeds.toFloat()).coerceIn(0f, 1f)
        }

    val ready: Boolean
        get() = phase == InitialSetupFeedSyncPhase.READY && totalRecords > 0
}
