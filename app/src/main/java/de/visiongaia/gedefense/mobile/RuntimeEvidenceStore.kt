package de.visiongaia.gedefense.mobile

import de.visiongaia.gedefense.mobile.core.EvidenceEvent
import de.visiongaia.gedefense.mobile.core.EvidenceStore
import de.visiongaia.gedefense.mobile.core.LedgerHealth
import de.visiongaia.gedefense.mobile.core.RecoveryArchiveHealth
import de.visiongaia.gedefense.mobile.core.RecoveryResult
import de.visiongaia.gedefense.mobile.core.UnavailableEvidenceStore
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

// STATUS: PLATIN
/**
 * Stable Evidence capability published with the runtime shell before AndroidKeyStore bootstrap.
 *
 * The delegate begins fail-closed and is installed exactly once by the background security
 * bootstrap. XDR and other runtime components can therefore keep one EvidenceStore reference
 * without forcing key acquisition during AppRuntime construction.
 */
internal class RuntimeEvidenceStore : EvidenceStore {
    private val installed = AtomicBoolean(false)
    private val delegate = AtomicReference<EvidenceStore>(UnavailableEvidenceStore(INITIAL_REASON))

    fun install(store: EvidenceStore): Boolean {
        require(store !== this) { "evidence delegate cycle" }
        if (!installed.compareAndSet(false, true)) return false
        delegate.set(store)
        return true
    }

    fun initialized(): Boolean = installed.get()

    override fun open(): LedgerHealth = delegate.get().open()

    override fun append(event: EvidenceEvent) = delegate.get().append(event)

    override fun verify(): LedgerHealth = delegate.get().verify()

    override fun recover(archiveDir: File, reason: String): RecoveryResult = delegate.get().recover(archiveDir, reason)

    override fun verifyRecoveryArchive(manifest: File): RecoveryArchiveHealth = delegate.get().verifyRecoveryArchive(manifest)

    companion object {
        const val INITIAL_REASON = "evidence_initializing"
    }
}
