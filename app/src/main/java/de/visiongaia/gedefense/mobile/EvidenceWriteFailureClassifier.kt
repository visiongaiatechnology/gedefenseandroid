package de.visiongaia.gedefense.mobile

import de.visiongaia.gedefense.mobile.core.EvidenceStoreUnavailableException
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStoreException
import java.security.ProviderException
import javax.crypto.AEADBadTagException

// STATUS: DIAMANT VGT SUPREME
object EvidenceWriteFailureClassifier {
    fun code(error: Throwable): String {
        var current: Throwable? = error
        repeat(8) {
            val candidate = current
            when (candidate) {
                is EvidenceStoreUnavailableException -> return candidate.reasonCode
                is AEADBadTagException -> return "evidence_crypto_auth_failure"
                is GeneralSecurityException,
                is KeyStoreException,
                is ProviderException -> return "evidence_crypto_failure"
                is IOException -> return "evidence_io_failure"
                is IllegalArgumentException -> return "evidence_validation_failure"
                is IllegalStateException -> {
                    val message = candidate.message.orEmpty()
                    if (message.contains("changed outside writer")) return "evidence_state_race"
                    if (message.contains("degraded")) return "evidence_integrity_unhealthy"
                    return "evidence_state_failure"
                }
            }
            current = candidate?.cause ?: return "evidence_write_failure"
        }
        return "evidence_write_failure"
    }
}
