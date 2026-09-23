package de.visiongaia.gedefense.mobile

import android.content.Context
import de.visiongaia.gedefense.mobile.core.PrivacyBreakageRisk
import de.visiongaia.gedefense.mobile.core.PrivacyCategory
import de.visiongaia.gedefense.mobile.core.PrivacyConfidence
import de.visiongaia.gedefense.mobile.core.PrivacyIntelligenceRegistry
import de.visiongaia.gedefense.mobile.core.PrivacyProvenance
import de.visiongaia.gedefense.mobile.core.PrivacyRule
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

// STATUS: PLATIN
/**
 * Loads the immutable, app-signed local Privacy Intelligence snapshot.
 *
 * No runtime network request is performed. The source asset is part of the signed APK and every
 * record carries provenance/license metadata. Malformed snapshots fail closed to an empty registry;
 * they never grant blocking authority from partially parsed input.
 */
class PrivacyIntelligenceRepository(context: Context) {
    private val appContext = context.applicationContext

    @Volatile
    private var state: State = State.Uninitialized

    fun registry(): PrivacyIntelligenceRegistry = when (val current = state) {
        is State.Ready -> current.registry
        is State.Failed -> EMPTY
        State.Uninitialized -> synchronized(this) {
            when (val recheck = state) {
                is State.Ready -> recheck.registry
                is State.Failed -> EMPTY
                State.Uninitialized -> load().also { loaded -> state = loaded }.let { loaded ->
                    if (loaded is State.Ready) loaded.registry else EMPTY
                }
            }
        }
    }

    fun healthy(): Boolean = state is State.Ready || registry().count > 0
    fun failureReason(): String? = (state as? State.Failed)?.reason

    /** Re-read the signed APK asset without weakening or resetting authority. */
    @Synchronized
    fun reloadSignedSnapshot(): Boolean {
        val loaded = load()
        state = loaded
        return loaded is State.Ready && loaded.registry.count > 0
    }

    private fun load(): State {
        return try {
            val rules = ArrayList<PrivacyRule>(128)
            appContext.assets.open(ASSET_NAME).use { input ->
                val decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                BufferedReader(InputStreamReader(input, decoder), 16 * 1024).use { reader ->
                    var lineNumber = 0
                    var totalChars = 0
                    while (true) {
                        val line = reader.readLine() ?: break
                        lineNumber++
                        totalChars += line.length + 1
                        require(lineNumber <= MAX_LINES && totalChars <= MAX_CHARS) { "privacy intelligence asset bound exceeded" }
                        val trimmed = line.trim()
                        if (trimmed.isEmpty() || trimmed.startsWith('#')) continue
                        val fields = line.split('\t')
                        require(fields.size == FIELD_COUNT) { "privacy intelligence field count invalid" }
                        rules += PrivacyRule(
                            id = fields[0],
                            domain = fields[1],
                            includeSubdomains = parseBoolean(fields[2]),
                            category = PrivacyCategory.valueOf(fields[3]),
                            confidence = PrivacyConfidence.valueOf(fields[4]),
                            breakageRisk = PrivacyBreakageRisk.valueOf(fields[5]),
                            essential = parseBoolean(fields[6]),
                            provenance = PrivacyProvenance(
                                sourceId = fields[7],
                                sourceUrl = fields[8],
                                licenseId = fields[9],
                                observedAt = fields[10],
                            ),
                        )
                    }
                }
            }
            require(rules.isNotEmpty()) { "privacy intelligence asset empty" }
            State.Ready(PrivacyIntelligenceRegistry.build(rules, MAX_RULES))
        } catch (_: Exception) {
            State.Failed("privacy_intelligence_invalid")
        }
    }

    private fun parseBoolean(value: String): Boolean = when (value) {
        "true" -> true
        "false" -> false
        else -> throw IllegalArgumentException("invalid privacy intelligence boolean")
    }

    private sealed interface State {
        data object Uninitialized : State
        data class Ready(val registry: PrivacyIntelligenceRegistry) : State
        data class Failed(val reason: String) : State
    }

    companion object {
        private const val ASSET_NAME = "privacy_intelligence_v1.tsv"
        private const val FIELD_COUNT = 11
        private const val MAX_RULES = 8_192
        private const val MAX_LINES = 16_384
        private const val MAX_CHARS = 4 * 1024 * 1024
        private val EMPTY = PrivacyIntelligenceRegistry.build(emptyList())
    }
}
