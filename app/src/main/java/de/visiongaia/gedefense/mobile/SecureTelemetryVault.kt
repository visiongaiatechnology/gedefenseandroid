package de.visiongaia.gedefense.mobile

import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotFailureKind
import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotRead
import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotState
import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotStore
import de.visiongaia.gedefense.mobile.core.BoundedSecretKeyCrypto
import de.visiongaia.gedefense.mobile.core.AeadVaultEnvelope
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.ProviderException
import java.security.SecureRandom
import java.util.ArrayDeque
import javax.crypto.SecretKey

// STATUS: DIAMANT VGT SUPREME
/**
 * Domain-separated, Android-Keystore-backed encryption for durable GeDefense state.
 *
 * Security composition:
 *  - an independent per-store HMAC key authenticates the outer crash-safe snapshot envelope,
 *  - an independent per-domain AES-256-GCM key protects confidentiality and authenticates payloads,
 *  - fresh 96-bit nonces are generated for every write,
 *  - AAD binds ciphertext to the domain, store binding, schema and key version,
 *  - legacy authenticated plaintext snapshots are upgraded in-place before being returned.
 *
 * Active generations use one installation-stable non-exportable AndroidKeyStore KEK to unwrap an
 * independent random root per domain/key generation. HKDF derives independent in-memory AES/HMAC
 * subkeys. APK/version/integrity measurements are intentionally not part of encryption custody.
 * Historical AES, wrapped-DEK and hardware-PRF generations remain readable for one-way migration.
 */
enum class VaultDomain(
    val id: String,
    val activeKeyVersion: Int = 1,
    val legacyOnly: Boolean = false,
    val preferStrongBox: Boolean = true,
    val hotPathWrapped: Boolean = false,
    val wrappedKeyVersion: Int = Int.MAX_VALUE,
    val derivedKeyVersion: Int = Int.MAX_VALUE,
    val persistentKeyVersion: Int = Int.MAX_VALUE,
    val infrastructureOnly: Boolean = false,
) {
    VPN_DISCLOSURE_LEGACY("vpn-disclosure", legacyOnly = true),
    VPN_DISCLOSURE("vpn-disclosure-receipt", activeKeyVersion = 1, persistentKeyVersion = 1),
    XDR_EVENTS("xdr-events", activeKeyVersion = 5, preferStrongBox = false, hotPathWrapped = true, wrappedKeyVersion = 3, derivedKeyVersion = 4, persistentKeyVersion = 5),
    BEHAVIOR_BASELINE("behavior-baseline", activeKeyVersion = 3, derivedKeyVersion = 2, persistentKeyVersion = 3),
    PACKAGE_BASELINE("package-baseline", activeKeyVersion = 3, derivedKeyVersion = 2, persistentKeyVersion = 3),
    MALWARE_ANALYSIS("malware-analysis", activeKeyVersion = 3, derivedKeyVersion = 2, persistentKeyVersion = 3),
    APP_APPROVALS("app-approvals", activeKeyVersion = 3, derivedKeyVersion = 2, persistentKeyVersion = 3),
    FIREWALL_POLICY("firewall-policy", activeKeyVersion = 3, derivedKeyVersion = 2, persistentKeyVersion = 3),
    NETWORK_DISCOVERY("network-discovery", activeKeyVersion = 3, derivedKeyVersion = 2, persistentKeyVersion = 3),
    PORT_SENTINEL("port-sentinel", activeKeyVersion = 3, derivedKeyVersion = 2, persistentKeyVersion = 3),
    TITAN_POLICY("titan-policy", activeKeyVersion = 3, derivedKeyVersion = 2, persistentKeyVersion = 3),
    SCANNER_STORAGE("scanner-storage", activeKeyVersion = 3, derivedKeyVersion = 2, persistentKeyVersion = 3),
    SCANNER_APPS("scanner-apps", activeKeyVersion = 3, derivedKeyVersion = 2, persistentKeyVersion = 3),
    WIREGUARD_PROFILE("wireguard-profile", activeKeyVersion = 2, derivedKeyVersion = 1, persistentKeyVersion = 2),
    EVIDENCE("evidence", activeKeyVersion = 5, preferStrongBox = false, hotPathWrapped = true, wrappedKeyVersion = 3, derivedKeyVersion = 4, persistentKeyVersion = 5),
    SECURITY_ROOT("security-root", activeKeyVersion = 1, preferStrongBox = false, persistentKeyVersion = 1, infrastructureOnly = true),
}

enum class SecureVaultFailureKind {
    NONE,
    OUTER_INTEGRITY,
    OUTER_KEY_UNAVAILABLE,
    OUTER_KEY_OPERATION,
    OUTER_IO_UNAVAILABLE,
    OUTER_RUNTIME_FAILURE,
    LEGACY_MIGRATION,
    KEY_CONTINUITY,
    ENVELOPE_DECODE,
}

data class VaultRecoveryArchive(
    val fileName: String,
    val sha256: String,
    val failureKind: SecureVaultFailureKind = SecureVaultFailureKind.NONE,
)


data class VaultRecoveryRecord(
    val domain: String,
    val failureKind: SecureVaultFailureKind,
    val archiveSha256: String,
)

data class VaultRecoveryBatch(
    val records: List<VaultRecoveryRecord>,
    val droppedRecords: Long,
)

object VaultRecoveryJournal {
    private const val MAX_RECORDS = 128
    private val lock = Any()
    private val records = ArrayDeque<VaultRecoveryRecord>(MAX_RECORDS)
    private var droppedRecords = 0L

    internal fun record(domain: VaultDomain, failureKind: SecureVaultFailureKind, archiveSha256: String) = synchronized(lock) {
        if (records.size >= MAX_RECORDS) {
            records.removeFirst()
            if (droppedRecords < Long.MAX_VALUE) droppedRecords++
        }
        records.addLast(VaultRecoveryRecord(domain.id, failureKind, archiveSha256))
    }

    fun drain(): VaultRecoveryBatch = synchronized(lock) {
        val batch = VaultRecoveryBatch(records.toList(), droppedRecords)
        records.clear()
        droppedRecords = 0L
        batch
    }
}

data class VaultProtectionStatus(
    val domain: VaultDomain,
    val keyVersion: Int,
    val initialized: Boolean,
    val securityLevel: AndroidSecrets.KeySecurityLevel?,
)

object SecureTelemetryVault {
    const val ENVELOPE_OVERHEAD_BYTES = AeadVaultEnvelope.ENVELOPE_OVERHEAD_BYTES

    fun initialize(context: android.content.Context) {
        WrappedHotPathKeys.initialize(context)
        PersistentVaultKeys.initialize(context)
    }

    fun isEncryptedEnvelope(bytes: ByteArray): Boolean = AeadVaultEnvelope.isEnvelope(bytes)

    fun seal(
        domain: VaultDomain,
        binding: String,
        schemaVersion: Int,
        plaintext: ByteArray,
    ): ByteArray {
        val version = domain.activeKeyVersion
        val key = when {
            version >= domain.persistentKeyVersion -> PersistentVaultKeys.keys(domain, version, create = true).aes
            version >= domain.derivedKeyVersion -> HardwareDerivedVaultKeys.keys(domain, version, create = true).aes
            domain.hotPathWrapped && version >= domain.wrappedKeyVersion -> WrappedHotPathKeys.keys(domain, version, create = true).aes
            else -> AndroidSecrets.aes256Gcm(aesAlias(domain, version), preferStrongBox = domain.preferStrongBox)
        }
        return BoundedSecretKeyCrypto.execute(key) {
            AeadVaultEnvelope.seal(
                key = key,
                domain = domain.id,
                binding = binding,
                schemaVersion = schemaVersion,
                keyVersion = version,
                plaintext = plaintext,
            )
        }
    }

    fun open(
        domain: VaultDomain,
        binding: String,
        expectedSchemaVersion: Int,
        envelope: ByteArray,
        maxPlaintextBytes: Int,
    ): ByteArray {
        val version = AeadVaultEnvelope.peekKeyVersion(envelope)
            ?: throw GeneralSecurityException("vault key version missing")
        val key = when {
            version >= domain.persistentKeyVersion -> PersistentVaultKeys.keys(domain, version, create = false).aes
            version >= domain.derivedKeyVersion -> HardwareDerivedVaultKeys.keys(domain, version, create = false).aes
            domain.hotPathWrapped && version >= domain.wrappedKeyVersion -> WrappedHotPathKeys.keys(domain, version, create = false).aes
            else -> AndroidSecrets.secretKeyIfPresent(aesAlias(domain, version))
                ?: throw GeneralSecurityException("vault key continuity unavailable")
        }
        if (!key.algorithm.equals("AES", ignoreCase = true)) {
            throw GeneralSecurityException("vault key algorithm mismatch")
        }
        val opened = BoundedSecretKeyCrypto.execute(key) {
            AeadVaultEnvelope.open(
                key = key,
                domain = domain.id,
                binding = binding,
                expectedSchemaVersion = expectedSchemaVersion,
                envelope = envelope,
                maxPlaintextBytes = maxPlaintextBytes,
                maxKeyVersion = domain.activeKeyVersion,
            )
        }
        return opened.plaintext
    }

    fun envelopeKeyVersion(envelope: ByteArray): Int? = AeadVaultEnvelope.peekKeyVersion(envelope)

    fun protectionStatus(domain: VaultDomain): VaultProtectionStatus {
        val version = domain.activeKeyVersion
        if (version >= domain.persistentKeyVersion) {
            val status = PersistentVaultKeys.status(domain, version)
            return VaultProtectionStatus(
                domain = domain,
                keyVersion = version,
                initialized = status.initialized,
                securityLevel = status.rootSecurityLevel,
            )
        }
        if (version >= domain.derivedKeyVersion) {
            val status = HardwareDerivedVaultKeys.status(domain, version)
            return VaultProtectionStatus(
                domain = domain,
                keyVersion = version,
                initialized = status.initialized,
                securityLevel = status.rootSecurityLevel,
            )
        }
        if (domain.hotPathWrapped && version >= domain.wrappedKeyVersion) {
            val status = WrappedHotPathKeys.status(domain, version)
            return VaultProtectionStatus(
                domain = domain,
                keyVersion = version,
                initialized = status.initialized,
                securityLevel = status.kekSecurityLevel,
            )
        }
        val key = AndroidSecrets.secretKeyIfPresent(aesAlias(domain, version))
        return VaultProtectionStatus(
            domain = domain,
            keyVersion = version,
            initialized = key != null,
            securityLevel = key?.let(AndroidSecrets::securityLevel),
        )
    }

    fun activeStatuses(): List<VaultProtectionStatus> =
        VaultDomain.entries.filterNot { it.legacyOnly || it.infrastructureOnly }.map(::protectionStatus)

    fun hotPathHmacKey(domain: VaultDomain): SecretKey {
        val version = domain.activeKeyVersion
        return when {
            version >= domain.persistentKeyVersion -> PersistentVaultKeys.keys(domain, version, create = true).hmac
            version >= domain.derivedKeyVersion -> HardwareDerivedVaultKeys.keys(domain, version, create = true).hmac
            domain.hotPathWrapped && version >= domain.wrappedKeyVersion -> WrappedHotPathKeys.keys(domain, version, create = true).hmac
            else -> throw IllegalArgumentException("domain has no hot-path HMAC key")
        }
    }

    /** Returns an already-existing historical hot-path HMAC generation without creating material. */
    fun historicalHotPathHmacKey(domain: VaultDomain, version: Int): SecretKey? {
        if (!domain.hotPathWrapped || version >= domain.activeKeyVersion || version < domain.wrappedKeyVersion) return null
        return try {
            when {
                version >= domain.persistentKeyVersion -> PersistentVaultKeys.keys(domain, version, create = false).hmac
                version >= domain.derivedKeyVersion -> HardwareDerivedVaultKeys.keys(domain, version, create = false).hmac
                version >= domain.wrappedKeyVersion -> WrappedHotPathKeys.keys(domain, version, create = false).hmac
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }

    fun preflightHotPath(domain: VaultDomain): String? {
        val active = domain.activeKeyVersion
        val hasActiveHotPath = active >= domain.persistentKeyVersion || active >= domain.derivedKeyVersion ||
            (domain.hotPathWrapped && active >= domain.wrappedKeyVersion)
        if (!hasActiveHotPath) return null
        val probe = ByteArray(32).also(SecureRandom()::nextBytes)
        val binding = "preflight/${domain.id}"
        return try {
            val envelope = seal(domain, binding, 1, probe)
            try {
                val opened = open(domain, binding, 1, envelope, 64)
                try {
                    if (!MessageDigest.isEqual(probe, opened)) "roundtrip_mismatch" else null
                } finally {
                    opened.fill(0)
                }
            } finally {
                envelope.fill(0)
            }
        } catch (_: GeneralSecurityException) {
            "crypto_unavailable"
        } catch (_: ProviderException) {
            "crypto_unavailable"
        } catch (_: IllegalArgumentException) {
            "validation_unavailable"
        } catch (_: IllegalStateException) {
            "state_unavailable"
        } catch (_: RuntimeException) {
            "runtime_unavailable"
        } finally {
            probe.fill(0)
        }
    }

    private fun aesAlias(domain: VaultDomain, version: Int): String =
        "vgt.gedefense.mobile.vault.${domain.id}.aes.v$version"
}

/**
 * Drop-in encrypted replacement for AuthenticatedSnapshotStore.
 *
 * Existing HMAC-authenticated plaintext payloads are migrated in place on the first successful
 * read. If re-encryption cannot be persisted, the store fails closed and does not return plaintext.
 */
class SecureSnapshotStore(
    file: File,
    hmacKey: SecretKey?,
    private val domain: VaultDomain,
    private val schemaVersion: Int,
    private val maxPlaintextBytes: Int,
    private val binding: String = file.name,
    hmacKeyProvider: (() -> SecretKey?)? = null,
    legacyHmacKey: SecretKey? = null,
    legacyHmacKeyProvider: (() -> SecretKey?)? = null,
) {
    private val lock = Any()
    private val random = SecureRandom()
    @Volatile private var lastFailureKind = SecureVaultFailureKind.NONE
    private val authenticatedStore = AuthenticatedSnapshotStore(
        file = file,
        key = hmacKey,
        schemaVersion = schemaVersion,
        maxPayloadBytes = Math.addExact(maxPlaintextBytes, SecureTelemetryVault.ENVELOPE_OVERHEAD_BYTES),
        keyProvider = hmacKeyProvider,
    )
    private val legacyAuthenticatedStore = if (legacyHmacKey != null || legacyHmacKeyProvider != null) {
        AuthenticatedSnapshotStore(
            file = file,
            key = legacyHmacKey,
            schemaVersion = schemaVersion,
            maxPayloadBytes = Math.addExact(maxPlaintextBytes, SecureTelemetryVault.ENVELOPE_OVERHEAD_BYTES),
            keyProvider = legacyHmacKeyProvider,
        )
    } else null

    init {
        require(maxPlaintextBytes > 0)
    }

    fun read(): AuthenticatedSnapshotRead = synchronized(lock) {
        lastFailureKind = SecureVaultFailureKind.NONE
        val outer = authenticatedStore.read()
        if (outer.state == AuthenticatedSnapshotState.VALID) {
            return@synchronized processAuthenticatedPayload(
                stored = outer.payload ?: return@synchronized invalid(
                    "vault outer payload missing",
                    SecureVaultFailureKind.ENVELOPE_DECODE,
                ),
                rewriteOuterAuthentication = false,
            )
        }
        if (outer.state == AuthenticatedSnapshotState.ABSENT) return@synchronized outer

        val primaryFailure = mapOuterFailure(outer.failureKind)
        lastFailureKind = primaryFailure

        // OEM AndroidKeyStore HMAC keys have been observed becoming unusable or excessively slow
        // across an application update on some devices. If the payload is already an encrypted vault
        // envelope, do not touch the historical OEM HMAC at all: parse only the bounded outer framing,
        // authenticate/decrypt the inner AES-GCM envelope, then durably re-HMAC the state with the
        // current update-stable domain key before plaintext is released. This both preserves the
        // independent cryptographic proof and prevents a broken legacy provider call from opening the
        // process-wide opaque-key circuit. Plaintext legacy data never enters this path.
        if (primaryFailure in OUTER_AEAD_RECOVERABLE_FAILURES) {
            val candidate = authenticatedStore.readPayloadWithoutAuthenticationForAeadRecovery()
            if (candidate != null) {
                try {
                    if (SecureTelemetryVault.isEncryptedEnvelope(candidate)) {
                        return@synchronized processAuthenticatedPayload(
                            stored = candidate,
                            rewriteOuterAuthentication = true,
                            recoveryFailureKind = primaryFailure,
                        )
                    }
                } finally {
                    candidate.fill(0)
                }
            }
        }

        // A historical direct AndroidKeyStore HMAC is consulted only for legacy plaintext, where no
        // inner AEAD exists to prove authenticity. It remains read-only migration material.
        legacyAuthenticatedStore?.let { legacy ->
            val historical = legacy.read()
            if (historical.state == AuthenticatedSnapshotState.VALID) {
                val stored = historical.payload ?: return@synchronized invalid(
                    "vault historical outer payload missing",
                    SecureVaultFailureKind.ENVELOPE_DECODE,
                )
                return@synchronized processAuthenticatedPayload(stored, rewriteOuterAuthentication = true)
            }
        }

        return@synchronized outer
    }

    private fun processAuthenticatedPayload(
        stored: ByteArray,
        rewriteOuterAuthentication: Boolean,
        recoveryFailureKind: SecureVaultFailureKind? = null,
    ): AuthenticatedSnapshotRead {
        if (!SecureTelemetryVault.isEncryptedEnvelope(stored)) {
            if (recoveryFailureKind != null) {
                lastFailureKind = recoveryFailureKind
                return AuthenticatedSnapshotRead(
                    AuthenticatedSnapshotState.INVALID,
                    reason = "legacy plaintext requires authenticated outer snapshot",
                )
            }
            if (stored.size > maxPlaintextBytes) return invalid(
                "legacy vault payload oversized",
                SecureVaultFailureKind.ENVELOPE_DECODE,
            )
            return try {
                // Migration is completed before plaintext is released to callers.
                val encrypted = SecureTelemetryVault.seal(domain, binding, schemaVersion, stored)
                try {
                    authenticatedStore.write(encrypted)
                } finally {
                    encrypted.fill(0)
                }
                lastFailureKind = SecureVaultFailureKind.NONE
                AuthenticatedSnapshotRead(AuthenticatedSnapshotState.VALID, stored)
            } catch (_: Exception) {
                invalid("legacy vault migration failed", SecureVaultFailureKind.LEGACY_MIGRATION)
            }
        }

        return try {
            val storedKeyVersion = SecureTelemetryVault.envelopeKeyVersion(stored)
                ?: return invalid("vault key version missing", SecureVaultFailureKind.ENVELOPE_DECODE)
            val plaintext = SecureTelemetryVault.open(domain, binding, schemaVersion, stored, maxPlaintextBytes)
            try {
                if (rewriteOuterAuthentication || storedKeyVersion < domain.activeKeyVersion) {
                    // Recovery/rotation is fail-closed: plaintext is never released until the state
                    // is durably authenticated with the current outer key and, when required, current
                    // inner key generation.
                    val replacement = if (storedKeyVersion < domain.activeKeyVersion) {
                        SecureTelemetryVault.seal(domain, binding, schemaVersion, plaintext)
                    } else {
                        stored.copyOf()
                    }
                    try {
                        authenticatedStore.write(replacement)
                    } finally {
                        replacement.fill(0)
                    }
                }
                lastFailureKind = SecureVaultFailureKind.NONE
                AuthenticatedSnapshotRead(AuthenticatedSnapshotState.VALID, plaintext)
            } catch (error: Exception) {
                plaintext.fill(0)
                if (recoveryFailureKind != null) {
                    invalid("vault outer authentication recovery failed", recoveryFailureKind)
                } else {
                    invalid("vault rotation persistence failed", SecureVaultFailureKind.LEGACY_MIGRATION)
                }
            }
        } catch (_: GeneralSecurityException) {
            if (recoveryFailureKind != null) {
                lastFailureKind = recoveryFailureKind
                AuthenticatedSnapshotRead(
                    AuthenticatedSnapshotState.INVALID,
                    reason = "vault outer authentication recovery rejected",
                )
            } else {
                invalid("vault decryption/authentication failed", SecureVaultFailureKind.KEY_CONTINUITY)
            }
        } catch (_: RuntimeException) {
            if (recoveryFailureKind != null) {
                lastFailureKind = recoveryFailureKind
                AuthenticatedSnapshotRead(
                    AuthenticatedSnapshotState.INVALID,
                    reason = "vault outer authentication recovery rejected",
                )
            } else {
                invalid("vault decode failed", SecureVaultFailureKind.ENVELOPE_DECODE)
            }
        }
    }

    fun write(payload: ByteArray) = synchronized(lock) {
        require(payload.size <= maxPlaintextBytes) { "vault payload exceeds limit" }
        val envelope = SecureTelemetryVault.seal(domain, binding, schemaVersion, payload)
        try {
            authenticatedStore.write(envelope)
        } finally {
            envelope.fill(0)
        }
    }

    fun failureKind(): SecureVaultFailureKind = lastFailureKind

    /**
     * Archives an authenticated-but-undecipherable ciphertext snapshot before clearing it.
     *
     * This path is deliberately unavailable for outer-HMAC failures: an unauthenticated/tampered
     * store must remain fail-closed and require explicit recovery. KEY_CONTINUITY means the outer
     * HMAC verified, so the bytes were produced by GeDefense (under the independent store key),
     * but the current vault key can no longer open them. Derived stores may safely rebuild after
     * preserving that ciphertext for forensics.
     */
    fun archiveAndClearKeyContinuityFailure(recoveryRoot: File): VaultRecoveryArchive? =
        archiveFailure(
            recoveryRoot = recoveryRoot,
            expectedFailures = setOf(SecureVaultFailureKind.KEY_CONTINUITY),
            clearSource = true,
        )

    fun archiveAndClearReconstructibleStartupFailure(
        recoveryRoot: File,
        betaUpdateBoundaryMillis: Long?,
    ): VaultRecoveryArchive? = when (failureKind()) {
        SecureVaultFailureKind.KEY_CONTINUITY -> archiveAndClearKeyContinuityFailure(recoveryRoot)
        SecureVaultFailureKind.OUTER_INTEGRITY -> betaUpdateBoundaryMillis?.let {
            archiveAndClearOuterIntegrityFailureForBetaMigration(recoveryRoot, it)
        }
        else -> null
    }

    /** Explicitly scoped compatibility recovery for authenticated beta stores whose outer snapshot
     * can no longer be authenticated after a historical pre-release format/key transition. Callers
     * must gate this to a known migration signature and reconstructible state only. */
    fun archiveAndClearOuterIntegrityFailureForBetaMigration(
        recoveryRoot: File,
        olderThanMillis: Long,
    ): VaultRecoveryArchive? = archiveFailure(
        recoveryRoot = recoveryRoot,
        expectedFailures = setOf(SecureVaultFailureKind.OUTER_INTEGRITY),
        olderThanMillis = olderThanMillis,
        clearSource = true,
    )

    /**
     * Archives a narrowly allowed, update-gated migration failure without deleting the source.
     *
     * This exists for reconstructible stores whose historical AndroidKeyStore HMAC key cannot be
     * used on a specific OEM/provider after an app update. The source is retained until the caller
     * has durably written a new-generation store and explicitly commits the migration.
     */
    fun archiveMigrationCandidate(
        recoveryRoot: File,
        olderThanMillis: Long,
        allowedFailures: Set<SecureVaultFailureKind>,
    ): VaultRecoveryArchive? {
        val allowed = allowedFailures.intersect(MIGRATION_RECOVERABLE_FAILURES)
        if (allowed.isEmpty()) return null
        return archiveFailure(
            recoveryRoot = recoveryRoot,
            expectedFailures = allowed,
            olderThanMillis = olderThanMillis,
            clearSource = false,
        )
    }

    /**
     * Deletes the historical source only after a replacement generation is durable.
     * Both source and archive hashes are rechecked to close the archive/write/delete TOCTOU window.
     */
    fun commitArchivedMigration(recoveryRoot: File, archive: VaultRecoveryArchive): Boolean = synchronized(lock) {
        if (archive.failureKind !in MIGRATION_RECOVERABLE_FAILURES) return@synchronized false
        if (archive.fileName.contains('/') || archive.fileName.contains('\\')) return@synchronized false
        val source = authenticatedStore.path()
        val sourcePath = source.toPath()
        val archived = File(recoveryRoot, archive.fileName)
        if (!Files.exists(sourcePath, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(sourcePath) ||
            !Files.isRegularFile(sourcePath, LinkOption.NOFOLLOW_LINKS)) return@synchronized false
        if (!Files.exists(archived.toPath(), LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(archived.toPath()) ||
            !Files.isRegularFile(archived.toPath(), LinkOption.NOFOLLOW_LINKS)) return@synchronized false
        val sourceHash = sha256(source)?.toHex() ?: return@synchronized false
        val archiveHash = sha256(archived)?.toHex() ?: return@synchronized false
        if (!constantTimeHexEquals(sourceHash, archive.sha256) || !constantTimeHexEquals(archiveHash, archive.sha256)) {
            return@synchronized false
        }
        return@synchronized try {
            Files.delete(sourcePath)
            VaultRecoveryJournal.record(domain, archive.failureKind, archive.sha256)
            lastFailureKind = SecureVaultFailureKind.NONE
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun archiveFailure(
        recoveryRoot: File,
        expectedFailures: Set<SecureVaultFailureKind>,
        olderThanMillis: Long? = null,
        clearSource: Boolean,
    ): VaultRecoveryArchive? = synchronized(lock) {
        if (expectedFailures.isEmpty()) return@synchronized null
        val verify = read()
        val observedFailure = lastFailureKind
        if (verify.state != AuthenticatedSnapshotState.INVALID || observedFailure !in expectedFailures) {
            return@synchronized null
        }
        val source = authenticatedStore.path()
        val sourcePath = source.toPath()
        if (!Files.exists(sourcePath, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(sourcePath) ||
            !Files.isRegularFile(sourcePath, LinkOption.NOFOLLOW_LINKS)) return@synchronized null
        val size = try { Files.size(sourcePath) } catch (_: Exception) { return@synchronized null }
        if (size !in 1..MAX_RECOVERY_FILE_BYTES) return@synchronized null
        if (olderThanMillis != null) {
            val modified = try { Files.getLastModifiedTime(sourcePath, LinkOption.NOFOLLOW_LINKS).toMillis() } catch (_: Exception) { return@synchronized null }
            if (modified <= 0L || modified >= olderThanMillis) return@synchronized null
        }

        val rootPath = recoveryRoot.toPath()
        try {
            if (!Files.exists(rootPath, LinkOption.NOFOLLOW_LINKS)) Files.createDirectories(rootPath)
            if (Files.isSymbolicLink(rootPath) || !Files.isDirectory(rootPath, LinkOption.NOFOLLOW_LINKS)) return@synchronized null
        } catch (_: Exception) {
            return@synchronized null
        }

        val suffix = ByteArray(6).also(random::nextBytes).toHex()
        val archive = File(recoveryRoot, "${domain.id}-${observedFailure.name.lowercase()}-${System.currentTimeMillis()}-$suffix.bin")
        return@synchronized try {
            Files.copy(sourcePath, archive.toPath(), StandardCopyOption.COPY_ATTRIBUTES)
            val recheck = read()
            if (recheck.state != AuthenticatedSnapshotState.INVALID || lastFailureKind != observedFailure) {
                archive.delete()
                return@synchronized null
            }
            val sourceHash = sha256(source) ?: run { archive.delete(); return@synchronized null }
            val archiveHash = sha256(archive) ?: run { archive.delete(); return@synchronized null }
            if (!MessageDigest.isEqual(sourceHash, archiveHash)) { archive.delete(); return@synchronized null }
            val archiveHex = archiveHash.toHex()
            if (clearSource) {
                if (!authenticatedStore.clear()) { archive.delete(); return@synchronized null }
                VaultRecoveryJournal.record(domain, observedFailure, archiveHex)
                lastFailureKind = SecureVaultFailureKind.NONE
            }
            VaultRecoveryArchive(archive.name, archiveHex, observedFailure)
        } catch (_: Exception) {
            archive.delete()
            null
        }
    }

    private fun mapOuterFailure(kind: AuthenticatedSnapshotFailureKind): SecureVaultFailureKind = when (kind) {
        AuthenticatedSnapshotFailureKind.KEY_UNAVAILABLE -> SecureVaultFailureKind.OUTER_KEY_UNAVAILABLE
        AuthenticatedSnapshotFailureKind.KEY_OPERATION -> SecureVaultFailureKind.OUTER_KEY_OPERATION
        AuthenticatedSnapshotFailureKind.IO_UNAVAILABLE -> SecureVaultFailureKind.OUTER_IO_UNAVAILABLE
        AuthenticatedSnapshotFailureKind.FORMAT_INVALID,
        AuthenticatedSnapshotFailureKind.AUTHENTICATION_FAILED -> SecureVaultFailureKind.OUTER_INTEGRITY
        AuthenticatedSnapshotFailureKind.RUNTIME_FAILURE -> SecureVaultFailureKind.OUTER_RUNTIME_FAILURE
        AuthenticatedSnapshotFailureKind.NONE -> SecureVaultFailureKind.OUTER_RUNTIME_FAILURE
    }

    private fun constantTimeHexEquals(left: String, right: String): Boolean =
        MessageDigest.isEqual(left.toByteArray(Charsets.US_ASCII), right.toByteArray(Charsets.US_ASCII))

    fun clear(): Boolean = synchronized(lock) { authenticatedStore.clear() }
    fun path(): File = authenticatedStore.path()

    private fun sha256(file: File): ByteArray? = try {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered(16 * 1024).use { input ->
            val buffer = ByteArray(16 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read > 0) digest.update(buffer, 0, read)
            }
        }
        digest.digest()
    } catch (_: Exception) { null }

    private fun invalid(reason: String, kind: SecureVaultFailureKind = SecureVaultFailureKind.ENVELOPE_DECODE): AuthenticatedSnapshotRead {
        lastFailureKind = kind
        return AuthenticatedSnapshotRead(AuthenticatedSnapshotState.INVALID, reason = reason)
    }

    private fun ByteArray.toHex(): String = buildString(size * 2) {
        for (byte in this@toHex) {
            val value = byte.toInt() and 0xff
            append(HEX[value ushr 4])
            append(HEX[value and 0x0f])
        }
    }

    companion object {
        private const val MAX_RECOVERY_FILE_BYTES = 18L * 1024L * 1024L
        private val MIGRATION_RECOVERABLE_FAILURES = setOf(
            SecureVaultFailureKind.KEY_CONTINUITY,
            SecureVaultFailureKind.OUTER_KEY_UNAVAILABLE,
            SecureVaultFailureKind.OUTER_KEY_OPERATION,
        )
        private val OUTER_AEAD_RECOVERABLE_FAILURES = setOf(
            SecureVaultFailureKind.OUTER_KEY_UNAVAILABLE,
            SecureVaultFailureKind.OUTER_KEY_OPERATION,
            SecureVaultFailureKind.OUTER_INTEGRITY,
        )
        private val HEX = "0123456789abcdef".toCharArray()
    }
}
