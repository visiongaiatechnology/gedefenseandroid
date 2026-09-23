package de.visiongaia.gedefense.mobile

import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest

object SecureFiles {
    private const val PRIVATE_FILE_MODE = 384 // 0600
    private const val VERIFY_BUFFER_BYTES = 32 * 1024

    fun createPrivateTempFile(directory: File, prefix: String, suffix: String = ".tmp"): File {
        require(prefix.length >= 3 && prefix.length <= 96) { "invalid temp prefix" }
        require(suffix.length in 1..32 && !suffix.contains('/') && !suffix.contains('\\')) { "invalid temp suffix" }
        require(directory.mkdirs() || directory.isDirectory) { "temp directory unavailable" }
        val parent = directory.canonicalFile
        val temp = File.createTempFile(prefix, suffix, parent)
        try {
            val canonical = temp.canonicalFile
            require(canonical.parentFile == parent) { "temp file escaped directory" }
            Os.chmod(canonical.absolutePath, PRIVATE_FILE_MODE)
            return canonical
        } catch (t: Throwable) {
            temp.delete()
            throw t
        }
    }

    /**
     * Atomic same-directory commit backed directly by Linux rename(2), followed by a parent-directory
     * fsync. Java's ATOMIC_MOVE fallback is deliberately not used: silently degrading to a non-atomic
     * replacement would violate the crash-safety contract of security state.
     */
    fun atomicReplace(temp: File, target: File) {
        val parent = target.parentFile ?: error("target has no parent")
        require(parent.mkdirs() || parent.isDirectory) { "target directory unavailable" }
        val canonicalParent = parent.canonicalFile
        val canonicalTemp = temp.canonicalFile
        require(canonicalTemp.parentFile == canonicalParent) { "atomic replace requires same directory" }
        val canonicalTarget = File(canonicalParent, target.name)
        Os.rename(canonicalTemp.absolutePath, canonicalTarget.absolutePath)
        fsyncDirectory(canonicalParent)
    }

    fun writeAtomic(target: File, bytes: ByteArray) {
        val parent = target.parentFile ?: error("target has no parent")
        val temp = createPrivateTempFile(parent, ".${target.name.take(72)}.tmp-")
        try {
            FileOutputStream(temp, false).use { output ->
                output.write(bytes)
                output.fd.sync()
            }
            verifyExactBytes(temp, bytes)
            atomicReplace(temp, target)
        } finally {
            if (temp.exists()) temp.delete()
        }
    }

    private fun verifyExactBytes(file: File, expected: ByteArray) {
        if (file.length() != expected.size.toLong()) throw IOException("durable write length verification failed")
        val expectedDigest = MessageDigest.getInstance("SHA-256").digest(expected)
        val actualDigest = try {
            val digest = MessageDigest.getInstance("SHA-256")
            FileInputStream(file).use { input ->
                val buffer = ByteArray(VERIFY_BUFFER_BYTES)
                try {
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        if (read > 0) digest.update(buffer, 0, read)
                    }
                } finally {
                    buffer.fill(0)
                }
            }
            digest.digest()
        } finally {
            // expectedDigest is cleared after comparison below; this branch only scopes actual read.
        }
        try {
            if (!MessageDigest.isEqual(expectedDigest, actualDigest)) {
                throw IOException("durable write digest verification failed")
            }
        } finally {
            expectedDigest.fill(0)
            actualDigest.fill(0)
        }
    }

    fun fsyncDirectory(directory: File) {
        val fd = Os.open(directory.absolutePath, OsConstants.O_RDONLY, 0)
        try {
            Os.fsync(fd)
        } finally {
            Os.close(fd)
        }
    }
}
