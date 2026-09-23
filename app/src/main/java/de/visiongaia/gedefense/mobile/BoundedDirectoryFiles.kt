package de.visiongaia.gedefense.mobile

import java.io.File
import java.io.IOException
import java.nio.file.DirectoryIteratorException
import java.nio.file.Files
import java.nio.file.LinkOption

/** Bounded, no-follow directory enumeration for app-private state that is still treated as hostile. */
internal object BoundedDirectoryFiles {
    fun list(directory: File, maxEntries: Int): List<File>? {
        require(maxEntries in 1..4096) { "invalid directory scan limit" }
        val path = directory.toPath()
        if (Files.isSymbolicLink(path) || !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) return emptyList()
        return try {
            val result = ArrayList<File>(minOf(maxEntries, 32))
            Files.newDirectoryStream(path).use { stream ->
                for (entry in stream) {
                    if (result.size >= maxEntries) return null
                    result += entry.toFile()
                }
            }
            result
        } catch (error: IOException) {
            RuntimeFailureLog.nonCritical("bounded-directory-scan", error)
            null
        } catch (error: DirectoryIteratorException) {
            RuntimeFailureLog.nonCritical("bounded-directory-scan", error)
            null
        } catch (error: SecurityException) {
            RuntimeFailureLog.nonCritical("bounded-directory-scan", error)
            null
        }
    }
}
