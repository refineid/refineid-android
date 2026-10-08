// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import java.io.File

/**
 * Points the generated RAPP binding at the host cdylib the unit-test build
 * produces, so bridge tests run on the JVM.
 */
internal object RappNativeTestLibrary {
    private val LIBRARY_NAMES = listOf("librefineid_rapp.dylib", "librefineid_rapp.so", "refineid_rapp.dll")

    private val found: Boolean by lazy {
        val candidate = findNativeLibrary() ?: return@lazy false
        val parentDir = candidate.parentFile?.canonicalPath ?: candidate.parent ?: ""
        val existing = System.getProperty("jna.library.path")
        System.setProperty(
            "jna.library.path",
            if (existing != null) "$existing:$parentDir" else parentDir,
        )
        System.setProperty(
            "uniffi.component.refineid_rapp.libraryOverride",
            candidate.canonicalPath,
        )
        true
    }

    /** Requires the library on CI and skips the test elsewhere when it is absent. */
    fun require() {
        val isCi = System.getenv("CI") == "true" || System.getenv("GITHUB_ACTIONS") == "true"
        if (isCi) {
            assertTrue("RAPP native host library must be built and available on CI", found)
        } else {
            assumeTrue("RAPP native library available", found)
        }
    }

    private fun findNativeLibrary(): File? {
        val jnaPath = System.getProperty("jna.library.path")
        if (!jnaPath.isNullOrBlank()) {
            for (dir in jnaPath.split(File.pathSeparator).map { File(it) }) {
                LIBRARY_NAMES.map { File(dir, it) }.firstOrNull { it.exists() }?.let { return it }
            }
        }
        var dir: File? = File(".").canonicalFile
        while (dir != null) {
            val found =
                LIBRARY_NAMES
                    .map { File(dir, "native/refineid-rapp-android/target/debug/$it") }
                    .firstOrNull { it.exists() }
            if (found != null) {
                return found
            }
            dir = dir.parentFile
        }
        return null
    }
}
