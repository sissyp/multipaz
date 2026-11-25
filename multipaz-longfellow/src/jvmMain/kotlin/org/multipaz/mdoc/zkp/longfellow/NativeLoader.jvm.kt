package org.multipaz.mdoc.zkp.longfellow

import java.io.File

internal actual object NativeLoader {
    actual fun loadLibrary(libraryName: String): String? {

        // Optional override for local native integration tests.
        val overridePath = System.getProperty("multipaz.longfellow.nativeLibraryPath")
        if (!overridePath.isNullOrBlank()) {
            require(java.io.File(overridePath).isFile) {
                "Native Longfellow library not found: $overridePath"
            }
            return overridePath
        }
        val os = System.getProperty("os.name").lowercase()
        val arch = System.getProperty("os.arch")

        val platformDir = when {
            os.contains("mac") && arch == "x86_64" -> "macos-x86_64"
            os.contains("mac") && arch == "aarch64" -> "macos-arm64"
            os.contains("linux") && (arch == "x86_64" || arch == "amd64") -> "linux-x86_64"
            else -> error("Unsupported platform: $os $arch")
        }

        val ext = if (os.contains("mac")) "dylib" else "so"
        val libFileName = "lib$libraryName.$ext"
        val libPath = "/nativeLibs/$platformDir/$libFileName"

        val url = {}::class.java.getResource(libPath)
            ?: error("Could not find native library: $libPath")

        val tempDir = kotlin.io.path.createTempDirectory("native_libs").toFile().apply {
            deleteOnExit()
        }
        val tempFile = File(tempDir, libFileName).apply {
            deleteOnExit()
            writeBytes(url.readBytes())
        }

        return tempFile.absolutePath
    }
}
