package com.phoenix.client.util

import android.content.Context
import java.io.File

/**
 * Returns the Go client binary from the app's native library directory.
 *
 * The binary is packaged as `libphoenixclient.so` in `jniLibs/arm64-v8a/`
 * and extracted by the Android installer to `nativeLibraryDir`. That path
 * is always executable — no chmod needed and no W^X policy restriction.
 */
object BinaryExtractor {

    private const val LIB_NAME = "libphoenixclient.so"

    fun extract(context: Context): File {
        val binary = File(context.applicationInfo.nativeLibraryDir, LIB_NAME)
        check(binary.exists()) {
            "Phoenix binary not found at ${binary.absolutePath}. " +
                "Run 'make android-client' before building the APK."
        }
        return binary
    }
}
