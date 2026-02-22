package com.phoenix.client.util

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class GeneratedKeyPair(
    /** File name (relative to filesDir) where the private key PEM was written. */
    val privateKeyFile: String,
    /** Base64-encoded Ed25519 public key to paste into the server's authorized_clients. */
    val publicKey: String,
)

/**
 * Generates an Ed25519 keypair by running the bundled Go binary with `-gen-keys`.
 * This guarantees byte-for-byte identical format to all other Phoenix platforms.
 */
object KeyManager {

    private const val PRIVATE_KEY_FILENAME = "client.private.key"

    /**
     * Extracts the binary if needed and runs `-gen-keys -files-dir <filesDir>`.
     * Parses the structured stdout lines:
     *   KEY_PATH=/data/.../files/client_private.key
     *   PUBLIC_KEY=<base64>
     *
     * @throws IllegalStateException if the process fails or output is malformed.
     */
    suspend fun generateKeys(context: Context): GeneratedKeyPair = withContext(Dispatchers.IO) {
        val binary = BinaryExtractor.extract(context)

        val process = ProcessBuilder(
            binary.absolutePath,
            "-gen-keys",
            "-files-dir", context.filesDir.absolutePath,
        )
            .redirectErrorStream(false)
            .start()

        val stdout = process.inputStream.bufferedReader().readText()
        val stderr = process.errorStream.bufferedReader().readText()
        val exitCode = process.waitFor()

        if (exitCode != 0) {
            throw IllegalStateException("Key generation failed (exit $exitCode): $stderr")
        }

        val publicKey = stdout.lines()
            .firstOrNull { it.startsWith("PUBLIC_KEY=") }
            ?.removePrefix("PUBLIC_KEY=")
            ?.trim()
            ?: throw IllegalStateException("PUBLIC_KEY not found in binary output:\n$stdout")

        GeneratedKeyPair(
            privateKeyFile = PRIVATE_KEY_FILENAME,
            publicKey = publicKey,
        )
    }
}
