package com.phoenix.client.util

import android.content.Context
import com.phoenix.client.domain.model.ClientConfig
import java.io.File

/**
 * Writes a TOML config file compatible with the Phoenix Go client binary.
 * Field names MUST match the Go struct tags in pkg/config/client_config.go:
 *   remote_addr, private_key, server_public_key, [[inbounds]], protocol, local_addr, enable_udp
 */
object ConfigWriter {

    private const val CONFIG_FILE = "client.toml"

    data class Result(val file: File, val tomlContent: String)

    fun write(context: Context, config: ClientConfig): Result {
        val file = File(context.filesDir, CONFIG_FILE)

        val toml = buildString {
            appendLine("remote_addr = \"${config.remoteAddr}\"")

            if (config.privateKeyFile.isNotBlank()) {
                val absPath = File(context.filesDir, config.privateKeyFile).absolutePath
                // Key: "private_key" — matches toml:"private_key" in ClientConfig Go struct
                appendLine("private_key = \"$absPath\"")
            }

            if (config.serverPubKey.isNotBlank()) {
                appendLine("server_public_key = \"${config.serverPubKey}\"")
            }

            appendLine()
            appendLine("[[inbounds]]")
            appendLine("protocol = \"socks5\"")
            appendLine("local_addr = \"${config.localSocksAddr}\"")
            appendLine("enable_udp = ${config.enableUdp}")
        }

        file.writeText(toml)
        return Result(file, toml)
    }
}
