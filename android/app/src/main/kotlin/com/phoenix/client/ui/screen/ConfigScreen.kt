package com.phoenix.client.ui.screen

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.phoenix.client.R
import com.phoenix.client.domain.model.ClientConfig
import com.phoenix.client.ui.theme.PhoenixOrange
import com.phoenix.client.ui.viewmodel.ConfigViewModel

@Composable
fun ConfigScreen(viewModel: ConfigViewModel = hiltViewModel()) {
    val savedConfig by viewModel.config.collectAsState()
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current
    val savedMessage = stringResource(R.string.config_saved)

    // Local form state — seeded from DataStore on first load
    var remoteAddr by remember(savedConfig.remoteAddr) { mutableStateOf(savedConfig.remoteAddr) }
    var serverPubKey by remember(savedConfig.serverPubKey) { mutableStateOf(savedConfig.serverPubKey) }
    var privateKeyFile by remember(savedConfig.privateKeyFile) { mutableStateOf(savedConfig.privateKeyFile) }
    var localSocksAddr by remember(savedConfig.localSocksAddr) { mutableStateOf(savedConfig.localSocksAddr) }
    var enableUdp by remember(savedConfig.enableUdp) { mutableStateOf(savedConfig.enableUdp) }

    // Keep private key field in sync when auto-saved after key generation
    LaunchedEffect(savedConfig.privateKeyFile) {
        privateKeyFile = savedConfig.privateKeyFile
    }

    LaunchedEffect(uiState.saved) {
        if (uiState.saved) {
            snackbarHostState.showSnackbar(savedMessage)
            viewModel.consumeSavedEvent()
        }
    }

    // Public key dialog — shown after successful key generation
    uiState.generatedPublicKey?.let { pubKey ->
        PublicKeyDialog(
            publicKey = pubKey,
            onCopy = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Phoenix Public Key", pubKey))
            },
            onDismiss = viewModel::dismissPublicKeyDialog,
        )
    }

    // Error dialog for key generation failures
    uiState.keyGenError?.let { err ->
        AlertDialog(
            onDismissRequest = viewModel::dismissPublicKeyDialog,
            title = { Text("Key generation failed") },
            text = { Text(err) },
            confirmButton = {
                TextButton(onClick = viewModel::dismissPublicKeyDialog) { Text("OK") }
            },
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
    ) {
        Text(
            text = stringResource(R.string.nav_config),
            style = MaterialTheme.typography.headlineLarge,
        )

        Spacer(Modifier.height(24.dp))

        OutlinedTextField(
            value = remoteAddr,
            onValueChange = { remoteAddr = it },
            label = { Text(stringResource(R.string.config_server_address)) },
            placeholder = { Text(stringResource(R.string.config_server_address_hint)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(16.dp))

        OutlinedTextField(
            value = serverPubKey,
            onValueChange = { serverPubKey = it },
            label = { Text(stringResource(R.string.config_server_pubkey)) },
            placeholder = { Text(stringResource(R.string.config_server_pubkey_hint)) },
            modifier = Modifier.fillMaxWidth(),
            maxLines = 3,
        )

        Spacer(Modifier.height(16.dp))

        // Private key row: text field + Generate button side by side
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            OutlinedTextField(
                value = privateKeyFile,
                onValueChange = { privateKeyFile = it },
                label = { Text(stringResource(R.string.config_private_key_path)) },
                placeholder = { Text(stringResource(R.string.config_private_key_hint)) },
                singleLine = true,
                modifier = Modifier.weight(1f),
                readOnly = uiState.isGeneratingKeys,
            )
        }

        Spacer(Modifier.height(8.dp))

        OutlinedButton(
            onClick = viewModel::generateKeys,
            enabled = !uiState.isGeneratingKeys,
            modifier = Modifier.fillMaxWidth(),
            border = androidx.compose.foundation.BorderStroke(1.dp, PhoenixOrange),
        ) {
            if (uiState.isGeneratingKeys) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    strokeWidth = 2.dp,
                    color = PhoenixOrange,
                )
            } else {
                Text(
                    text = stringResource(R.string.config_gen_keys),
                    color = PhoenixOrange,
                )
            }
        }

        Spacer(Modifier.height(16.dp))

        OutlinedTextField(
            value = localSocksAddr,
            onValueChange = { localSocksAddr = it },
            label = { Text("Local SOCKS5 address") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(16.dp))

        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                text = stringResource(R.string.config_enable_udp),
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodyMedium,
            )
            Switch(checked = enableUdp, onCheckedChange = { enableUdp = it })
        }

        Spacer(Modifier.height(32.dp))

        Button(
            onClick = {
                viewModel.save(
                    ClientConfig(
                        remoteAddr = remoteAddr.trim(),
                        serverPubKey = serverPubKey.trim(),
                        privateKeyFile = privateKeyFile.trim(),
                        localSocksAddr = localSocksAddr.trim(),
                        enableUdp = enableUdp,
                    ),
                )
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.config_save))
        }
    }

    SnackbarHost(hostState = snackbarHostState)
}

@Composable
private fun PublicKeyDialog(
    publicKey: String,
    onCopy: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Keys Generated") },
        text = {
            Column {
                Text(
                    text = "Your client key pair has been created. " +
                        "Add this public key to your server's authorized_clients list:",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(12.dp))
                SelectionContainer {
                    Text(
                        text = publicKey,
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                        color = PhoenixOrange,
                    )
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "Private key saved to app storage as client.private.key",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onCopy()
                    onDismiss()
                },
                colors = ButtonDefaults.buttonColors(containerColor = PhoenixOrange),
            ) {
                Text("Copy & Close")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        },
    )
}
