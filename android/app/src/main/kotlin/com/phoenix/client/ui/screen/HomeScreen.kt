package com.phoenix.client.ui.screen

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.phoenix.client.ui.theme.PhoenixGreen
import com.phoenix.client.ui.theme.PhoenixOnSurfaceSecondary
import com.phoenix.client.ui.theme.PhoenixOrange
import com.phoenix.client.ui.theme.PhoenixRed
import com.phoenix.client.ui.theme.PhoenixSurface
import com.phoenix.client.ui.viewmodel.ConnectionMode
import com.phoenix.client.ui.viewmodel.ConnectionStatus
import com.phoenix.client.ui.viewmodel.HomeUiState
import com.phoenix.client.ui.viewmodel.HomeViewModel
import kotlinx.coroutines.launch

@Composable
fun HomeScreen(
    viewModel: HomeViewModel = hiltViewModel(),
    onNavigateToConfig: () -> Unit = {},
) {
    val uiState by viewModel.uiState.collectAsState()
    val connectionMode by viewModel.connectionMode.collectAsState()
    val isConfigured by viewModel.isConfigured.collectAsState()

    val drawerState = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()

    // VPN permission launcher
    val vpnLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.onVpnPermissionGranted()
        } else {
            viewModel.onVpnPermissionDenied()
        }
    }

    LaunchedEffect(uiState.vpnPermissionIntent) {
        uiState.vpnPermissionIntent?.let { intent ->
            viewModel.clearVpnPermissionIntent()
            vpnLauncher.launch(intent)
        }
    }

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            ModalDrawerSheet(
                modifier = Modifier
                    .fillMaxWidth(0.88f)
                    .fillMaxHeight(),
                drawerContainerColor = Color(0xFF111111),
            ) {
                DevLogDrawer(
                    logs = uiState.logs,
                    onClear = viewModel::clearLogs,
                )
            }
        },
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {

            // ── Header ─────────────────────────────────────────────────────────
            HomeHeader(
                connectionMode = connectionMode,
                onDebugClick = { scope.launch { drawerState.open() } },
            )

            Spacer(Modifier.height(24.dp))

            // ── Status block — prominent, always visible ────────────────────────
            StatusBlock(
                status = uiState.connectionStatus,
                mode = connectionMode,
                uptimeSeconds = uiState.uptimeSeconds,
                errorMessage = uiState.errorMessage,
            )

            Spacer(Modifier.height(36.dp))

            // ── Connect button — disabled while CONNECTING ─────────────────────
            ConnectButton(
                status = uiState.connectionStatus,
                onClick = viewModel::onMainButtonClicked,
            )

            // ── Cancel button — only visible during CONNECTING ─────────────────
            AnimatedVisibility(
                visible = uiState.connectionStatus == ConnectionStatus.CONNECTING,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically(),
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Spacer(Modifier.height(8.dp))
                    TextButton(onClick = viewModel::onCancelClicked) {
                        Text(
                            "Cancel",
                            style = MaterialTheme.typography.bodyMedium,
                            color = PhoenixOnSurfaceSecondary,
                        )
                    }
                }
            }

            Spacer(Modifier.height(16.dp))

            // ── Contextual hint ────────────────────────────────────────────────
            ContextualHint(
                status = uiState.connectionStatus,
                isConfigured = isConfigured,
                onNavigateToConfig = onNavigateToConfig,
            )

            Spacer(Modifier.height(28.dp))

            // ── Stats card — always visible ────────────────────────────────────
            StatsCard(uiState = uiState, connectionMode = connectionMode)

            Spacer(Modifier.height(24.dp))
        }
    }
}

// ── Header ─────────────────────────────────────────────────────────────────────

@Composable
private fun HomeHeader(
    connectionMode: ConnectionMode,
    onDebugClick: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = "Phoenix",
            style = MaterialTheme.typography.headlineLarge,
            color = PhoenixOrange,
            modifier = Modifier.weight(1f),
        )

        // Mode chip — always shows the active mode at a glance
        Surface(
            shape = RoundedCornerShape(50),
            color = PhoenixSurface,
        ) {
            Text(
                text = if (connectionMode == ConnectionMode.VPN) "VPN" else "SOCKS5",
                style = MaterialTheme.typography.labelSmall,
                color = PhoenixOnSurfaceSecondary,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
            )
        }

        Spacer(Modifier.width(4.dp))

        // Debug log drawer trigger — 48dp touch target
        IconButton(
            onClick = onDebugClick,
            modifier = Modifier.size(48.dp),
        ) {
            Icon(
                imageVector = Icons.Filled.BugReport,
                contentDescription = "Developer Logs",
                tint = Color(0xFF555555),
                modifier = Modifier.size(20.dp),
            )
        }
    }
}

// ── Status block ───────────────────────────────────────────────────────────────

@Composable
private fun StatusBlock(
    status: ConnectionStatus,
    mode: ConnectionMode,
    uptimeSeconds: Long,
    errorMessage: String?,
) {
    val statusColor by animateColorAsState(
        targetValue = when (status) {
            ConnectionStatus.CONNECTED -> PhoenixGreen
            ConnectionStatus.ERROR -> PhoenixRed
            ConnectionStatus.CONNECTING -> PhoenixOrange
            ConnectionStatus.DISCONNECTED -> Color(0xFF757575)
        },
        animationSpec = tween(400),
        label = "statusColor",
    )

    val statusLabel = when (status) {
        ConnectionStatus.DISCONNECTED -> "Disconnected"
        ConnectionStatus.CONNECTING -> "Connecting…"
        ConnectionStatus.CONNECTED -> "Connected"
        ConnectionStatus.ERROR -> "Connection Error"
    }

    val statusSubtitle = when (status) {
        ConnectionStatus.CONNECTED ->
            "${if (mode == ConnectionMode.VPN) "VPN" else "SOCKS5"} · ${formatUptime(uptimeSeconds)}"
        ConnectionStatus.ERROR ->
            errorMessage ?: "An unknown error occurred"
        ConnectionStatus.CONNECTING ->
            "Establishing secure tunnel…"
        ConnectionStatus.DISCONNECTED ->
            "Your traffic is not protected"
    }

    Surface(
        shape = RoundedCornerShape(16.dp),
        color = statusColor.copy(alpha = 0.10f),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 20.dp, vertical = 18.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(12.dp)
                    .clip(CircleShape)
                    .background(statusColor),
            )
            Spacer(Modifier.width(14.dp))
            Column {
                Text(
                    text = statusLabel,
                    style = MaterialTheme.typography.titleMedium,
                    color = statusColor,
                )
                Spacer(Modifier.height(3.dp))
                Text(
                    text = statusSubtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (status == ConnectionStatus.ERROR)
                        PhoenixRed.copy(alpha = 0.75f)
                    else
                        PhoenixOnSurfaceSecondary,
                )
            }
        }
    }
}

// ── Connect button ─────────────────────────────────────────────────────────────

@Composable
private fun ConnectButton(status: ConnectionStatus, onClick: () -> Unit) {
    val buttonColor by animateColorAsState(
        targetValue = when (status) {
            ConnectionStatus.CONNECTED -> PhoenixRed
            else -> PhoenixOrange
        },
        animationSpec = tween(400),
        label = "btnColor",
    )

    Button(
        onClick = onClick,
        enabled = status != ConnectionStatus.CONNECTING,
        modifier = Modifier.size(140.dp),
        shape = CircleShape,
        colors = ButtonDefaults.buttonColors(
            containerColor = buttonColor,
            disabledContainerColor = PhoenixOrange.copy(alpha = 0.45f),
        ),
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            when (status) {
                ConnectionStatus.CONNECTING -> CircularProgressIndicator(
                    modifier = Modifier.size(28.dp),
                    color = Color.White,
                    strokeWidth = 2.5.dp,
                )
                ConnectionStatus.CONNECTED ->
                    Text("Disconnect", style = MaterialTheme.typography.titleMedium)
                else ->
                    Text("Connect", style = MaterialTheme.typography.titleMedium)
            }
        }
    }
}

// ── Contextual hint ────────────────────────────────────────────────────────────

@Composable
private fun ContextualHint(
    status: ConnectionStatus,
    isConfigured: Boolean,
    onNavigateToConfig: () -> Unit,
) {
    when {
        // Error — show recovery action
        status == ConnectionStatus.ERROR -> {
            TextButton(onClick = onNavigateToConfig) {
                Text(
                    text = "Connection failed · ",
                    style = MaterialTheme.typography.bodySmall,
                    color = PhoenixOnSurfaceSecondary,
                )
                Text(
                    text = "Check Config →",
                    style = MaterialTheme.typography.bodySmall,
                    color = PhoenixOrange,
                )
            }
        }
        // No server configured yet — guide user to Config
        !isConfigured -> {
            TextButton(onClick = onNavigateToConfig) {
                Text(
                    text = "No server configured · ",
                    style = MaterialTheme.typography.bodySmall,
                    color = PhoenixOnSurfaceSecondary,
                )
                Text(
                    text = "Set up →",
                    style = MaterialTheme.typography.bodySmall,
                    color = PhoenixOrange,
                )
            }
        }
        // Connected — positive confirmation
        status == ConnectionStatus.CONNECTED -> {
            Text(
                text = "Tunnel active · traffic is routed",
                style = MaterialTheme.typography.bodySmall,
                color = PhoenixGreen.copy(alpha = 0.85f),
                textAlign = TextAlign.Center,
            )
        }
        // Connecting — status block already shows subtitle; show nothing extra
        status == ConnectionStatus.CONNECTING -> Unit
        // Ready
        else -> {
            Text(
                text = "Tap Connect to start tunneling",
                style = MaterialTheme.typography.bodySmall,
                color = PhoenixOnSurfaceSecondary,
                textAlign = TextAlign.Center,
            )
        }
    }
}

// ── Stats card — always visible ────────────────────────────────────────────────

@Composable
private fun StatsCard(uiState: HomeUiState, connectionMode: ConnectionMode) {
    val isConnected = uiState.connectionStatus == ConnectionStatus.CONNECTED

    Surface(
        shape = RoundedCornerShape(12.dp),
        color = PhoenixSurface,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Connection Info",
                style = MaterialTheme.typography.labelSmall,
                color = PhoenixOnSurfaceSecondary,
            )
            Spacer(Modifier.height(10.dp))

            StatRow(
                label = "State",
                value = uiState.connectionStatus.name
                    .lowercase()
                    .replaceFirstChar { it.uppercase() },
            )
            StatRow(
                label = "Attempts",
                value = if (uiState.connectionAttempts > 0)
                    uiState.connectionAttempts.toString() else "—",
            )
            StatRow(
                label = "Mode",
                value = if (connectionMode == ConnectionMode.VPN) "VPN" else "SOCKS5 Proxy",
            )
            StatRow(
                label = "Uptime",
                value = if (isConnected) formatUptime(uiState.uptimeSeconds) else "—",
            )
            StatRow(label = "Local proxy", value = "127.0.0.1:10080")
        }
    }
}

@Composable
private fun StatRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = PhoenixOnSurfaceSecondary)
        Text(value, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
    }
}

private fun formatUptime(seconds: Long): String {
    val h = seconds / 3600
    val m = (seconds % 3600) / 60
    val s = seconds % 60
    return "%02d:%02d:%02d".format(h, m, s)
}

// ── Developer log drawer (left panel) ─────────────────────────────────────────

@Composable
private fun DevLogDrawer(logs: List<String>, onClear: () -> Unit) {
    val listState = rememberLazyListState()
    val context = LocalContext.current

    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) {
            listState.animateScrollToItem(logs.size - 1)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = "Developer Logs (${logs.size})",
                style = MaterialTheme.typography.titleMedium,
                color = PhoenixOnSurfaceSecondary,
            )
            if (logs.isNotEmpty()) {
                Row {
                    TextButton(onClick = {
                        val clipboard =
                            context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(
                            ClipData.newPlainText("Phoenix Logs", logs.joinToString("\n")),
                        )
                    }) {
                        Text(
                            "Copy",
                            style = MaterialTheme.typography.labelSmall,
                            color = PhoenixOnSurfaceSecondary,
                        )
                    }
                    TextButton(onClick = onClear) {
                        Text(
                            "Clear",
                            style = MaterialTheme.typography.labelSmall,
                            color = PhoenixOnSurfaceSecondary,
                        )
                    }
                }
            }
        }

        Spacer(Modifier.height(8.dp))
        HorizontalDivider(color = Color.Gray.copy(alpha = 0.25f))
        Spacer(Modifier.height(8.dp))

        Surface(
            shape = RoundedCornerShape(8.dp),
            color = Color(0xFF0A0A0A),
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
        ) {
            if (logs.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        "No logs yet",
                        style = MaterialTheme.typography.labelSmall,
                        color = PhoenixOnSurfaceSecondary,
                    )
                }
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.padding(8.dp),
                ) {
                    items(logs) { line ->
                        val lineColor = when {
                            line.startsWith("ERROR") -> Color(0xFFFF6666)
                            line.startsWith("CMD:") -> Color(0xFFFFCC44)
                            else -> Color(0xFF88FF88)
                        }
                        Text(
                            text = line,
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                            ),
                            color = lineColor,
                            modifier = Modifier.padding(vertical = 1.dp),
                        )
                    }
                }
            }
        }
    }
}
