package dev.michaelylee.freeblocker.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.SplitButtonDefaults
import androidx.compose.material3.SplitButtonLayout
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.michaelylee.freeblocker.data.BlocklistState
import kotlinx.coroutines.delay

@Composable
fun BlockedWebsitesScreen(
    viewModel: VpnViewModel,
    onCloseApp: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val isVpnEnabled      by viewModel.isVpnEnabled.collectAsState()
    val isBlockingEnabled by viewModel.isBlockingEnabled.collectAsState()
    val isStartOnBoot     by viewModel.isStartOnBoot.collectAsState()
    val blocklistState    by viewModel.blocklistState.collectAsState()
    val pendingRestart    by viewModel.pendingRestartReason.collectAsState()
    val upstream          by viewModel.upstreamConfig.collectAsState()
    val manualBlocked     by viewModel.manualBlockedDomains.collectAsState()
    val pausedDomains     by viewModel.pausedDomains.collectAsState()
    val customUrls        by viewModel.customSourceUrls.collectAsState()
    val snackbarHost      = remember { SnackbarHostState() }
    var isListVisible     by remember { mutableStateOf(true) }
    var showInfoDialog    by remember { mutableStateOf(false) }

    if (showInfoDialog) {
        androidx.compose.ui.window.Dialog(onDismissRequest = { showInfoDialog = false }) {
            androidx.compose.material3.Surface(
                shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.surface,
                tonalElevation = 6.dp
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = """
                            The VPN automatically starts with the app and runs in the background. To stop the app completely, press the Stop VPN & Close button.
                            
                            This app will not work properly with private DNS enabled. If you have not touched this Android setting before, you don't need to worry about this.
                            
                            If the app stops working after long periods it could be due to battery optimization. Consider changing this under Settings > Apps > Free Blocker to Unrestricted.
                        """.trimIndent(),
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End
                    ) {
                        androidx.compose.material3.TextButton(onClick = { showInfoDialog = false }) {
                            Text("OK")
                        }
                    }
                }
            }
        }
    }

    LaunchedEffect(pendingRestart) {
        if (pendingRestart != null) {
            val result = snackbarHost.showSnackbar(
                message     = "Restart VPN to apply changes",
                actionLabel = "Restart",
            )
            if (result == SnackbarResult.ActionPerformed) viewModel.restartVpn()
            else viewModel.dismissRestartBanner()
        }
    }

    Scaffold(
        modifier = modifier,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        snackbarHost = { SnackbarHost(snackbarHost) }
    ) { scaffoldPadding ->
        LazyColumn(
            modifier            = Modifier
                .fillMaxSize()
                .padding(scaffoldPadding)
                .padding(horizontal = 8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {

            // ── App Header ────────────────────────────────────────────────────
            item {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp)
                ) {
                    androidx.compose.foundation.Image(
                        painter = androidx.compose.ui.res.painterResource(id = dev.michaelylee.freeblocker.R.drawable.ic_launcher_foreground),
                        contentDescription = "App Icon",
                        modifier = Modifier.size(56.dp)
                    )
                    Spacer(Modifier.width(4.dp))
                    Text(
                        text = "Free Block",
                        style = MaterialTheme.typography.headlineSmall.copy(
                            fontFamily = dev.michaelylee.freeblocker.ui.theme.RighteousFamily
                        )
                    )
                    Spacer(Modifier.weight(1f))
                    androidx.compose.material3.IconButton(
                        onClick = { showInfoDialog = true },
                        modifier = Modifier.size(56.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Info,
                            contentDescription = "Info",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(32.dp)
                        )
                    }
                }
            }

            // ── Status card ───────────────────────────────────────────────────
            item {
                VpnStatusCard(
                    isVpnEnabled        = isVpnEnabled,
                    isBlockingEnabled   = isBlockingEnabled,
                    isStartOnBoot       = isStartOnBoot,
                    onBlockingToggle    = { viewModel.setBlockingEnabled(it) },
                    onStartOnBootToggle = { viewModel.setStartOnBoot(it) },
                    onCloseApp          = onCloseApp,
                )
            }

            // ── Manual blocked domains ────────────────────────────────────────
            item {
                Column(
                    modifier = Modifier
                        .padding(top = 12.dp, bottom = 4.dp)
                        .padding(horizontal = 8.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text  = "Blocked Websites",
                            style = MaterialTheme.typography.titleLarge,
                        )
                        Spacer(Modifier.weight(1f))
                        androidx.compose.material3.FilledIconButton(
                            onClick = { isListVisible = !isListVisible },
                            shape = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
                            modifier = Modifier.size(32.dp)
                        ) {
                            Icon(
                                imageVector = if (isListVisible) Icons.Default.Visibility else Icons.Default.VisibilityOff,
                                contentDescription = if (isListVisible) "Hide list" else "Show list",
                                modifier = Modifier.size(20.dp)
                            )
                        }
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text  = "${manualBlocked.size} websites blocked manually",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    val blocklistText = if (customUrls.isNotEmpty()) {
                        when (blocklistState) {
                            is BlocklistState.Loading -> "updating blocklists…"
                            is BlocklistState.Error   -> "⚠ error updating blocklists"
                            else                      -> ""
                        }
                    } else {
                        ""
                    }
                    if (blocklistText.isNotEmpty()) {
                        Text(
                            text  = blocklistText,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                HorizontalDivider(modifier = Modifier.padding(horizontal = 8.dp))
                Spacer(Modifier.height(4.dp))
                DomainInputRow(
                    placeholder = "e.g. ads.example.com",
                    onAdd       = { viewModel.addManualBlockedDomain(it) },
                    modifier    = Modifier.padding(8.dp),
                )
            }

            if (isListVisible) {
                items(manualBlocked.toList().sorted(), key = { "blocked_$it" }) { domain ->
                    val expiresAt = pausedDomains[domain]
                    BlockedDomainRow(
                        domain     = domain,
                        expiresAt  = expiresAt,
                        onPause    = { durationMs -> viewModel.pauseBlockedDomain(domain, durationMs) },
                        onResume   = { viewModel.resumeBlockedDomain(domain) },
                        onDelete   = { viewModel.removeManualBlockedDomain(domain) },
                    )
                }
            }

            item { Spacer(Modifier.height(8.dp)) }
        }
    }
}

// ── VPN status card ───────────────────────────────────────────────────────────

@Composable
private fun VpnStatusCard(
    isVpnEnabled        : Boolean,
    isBlockingEnabled   : Boolean,
    isStartOnBoot       : Boolean,
    onBlockingToggle    : (Boolean) -> Unit,
    onStartOnBootToggle : (Boolean) -> Unit,
    onCloseApp          : () -> Unit,
) {
    val containerColor = if (isBlockingEnabled)
        MaterialTheme.colorScheme.primaryContainer
    else
        MaterialTheme.colorScheme.secondaryContainer

    Card(
        colors   = CardDefaults.cardColors(containerColor = containerColor),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(start = 12.dp, end = 12.dp, top = 4.dp, bottom = 12.dp)) {

            // ── Blocking enabled row ──────────────────────────────────────────
            Row(
                verticalAlignment     = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier              = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text  = "Enable blocking",
                    style = MaterialTheme.typography.bodyLarge,
                )
                Switch(
                    checked         = isBlockingEnabled,
                    onCheckedChange = onBlockingToggle,
                )
            }

            Spacer(Modifier.height(2.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f))
            Spacer(Modifier.height(2.dp))

            // ── Start on boot row ─────────────────────────────────────────────
            Row(
                verticalAlignment     = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier              = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text  = "Start on boot",
                    style = MaterialTheme.typography.bodyLarge,
                )
                Switch(
                    checked         = isStartOnBoot,
                    onCheckedChange = onStartOnBootToggle,
                )
            }

            Spacer(Modifier.height(2.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f))

            Spacer(Modifier.height(8.dp))

            // ── VPN status + Stop button ──────────────────────────────────────
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "VPN Status:",
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Spacer(Modifier.width(8.dp))
                    val dotColor = if (isVpnEnabled) Color(0xFF4CAF50) else Color(0xFFF44336)
                    Canvas(modifier = Modifier.size(14.dp)) {
                        drawCircle(color = dotColor)
                    }
                    Spacer(Modifier.width(6.dp))
                    Text(
                        text = if (isVpnEnabled) "ON" else "OFF",
                        style = MaterialTheme.typography.titleMedium,
                        color = dotColor,
                    )
                }
                Button(onClick = onCloseApp) {
                    Text("Stop VPN & Close")
                }
            }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 10.dp),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                val uriHandler = androidx.compose.ui.platform.LocalUriHandler.current
                Text(
                    text = "WEBSITE",
                    style = MaterialTheme.typography.labelSmall.copy(
                        textDecoration = TextDecoration.Underline
                    ),
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier
                        .clickable { uriHandler.openUri("https://example.com") }
                        .padding(4.dp),
                )
                Text(
                    text = "PRIVACY",
                    style = MaterialTheme.typography.labelSmall.copy(
                        textDecoration = TextDecoration.Underline
                    ),
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier
                        .clickable { uriHandler.openUri("https://example.com/privacy") }
                        .padding(4.dp),
                )
            }
        }
    }
}

// ── Blocked domain row with SplitButton ──────────────────────────────────────

/**
 * Pause duration choices exposed in the split-button dropdown.
 */
private data class PauseDuration(val label: String, val millis: Long?)

private val PAUSE_DURATIONS = listOf(
    PauseDuration("15 minutes",  15 * 60 * 1_000L),
    PauseDuration("1 hour",      60 * 60 * 1_000L),
    PauseDuration("1 day",       24 * 60 * 60 * 1_000L),
    PauseDuration("Indefinitely", null),
)

/**
 * Formats a remaining-time in millis into a compact human string.
 * e.g. "14m left", "23h left", "<1m left"
 */
private fun formatRemaining(remainingMs: Long): String {
    val totalMinutes = remainingMs / 60_000
    return when {
        totalMinutes < 1   -> "<1m left"
        totalMinutes < 60  -> "${totalMinutes}m left"
        totalMinutes < 1440 -> "${totalMinutes / 60}h left"
        else               -> "${totalMinutes / 1440}d left"
    }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
private fun BlockedDomainRow(
    domain: String,
    expiresAt: Long?,
    onPause: (durationMs: Long?) -> Unit,
    onResume: () -> Unit,
    onDelete: () -> Unit,
) {
    val isPaused = expiresAt != null
    var menuExpanded by remember { mutableStateOf(false) }

    // Live countdown: re-read current time every second while paused with a timer
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    if (isPaused && expiresAt != Long.MAX_VALUE) {
        LaunchedEffect(expiresAt) {
            while (true) {
                now = System.currentTimeMillis()
                delay(1_000L)
            }
        }
    }

    val subtitle = when {
        !isPaused                  -> null
        expiresAt == Long.MAX_VALUE -> "paused indefinitely"
        else                       -> "paused · ${formatRemaining(expiresAt - now)}"
    }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 12.dp, top = 4.dp, end = 8.dp, bottom = 4.dp),
    ) {
        // Domain label
        var isExpanded by remember { mutableStateOf(false) }
        Column(
            modifier = Modifier
                .weight(1f)
                .clickable { isExpanded = !isExpanded }
        ) {
            Text(
                text      = domain,
                style     = MaterialTheme.typography.bodyMedium,
                maxLines  = if (isExpanded) Int.MAX_VALUE else 1,
                overflow  = if (isExpanded) TextOverflow.Clip else TextOverflow.Ellipsis,
                color     = if (isPaused) MaterialTheme.colorScheme.onSurfaceVariant
                            else MaterialTheme.colorScheme.onSurface,
            )
            if (subtitle != null) {
                Text(
                    text  = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        Spacer(Modifier.width(8.dp))

        // Pause / Resume split button
        SplitButtonLayout(
            leadingButton = {
                SplitButtonDefaults.LeadingButton(
                    onClick = { if (isPaused) onResume() else onPause(PAUSE_DURATIONS.first().millis) },
                ) {
                    Icon(
                        imageVector = if (isPaused) Icons.Default.PlayArrow else Icons.Default.Pause,
                        contentDescription = if (isPaused) "Resume" else "Pause",
                        modifier = Modifier.size(18.dp),
                    )
                }
            },
            trailingButton = {
                SplitButtonDefaults.TrailingButton(
                    checked = menuExpanded,
                    onCheckedChange = { menuExpanded = it },
                ) {
                    val rotation by animateFloatAsState(targetValue = if (menuExpanded) 180f else 0f)
                    Icon(
                        imageVector = Icons.Default.ArrowDropDown,
                        contentDescription = "Expand menu",
                        modifier = Modifier.rotate(rotation)
                    )
                }
            },
        )

        // Dropdown menu anchored to the split button
        DropdownMenu(
            expanded         = menuExpanded,
            onDismissRequest = { menuExpanded = false },
            shape            = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
            modifier         = Modifier.padding(4.dp)
        ) {
            PAUSE_DURATIONS.forEach { duration ->
                DropdownMenuItem(
                    text    = { Text(duration.label, style = MaterialTheme.typography.bodyLarge) },
                    onClick = {
                        menuExpanded = false
                        onPause(duration.millis)
                    },
                    leadingIcon = {
                        Icon(
                            imageVector = Icons.Default.Schedule,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                )
            }
            HorizontalDivider(modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp))
            DropdownMenuItem(
                text = { Text("Delete", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyLarge) },
                onClick = {
                    menuExpanded = false
                    onDelete()
                },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Default.Delete,
                        contentDescription = "Delete",
                        tint = MaterialTheme.colorScheme.error
                    )
                }
            )
        }
    }
}

// ── Shared sub-composables ────────────────────────────────────────────────────

@Composable
internal fun DomainInputRow(
    placeholder: String,
    onAdd: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var text by remember { mutableStateOf("") }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier          = modifier.fillMaxWidth(),
    ) {
        OutlinedTextField(
            value         = text,
            onValueChange = { text = it },
            placeholder   = { Text(placeholder) },
            singleLine    = true,
            modifier      = Modifier.weight(1f),
        )
        Spacer(Modifier.width(8.dp))
        Button(
            onClick = {
                if (text.isNotBlank()) {
                    onAdd(text.trim())
                    text = ""
                }
            },
        ) {
            Text("Add")
        }
    }
}

@Composable
internal fun DomainRow(label: String, onDelete: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier          = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
    ) {
        Text(
            text     = label,
            style    = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f),
        )
        IconButton(onClick = onDelete) {
            Icon(Icons.Default.Delete, contentDescription = "Remove")
        }
    }
}