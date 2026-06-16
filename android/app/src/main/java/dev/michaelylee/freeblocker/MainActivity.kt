package dev.michaelylee.freeblocker

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Smartphone
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.unit.dp
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.core.content.ContextCompat
import dev.michaelylee.freeblocker.ui.AppsScreen
import dev.michaelylee.freeblocker.ui.BlockedWebsitesScreen
import dev.michaelylee.freeblocker.ui.BlocklistsScreen
import dev.michaelylee.freeblocker.ui.VpnViewModel
import dev.michaelylee.freeblocker.ui.theme.FreeBlockerTheme
import dev.michaelylee.freeblocker.ui.theme.ThemeMode

class MainActivity : ComponentActivity() {

    companion object {
        const val ACTION_STOP_AND_CLOSE = "dev.michaelylee.freeblocker.STOP_AND_CLOSE"
    }

    private val viewModel: VpnViewModel by viewModels()

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.setVpnEnabled(true)
        }
    }

    /**
     * Requests POST_NOTIFICATIONS at runtime (required on Android 13+ / API 33+).
     * After the user responds (grant or deny), we proceed to start the VPN.
     */
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        // Whether granted or denied, continue starting the VPN.
        // The foreground service will still run; the notification simply won't
        // appear if the user chose "Don't allow".
        requestVpnPermissionIfNeeded()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (intent?.action == ACTION_STOP_AND_CLOSE) {
            stopVpnAndClose()
            return
        }

        // The permission check is now deferred until after the welcome dialog is resolved,
        // or immediately if the user has already seen it.

        setContent {
            var selectedTab by remember { mutableStateOf(0) }
            val themeMode by viewModel.themeMode.collectAsState()
            val hasSeenWelcome by viewModel.hasSeenWelcome.collectAsState()

            var showWelcomeDialog by remember { mutableStateOf(false) }
            var permissionsRequested by remember { mutableStateOf(false) }

            LaunchedEffect(hasSeenWelcome) {
                if (hasSeenWelcome == false && !permissionsRequested) {
                    showWelcomeDialog = true
                } else if (hasSeenWelcome == true && !permissionsRequested) {
                    permissionsRequested = true
                    checkAndRequestPermissions()
                }
            }

            if (showWelcomeDialog) {
                var dontShowAgain by remember { mutableStateOf(false) }
                FreeBlockerTheme(themeMode = ThemeMode.Dark) {
                    AlertDialog(
                    onDismissRequest = {
                        // User dismissed by clicking outside or back button
                        showWelcomeDialog = false
                        if (dontShowAgain) {
                            viewModel.setHasSeenWelcome(true)
                        }
                        permissionsRequested = true
                        checkAndRequestPermissions()
                    },
                    title = {
                        Text(
                            text = "Welcome to Free Blocker!",
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Bold
                        )
                    },
                    text = {
                        Column {
                            Text(
                                "To provide you with a distraction-free experience, Free Blocker requires two permissions:",
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            
                            Text(
                                "• Notification Permission:\nThis allows us to show a persistent notification while the blocker is active. This ensures the Android system doesn't kill the blocker in the background and lets you quickly manage it.",
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            
                            Text(
                                "• VPN Permission:\nWe use a local VPN to filter your network traffic and block selected domains directly on your device. Your data never leaves your phone and is not sent to any external server.",
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            
                            Text(
                                "Please grant these permissions on the next screens to start using Free Blocker.",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold
                            )
                            
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.padding(top = 8.dp)
                            ) {
                                Checkbox(
                                    checked = dontShowAgain,
                                    onCheckedChange = { dontShowAgain = it }
                                )
                                Text("Don't show again", style = MaterialTheme.typography.bodyMedium)
                            }
                        }
                    },
                    confirmButton = {
                        TextButton(onClick = {
                            showWelcomeDialog = false
                            if (dontShowAgain) {
                                viewModel.setHasSeenWelcome(true)
                            }
                            permissionsRequested = true
                            checkAndRequestPermissions()
                        }) {
                            Text("OK")
                        }
                    }
                )
                }
            }

            FreeBlockerTheme(themeMode = themeMode) {
                Scaffold(
                    bottomBar = {
                        NavigationBar {
                            NavigationBarItem(
                                selected = selectedTab == 0,
                                onClick  = { selectedTab = 0 },
                                icon     = { Icon(Icons.Default.Block, contentDescription = "Blocked") },
                                label    = { Text("Blocked") },
                            )
                            NavigationBarItem(
                                selected = selectedTab == 1,
                                onClick  = { selectedTab = 1 },
                                icon     = { Icon(Icons.Default.Shield, contentDescription = "Blocklists") },
                                label    = { Text("Blocklists") },
                            )
                            NavigationBarItem(
                                selected = selectedTab == 2,
                                onClick  = { selectedTab = 2 },
                                icon     = { Icon(Icons.Default.Smartphone, contentDescription = "") },
                                label    = { Text("Whitelist") },
                            )
                        }
                    }
                ) { padding ->
                    when (selectedTab) {
                        0 -> BlockedWebsitesScreen(
                            viewModel  = viewModel,
                            themeMode = themeMode,
                            onThemeModeChange = { viewModel.setThemeMode(it) },
                            onCloseApp = ::stopVpnAndClose,
                            modifier   = Modifier.padding(padding),
                        )
                        1 -> BlocklistsScreen(
                            viewModel = viewModel,
                            modifier  = Modifier.padding(padding),
                        )
                        2 -> AppsScreen(
                            viewModel = viewModel,
                            modifier  = Modifier.padding(padding),
                        )
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.action == ACTION_STOP_AND_CLOSE) {
            stopVpnAndClose()
        }
    }

    fun stopVpnAndClose() {
        viewModel.setVpnEnabled(false)
        finishAndRemoveTask()
    }

    private fun checkAndRequestPermissions() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            requestVpnPermissionIfNeeded()
        }
    }

    fun requestVpnPermissionIfNeeded() {
        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent != null) {
            vpnPermissionLauncher.launch(permissionIntent)
        } else {
            viewModel.setVpnEnabled(true)
        }
    }
}