package dev.michaelylee.freeblocker

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import dev.michaelylee.freeblocker.core.MyVpnService
import dev.michaelylee.freeblocker.ui.AppsScreen
import dev.michaelylee.freeblocker.ui.BlockedWebsitesScreen
import dev.michaelylee.freeblocker.ui.BlocklistsScreen
import dev.michaelylee.freeblocker.ui.VpnViewModel
import dev.michaelylee.freeblocker.ui.theme.FreeBlockerTheme

class MainActivity : ComponentActivity() {

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

        // On Android 13+ we must ask the user to allow notifications before the
        // foreground-service notification will appear. If already granted (or on
        // older API levels), skip straight to starting the VPN.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            // Permission already granted (or API < 33) — start VPN immediately.
            requestVpnPermissionIfNeeded()
        }

        setContent {
            var selectedTab by remember { mutableStateOf(0) }

            FreeBlockerTheme(darkTheme = true) {
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
                                icon     = { Icon(Icons.Default.PhoneAndroid, contentDescription = "Allowed") },
                                label    = { Text("Allowed") },
                            )
                        }
                    }
                ) { padding ->
                    when (selectedTab) {
                        0 -> BlockedWebsitesScreen(
                            viewModel  = viewModel,
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
    }

    fun stopVpnAndClose() {
        viewModel.setVpnEnabled(false)
        finishAndRemoveTask()
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