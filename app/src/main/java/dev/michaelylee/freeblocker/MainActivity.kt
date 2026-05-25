package dev.michaelylee.freeblocker

import android.app.Activity
import android.net.VpnService
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
import dev.michaelylee.freeblocker.ui.AppsScreen
import dev.michaelylee.freeblocker.ui.BlockedWebsitesScreen
import dev.michaelylee.freeblocker.ui.BlocklistsScreen
import dev.michaelylee.freeblocker.ui.VpnViewModel

class MainActivity : ComponentActivity() {

    private val viewModel: VpnViewModel by viewModels()

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.setVpnEnabled(true)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            var selectedTab by remember { mutableStateOf(0) }

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
                            icon     = { Icon(Icons.Default.PhoneAndroid, contentDescription = "Apps") },
                            label    = { Text("Apps") },
                        )
                    }
                }
            ) { padding ->
                when (selectedTab) {
                    0 -> BlockedWebsitesScreen(
                        viewModel              = viewModel,
                        onRequestVpnPermission = ::requestVpnPermissionIfNeeded,
                        onCloseApp             = ::stopVpnAndClose,
                        modifier               = Modifier.padding(padding),
                    )
                    1 -> BlocklistsScreen(
                        viewModel = viewModel,
                        modifier  = Modifier.padding(padding),
                    )
                    2 -> AppsScreen(
                        modifier = Modifier.padding(padding),
                    )
                }
            }
        }
    }

    fun stopVpnAndClose() {
        viewModel.setVpnEnabled(false)
        finish()
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