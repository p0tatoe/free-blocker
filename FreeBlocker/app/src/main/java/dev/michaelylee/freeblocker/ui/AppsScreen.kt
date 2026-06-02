package dev.michaelylee.freeblocker.ui

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Data class holding the display-relevant info for a single installed app.
 * Resolved eagerly from [PackageManager] so the lazy list doesn't hit
 * the PM on every recomposition.
 */
private data class AppInfo(
    val packageName: String,
    val label: String,
    val icon: Drawable,
    val isSystemApp: Boolean,
)

/** Converts any [Drawable] to a [Bitmap]. Handles both BitmapDrawable and other types. */
private fun Drawable.toBitmap(size: Int = 96): Bitmap {
    if (this is BitmapDrawable && bitmap != null) return bitmap
    val bmp = Bitmap.createBitmap(
        if (intrinsicWidth > 0) intrinsicWidth else size,
        if (intrinsicHeight > 0) intrinsicHeight else size,
        Bitmap.Config.ARGB_8888,
    )
    val canvas = Canvas(bmp)
    setBounds(0, 0, canvas.width, canvas.height)
    draw(canvas)
    return bmp
}

@Composable
fun AppsScreen(
    viewModel: VpnViewModel,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val whitelistedApps by viewModel.whitelistedApps.collectAsState()

    // Resolve installed apps off the main thread
    var installedApps by remember { mutableStateOf<List<AppInfo>>(emptyList()) }
    LaunchedEffect(Unit) {
        installedApps = withContext(Dispatchers.IO) {
            val pm = context.packageManager
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
                .filter { it.packageName != context.packageName }  // Exclude ourselves
                .map { appInfo ->
                    AppInfo(
                        packageName = appInfo.packageName,
                        label       = appInfo.loadLabel(pm).toString(),
                        icon        = appInfo.loadIcon(pm),
                        isSystemApp = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                    )
                }
                .sortedBy { it.label.lowercase() }
        }
    }

    var searchQuery by remember { mutableStateOf("") }
    var showSystemApps by remember { mutableStateOf(false) }

    val filteredApps = remember(installedApps, searchQuery, showSystemApps, whitelistedApps) {
        installedApps
            .filter { app ->
                // Always show whitelisted apps, even if they're system apps
                val isWhitelisted = app.packageName in whitelistedApps
                if (!showSystemApps && app.isSystemApp && !isWhitelisted) return@filter false
                if (searchQuery.isBlank()) return@filter true
                app.label.contains(searchQuery, ignoreCase = true) ||
                    app.packageName.contains(searchQuery, ignoreCase = true)
            }
            .sortedWith(compareByDescending<AppInfo> { it.packageName in whitelistedApps }
                .thenBy { it.label.lowercase() })
    }

    var showInfoDialog by remember { mutableStateOf(false) }

    if (showInfoDialog) {
        androidx.compose.ui.window.Dialog(onDismissRequest = { showInfoDialog = false }) {
            androidx.compose.material3.Surface(
                shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.surface,
                tonalElevation = 6.dp
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "App Whitelist Info",
                        style = MaterialTheme.typography.titleLarge
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Whitelisted apps bypass the VPN — their traffic won't be filtered.\n\nNote: Android Auto is whitelisted by default.",
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

    Column(modifier = modifier.fillMaxSize()) {
        // ── Header ────────────────────────────────────────────────────────
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text  = "App Whitelist",
                style = MaterialTheme.typography.headlineSmall,
            )
            Spacer(Modifier.weight(1f))
            androidx.compose.material3.IconButton(
                onClick = { showInfoDialog = true },
                modifier = Modifier.size(56.dp)
            ) {
                Icon(
                    imageVector = androidx.compose.material.icons.Icons.Outlined.Info,
                    contentDescription = "Info",
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(32.dp)
                )
            }
        }

        // ── Search bar ────────────────────────────────────────────────────
        OutlinedTextField(
            value         = searchQuery,
            onValueChange = { searchQuery = it },
            modifier      = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            placeholder   = { Text("Search apps…") },
            leadingIcon   = { Icon(Icons.Default.Search, contentDescription = null) },
            singleLine    = true,
            shape         = RoundedCornerShape(12.dp),
        )

        // ── Filter chips ──────────────────────────────────────────────────
        Row(
            modifier            = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = showSystemApps,
                onClick  = { showSystemApps = !showSystemApps },
                label    = { Text("Show system apps") },
            )
        }

        HorizontalDivider()

        // ── App list ──────────────────────────────────────────────────────
        if (installedApps.isEmpty()) {
            Column(
                modifier            = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    text  = "Loading apps…",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(
                contentPadding = PaddingValues(vertical = 4.dp),
            ) {
                items(
                    items = filteredApps,
                    key   = { it.packageName },
                ) { app ->
                    AppRow(
                        app           = app,
                        isWhitelisted = app.packageName in whitelistedApps,
                        onToggle      = { checked ->
                            viewModel.setAppWhitelisted(app.packageName, checked)
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun AppRow(
    app: AppInfo,
    isWhitelisted: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    Row(
        modifier            = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment   = Alignment.CenterVertically,
    ) {
        val bitmap = remember(app.icon) { app.icon.toBitmap() }
        Image(
            bitmap             = bitmap.asImageBitmap(),
            contentDescription = app.label,
            modifier           = Modifier.size(40.dp),
        )

        Spacer(Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text      = app.label,
                style     = MaterialTheme.typography.bodyLarge,
                maxLines  = 1,
                overflow  = TextOverflow.Ellipsis,
            )
            Text(
                text      = app.packageName,
                style     = MaterialTheme.typography.bodySmall,
                color     = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines  = 1,
                overflow  = TextOverflow.Ellipsis,
            )
        }

        Spacer(Modifier.width(8.dp))

        Switch(
            checked    = isWhitelisted,
            onCheckedChange = onToggle,
        )
    }
}