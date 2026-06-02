package dev.michaelylee.freeblocker.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.michaelylee.freeblocker.data.BlocklistState
import dev.michaelylee.freeblocker.data.DefaultSourceProvider

@Composable
fun BlocklistsScreen(
    viewModel: VpnViewModel,
    modifier: Modifier = Modifier,
) {
    val blocklistState by viewModel.blocklistState.collectAsState()
    val customUrls     by viewModel.customSourceUrls.collectAsState()
    val disabledUrls   by viewModel.disabledBuiltInUrls.collectAsState()
    val builtInSources = DefaultSourceProvider().getSources()

    LazyColumn(
        modifier            = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {

        // ── Status + refresh ──────────────────────────────────────────────────
        item {
            Spacer(Modifier.height(16.dp))
            
            Text(
                text = "Blocklist Sources",
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.padding(bottom = 8.dp)
            )

            val stateLabel = when (val s = blocklistState) {
                is BlocklistState.Idle    -> "Blocklist not loaded"
                is BlocklistState.Loading -> "Updating blocklist…"
                is BlocklistState.Success -> "${s.totalDomains} domains loaded"
                is BlocklistState.Error   -> "⚠ Error: ${s.message}"
            }

            Text(
                text  = stateLabel,
                style = MaterialTheme.typography.bodyMedium,
                color = if (blocklistState is BlocklistState.Error)
                    MaterialTheme.colorScheme.error
                else
                    MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(Modifier.height(8.dp))

            OutlinedButton(
                onClick  = { viewModel.refreshBlocklists() },
                enabled  = blocklistState !is BlocklistState.Loading,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (blocklistState is BlocklistState.Loading)
                        "Updating…"
                    else
                        "Refresh Blocklists"
                )
            }

            Spacer(Modifier.height(24.dp))
        }

        // ── Default sources ───────────────────────────────────────────────────
        item {
            Text(
                text     = "Default Sources",
                style    = MaterialTheme.typography.titleSmall,
                modifier = Modifier.padding(bottom = 8.dp),
            )
            HorizontalDivider()
            Spacer(Modifier.height(8.dp))
        }

        items(builtInSources, key = { "builtin_${it.url}" }) { source ->
            val isDisabled = source.url in disabledUrls
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier          = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp),
            ) {
                var isExpanded by remember { mutableStateOf(false) }
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .clickable { isExpanded = !isExpanded }
                ) {
                    Text(
                        text  = source.url
                            .removePrefix("https://")
                            .substringBefore("/"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = if (isDisabled)
                            MaterialTheme.colorScheme.onSurfaceVariant
                        else
                            MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text  = source.url,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = if (isExpanded) Int.MAX_VALUE else 1,
                        overflow = if (isExpanded) androidx.compose.ui.text.style.TextOverflow.Clip else androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                    )
                    if (isDisabled) {
                        Text(
                            text  = "Disabled",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
                if (isDisabled) {
                    IconButton(onClick = {
                        viewModel.restoreBuiltInSource(source.url)
                        viewModel.refreshBlocklists()
                    }) {
                        Icon(
                            Icons.Default.Restore,
                            contentDescription = "Restore",
                            tint = MaterialTheme.colorScheme.primary,
                        )
                    }
                } else {
                    IconButton(onClick = {
                        viewModel.removeBuiltInSource(source.url)
                        viewModel.refreshBlocklists()
                    }) {
                        Icon(
                            Icons.Default.Delete,
                            contentDescription = "Remove",
                            tint = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }
            HorizontalDivider(modifier = Modifier.padding(vertical = 2.dp))
        }

        // ── Custom sources ────────────────────────────────────────────────────
        item {
            Spacer(Modifier.height(24.dp))
            Text(
                text     = "Custom Sources",
                style    = MaterialTheme.typography.titleSmall,
                modifier = Modifier.padding(bottom = 8.dp),
            )
            HorizontalDivider()
            Spacer(Modifier.height(8.dp))
            DomainInputRow(
                placeholder = "https://example.com/blocklist.txt",
                onAdd       = { viewModel.addCustomSourceUrl(it) },
            )
            Spacer(Modifier.height(8.dp))
        }

        if (customUrls.isEmpty()) {
            item {
                Text(
                    text  = "No custom sources added yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        items(customUrls.toList(), key = { "url_$it" }) { url ->
            DomainRow(
                label    = url,
                onDelete = { viewModel.removeCustomSourceUrl(url) },
            )
        }

        item { Spacer(Modifier.height(16.dp)) }
    }
}