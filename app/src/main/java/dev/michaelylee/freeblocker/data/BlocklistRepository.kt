package dev.michaelylee.freeblocker.data

import android.util.Log
import dev.michaelylee.freeblocker.core.DnsFilter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.util.Locale

sealed interface BlocklistState {
    object Idle : BlocklistState
    object Loading : BlocklistState
    data class Success(val totalDomains: Int) : BlocklistState
    data class Error(val message: String) : BlocklistState
}

data class FilterSource(
    val url: String,
    val enabled: Boolean = true
)

interface SourceProvider {
    fun getSources(): List<FilterSource>
}

class DefaultSourceProvider : SourceProvider {
    override fun getSources(): List<FilterSource> = listOf(
        FilterSource("https://pgl.yoyo.org/adservers/serverlist.php"),
        FilterSource("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
        FilterSource("https://big.oisd.nl/domainswild")
    )
}

class FilterParser {
    /**
     * Normalizes blocking rules: Adblock syntax (`||badsite.com^`) etc.
     * Returns null for comment lines, empty lines, and invalid entries.
     */
    fun parse(rawLine: String): String? {
        var line = rawLine.trim()

        // Strip inline comments
        if (line.contains("#")) line = line.substringBefore("#").trim()
        if (line.contains(";")) line = line.substringBefore(";").trim()

        if (line.isEmpty()) return null

        // Support popular AdBlock/uBlock style simple wildcard domains: ||example.com^
        line = when {
            line.startsWith("||") && line.endsWith("^") -> line.substring(2, line.length - 1)
            line.startsWith("||")                              -> line.substring(2)
            else                                                      -> line
        }

        // Clean up leading wildcard formatting indicators
        if (line.startsWith("*.")) line = line.substring(2)

        // Split tokens to break up standard hosts records (IP <space> Host)
        val segments = line.split(Regex("\\s+"))
        val candidate = if (segments.size >= 2) segments[1] else segments[0]

        val cleaned = candidate.lowercase(Locale.ROOT).trim()
        return if (isValid(cleaned)) cleaned else null
    }

    private fun isValid(domain: String): Boolean {
        if (domain.isEmpty() || domain.length > 253) return false
        if (domain == "localhost" || domain == "127.0.0.1" || domain == "0.0.0.0") return false
        return domain.contains(".") && !domain.startsWith(".") && !domain.endsWith(".")
    }
}

class BlocklistFetcher {
    private val parser: FilterParser = FilterParser()
    suspend fun fetch(url: String): Set<String> = withContext(Dispatchers.IO) {
        val result = HashSet<String>()
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.inputStream.bufferedReader().useLines { lines ->
            lines.forEach {
                val parsed = parser.parse(it)
                if (parsed != null) result.add(parsed)
            }
        }
        result
    }
}

class BlocklistRepository(
    private val context: android.content.Context,
    private val dnsFilter: DnsFilter,
    private val userPreferences: UserPreferences,
    private val fetcher: BlocklistFetcher,
    private val sourceProvider: SourceProvider = DefaultSourceProvider()
) {
    private val TAG = "BlocklistRepository"

    private val _state = MutableStateFlow<BlocklistState>(BlocklistState.Idle)
    val state: StateFlow<BlocklistState> = _state.asStateFlow()

    /**
     * Populates DnsFilter with blocklists, user rules, and whitelist rules
     */
    suspend fun loadAndCompileBlocklists() = withContext(Dispatchers.IO + kotlinx.coroutines.NonCancellable) {

        _state.value = BlocklistState.Loading

        try {
            val cacheFile = java.io.File(context.cacheDir, "blocklist_cache.txt")
            val manualBlocks = userPreferences.getManualBlockedDomains().map { it.lowercase() }
            val whitelist = userPreferences.getWhitelistedDomains().map { it.lowercase() }.toSet()

            // 1. Instant Arming: Load cached remote lists and manual rules immediately
            val initialSet = HashSet<String>(250_000)
            initialSet.addAll(manualBlocks)
            
            if (cacheFile.exists()) {
                try {
                    cacheFile.useLines { lines ->
                        initialSet.addAll(lines)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to read blocklist cache", e)
                }
            }
            initialSet.removeAll(whitelist)
            dnsFilter.updateBlocklist(initialSet)
            Log.i(TAG, "Instantly armed ${initialSet.size} domains from cache/manual rules")

            // 2. Network Load: Fetch latest remote blocklists in the background
            val remoteCompiled = HashSet<String>(250_000)
            val customUrls = userPreferences.getCustomSourceUrls()
            val disabledUrls = userPreferences.getDisabledBuiltInUrls()

            val allSources = sourceProvider.getSources()
                .filter { it.url !in disabledUrls } +
                customUrls.map { FilterSource(it) }

            kotlinx.coroutines.supervisorScope {
                allSources
                    .filter { it.enabled }
                    .map { source -> 
                        async { 
                            try {
                                fetcher.fetch(source.url)
                            } catch (e: Exception) {
                                Log.e(TAG, "Failed to fetch source: ${source.url}", e)
                                emptySet<String>()
                            }
                        } 
                    }
                    .awaitAll()
                    .forEach { remoteCompiled.addAll(it) }
            }

            // Save the newly fetched remote blocklists to the local cache
            try {
                cacheFile.bufferedWriter().use { writer ->
                    remoteCompiled.forEach { 
                        writer.write(it)
                        writer.newLine()
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to write blocklist cache", e)
            }

            // 3. Final Merge: Apply the updated lists
            val finalCompiled = HashSet<String>(remoteCompiled.size + manualBlocks.size)
            finalCompiled.addAll(remoteCompiled)
            finalCompiled.addAll(manualBlocks)
            finalCompiled.removeAll(whitelist)

            dnsFilter.updateBlocklist(finalCompiled)

            _state.value = BlocklistState.Success(finalCompiled.size)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load blocklists", e)
            _state.value = BlocklistState.Error(e.message ?: "Unknown error")
        }
    }
}