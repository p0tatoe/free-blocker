package dev.michaelylee.freeblocker.data

import dev.michaelylee.freeblocker.core.UpstreamConfig
import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.io.IOException

// Singleton DataStore instance scoped to the application context
private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "vpn_settings")

class UserPreferences(private val context: Context) {

    private object Keys {
        val IS_VPN_ENABLED         = booleanPreferencesKey("is_vpn_enabled")
        val MANUAL_BLOCKED         = stringSetPreferencesKey("manual_blocked_domains")
        val WHITELISTED            = stringSetPreferencesKey("whitelisted_domains")
        val CUSTOM_SOURCE_URLS     = stringSetPreferencesKey("custom_source_urls")

        /**
         * Stores the active upstream as a single encoded string.
         * Encoding format is defined in [UpstreamConfig.encode] / [UpstreamConfig.decode].
         * Example value: "94.140.14.14|853|dns.adguard-dns.com|https://dns.adguard-dns.com/dns-query"
         */
        val UPSTREAM_CONFIG        = stringPreferencesKey("upstream_config")
        val IS_BLOCKING_ENABLED    = booleanPreferencesKey("is_blocking_enabled")
        val IS_START_ON_BOOT       = booleanPreferencesKey("is_start_on_boot")
        val BYPASSED_APPS          = stringSetPreferencesKey("bypassed_app_packages")
        val PAUSED_DOMAINS         = stringSetPreferencesKey("paused_domains")
    }

    companion object {
        val DEFAULT_UPSTREAM = UpstreamConfig()

        /** Apps that bypass the VPN entirely. */
        val DEFAULT_BYPASSED_APPS = emptySet<String>()
    }


    private fun <T> Flow<T>.catchIo(default: T): Flow<T> =
        catch { e -> if (e is IOException) emit(default) else throw e }

    val isVpnEnabledFlow: Flow<Boolean> = context.dataStore.data
        .catchIo(emptyPreferences())
        .map { it[Keys.IS_VPN_ENABLED] ?: false }

    suspend fun setVpnEnabled(enabled: Boolean) {
        context.dataStore.edit { it[Keys.IS_VPN_ENABLED] = enabled }
    }


    val upstreamConfigFlow: Flow<UpstreamConfig> = context.dataStore.data
        .catchIo(emptyPreferences())
        .map { preferences ->
            preferences[Keys.UPSTREAM_CONFIG]
                ?.let { UpstreamConfig.decode(it) }
                ?: DEFAULT_UPSTREAM
        }

    suspend fun getUpstreamConfig(): UpstreamConfig =
        upstreamConfigFlow.first()

    /**
     * Persists [config] to DataStore.
     * [MyVpnService] reads this at TUN startup and passes the host/SNI
     * to the Rust [DnsProxy] constructor.
     */
    suspend fun setUpstreamConfig(config: UpstreamConfig) {
        context.dataStore.edit { it[Keys.UPSTREAM_CONFIG] = UpstreamConfig.encode(config) }
    }

    val manualBlockedDomainsFlow: Flow<Set<String>> = context.dataStore.data
        .catchIo(emptyPreferences())
        .map { it[Keys.MANUAL_BLOCKED] ?: emptySet() }

    suspend fun getManualBlockedDomains(): Set<String> =
        manualBlockedDomainsFlow.first()

    suspend fun addManualBlockedDomain(domain: String) {
        context.dataStore.edit { prefs ->
            val current = prefs[Keys.MANUAL_BLOCKED] ?: emptySet()
            prefs[Keys.MANUAL_BLOCKED] = current + domain.trim().lowercase()
        }
    }

    suspend fun removeManualBlockedDomain(domain: String) {
        context.dataStore.edit { prefs ->
            val current = prefs[Keys.MANUAL_BLOCKED] ?: emptySet()
            prefs[Keys.MANUAL_BLOCKED] = current - domain.trim().lowercase()
        }
    }

    val whitelistedDomainsFlow: Flow<Set<String>> = context.dataStore.data
        .catchIo(emptyPreferences())
        .map { it[Keys.WHITELISTED] ?: emptySet() }

    suspend fun getWhitelistedDomains(): Set<String> =
        whitelistedDomainsFlow.first()

    suspend fun addWhitelistedDomain(domain: String) {
        context.dataStore.edit { prefs ->
            val current = prefs[Keys.WHITELISTED] ?: emptySet()
            prefs[Keys.WHITELISTED] = current + domain.trim().lowercase()
        }
    }

    suspend fun removeWhitelistedDomain(domain: String) {
        context.dataStore.edit { prefs ->
            val current = prefs[Keys.WHITELISTED] ?: emptySet()
            prefs[Keys.WHITELISTED] = current - domain.trim().lowercase()
        }
    }

    val customSourceUrlsFlow: Flow<Set<String>> = context.dataStore.data
        .catchIo(emptyPreferences())
        .map { it[Keys.CUSTOM_SOURCE_URLS] ?: emptySet() }

    suspend fun getCustomSourceUrls(): Set<String> =
        customSourceUrlsFlow.first()

    suspend fun addCustomSourceUrl(url: String) {
        context.dataStore.edit { prefs ->
            val current = prefs[Keys.CUSTOM_SOURCE_URLS] ?: emptySet()
            prefs[Keys.CUSTOM_SOURCE_URLS] = current + url.trim()
        }
    }

    suspend fun removeCustomSourceUrl(url: String) {
        context.dataStore.edit { prefs ->
            val current = prefs[Keys.CUSTOM_SOURCE_URLS] ?: emptySet()
            prefs[Keys.CUSTOM_SOURCE_URLS] = current - url.trim()
        }
    }



    val isBlockingEnabledFlow: Flow<Boolean> = context.dataStore.data
        .catchIo(emptyPreferences())
        .map { it[Keys.IS_BLOCKING_ENABLED] ?: true }  // default: blocking on

    suspend fun setBlockingEnabled(enabled: Boolean) {
        context.dataStore.edit { it[Keys.IS_BLOCKING_ENABLED] = enabled }
    }

    val isStartOnBootFlow: Flow<Boolean> = context.dataStore.data
        .catchIo(emptyPreferences())
        .map { it[Keys.IS_START_ON_BOOT] ?: false }  // default: don't autostart

    suspend fun setStartOnBoot(enabled: Boolean) {
        context.dataStore.edit { it[Keys.IS_START_ON_BOOT] = enabled }
    }

    // ── Bypassed apps (exceptions) ─────────────────────────────────────────

    /**
     * Package names of apps whose traffic bypasses the VPN entirely.
     * Backed by [VpnService.Builder.addDisallowedApplication] at tunnel
     * creation time. Defaults to [DEFAULT_BYPASSED_APPS].
     */
    val bypassedAppsFlow: Flow<Set<String>> = context.dataStore.data
        .catchIo(emptyPreferences())
        .map { it[Keys.BYPASSED_APPS] ?: DEFAULT_BYPASSED_APPS }

    suspend fun getBypassedApps(): Set<String> =
        bypassedAppsFlow.first()

    suspend fun addBypassedApp(packageName: String) {
        context.dataStore.edit { prefs ->
            val current = prefs[Keys.BYPASSED_APPS] ?: DEFAULT_BYPASSED_APPS
            prefs[Keys.BYPASSED_APPS] = current + packageName
        }
    }

    suspend fun removeBypassedApp(packageName: String) {
        context.dataStore.edit { prefs ->
            val current = prefs[Keys.BYPASSED_APPS] ?: DEFAULT_BYPASSED_APPS
            prefs[Keys.BYPASSED_APPS] = current - packageName
        }
    }

    // ── Paused domains (per-domain temporary unblock) ─────────────────────────

    /**
     * Persisted pause state for manually blocked domains.
     * Each entry in the set is encoded as `"domain|expiresAtMillis"`.
     * [Long.MAX_VALUE] represents an indefinite pause.
     */
    val pausedDomainsFlow: Flow<Map<String, Long>> = context.dataStore.data
        .catchIo(emptyPreferences())
        .map { prefs ->
            decodePausedSet(prefs[Keys.PAUSED_DOMAINS] ?: emptySet())
        }

    suspend fun getPausedDomains(): Map<String, Long> =
        pausedDomainsFlow.first()

    suspend fun addPausedDomain(domain: String, expiresAt: Long) {
        context.dataStore.edit { prefs ->
            val current = prefs[Keys.PAUSED_DOMAINS] ?: emptySet()
            // Remove any existing entry for this domain before adding the new one
            val cleaned = domain.lowercase().trim()
            if (cleaned.contains("|")) return@edit
            val filtered = current.filterNot { it.startsWith("$cleaned|") }.toSet()
            prefs[Keys.PAUSED_DOMAINS] = filtered + "$cleaned|$expiresAt"
        }
    }

    suspend fun removePausedDomain(domain: String) {
        context.dataStore.edit { prefs ->
            val current = prefs[Keys.PAUSED_DOMAINS] ?: emptySet()
            val cleaned = domain.lowercase().trim()
            prefs[Keys.PAUSED_DOMAINS] = current.filterNot { it.startsWith("$cleaned|") }.toSet()
        }
    }

    suspend fun clearPausedDomains() {
        context.dataStore.edit { prefs ->
            prefs[Keys.PAUSED_DOMAINS] = emptySet()
        }
    }

    private fun decodePausedSet(encoded: Set<String>): Map<String, Long> {
        val result = mutableMapOf<String, Long>()
        for (entry in encoded) {
            val parts = entry.split("|", limit = 2)
            if (parts.size == 2) {
                val domain = parts[0]
                val expiresAt = parts[1].toLongOrNull() ?: continue
                result[domain] = expiresAt
            }
        }
        return result
    }
}