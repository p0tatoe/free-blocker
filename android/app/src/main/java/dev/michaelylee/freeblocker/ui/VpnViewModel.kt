package dev.michaelylee.freeblocker.ui

import android.app.Application
import android.content.Intent
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.michaelylee.freeblocker.ServiceLocator
import dev.michaelylee.freeblocker.core.UpstreamConfig
import dev.michaelylee.freeblocker.core.MyVpnService
import dev.michaelylee.freeblocker.data.BlocklistRepository
import dev.michaelylee.freeblocker.data.BlocklistState
import dev.michaelylee.freeblocker.data.UserPreferences
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * Bridges the UI layer to [UserPreferences], [BlocklistRepository], and [MyVpnService].
 *
 * All state the UI needs is exposed as [StateFlow]s so Compose can collect them
 * efficiently. All user actions are plain functions the UI calls directly — no
 * events/channels needed at this scale.
 *
 * Uses [AndroidViewModel] rather than [ViewModel] because starting/stopping
 * [MyVpnService] requires an [Application] context.
 */
class VpnViewModel(application: Application) : AndroidViewModel(application) {

    private val prefs      = UserPreferences(application)
    private val repository get() = ServiceLocator.blocklistRepository

    /** Active auto-resume coroutines, keyed by domain. */
    private val pauseTimers = mutableMapOf<String, Job>()

    init {
        // Restore persisted pauses into the live DnsFilter and schedule
        // auto-resume timers for any non-indefinite pauses that haven't
        // expired yet.
        viewModelScope.launch {
            val persisted = prefs.getPausedDomains()
            val now = System.currentTimeMillis()
            for ((domain, expiresAt) in persisted) {
                if (expiresAt != Long.MAX_VALUE && now >= expiresAt) {
                    // Already expired — clean up and skip
                    prefs.removePausedDomain(domain)
                    continue
                }
                ServiceLocator.dnsFilter.pauseDomain(domain, expiresAt)
                if (expiresAt != Long.MAX_VALUE) {
                    schedulePauseTimer(domain, expiresAt - now)
                }
            }
            // Emit initial state
            _pausedDomains.value = prefs.getPausedDomains()
        }
    }

    // -------------------------------------------------------------------------
    // VPN on/off state
    // -------------------------------------------------------------------------

    /**
     * Whether the VPN is currently active. Persisted in DataStore so the toggle
     * reflects the correct state after process death and recreation.
     */
    val isVpnEnabled: StateFlow<Boolean> = prefs.isVpnEnabledFlow
        .stateIn(
            scope         = viewModelScope,
            started       = SharingStarted.WhileSubscribed(5_000),
            initialValue  = false,
        )

    // ── Blocking enabled toggle ───────────────────────────────────────────────────

    /**
     * Toggles the VPN on or off.
     *
     * Persists the new state to DataStore first, then starts or stops the service.
     * The service reads its own upstream config independently on start, so no
     * extra coordination is needed here.
     *
     * If [isVpnEnabled] is already in the requested state (e.g. double-tap) this
     * is a no-op at the service level — [MyVpnService.startVpn] guards against
     * duplicate starts internally.
     */
    fun setVpnEnabled(enabled: Boolean) {
        viewModelScope.launch {
            prefs.setVpnEnabled(enabled)
            val action = if (enabled) MyVpnService.ACTION_START else MyVpnService.ACTION_STOP
            val serviceIntent = Intent(getApplication(), MyVpnService::class.java).apply {
                this.action = action
            }
            if (enabled && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                getApplication<Application>().startForegroundService(serviceIntent)
            } else {
                getApplication<Application>().startService(serviceIntent)
            }
        }
    }

    /**
     * Whether DNS filtering is currently active. When false, the VPN tunnel is
     * still up (traffic is protected / encrypted upstream) but no domains are
     * blocked. Persisted so the setting survives process death.
     */
    val isBlockingEnabled: StateFlow<Boolean> = prefs.isBlockingEnabledFlow
        .stateIn(
            scope        = viewModelScope,
            started      = SharingStarted.WhileSubscribed(5_000),
            initialValue = true,
        )

    fun setBlockingEnabled(enabled: Boolean) {
        viewModelScope.launch {
            prefs.setBlockingEnabled(enabled)
            // Push the change to the live proxy immediately — no restart needed
            // since isBlockingEnabled is a plain @Volatile field on DnsProxyServer.
            // We reach it via the service; if the service isn't running this is a
            // no-op (the value will be read from prefs when the service next starts).
            val serviceIntent = Intent(getApplication(), MyVpnService::class.java).apply {
                action = MyVpnService.ACTION_SET_BLOCKING
                putExtra(MyVpnService.EXTRA_BLOCKING_ENABLED, enabled)
            }
            if (isVpnEnabled.value && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                getApplication<Application>().startForegroundService(serviceIntent)
            } else {
                getApplication<Application>().startService(serviceIntent)
            }
        }
    }

    // ── Start on boot ─────────────────────────────────────────────────────────────

    val isStartOnBoot: StateFlow<Boolean> = prefs.isStartOnBootFlow
        .stateIn(
            scope        = viewModelScope,
            started      = SharingStarted.WhileSubscribed(5_000),
            initialValue = false,
        )

    fun setStartOnBoot(enabled: Boolean) {
        viewModelScope.launch { prefs.setStartOnBoot(enabled) }
    }

    // -------------------------------------------------------------------------
    // Upstream DNS config
    // -------------------------------------------------------------------------

    /**
     * The currently saved upstream resolver.
     * The UI uses this to show which resolver is active and pre-populate the
     * settings screen. [MyVpnService] reads this independently via DataStore
     * on start — the ViewModel doesn't push it to the service directly.
     */
    val upstreamConfig: StateFlow<UpstreamConfig> = prefs.upstreamConfigFlow
        .stateIn(
            scope        = viewModelScope,
            started      = SharingStarted.WhileSubscribed(5_000),
            initialValue = UserPreferences.DEFAULT_UPSTREAM,
        )

    /**
     * Saves a new upstream resolver.
     *
     * If the VPN is currently running, a restart is required for the change to
     * take effect. The UI should surface this via [pendingRestartReason].
     */
    fun setUpstreamConfig(config: UpstreamConfig) {
        viewModelScope.launch {
            prefs.setUpstreamConfig(config)
            if (isVpnEnabled.value) {
                _pendingRestartReason.update { PendingRestartReason.UPSTREAM_CHANGED }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Pending restart banner
    // -------------------------------------------------------------------------

    /**
     * Set when a settings change requires a VPN restart to take effect.
     * The UI should show a non-intrusive banner ("Restart VPN to apply changes")
     * while this is non-null, and clear it once the user restarts or dismisses.
     */
    enum class PendingRestartReason { UPSTREAM_CHANGED }

    private val _pendingRestartReason = MutableStateFlow<PendingRestartReason?>(null)
    val pendingRestartReason: StateFlow<PendingRestartReason?> = _pendingRestartReason.asStateFlow()

    fun dismissRestartBanner() {
        _pendingRestartReason.update { null }
    }

    /**
     * Restarts the VPN to apply pending settings changes, then clears the banner.
     */
    fun restartVpn() {
        viewModelScope.launch {
            setVpnEnabled(false)
            delay(500) // Give the service time to tear down the TUN interface
            setVpnEnabled(true)
            _pendingRestartReason.update { null }
        }
    }

    // -------------------------------------------------------------------------
    // Manual blocked domains
    // -------------------------------------------------------------------------

    val manualBlockedDomains: StateFlow<Set<String>> = prefs.manualBlockedDomainsFlow
        .stateIn(
            scope        = viewModelScope,
            started      = SharingStarted.WhileSubscribed(5_000),
            initialValue = emptySet(),
        )

    fun addManualBlockedDomain(domain: String) {
        val cleaned = domain.trim().lowercase()
        if (cleaned.isBlank() || cleaned.contains("|")) return
        viewModelScope.launch { prefs.addManualBlockedDomain(cleaned) }
        // Push to the live DNS filter immediately so blocking takes effect
        // without waiting for a full blocklist refresh.
        ServiceLocator.dnsFilter.addDomain(cleaned)
        flushDnsCache()
    }

    fun removeManualBlockedDomain(domain: String) {
        val cleaned = domain.trim().lowercase()
        viewModelScope.launch {
            prefs.removeManualBlockedDomain(cleaned)
            // Also clear any active pause for this domain
            prefs.removePausedDomain(cleaned)
        }
        // Remove from the live filter. If the domain also appears in a
        // remote blocklist it will reappear on the next full refresh,
        // which is the expected behaviour (user should whitelist instead).
        ServiceLocator.dnsFilter.removeDomain(cleaned)
        cancelPauseTimer(cleaned)
        _pausedDomains.update { it - cleaned }
        flushDnsCache()
    }

    // -------------------------------------------------------------------------
    // Per-domain pause
    // -------------------------------------------------------------------------

    private val _pausedDomains = MutableStateFlow<Map<String, Long>>(emptyMap())

    /**
     * Currently paused domains and their epoch-millis expiry times.
     * [Long.MAX_VALUE] represents an indefinite pause.
     */
    val pausedDomains: StateFlow<Map<String, Long>> = _pausedDomains.asStateFlow()

    /**
     * Pauses blocking for [domain] for the given [durationMs].
     * Pass `null` for an indefinite pause.
     */
    fun pauseBlockedDomain(domain: String, durationMs: Long?) {
        val cleaned = domain.trim().lowercase()
        if (cleaned.contains("|")) return
        val expiresAt = if (durationMs != null)
            System.currentTimeMillis() + durationMs
        else
            Long.MAX_VALUE

        // Update live filter
        ServiceLocator.dnsFilter.pauseDomain(cleaned, expiresAt)

        // Persist
        viewModelScope.launch { prefs.addPausedDomain(cleaned, expiresAt) }

        // Update UI state
        _pausedDomains.update { it + (cleaned to expiresAt) }

        // Schedule auto-resume timer (cancel any existing one first)
        cancelPauseTimer(cleaned)
        if (durationMs != null) {
            schedulePauseTimer(cleaned, durationMs)
        }
        flushDnsCache()
    }

    /**
     * Immediately resumes blocking for a previously paused [domain].
     */
    fun resumeBlockedDomain(domain: String) {
        val cleaned = domain.trim().lowercase()

        // Update live filter
        ServiceLocator.dnsFilter.resumeDomain(cleaned)

        // Persist
        viewModelScope.launch { prefs.removePausedDomain(cleaned) }

        // Update UI state
        _pausedDomains.update { it - cleaned }

        cancelPauseTimer(cleaned)
        flushDnsCache()
    }

    private fun schedulePauseTimer(domain: String, delayMs: Long) {
        pauseTimers[domain] = viewModelScope.launch {
            delay(delayMs)
            // Auto-resume when the timer fires
            resumeBlockedDomain(domain)
        }
    }

    private fun cancelPauseTimer(domain: String) {
        pauseTimers.remove(domain)?.cancel()
    }

    // -------------------------------------------------------------------------
    // Whitelisted domains
    // -------------------------------------------------------------------------

    val whitelistedDomains: StateFlow<Set<String>> = prefs.whitelistedDomainsFlow
        .stateIn(
            scope        = viewModelScope,
            started      = SharingStarted.WhileSubscribed(5_000),
            initialValue = emptySet(),
        )

    fun addWhitelistedDomain(domain: String) {
        val cleaned = domain.trim().lowercase()
        if (cleaned.isBlank()) return
        viewModelScope.launch { prefs.addWhitelistedDomain(cleaned) }
        // Immediately remove from the live filter so the domain is
        // unblocked without waiting for a full blocklist refresh.
        ServiceLocator.dnsFilter.removeDomain(cleaned)
        flushDnsCache()
    }

    fun removeWhitelistedDomain(domain: String) {
        val cleaned = domain.trim().lowercase()
        viewModelScope.launch { prefs.removeWhitelistedDomain(cleaned) }
        // Re-add to the live filter so it takes effect immediately.
        // If it wasn't in any blocklist this is a harmless no-op since
        // shouldBlock() only matches known domains.
        ServiceLocator.dnsFilter.addDomain(cleaned)
        flushDnsCache()
    }

    // -------------------------------------------------------------------------
    // Bypassed apps (exceptions)
    // -------------------------------------------------------------------------

    /**
     * Package names of apps whose traffic bypasses the VPN entirely.
     * Backed by [VpnService.Builder.addDisallowedApplication] at tunnel
     * creation time.
     */
    val bypassedApps: StateFlow<Set<String>> = prefs.bypassedAppsFlow
        .stateIn(
            scope        = viewModelScope,
            started      = SharingStarted.WhileSubscribed(5_000),
            initialValue = UserPreferences.DEFAULT_BYPASSED_APPS,
        )

    /**
     * Toggles whether [packageName] bypasses the VPN.
     * Persists the change to DataStore and flushes DNS cache so connections rebuild.
     */
    fun setAppBypassed(packageName: String, bypassed: Boolean) {
        viewModelScope.launch {
            if (bypassed) {
                prefs.addBypassedApp(packageName)
            } else {
                prefs.removeBypassedApp(packageName)
            }
            flushDnsCache()
        }
    }

    private fun flushDnsCache() {
        if (isVpnEnabled.value) {
            val serviceIntent = Intent(getApplication(), MyVpnService::class.java).apply {
                action = MyVpnService.ACTION_FLUSH_DNS_CACHE
            }
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                getApplication<Application>().startForegroundService(serviceIntent)
            } else {
                getApplication<Application>().startService(serviceIntent)
            }
        }
    }

    // -------------------------------------------------------------------------
    // Custom blocklist source URLs
    // -------------------------------------------------------------------------

    val customSourceUrls: StateFlow<Set<String>> = prefs.customSourceUrlsFlow
        .stateIn(
            scope        = viewModelScope,
            started      = SharingStarted.WhileSubscribed(5_000),
            initialValue = emptySet(),
        )

    fun addCustomSourceUrl(url: String) {
        val cleaned = url.trim()
        if (cleaned.isBlank()) return
        viewModelScope.launch { prefs.addCustomSourceUrl(cleaned) }
    }

    fun removeCustomSourceUrl(url: String) {
        viewModelScope.launch { prefs.removeCustomSourceUrl(url) }
    }



    // -------------------------------------------------------------------------
    // Blocklist refresh
    // -------------------------------------------------------------------------

    /**
     * Live state of the blocklist download pipeline, sourced directly from
     * [BlocklistRepository.state]. The UI observes this to show a loading
     * indicator, a domain count on success, or an error message.
     *
     * Possible values:
     *   [BlocklistState.Idle]    — nothing running, initial state
     *   [BlocklistState.Loading] — download + parse in progress
     *   [BlocklistState.Success] — done, carries total domain count
     *   [BlocklistState.Error]   — failed, carries error message string
     */
    val blocklistState: StateFlow<BlocklistState> = repository.state
        .stateIn(
            scope        = viewModelScope,
            started      = SharingStarted.WhileSubscribed(5_000),
            initialValue = BlocklistState.Idle,
        )

    /**
     * Triggers a fresh download and parse of all enabled blocklists via
     * [BlocklistRepository.loadAndCompileBlocklists]. Pulls the latest custom
     * source URLs from [UserPreferences] and merges them with the built-in lists.
     * Ignores the call if a refresh is already in progress.
     */
    fun refreshBlocklists() {
        if (blocklistState.value is BlocklistState.Loading) return
        viewModelScope.launch {
            repository.loadAndCompileBlocklists()
        }
    }
}