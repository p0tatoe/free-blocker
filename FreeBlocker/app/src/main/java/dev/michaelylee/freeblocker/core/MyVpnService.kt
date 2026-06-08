package dev.michaelylee.freeblocker.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import uniffi.free_block_rust.DnsProxy
import dev.michaelylee.freeblocker.MainActivity
import dev.michaelylee.freeblocker.ServiceLocator
import dev.michaelylee.freeblocker.data.BlocklistFetcher
import dev.michaelylee.freeblocker.data.BlocklistRepository
import dev.michaelylee.freeblocker.data.BlocklistState
import dev.michaelylee.freeblocker.data.UserPreferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

/**
 * Android VpnService that creates a local TUN interface and routes all DNS traffic
 * through the Rust-based [DnsProxy] (via UniFFI) for blocklist enforcement.
 *
 * Startup sequence:
 *   1. Build and establish the TUN interface.
 *   2. Pass the TUN file descriptor to [DnsProxy], which spawns an async Tokio
 *      loop that reads raw packets, parses IP/UDP/DNS headers, checks the
 *      blocklist trie, and forwards allowed queries upstream via DoQ.
 *   3. Download and compile the blocklist via [BlocklistRepository] in the
 *      background. Once complete, [DnsFilter] is populated and the blocklist
 *      is pushed to the Rust proxy via [DnsProxy.updateBlocklist].
 *
 * This means there is a short window at startup where no domains are blocked.
 * The alternative — waiting for the blocklist before starting the proxy — would
 * leave the device with no DNS resolution while downloading, which is worse.
 */
class MyVpnService : VpnService() {

    companion object {
        private const val TAG = "MyVpnService"

        const val ACTION_START         = "dev.michaelylee.freeblocker.START"
        const val ACTION_STOP          = "dev.michaelylee.freeblocker.STOP"
        const val ACTION_SET_BLOCKING  = "dev.michaelylee.freeblocker.SET_BLOCKING"
        const val ACTION_FLUSH_DNS_CACHE = "dev.michaelylee.freeblocker.FLUSH_DNS_CACHE"
        const val EXTRA_BLOCKING_ENABLED = "blocking_enabled"

        private const val NOTIFICATION_ID      = 1
        private const val NOTIFICATION_CHANNEL = "freeblocker_vpn"
    }

    private val userPreferences by lazy { UserPreferences(applicationContext) }

    private val dnsFilter get() = ServiceLocator.dnsFilter

    private var dnsProxy: DnsProxy? = null
    @Volatile
    private var isBlockingEnabled = true

    private val blocklistRepository get() = ServiceLocator.blocklistRepository

    private val serviceScope = CoroutineScope(Dispatchers.IO + Job())
    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START        -> startVpn()
            ACTION_STOP         -> {
                serviceScope.launch { userPreferences.setVpnEnabled(false) }
                stopVpn()
            }
            ACTION_SET_BLOCKING -> {
                val enabled = intent.getBooleanExtra(EXTRA_BLOCKING_ENABLED, true)
                isBlockingEnabled = enabled
                Log.i(TAG, "Blocking ${if (enabled) "enabled" else "disabled"}")
                if (vpnInterface != null) {
                    debounceRebuild()
                }
            }
            ACTION_FLUSH_DNS_CACHE -> {
                if (vpnInterface != null) {
                    debounceRebuild()
                }
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterNetworkCallback()
        serviceScope.cancel()
        Log.d(TAG, "MyVpnService destroyed")
    }

    private fun startVpn() {
        if (vpnInterface != null) {
            Log.w(TAG, "VPN already running — ignoring start command")
            return
        }

        Log.i(TAG, "Starting VPN engine…")

        val notification = buildNotification()

        startForeground(
            NOTIFICATION_ID,
            notification,
            android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        )

        serviceScope.launch {
            try {
                connectivityManager = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager
                activePhysicalNetwork = connectivityManager?.activeNetwork

                vpnInterface = buildTunInterface() ?: run {
                    Log.e(TAG, "Failed to establish TUN interface")
                    stopVpn()
                    return@launch
                }

                startTunLoop()
                registerNetworkCallback()

                // Apply saved upstream config
                val savedUpstream = userPreferences.getUpstreamConfig()
                // Upstream config is now handled at proxy start
                Log.i(TAG, "Upstream initialised: $savedUpstream")

                // Restore blocking enabled state
                isBlockingEnabled = userPreferences.isBlockingEnabledFlow.first()
                Log.i(TAG, "Blocking enabled: $isBlockingEnabled")

                // Load blocklists in the background so blocking starts
                // as soon as the download + compile finishes.
                Log.i(TAG, "Fetching blocklist in background…")
                blocklistRepository.loadAndCompileBlocklists()

                when (val state = blocklistRepository.state.value) {
                    is BlocklistState.Success ->
                        Log.i(TAG, "Blocklist ready — ${state.totalDomains} domains loaded")
                    is BlocklistState.Error   ->
                        Log.e(TAG, "Blocklist failed to load: ${state.message}")
                    else -> Unit
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error starting VPN — cleaning up", e)
                stopVpn()
            }
        }
    }

    private fun stopVpn() {
        Log.i(TAG, "Stopping VPN engine…")

        unregisterNetworkCallback()
        dnsProxy?.stop()
        dnsProxy = null

        try {
            vpnInterface?.close()
        } catch (e: IOException) {
            Log.e(TAG, "Failed to close TUN interface cleanly", e)
        } finally {
            vpnInterface = null
        }

        dnsFilter.clear()

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startTunLoop() {
        val fd = vpnInterface?.fd ?: return

        serviceScope.launch {
            val upstreamConfig = userPreferences.getUpstreamConfig()
            
            var upstreamV4: String? = null
            var upstreamV6: String? = null
            
            try {
                val activeNetwork = connectivityManager?.activeNetwork
                val addresses = if (activeNetwork != null) {
                    activeNetwork.getAllByName(upstreamConfig.host)
                } else {
                    java.net.InetAddress.getAllByName(upstreamConfig.host)
                }
                
                upstreamV4 = addresses.firstOrNull { it is java.net.Inet4Address }?.hostAddress
                upstreamV6 = addresses.firstOrNull { it is java.net.Inet6Address }?.hostAddress
            } catch (e: Exception) {
                Log.e(TAG, "Failed to resolve upstream IP", e)
            }
            
            // Fallbacks in case it's already an IP string
            if (upstreamV4 == null && upstreamV6 == null) {
                if (upstreamConfig.host.contains(":")) {
                    upstreamV6 = upstreamConfig.host
                } else {
                    upstreamV4 = upstreamConfig.host
                }
            }

            Log.i(TAG, "Resolved upstream ${upstreamConfig.host} to v4: $upstreamV4, v6: $upstreamV6")
            
            // Pass resolved IPs, but keep SNI hostname for the QUIC handshake
            dnsProxy = DnsProxy(fd, upstreamV4, upstreamV6, upstreamConfig.sniHostname)
            
            val proxy = dnsProxy
            if (proxy != null) {
                proxy.getQuicFdV4()?.let { quicFd ->
                    if (protect(quicFd)) {
                        Log.i(TAG, "Protected IPv4 QUIC socket (fd: $quicFd) from VPN tunnel")
                    } else {
                        Log.e(TAG, "Failed to protect IPv4 QUIC socket (fd: $quicFd) from VPN tunnel")
                    }
                }
                proxy.getQuicFdV6()?.let { quicFd ->
                    if (protect(quicFd)) {
                        Log.i(TAG, "Protected IPv6 QUIC socket (fd: $quicFd) from VPN tunnel")
                    } else {
                        Log.e(TAG, "Failed to protect IPv6 QUIC socket (fd: $quicFd) from VPN tunnel")
                    }
                }
            }
            
            dnsFilter.rustProxyCallback = { domains ->
                if (isBlockingEnabled) {
                    dnsProxy?.updateBlocklist(domains)
                }
            }
            if (isBlockingEnabled) {
                dnsProxy?.updateBlocklist(dnsFilter.getBlocklist())
            }

            dnsProxy?.start()
        }
    }

    private val rebuildMutex = Mutex()
    private var rebuildJob: Job? = null

    private fun debounceRebuild() {
        rebuildJob?.cancel()
        rebuildJob = serviceScope.launch {
            kotlinx.coroutines.delay(500)
            rebuildTunInterface()
        }
    }

    /**
     * Tears down and re-establishes the TUN interface.
     *
     * Closing the old file descriptor causes the Rust [DnsProxy] read loop to
     * exit (the TUN fd returns EOF / error).  A new TUN is established and a
     * fresh [DnsProxy] is started, which also forces Android to flush its DNS
     * resolver cache so all apps immediately re-query through our filter
     * instead of using stale cached results.
     */
    private suspend fun rebuildTunInterface() {
        rebuildMutex.withLock {
            Log.i(TAG, "Rebuilding TUN to flush DNS cache…")

            dnsProxy?.stop()
            dnsProxy = null

            try {
                vpnInterface?.close()
            } catch (e: IOException) {
                Log.w(TAG, "Error closing old TUN fd", e)
            }

            vpnInterface = buildTunInterface() ?: run {
                Log.e(TAG, "Failed to re-establish TUN after blocking re-enabled")
                return
            }

            startTunLoop()
            Log.i(TAG, "TUN rebuilt — DNS cache flushed")
        }
    }

    /**
     * Builds and establishes the TUN interface to redirect DNS queries to the
     * Rust [DnsProxy]. Reads whitelisted apps from [UserPreferences] and
     * excludes them from the VPN via [Builder.addDisallowedApplication].
     */
    private suspend fun buildTunInterface(): ParcelFileDescriptor? {
        if (connectivityManager == null) {
            connectivityManager = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager
        }

        val builder = Builder()
            .setSession("FreeBlockerVPN")
            // IPv4 Setup
            .addAddress("10.0.0.2", 32)
            .addDnsServer("10.0.0.1")
            .addRoute("10.0.0.1", 32)  // Route DNS traffic through TUN to our packet router

            // IPv6 Setup
            .addAddress("fd00:1::2", 128)
            .addDnsServer("fd00:1::1")
            .addRoute("fd00:1::1", 128)

            .setMtu(1500)

        // Set underlying network explicitly to inherit NET_CAPABILITY_INTERNET immediately
        if (activePhysicalNetwork != null) {
            builder.setUnderlyingNetworks(arrayOf(activePhysicalNetwork!!))
        } else {
            val activeNetwork = connectivityManager?.activeNetwork
            if (activeNetwork != null) {
                builder.setUnderlyingNetworks(arrayOf(activeNetwork))
            }
        }

        // Allow apps to explicitly bypass the VPN to fix Google SMS / RCS
        builder.allowBypass()

        // Only include target apps in the VPN tunnel
        val filteredApps = userPreferences.getFilteredApps()
        if (filteredApps.isEmpty()) {
            // If no apps are selected, Android routes all apps by default.
            // To prevent this and truly route nothing, we add our own app as the only allowed app.
            try {
                builder.addAllowedApplication(packageName)
                Log.d(TAG, "No apps targeted. Routing only FreeBlocker to keep VPN idle.")
            } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
                Log.w(TAG, "Could not add self to allowed applications")
            }
        } else {
            for (pkg in filteredApps) {
                try {
                    builder.addAllowedApplication(pkg)
                    Log.d(TAG, "Included app in VPN: $pkg")
                } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
                    Log.w(TAG, "Skipping unknown package: $pkg")
                }
            }
        }

        return builder.establish()
    }

    private var activePhysicalNetwork: Network? = null

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val caps = connectivityManager?.getNetworkCapabilities(network)
            if (caps == null || !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                Log.w(TAG, "Ignoring network $network because it lacks INTERNET capability")
                return
            }
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
                Log.d(TAG, "Ignoring VPN network $network")
                return
            }

            if (network == activePhysicalNetwork) {
                Log.d(TAG, "Ignoring duplicate onAvailable for network $network")
                return
            }

            Log.i(TAG, "Network change detected: $network — draining upstream connection pool")
            activePhysicalNetwork = network
            setUnderlyingNetworks(arrayOf(network))
            
            // Rebuild the TUN interface to tear down the old proxy and start a fresh one,
            // which creates a new UDP socket that properly inherits the new network routing.
            // This also flushes the stale DNS cache which is vital when moving between networks.
            debounceRebuild()
        }

        override fun onLost(network: Network) {
            if (network == activePhysicalNetwork) {
                Log.w(TAG, "Active physical network lost: $network")
                activePhysicalNetwork = null
            }
        }
    }

    private var connectivityManager: ConnectivityManager? = null

    private fun registerNetworkCallback() {
        connectivityManager = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            // Tracking the default network perfectly aligns with protect(fd) routing
            connectivityManager?.registerDefaultNetworkCallback(networkCallback)
        } else {
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            connectivityManager?.registerNetworkCallback(request, networkCallback)
        }
        Log.d(TAG, "Network callback registered")
    }

    private fun unregisterNetworkCallback() {
        runCatching { connectivityManager?.unregisterNetworkCallback(networkCallback) }
        connectivityManager = null
    }

    private fun buildNotification(): Notification {
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL,
            "VPN Status",
            NotificationManager.IMPORTANCE_LOW,
        ).apply { description = "Shows while FreeBlocker VPN is active" }

        getSystemService(NotificationManager::class.java)
            ?.createNotificationChannel(channel)

        val openAppIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )

        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, MyVpnService::class.java).apply {
                action = ACTION_STOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL)
            .setContentTitle("FreeBlocker is active")
            .setContentText("Blocking ads and trackers")
            .setSmallIcon(android.R.drawable.ic_lock_lock)  // Replace with your own icon
            .setContentIntent(openAppIntent)
            .setOngoing(true)
            .addAction(android.R.drawable.ic_delete, "Stop", stopIntent)
            .build()
    }
}