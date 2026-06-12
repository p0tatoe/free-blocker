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
    private var networkReconnectJob: Job? = null

    private fun debounceRebuild() {
        rebuildJob?.cancel()
        rebuildJob = serviceScope.launch {
            kotlinx.coroutines.delay(200)
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
     *
     * Used for blocking toggle and DNS cache flush — NOT for network changes,
     * which use [reconnectUpstream] instead to avoid tearing down the VPN.
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
     * Recycles the upstream [DnsProxy] without tearing down the TUN interface.
     *
     * When the physical network changes (WiFi ↔ Mobile), the old QUIC sockets
     * are bound to the previous network's routing and can no longer reach the
     * upstream DNS server.  This method:
     *   1. Stops the old [DnsProxy] (kills stale QUIC connections).
     *   2. Updates the VPN's underlying network so Android reports correct
     *      connectivity status for bypassed apps (GMS, etc.).
     *   3. Starts a fresh [DnsProxy] with new QUIC sockets on the same TUN fd.
     *
     * Crucially, the TUN interface stays alive throughout, so Android never
     * deregisters the VPN as the default network.  This prevents the
     * connectivity disruption that caused bypassed apps like Google Messages
     * to lose their RCS / Play Services connections.
     */
    private suspend fun reconnectUpstream() {
        rebuildMutex.withLock {
            if (vpnInterface == null) return

            Log.i(TAG, "Reconnecting upstream on new network…")

            // 1. Stop old proxy (kills stale QUIC connections bound to old network)
            dnsProxy?.stop()
            dnsProxy = null

            // 2. Give the old proxy's Tokio task time to exit and release the
            //    AsyncFd on the TUN fd.  The task may be waiting on a QUIC query
            //    timeout (up to 3 s), but the cancel token should interrupt the
            //    select! loop within a few hundred ms.
            kotlinx.coroutines.delay(1000)

            // 3. Update underlying network so the VPN inherits the new network's
            //    connectivity status — bypassed apps see uninterrupted internet.
            activePhysicalNetwork?.let { setUnderlyingNetworks(arrayOf(it)) }

            // 4. Start a fresh proxy on the same TUN fd with new QUIC sockets
            startTunLoop()
            Log.i(TAG, "Upstream reconnected — new QUIC sockets on current network")
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

        // Exclude bypassed apps from the VPN tunnel
        val bypassedApps = userPreferences.getBypassedApps().toMutableSet()
        
        // Critical system packages that must bypass the VPN to maintain connectivity signalling
        val systemBypasses = listOf(
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.google.android.networkstack",
            "com.google.android.captiveportallogin",
            "com.google.android.projection.gearhead", // Android Auto
            packageName // FreeBlocker itself
        )
        bypassedApps.addAll(systemBypasses)

        for (pkg in bypassedApps) {
            try {
                builder.addDisallowedApplication(pkg)
                Log.d(TAG, "Excluded app from VPN: $pkg")
            } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
                Log.w(TAG, "Skipping unknown package: $pkg")
            }
        }

        return builder.establish()
    }

    private var activePhysicalNetwork: Network? = null

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.d(TAG, "Physical network available: $network (waiting for validation)")
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            // NOT_VPN is already filtered by the NetworkRequest — no need to check here.
            // Only act once the network passes Android's connectivity validation.
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) return
            if (network == activePhysicalNetwork) return

            Log.i(TAG, "Validated physical network: $network — reconnecting upstream")
            activePhysicalNetwork = network

            // Recycle the DnsProxy without tearing down the TUN.
            // This keeps the VPN interface alive so Android never reports a
            // connectivity gap to bypassed apps (GMS, Google Messages, etc.).
            networkReconnectJob?.cancel()
            networkReconnectJob = serviceScope.launch { reconnectUpstream() }
        }

        override fun onLost(network: Network) {
            Log.w(TAG, "Physical network lost: $network")
            if (network == activePhysicalNetwork) {
                activePhysicalNetwork = null
                // Try to reconnect on any other available network.
                // The ConnectivityManager will deliver onCapabilitiesChanged
                // for any remaining validated network, which will trigger reconnect.
            }
        }
    }

    private var connectivityManager: ConnectivityManager? = null

    /**
     * Registers a callback that explicitly tracks physical (non-VPN) networks.
     *
     * We use [ConnectivityManager.registerNetworkCallback] with a request that
     * requires [NetworkCapabilities.NET_CAPABILITY_NOT_VPN] instead of
     * [ConnectivityManager.registerDefaultNetworkCallback] because the latter
     * reports the VPN itself as the default network when the VPN is active.
     * The NOT_VPN check in the callback would then filter out every event,
     * meaning we'd never detect physical network changes.
     */
    private fun registerNetworkCallback() {
        connectivityManager = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        connectivityManager?.registerNetworkCallback(request, networkCallback)
        Log.d(TAG, "Network callback registered (tracking physical networks)")
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