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
import dev.michaelylee.freeblocker.MainActivity
import dev.michaelylee.freeblocker.ServiceLocator
import dev.michaelylee.freeblocker.data.BlocklistFetcher
import dev.michaelylee.freeblocker.data.BlocklistRepository
import dev.michaelylee.freeblocker.data.BlocklistState
import dev.michaelylee.freeblocker.data.DefaultSourceProvider
import dev.michaelylee.freeblocker.data.UserPreferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

/**
 * Android VpnService that creates a local TUN interface and routes all DNS traffic
 * through [DnsProxyServer] for blocklist enforcement.
 *
 * Startup sequence:
 *   1. Build and establish the TUN interface.
 *   2. Start the DNS proxy so queries are answered immediately (empty blocklist
 *      means everything is allowed through until step 3 completes).
 *   3. Download and compile the blocklist via [BlocklistRepository] in the
 *      background. Once complete, [DnsFilter] is populated and blocking begins.
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
        const val ACTION_STOP_AND_CLOSE = "dev.michaelylee.freeblocker.STOP_AND_CLOSE"
        const val ACTION_SET_BLOCKING  = "dev.michaelylee.freeblocker.SET_BLOCKING"
        const val EXTRA_BLOCKING_ENABLED = "blocking_enabled"

        private const val NOTIFICATION_ID      = 1
        private const val NOTIFICATION_CHANNEL = "freeblocker_vpn"
    }

    private val userPreferences by lazy { UserPreferences(applicationContext) }

    private val dnsFilter get() = ServiceLocator.dnsFilter

    private val dnsProxy by lazy {
        DnsProxyServer(
            context   = applicationContext,
            dnsFilter = dnsFilter,
        )
    }

    private val blocklistRepository get() = ServiceLocator.blocklistRepository

    private val serviceScope = CoroutineScope(Dispatchers.IO + Job())
    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START        -> startVpn()
            ACTION_STOP         -> stopVpn()
            ACTION_SET_BLOCKING -> {
                val enabled = intent.getBooleanExtra(EXTRA_BLOCKING_ENABLED, true)
                dnsProxy.isBlockingEnabled = enabled
                Log.i(TAG, "Blocking ${if (enabled) "enabled" else "disabled"}")

                // When re-enabling blocking, rebuild the TUN interface to flush
                // the system DNS cache.  Without this, cached DNS results from
                // the "blocking disabled" period prevent blocked domains from
                // being re-queried until their TTL expires.
                if (enabled && vpnInterface != null) {
                    serviceScope.launch { rebuildTunInterface() }
                }
            }
        }
        return START_NOT_STICKY
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
                vpnInterface = buildTunInterface() ?: run {
                    Log.e(TAG, "Failed to establish TUN interface")
                    stopVpn()
                    return@launch
                }

                startTunLoop()
                registerNetworkCallback()

                // Apply saved upstream config
                val savedUpstream = userPreferences.getUpstreamConfig()
                dnsProxy.updateUpstream(savedUpstream)
                Log.i(TAG, "Upstream initialised: $savedUpstream")

                // Restore blocking enabled state
                dnsProxy.isBlockingEnabled = userPreferences.isBlockingEnabledFlow.first()
                Log.i(TAG, "Blocking enabled: ${dnsProxy.isBlockingEnabled}")

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
        dnsProxy.stop()

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
        val fd = vpnInterface?.fileDescriptor ?: return

        val router = TunPacketRouter(
            tunInput   = FileInputStream(fd),
            tunOutput  = FileOutputStream(fd),
            dnsHandler = { queryBytes -> dnsProxy.handleDnsQuery(queryBytes) },
        )

        serviceScope.launch {
            router.run()
        }
    }

    /**
     * Tears down and re-establishes the TUN interface.
     *
     * Closing the old file descriptor causes [TunPacketRouter.run] to exit
     * gracefully (it catches [IOException]).  The new TUN forces Android to
     * flush its DNS resolver cache, so all apps immediately re-query through
     * our filter instead of using stale cached results.
     */
    private suspend fun rebuildTunInterface() {
        Log.i(TAG, "Rebuilding TUN to flush DNS cache…")

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

    /**
     * Briefly establishes a VPN with a default route (0.0.0.0/0) and immediately
     * closes it. This forces Android to see a network change for the default
     * network, which causes apps (like Chrome) to drop all their existing
     * TCP sockets and flush their DNS caches.
     *
     * Without this, since we only route DNS traffic (split tunnel), existing
     * HTTP keep-alive connections to blocked domains would remain open.
     */
    private suspend fun flushSystemSockets() {
        try {
            val dummyFd = Builder()
                .setSession("FreeBlockerVPN-Flush")
                .addAddress("10.0.0.2", 32)
                .addAddress("fd00::2", 128)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .setMtu(1500)
                .establish()
            
            // Give Android enough time to register the default network
            // and notify apps to tear down their existing sockets.
            // Without this delay, the dummy VPN is closed too quickly
            // for the ConnectivityService to broadcast the change.
            kotlinx.coroutines.delay(1000)
            
            dummyFd?.close()
            Log.i(TAG, "System sockets and DNS cache flushed")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to flush system sockets", e)
        }
    }

    /**
     * Builds and establishes the TUN interface to redirect DNS queries to [DnsProxyServer].
     * Reads whitelisted apps from [UserPreferences] and excludes them from the VPN
     * via [Builder.addDisallowedApplication].
     */
    private suspend fun buildTunInterface(): ParcelFileDescriptor? {
        flushSystemSockets()

        val builder = Builder()
            .setSession("FreeBlockerVPN")
            // IPv4 Setup
            .addAddress("10.0.0.2", 32)
            .addDnsServer("10.0.0.1")
            .addRoute("10.0.0.1", 32)  // Route DNS traffic through TUN to our packet router

            // IPv6 Setup
            .addAddress("fd00::2", 128)
            .addDnsServer("fd00::1")
            .addRoute("fd00::1", 128)  // Route IPv6 DNS traffic through TUN

            .setMtu(1500)

        // Exclude whitelisted apps from the VPN tunnel
        val whitelistedApps = userPreferences.getWhitelistedApps()
        for (packageName in whitelistedApps) {
            try {
                builder.addDisallowedApplication(packageName)
                Log.d(TAG, "Excluded app from VPN: $packageName")
            } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
                Log.w(TAG, "Skipping unknown package: $packageName")
            }
        }

        return builder.establish()
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.i(TAG, "Network change detected — draining upstream connection pool")
            setUnderlyingNetworks(arrayOf(network))

            // The Silver Bullet: Bind the entire VPN process to the physical network.
            // This natively forces all C++ (Cronet) and Java (OkHttp) sockets to bypass the VPN.
            connectivityManager?.bindProcessToNetwork(network)

            dnsProxy.drainConnections()
        }

        override fun onLost(network: Network) {
            // Unbind when the network drops
            connectivityManager?.bindProcessToNetwork(null)
        }
    }

    private var connectivityManager: ConnectivityManager? = null

    private fun registerNetworkCallback() {
        connectivityManager = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        connectivityManager?.registerNetworkCallback(request, networkCallback)
        Log.d(TAG, "Network callback registered")
    }

    private fun unregisterNetworkCallback() {
        runCatching { connectivityManager?.unregisterNetworkCallback(networkCallback) }
        connectivityManager = null
    }

    private fun buildNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL,
                "VPN Status",
                NotificationManager.IMPORTANCE_LOW,
            ).apply { description = "Shows while FreeBlocker VPN is active" }

            getSystemService(NotificationManager::class.java)
                ?.createNotificationChannel(channel)
        }

        val openAppIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )

        val stopIntent = PendingIntent.getActivity(
            this, 1,
            Intent(this, MainActivity::class.java).apply {
                action = ACTION_STOP_AND_CLOSE
                flags  = Intent.FLAG_ACTIVITY_NEW_TASK or
                         Intent.FLAG_ACTIVITY_SINGLE_TOP or
                         Intent.FLAG_ACTIVITY_CLEAR_TOP
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