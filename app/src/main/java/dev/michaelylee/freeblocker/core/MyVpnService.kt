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

        const val ACTION_START        = "dev.michaelylee.freeblocker.START"
        const val ACTION_STOP         = "dev.michaelylee.freeblocker.STOP"
        const val ACTION_SET_BLOCKING = "dev.michaelylee.freeblocker.SET_BLOCKING"
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

        try {
            vpnInterface = buildTunInterface() ?: run {
                Log.e(TAG, "Failed to establish TUN interface")
                stopVpn()
                return
            }

            startTunLoop()
            registerNetworkCallback()

            serviceScope.launch {
                // Apply saved upstream config
                val savedUpstream = userPreferences.getUpstreamConfig()
                dnsProxy.updateUpstream(savedUpstream)
                Log.i(TAG, "Upstream initialised: $savedUpstream")

                // Restore blocking enabled state
                dnsProxy.isBlockingEnabled = userPreferences.isBlockingEnabledFlow.first()
                Log.i(TAG, "Blocking enabled: ${dnsProxy.isBlockingEnabled}")



                // TODO: Re-enable blocklist loading once manual blocking is validated.
                // Temporarily disabled to isolate the TUN packet pipeline.
                // Log.i(TAG, "Fetching blocklist in background…")
                // blocklistRepository.loadAndCompileBlocklists()
                //
                // when (val state = blocklistRepository.state.value) {
                //     is BlocklistState.Success ->
                //         Log.i(TAG, "Blocklist ready — ${state.totalDomains} domains loaded")
                //     is BlocklistState.Error   ->
                //         Log.e(TAG, "Blocklist failed to load: ${state.message}")
                //     else -> Unit
                // }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error starting VPN — cleaning up", e)
            stopVpn()
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
     * Builds and establishes the TUN interface to redirect DNS queries to [DnsProxyServer].
     */
    private fun buildTunInterface(): ParcelFileDescriptor? =
        Builder()
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
            .establish()

    /**
     * When the device switches networks, open sockets to resolvers break.
     * We drain the connection pool so the next query opens a new socket.
     */
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.i(TAG, "Network change detected — draining upstream connection pool")
            setUnderlyingNetworks(arrayOf(network))
            dnsProxy.drainConnections()
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

        val stopIntent = PendingIntent.getService(
            this, 0,
            Intent(this, MyVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE,
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