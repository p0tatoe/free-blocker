package dev.michaelylee.freeblocker.core

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.suspendCancellableCoroutine
import java.io.*
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import kotlin.time.Duration.Companion.milliseconds
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.chromium.net.CronetEngine
import org.chromium.net.CronetException
import org.chromium.net.UploadDataProvider
import org.chromium.net.UploadDataSink
import org.chromium.net.UrlRequest
import org.chromium.net.UrlResponseInfo
import java.nio.ByteBuffer as NioByteBuffer

/**
 * DNS query handler that filters domains against [DnsFilter] and forwards
 * allowed queries upstream via a Happy Eyeballs race between DoQ
 * (DNS-over-QUIC) and DoH (DNS-over-HTTPS).
 *
 * Architecture:
 *  - [TunPacketRouter] reads raw IP packets from the VPN TUN interface,
 *    extracts DNS payloads, and calls [handleDnsQuery] directly.
 *
 *  - Blocked domains receive an immediate NXDOMAIN response without
 *    touching the network.
 *
 *  - Allowed queries are forwarded upstream using encrypted transports
 *    only (DoQ/DoH) to comply with Google Play's VpnService policy.
 *
 *  Happy Eyeballs upstream strategy (RFC 8305 inspired):
 *  - DoQ is attempted first (fastest — raw QUIC, no HTTP framing overhead).
 *  - After [DOH_DELAY] with no DoQ response, DoH is started in parallel
 *    (TCP 443, universally reachable even on restrictive networks).
 *  - Whichever responds first wins; the other is cancelled.
 *  - This gives DoQ a fair head start on healthy networks while bounding
 *    worst-case latency on networks that block UDP 853.
 *
 *  - DoH reuses a single OkHttpClient (HTTP/2 multiplexes over one TLS connection).
 *  - DoQ uses Cronet's QUIC stack (available on Android via Play Services). Cronet
 *    manages its own QUIC connection internally.
 */
class DnsProxyServer(
    private val context: Context,
    private val dnsFilter: DnsFilter,
    @Volatile private var upstream: UpstreamConfig = UpstreamConfig(),
) {

    companion object {
        private const val TAG               = "DnsProxyServer"
        private val SOCKET_TIMEOUT  = 5_000.milliseconds
        private val DOH_DELAY       = 100.milliseconds   // head-start for DoQ before DoH races
    }

    // -------------------------------------------------------------------------
    // UpstreamConfig
    // -------------------------------------------------------------------------

    /**
     * Connection parameters for the upstream encrypted DNS resolver.
     *
     * Both DoQ and DoH always point at the same resolver; the Happy Eyeballs
     * race picks whichever protocol responds first.
     *
     * @param host        IP address of the upstream server.
     * @param doqPort     QUIC port for DoQ (default 853).
     * @param sniHostname TLS SNI hostname used for DoQ (e.g. "cloudflare-dns.com").
     * @param dohUrl      Full HTTPS URL for DoH (e.g. "https://cloudflare-dns.com/dns-query").
     */
    data class UpstreamConfig(
        val host        : String = "1.1.1.1",
        val doqPort     : Int    = 853,
        val sniHostname : String = "cloudflare-dns.com",
        val dohUrl      : String = "https://cloudflare-dns.com/dns-query",
    ) {
        companion object {
            private const val SEPARATOR = "|"

            /**
             * Encodes this config to a single string for DataStore persistence.
             * Format: "host|doqPort|sniHostname|dohUrl"
             * Example: "1.1.1.1|853|cloudflare-dns.com|https://cloudflare-dns.com/dns-query"
             */
            fun encode(config: UpstreamConfig): String = listOf(
                config.host,
                config.doqPort.toString(),
                config.sniHostname,
                config.dohUrl,
            ).joinToString(SEPARATOR)

            /**
             * Decodes a string produced by [encode] back into an [UpstreamConfig].
             * Returns null if the string is malformed so callers can fall back to
             * the default.
             */
            fun decode(encoded: String): UpstreamConfig? {
                val parts = encoded.split(SEPARATOR)
                if (parts.size != 4) return null
                val port = parts[1].toIntOrNull() ?: return null
                return UpstreamConfig(
                    host        = parts[0].ifEmpty { return null },
                    doqPort     = port,
                    sniHostname = parts[2],
                    dohUrl      = parts[3],
                )
            }
        }
    }

    // -------------------------------------------------------------------------
    // Public control surface
    // -------------------------------------------------------------------------

    fun updateUpstream(config: UpstreamConfig) {
        upstream = config
        upstreamClients.drain()
        Log.i(TAG, "Upstream updated to $config — clients drained")
    }

    fun drainConnections() {
        upstreamClients.drain()
        Log.i(TAG, "Upstream clients drained (network change)")
    }

    /**
     * Controls whether DNS queries are filtered against the blocklist.
     * When false, all queries are forwarded upstream regardless of domain.
     * The blocklist itself is preserved in memory so re-enabling is instant.
     */
    @Volatile var isBlockingEnabled: Boolean = true

    // -------------------------------------------------------------------------
    // Upstream clients (one OkHttpClient + one CronetEngine, lazily created)
    // -------------------------------------------------------------------------

    /**
     * Holds the singleton DoH and DoQ client instances.
     * Both are cheap to hold onto between queries; they manage their own
     * internal connection pooling and QUIC session state.
     */
    private inner class UpstreamClients {

        private val httpClients  = ConcurrentHashMap<UpstreamConfig, OkHttpClient>()
        private val cronetLock   = Any()
        @Volatile private var cronetEngine: CronetEngine? = null

        // ---- DoH ----------------------------------------------------------------

        fun httpClientFor(config: UpstreamConfig): OkHttpClient =
            httpClients.getOrPut(config) {
                OkHttpClient.Builder()
                    .protocols(listOf(okhttp3.Protocol.HTTP_2, okhttp3.Protocol.HTTP_1_1))
                    .connectTimeout(SOCKET_TIMEOUT)
                    .readTimeout(SOCKET_TIMEOUT)
                    .writeTimeout(SOCKET_TIMEOUT)
                    // Resolve the upstream hostname directly to its known IP so
                    // DNS resolution doesn't loop back through our own VPN.
                    .dns { listOf(InetAddress.getByName(config.host)) }
                    .build()
                    .also { Log.d(TAG, "Clients: created OkHttpClient for ${config.host}") }
            }

        // ---- DoQ ----------------------------------------------------------------

        /**
         * Returns the shared [CronetEngine], creating it on first call.
         * A QUIC hint is pre-loaded for the upstream host so Cronet can begin
         * the QUIC handshake before the first query arrives.
         */
        fun cronetEngineFor(config: UpstreamConfig): CronetEngine {
            cronetEngine?.let { return it }
            return synchronized(cronetLock) {
                cronetEngine ?: CronetEngine.Builder(context)
                    .enableQuic(true)
                    .enableHttp2(false)
                    .addQuicHint(config.host, config.doqPort, config.doqPort)
                    .build()
                    .also {
                        cronetEngine = it
                        Log.d(TAG, "Clients: created CronetEngine for ${config.host}:${config.doqPort}")
                    }
            }
        }

        // ---- Teardown -----------------------------------------------------------

        /**
         * Clears cached clients. The Cronet engine is intentionally kept alive
         * across upstream swaps — rebuilding it is expensive and it handles new
         * hosts gracefully on its own.
         */
        fun drain() {
            httpClients.clear()
            Log.d(TAG, "Clients: drained")
        }
    }

    private val upstreamClients = UpstreamClients()

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    fun stop() {
        upstreamClients.drain()
        Log.i(TAG, "DNS proxy stopped — upstream clients drained")
    }

    // -------------------------------------------------------------------------
    // Core query handler
    // -------------------------------------------------------------------------

    /**
     * Entry point for every DNS query regardless of inbound transport.
     * Never throws — always returns at least a SERVFAIL on error.
     */
    internal suspend fun handleDnsQuery(queryBytes: ByteArray): ByteArray {
        return try {
            val domain = parseDnsQueryDomain(queryBytes)

            if (isBlockingEnabled && domain != null && dnsFilter.shouldBlock(domain)) {
                Log.d(TAG, "BLOCK  $domain")
                buildNxdomainResponse(queryBytes)
            } else {
                Log.d(TAG, "ALLOW  ${domain ?: "<unparseable>"}")
                forwardHappyEyeballs(queryBytes, upstream)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Query handling failed", e)
            buildServfailResponse(queryBytes)
        }
    }

    // -------------------------------------------------------------------------
    // Happy Eyeballs upstream race (DoQ first, DoH after delay)
    // -------------------------------------------------------------------------

    /**
     * Races DoQ and DoH using a Happy Eyeballs strategy (RFC 8305 inspired):
     *
     *   t=0ms      DoQ attempt starts.
     *   t=100ms    If DoQ hasn't responded yet, DoH attempt starts in parallel.
     *   t=first    Whichever resolves first wins; the other coroutine is cancelled.
     *
     * The [DOH_DELAY] head-start ensures DoQ wins on healthy networks without
     * requiring any extra round-trips. DoH acts as a silent fallback for networks
     * that block UDP 853 (corporate firewalls, some mobile carriers, captive portals).
     *
     * Uses [select] to race the two [Deferred]s. The loser is cancelled but its
     * resources (OkHttp call, Cronet request) are cleaned up in each method's
     * finally block.
     */
    private suspend fun forwardHappyEyeballs(queryBytes: ByteArray, config: UpstreamConfig): ByteArray =
        coroutineScope {
            // DoQ starts immediately
            val doqDeferred = async(Dispatchers.IO) {
                runCatching { forwardDoq(queryBytes, config) }
            }

            // DoH starts after a delay, giving DoQ a head start
            val dohDeferred = async(Dispatchers.IO) {
                delay(DOH_DELAY)
                runCatching { forwardDoh(queryBytes, config) }
            }

            try {
                // Wait for the first successful result.
                // If DoQ wins with a failure and DoH hasn't started yet, we still
                // wait for DoH to complete before giving up.
                val result = select<Result<ByteArray>> {
                    doqDeferred.onAwait { it }
                    dohDeferred.onAwait { it }
                }

                if (result.isSuccess) {
                    // Winner succeeded — cancel the loser
                    doqDeferred.cancel()
                    dohDeferred.cancel()
                    Log.d(TAG, "Happy Eyeballs: winner resolved")
                    result.getOrThrow()
                } else {
                    // Winner failed — wait for the other one
                    Log.d(TAG, "Happy Eyeballs: first attempt failed (${result.exceptionOrNull()?.message}), waiting for other")
                    val fallback = if (doqDeferred.isCompleted) dohDeferred.await() else doqDeferred.await()
                    fallback.getOrThrow()
                }
            } finally {
                doqDeferred.cancel()
                dohDeferred.cancel()
            }
        }

    // -------------------------------------------------------------------------
    // DNS-over-QUIC (RFC 9250)
    // -------------------------------------------------------------------------

    /**
     * Sends [queryBytes] to the upstream resolver over QUIC via Cronet.
     *
     * Wire format (RFC 9250 §4.2): 2-byte big-endian length prefix + DNS message,
     * identical to DNS-over-TCP but carried over a QUIC stream.
     *
     * Cronet dispatches its callbacks on its own executor threads; we bridge back
     * to the coroutine world via [suspendCancellableCoroutine], which also handles
     * cancellation by calling [UrlRequest.cancel] on the Cronet request.
     */
    private suspend fun forwardDoq(queryBytes: ByteArray, config: UpstreamConfig): ByteArray =
        withContext(Dispatchers.IO) {
            val engine   = upstreamClients.cronetEngineFor(config)
            val executor = Executors.newSingleThreadExecutor()

            // Prepend the 2-byte length prefix required by RFC 9250 §4.2
            val wireBytes = ByteArray(queryBytes.size + 2).also { buf ->
                buf[0] = (queryBytes.size ushr 8).toByte()
                buf[1] = (queryBytes.size and 0xFF).toByte()
                queryBytes.copyInto(buf, destinationOffset = 2)
            }

            // Use the IP address directly to avoid DNS resolution through our own VPN
            val url = "https://${config.host}:${config.doqPort}/dns-query"

            try {
                suspendCancellableCoroutine { continuation ->
                    val response = ByteArrayOutputStream()

                    val callback = object : UrlRequest.Callback() {
                        override fun onRedirectReceived(
                            request: UrlRequest, info: UrlResponseInfo, newLocationUrl: String,
                        ) { request.followRedirect() }

                        override fun onResponseStarted(request: UrlRequest, info: UrlResponseInfo) {
                            request.read(NioByteBuffer.allocateDirect(32 * 1024))
                        }

                        override fun onReadCompleted(
                            request: UrlRequest, info: UrlResponseInfo, byteBuffer: NioByteBuffer,
                        ) {
                            byteBuffer.flip()
                            val chunk = ByteArray(byteBuffer.remaining()).also { byteBuffer.get(it) }
                            response.write(chunk)
                            byteBuffer.clear()
                            request.read(byteBuffer)
                        }

                        override fun onSucceeded(request: UrlRequest, info: UrlResponseInfo) {
                            val raw = response.toByteArray()
                            val result = runCatching {
                                if (raw.size < 2) throw IOException("DoQ response too short (${raw.size} bytes)")
                                val msgLen = ((raw[0].toInt() and 0xFF) shl 8) or (raw[1].toInt() and 0xFF)
                                if (raw.size < 2 + msgLen) throw IOException("DoQ response truncated (expected ${2 + msgLen}, got ${raw.size})")
                                raw.copyOfRange(2, 2 + msgLen)
                            }
                            continuation.resumeWith(result)
                        }

                        override fun onFailed(
                            request: UrlRequest, info: UrlResponseInfo?, e: CronetException,
                        ) {
                            continuation.resumeWith(Result.failure(IOException("DoQ failed: ${e.message}", e)))
                        }

                        override fun onCanceled(request: UrlRequest, info: UrlResponseInfo?) {
                            continuation.resumeWith(Result.failure(IOException("DoQ cancelled")))
                        }
                    }

                    val request = engine.newUrlRequestBuilder(url, callback, executor)
                        .setHttpMethod("POST")
                        .addHeader("Content-Type", "application/dns-message")
                        .addHeader("Accept", "application/dns-message")
                        .setUploadDataProvider(
                            object : UploadDataProvider() {
                                private var position = 0
                                override fun getLength() = wireBytes.size.toLong()
                                override fun read(sink: UploadDataSink, buf: NioByteBuffer) {
                                    val n = minOf(buf.remaining(), wireBytes.size - position)
                                    buf.put(wireBytes, position, n)
                                    position += n
                                    sink.onReadSucceeded(false)
                                }
                                override fun rewind(sink: UploadDataSink) {
                                    position = 0
                                    sink.onRewindSucceeded()
                                }
                            },
                            executor,
                        )
                        .build()

                    // Cancel the Cronet request if the coroutine is cancelled
                    continuation.invokeOnCancellation { request.cancel() }
                    request.start()
                }
            } finally {
                executor.shutdown()
            }
        }

    // -------------------------------------------------------------------------
    // DNS-over-HTTPS (RFC 8484)
    // -------------------------------------------------------------------------

    /**
     * Sends [queryBytes] to the upstream resolver over HTTPS via OkHttp.
     *
     * OkHttp's HTTP/2 support multiplexes all DoH queries over a single TLS
     * connection internally — no manual socket pooling needed.
     *
     * The request and response bodies are raw DNS wire-format messages.
     * OkHttp's synchronous [execute] is run on [Dispatchers.IO] so it doesn't
     * block a coroutine thread.
     */
    private suspend fun forwardDoh(queryBytes: ByteArray, config: UpstreamConfig): ByteArray =
        withContext(Dispatchers.IO) {
            val client = upstreamClients.httpClientFor(config)

            val request = Request.Builder()
                .url(config.dohUrl)
                .header("Accept", "application/dns-message")
                .post(queryBytes.toRequestBody("application/dns-message".toMediaType()))
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw IOException("DoH upstream returned HTTP ${response.code} for ${config.dohUrl}")
                }
                response.body?.bytes()
                    ?: throw IOException("DoH upstream returned empty body for ${config.dohUrl}")
            }
        }

    // -------------------------------------------------------------------------
    // DNS response builders
    // -------------------------------------------------------------------------

    private fun buildNxdomainResponse(queryBytes: ByteArray) = buildMinimalResponse(queryBytes, rcode = 3)
    private fun buildServfailResponse(queryBytes: ByteArray) = buildMinimalResponse(queryBytes, rcode = 2)

    /**
     * Constructs a minimal DNS response mirroring the query header.
     *
     * Flags written (16-bit word at offset 2):
     *   QR=1   — this is a response
     *   RD     — mirrored from the query's Recursion Desired bit
     *   RA=1   — recursion available
     *   RCODE  — supplied by caller (3 = NXDOMAIN, 2 = SERVFAIL)
     *
     * The question section is left intact so the client can match by transaction ID.
     * Answer, authority, and additional record counts are zeroed.
     */
    private fun buildMinimalResponse(queryBytes: ByteArray, rcode: Int): ByteArray {
        if (queryBytes.size < 12) return queryBytes

        val response = queryBytes.copyOf()
        val buf      = ByteBuffer.wrap(response)

        val rd            = buf.getShort(2).toInt() and 0x0100
        val responseFlags = 0x8000 or rd or 0x0080 or (rcode and 0x000F)
        buf.putShort(2, responseFlags.toShort())

        buf.putShort(6,  0)   // ANCOUNT = 0
        buf.putShort(8,  0)   // NSCOUNT = 0
        buf.putShort(10, 0)   // ARCOUNT = 0

        return response
    }

    // -------------------------------------------------------------------------
    // DNS query domain parser
    // -------------------------------------------------------------------------

    /**
     * Extracts the queried domain name from raw DNS query bytes.
     * Returns null if the packet is malformed or too short.
     *
     * The question section starts at byte 12. Each label is preceded by its
     * 1-byte length; a zero-length byte terminates the name.
     *
     * Wire encoding example for "ads.example.com":
     *   03 61 64 73              → "ads"
     *   07 65 78 61 6d 70 6c 65 → "example"
     *   03 63 6f 6d              → "com"
     *   00                       → end
     */
    private fun parseDnsQueryDomain(packet: ByteArray): String? {
        if (packet.size < 13) return null
        return try {
            val sb  = StringBuilder()
            var pos = 12

            while (pos < packet.size) {
                val labelLen = packet[pos].toInt() and 0xFF
                if (labelLen == 0) break
                if (labelLen > 63) return null   // compression pointer or malformed

                pos++
                if (pos + labelLen > packet.size) return null

                if (sb.isNotEmpty()) sb.append('.')
                sb.append(String(packet, pos, labelLen, Charsets.US_ASCII))
                pos += labelLen
            }

            if (sb.isEmpty()) null else sb.toString().lowercase()
        } catch (e: Exception) {
            null
        }
    }
}