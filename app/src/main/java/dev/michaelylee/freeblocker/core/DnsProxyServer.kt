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
        // Pre-warm the clients to avoid delay on first query
        CoroutineScope(Dispatchers.IO).launch {
            upstreamClients.cronetEngineFor(config)
            upstreamClients.httpClientFor(config)
        }
        Log.i(TAG, "Upstream updated to $config — clients drained and warming up")
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
        val cronetExecutor = Executors.newFixedThreadPool(4)

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
                    .enableHttp2(true) // Enable HTTP/2 fallback for Cronet
                    .addQuicHint(config.host, 443, 443)
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
                forwardUpstream(queryBytes, upstream)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Query handling failed", e)
            buildServfailResponse(queryBytes)
        }
    }

    // -------------------------------------------------------------------------
    // Sequential upstream forwarding (DoQ with fallback to DoH)
    // -------------------------------------------------------------------------

    /**
     * Attempts DoQ first. If it fails or times out, falls back to DoH.
     */
    private suspend fun forwardUpstream(queryBytes: ByteArray, config: UpstreamConfig): ByteArray {
        return try {
            withTimeout(1500) {
                forwardDoq(queryBytes, config)
            }
        } catch (e: Exception) {
            Log.d(TAG, "DoQ failed or timed out (${e.message}), falling back to DoH")
            forwardDoh(queryBytes, config)
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
            val executor = upstreamClients.cronetExecutor

            // Use the IP address directly to avoid DNS resolution through our own VPN
            // We use port 443 for HTTP/3 (DoH3) instead of 853 because Cronet speaks HTTP/3, not raw DoQ.
            val url = "https://${config.host}:443/dns-query"

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
                            if (raw.isEmpty()) throw IOException("DoH3 response empty")
                            raw
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
                            override fun getLength() = queryBytes.size.toLong()
                            override fun read(sink: UploadDataSink, buf: NioByteBuffer) {
                                val n = minOf(buf.remaining(), queryBytes.size - position)
                                buf.put(queryBytes, position, n)
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

        // Find the end of the question section so we truncate any trailing
        // records (e.g. EDNS0 OPT) from the original query.  Leaving those
        // bytes in the response while ARCOUNT=0 produces trailing garbage
        // that strict resolvers (Chrome's async DNS) reject as malformed,
        // causing a silent fallback to cached/offline content instead of
        // the expected NXDOMAIN error page.
        val qdcount = ((queryBytes[4].toInt() and 0xFF) shl 8) or
                       (queryBytes[5].toInt() and 0xFF)
        var pos = 12
        for (i in 0 until qdcount) {
            // Walk past each QNAME (sequence of length-prefixed labels ending with 0x00)
            while (pos < queryBytes.size) {
                val labelLen = queryBytes[pos].toInt() and 0xFF
                pos++
                if (labelLen == 0) break          // end-of-name sentinel
                if (labelLen > 63) break          // compression pointer — shouldn't appear in queries
                pos += labelLen
            }
            pos += 4  // skip QTYPE (2 bytes) + QCLASS (2 bytes)
        }

        // Clamp to array bounds in case of a malformed query
        val truncatedLen = pos.coerceAtMost(queryBytes.size)
        val response = queryBytes.copyOf(truncatedLen)
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