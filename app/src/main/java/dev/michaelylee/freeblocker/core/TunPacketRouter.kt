package dev.michaelylee.freeblocker.core

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

/**
 * Continuously reads raw IP packets from the TUN file descriptor, identifies
 * DNS-over-UDP queries, dispatches them to a handler, and writes the response
 * packets back into the TUN.
 *
 * This is the "packet pump" that connects the Android VPN TUN interface to
 * [DnsProxyServer]'s query processing pipeline.
 *
 * Flow for each packet:
 *   1. [tunInput].read()  — blocking read of the next raw IP packet
 *   2. [IpPacketParser.parseDnsUdpPacket] — parse IP + UDP, extract DNS payload
 *   3. [dnsHandler] — filter / forward the DNS query (runs in a child coroutine)
 *   4. [IpPacketParser.buildDnsUdpResponse] — wrap the DNS response in IP + UDP
 *   5. [tunOutput].write() — inject the response packet back into the TUN
 *
 * Non-DNS and non-UDP packets are silently dropped (with a debug log).
 * Since [buildTunInterface][MyVpnService] only routes 127.0.0.1/32 and ::1/128,
 * the TUN exclusively receives DNS traffic — there is no general internet
 * traffic to forward.
 *
 * @param tunInput  [FileInputStream] wrapping the TUN file descriptor.
 * @param tunOutput [FileOutputStream] wrapping the same TUN file descriptor.
 * @param dnsHandler Suspend function that processes a raw DNS query payload and
 *                   returns the raw DNS response payload. Typically this is
 *                   [DnsProxyServer.handleDnsQuery].
 */
class TunPacketRouter(
    private val tunInput: FileInputStream,
    private val tunOutput: FileOutputStream,
    private val dnsHandler: suspend (ByteArray) -> ByteArray,
) {
    companion object {
        private const val TAG = "TunPacketRouter"
        private const val BUFFER_SIZE = 32767  // well above 1500-byte MTU
    }

    /** Synchronises writes to [tunOutput] across concurrent query coroutines. */
    private val outputLock = Any()

    /**
     * Blocking read loop. Call from a coroutine on [Dispatchers.IO].
     *
     * The loop exits when:
     * - The TUN fd is closed (throws [IOException], normal shutdown)
     * - The parent coroutine is cancelled
     */
    suspend fun run() = coroutineScope {
        val buffer = ByteArray(BUFFER_SIZE)
        Log.i(TAG, "Packet pump started")

        try {
            while (isActive) {
                val length = tunInput.read(buffer)
                if (length <= 0) continue

                // Copy before the buffer is reused on the next iteration
                val packetCopy = buffer.copyOf(length)

                // Process each packet in a child coroutine so the read loop
                // is not blocked while waiting for upstream DNS responses.
                launch(Dispatchers.IO) {
                    processPacket(packetCopy, length)
                }
            }
        } catch (_: IOException) {
            // TUN fd was closed — normal during VPN shutdown
            Log.i(TAG, "TUN read loop ended (fd closed)")
        } catch (e: Exception) {
            Log.e(TAG, "TUN read loop unexpected error", e)
        }

        Log.i(TAG, "Packet pump stopped")
    }

    /**
     * Parses a single raw IP packet, extracts the DNS payload, processes it,
     * builds the response packet, and writes it back into the TUN.
     */
    private suspend fun processPacket(packet: ByteArray, length: Int) {
        val parsed = IpPacketParser.parseDnsUdpPacket(packet, length)
        if (parsed == null) {
            Log.d(TAG, "Non-DNS/non-UDP packet ($length bytes) — dropped")
            return
        }

        Log.d(TAG, "DNS query: ${parsed.dnsPayload.size} bytes " +
                "(IPv${parsed.ipVersion} :${parsed.sourcePort}→:${parsed.destPort})")

        try {
            val dnsResponse = dnsHandler(parsed.dnsPayload)
            val responsePacket = IpPacketParser.buildDnsUdpResponse(parsed, dnsResponse)

            synchronized(outputLock) {
                tunOutput.write(responsePacket)
                tunOutput.flush()
            }

            Log.d(TAG, "DNS response injected: " +
                    "${dnsResponse.size} DNS bytes in ${responsePacket.size}-byte IP packet")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to process DNS packet", e)
        }
    }
}
