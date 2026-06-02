package dev.michaelylee.freeblocker.core

import android.util.Log

/**
 * Stateless parser and builder for IP/UDP packets carrying DNS payloads.
 *
 * Used by [TunPacketRouter] to extract DNS queries from raw TUN packets
 * and construct matching response packets for reinjection into the TUN.
 *
 * Only UDP (protocol 17) is handled. TCP DNS is rare and a hassle to implement
 */
object IpPacketParser {

    private const val TAG = "IpPacketParser"

    // IP protocol numbers
    private const val PROTOCOL_UDP = 17

    // DNS port
    private const val DNS_PORT = 53

    // Header sizes
    private const val IPV4_MIN_HEADER_SIZE = 20
    private const val IPV6_HEADER_SIZE = 40
    private const val UDP_HEADER_SIZE = 8

    /**
     * Holds the parsed components of a DNS-over-UDP-over-IP packet.
     *
     * [originalPacket] retains the full raw packet so [buildDnsUdpResponse]
     * can copy the IP header template when constructing the response.
     */
    data class ParsedDnsPacket(
        val ipVersion: Int,
        val sourceAddress: ByteArray,
        val destAddress: ByteArray,
        val sourcePort: Int,
        val destPort: Int,
        val dnsPayload: ByteArray,
        val ipHeaderLength: Int,
        val originalPacket: ByteArray,
    )

    // -------------------------------------------------------------------------
    // Parsing
    // -------------------------------------------------------------------------

    /**
     * Attempts to parse [packet] (first [length] bytes) as a UDP DNS packet.
     *
     * @return A [ParsedDnsPacket] if this is a UDP packet with source or
     *         destination port 53, or `null` otherwise.
     */
    fun parseDnsUdpPacket(packet: ByteArray, length: Int): ParsedDnsPacket? {
        if (length < 1) return null

        val version = (packet[0].toInt() ushr 4) and 0x0F
        return when (version) {
            4 -> parseIpv4(packet, length)
            6 -> parseIpv6(packet, length)
            else -> {
                Log.d(TAG, "Unknown IP version: $version")
                null
            }
        }
    }

    private fun parseIpv4(packet: ByteArray, length: Int): ParsedDnsPacket? {
        if (length < IPV4_MIN_HEADER_SIZE) return null

        val ihl = packet[0].toInt() and 0x0F
        val ipHeaderLen = ihl * 4
        if (ipHeaderLen < IPV4_MIN_HEADER_SIZE) return null
        if (length < ipHeaderLen + UDP_HEADER_SIZE) return null

        val protocol = packet[9].toInt() and 0xFF
        if (protocol != PROTOCOL_UDP) {
            Log.d(TAG, "IPv4 non-UDP protocol: $protocol")
            return null
        }

        val srcAddr = packet.copyOfRange(12, 16)
        val dstAddr = packet.copyOfRange(16, 20)

        // Parse UDP header (starts immediately after IP header)
        val udpOffset = ipHeaderLen
        val srcPort = readUint16(packet, udpOffset)
        val dstPort = readUint16(packet, udpOffset + 2)
        val udpLength = readUint16(packet, udpOffset + 4)

        if (dstPort != DNS_PORT && srcPort != DNS_PORT) {
            Log.d(TAG, "IPv4 UDP not DNS: src=$srcPort dst=$dstPort")
            return null
        }

        val dnsOffset = udpOffset + UDP_HEADER_SIZE
        val dnsLength = udpLength - UDP_HEADER_SIZE
        if (dnsLength <= 0 || dnsOffset + dnsLength > length) return null

        return ParsedDnsPacket(
            ipVersion = 4,
            sourceAddress = srcAddr,
            destAddress = dstAddr,
            sourcePort = srcPort,
            destPort = dstPort,
            dnsPayload = packet.copyOfRange(dnsOffset, dnsOffset + dnsLength),
            ipHeaderLength = ipHeaderLen,
            originalPacket = packet.copyOf(length),
        )
    }

    private fun parseIpv6(packet: ByteArray, length: Int): ParsedDnsPacket? {
        if (length < IPV6_HEADER_SIZE + UDP_HEADER_SIZE) return null

        // NOTE: we only check the "next header" field directly. Extension
        // headers (hop-by-hop, routing, etc.) are not walked. For DNS
        // traffic on a local TUN this is fine — the kernel won't insert
        // extension headers for loopback DNS.
        val nextHeader = packet[6].toInt() and 0xFF
        if (nextHeader != PROTOCOL_UDP) {
            Log.d(TAG, "IPv6 non-UDP next header: $nextHeader")
            return null
        }

        val srcAddr = packet.copyOfRange(8, 24)
        val dstAddr = packet.copyOfRange(24, 40)

        val udpOffset = IPV6_HEADER_SIZE
        val srcPort = readUint16(packet, udpOffset)
        val dstPort = readUint16(packet, udpOffset + 2)
        val udpLength = readUint16(packet, udpOffset + 4)

        if (dstPort != DNS_PORT && srcPort != DNS_PORT) {
            Log.d(TAG, "IPv6 UDP not DNS: src=$srcPort dst=$dstPort")
            return null
        }

        val dnsOffset = udpOffset + UDP_HEADER_SIZE
        val dnsLength = udpLength - UDP_HEADER_SIZE
        if (dnsLength <= 0 || dnsOffset + dnsLength > length) return null

        return ParsedDnsPacket(
            ipVersion = 6,
            sourceAddress = srcAddr,
            destAddress = dstAddr,
            sourcePort = srcPort,
            destPort = dstPort,
            dnsPayload = packet.copyOfRange(dnsOffset, dnsOffset + dnsLength),
            ipHeaderLength = IPV6_HEADER_SIZE,
            originalPacket = packet.copyOf(length),
        )
    }

    // -------------------------------------------------------------------------
    // Response construction
    // -------------------------------------------------------------------------

    /**
     * Builds a complete IP+UDP response packet from a parsed inbound request
     * and a DNS response payload.
     *
     * The response packet has:
     * - Source and destination IP addresses swapped
     * - Source and destination UDP ports swapped
     * - Correct IP header checksum (IPv4) and UDP checksum (both v4 and v6)
     * - Updated length fields
     */
    fun buildDnsUdpResponse(request: ParsedDnsPacket, dnsResponse: ByteArray): ByteArray {
        return when (request.ipVersion) {
            4 -> buildIpv4Response(request, dnsResponse)
            6 -> buildIpv6Response(request, dnsResponse)
            else -> throw IllegalArgumentException("Unsupported IP version: ${request.ipVersion}")
        }
    }

    private fun buildIpv4Response(request: ParsedDnsPacket, dnsResponse: ByteArray): ByteArray {
        val ipHeaderLen = request.ipHeaderLength
        val totalLength = ipHeaderLen + UDP_HEADER_SIZE + dnsResponse.size
        val packet = ByteArray(totalLength)

        // Copy original IP header as a template (preserves version, IHL, DSCP,
        // identification, TTL, protocol, etc.)
        System.arraycopy(request.originalPacket, 0, packet, 0, ipHeaderLen)

        // -- IP header fixups --

        // Total length
        writeUint16(packet, 2, totalLength)

        // Swap source ↔ destination IP addresses
        System.arraycopy(request.destAddress, 0, packet, 12, 4)    // orig dst → new src
        System.arraycopy(request.sourceAddress, 0, packet, 16, 4)  // orig src → new dst

        // Recompute IP header checksum
        packet[10] = 0
        packet[11] = 0
        val ipChecksum = internetChecksum(packet, 0, ipHeaderLen)
        writeUint16(packet, 10, ipChecksum)

        // -- UDP header --
        val udpOffset = ipHeaderLen
        val udpLength = UDP_HEADER_SIZE + dnsResponse.size

        // Swap ports
        writeUint16(packet, udpOffset, request.destPort)        // orig dst port → new src port
        writeUint16(packet, udpOffset + 2, request.sourcePort)  // orig src port → new dst port
        writeUint16(packet, udpOffset + 4, udpLength)

        // Zero checksum before computing
        packet[udpOffset + 6] = 0
        packet[udpOffset + 7] = 0

        // Copy DNS response payload
        System.arraycopy(dnsResponse, 0, packet, udpOffset + UDP_HEADER_SIZE, dnsResponse.size)

        // Compute UDP checksum (optional for IPv4 but we include it for correctness)
        val udpChecksum = udpChecksumIpv4(packet, ipHeaderLen, udpLength)
        writeUint16(packet, udpOffset + 6, udpChecksum)

        return packet
    }

    private fun buildIpv6Response(request: ParsedDnsPacket, dnsResponse: ByteArray): ByteArray {
        val totalLength = IPV6_HEADER_SIZE + UDP_HEADER_SIZE + dnsResponse.size
        val packet = ByteArray(totalLength)

        // Copy original IPv6 header as template
        System.arraycopy(request.originalPacket, 0, packet, 0, IPV6_HEADER_SIZE)

        // -- IPv6 header fixups --

        // Payload length (excludes the 40-byte fixed header)
        val payloadLength = UDP_HEADER_SIZE + dnsResponse.size
        writeUint16(packet, 4, payloadLength)

        // Swap source ↔ destination addresses
        System.arraycopy(request.destAddress, 0, packet, 8, 16)     // orig dst → new src
        System.arraycopy(request.sourceAddress, 0, packet, 24, 16)  // orig src → new dst

        // -- UDP header --
        val udpOffset = IPV6_HEADER_SIZE
        val udpLength = UDP_HEADER_SIZE + dnsResponse.size

        writeUint16(packet, udpOffset, request.destPort)
        writeUint16(packet, udpOffset + 2, request.sourcePort)
        writeUint16(packet, udpOffset + 4, udpLength)

        packet[udpOffset + 6] = 0
        packet[udpOffset + 7] = 0

        // Copy DNS response payload
        System.arraycopy(dnsResponse, 0, packet, udpOffset + UDP_HEADER_SIZE, dnsResponse.size)

        // Compute UDP checksum (mandatory for IPv6)
        val udpChecksum = udpChecksumIpv6(packet, udpLength)
        writeUint16(packet, udpOffset + 6, udpChecksum)

        return packet
    }

    // -------------------------------------------------------------------------
    // Checksum helpers  (RFC 1071)
    // -------------------------------------------------------------------------

    /**
     * Standard Internet checksum: ones-complement of the ones-complement sum
     * of all 16-bit words in the given range.
     */
    private fun internetChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length

        while (i < end - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        // Odd trailing byte
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        // Fold 32-bit → 16-bit
        while (sum > 0xFFFF) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.toInt().inv() and 0xFFFF
    }

    /**
     * UDP checksum with IPv4 pseudo-header:
     *   src IP (4) + dst IP (4) + zero (1) + protocol (1) + UDP length (2)
     */
    private fun udpChecksumIpv4(packet: ByteArray, ipHeaderLen: Int, udpLength: Int): Int {
        val pseudo = ByteArray(12)
        System.arraycopy(packet, 12, pseudo, 0, 4)  // src IP (already swapped in packet)
        System.arraycopy(packet, 16, pseudo, 4, 4)  // dst IP
        pseudo[8] = 0
        pseudo[9] = PROTOCOL_UDP.toByte()
        pseudo[10] = (udpLength ushr 8).toByte()
        pseudo[11] = (udpLength and 0xFF).toByte()

        var sum = 0L
        for (i in 0 until 12 step 2) {
            sum += ((pseudo[i].toInt() and 0xFF) shl 8) or (pseudo[i + 1].toInt() and 0xFF)
        }

        val udpOffset = ipHeaderLen
        var i = udpOffset
        val end = udpOffset + udpLength
        while (i < end - 1) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (packet[i].toInt() and 0xFF) shl 8
        }

        while (sum > 0xFFFF) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }

        val result = sum.toInt().inv() and 0xFFFF
        return if (result == 0) 0xFFFF else result   // RFC 768: transmit 0xFFFF instead of 0
    }

    /**
     * UDP checksum with IPv6 pseudo-header (mandatory for IPv6):
     *   src IP (16) + dst IP (16) + UDP length (4) + zeros (3) + next header (1)
     */
    private fun udpChecksumIpv6(packet: ByteArray, udpLength: Int): Int {
        val pseudo = ByteArray(40)
        System.arraycopy(packet, 8, pseudo, 0, 16)   // src IP
        System.arraycopy(packet, 24, pseudo, 16, 16)  // dst IP
        // UDP length as 32-bit big-endian
        pseudo[32] = 0
        pseudo[33] = 0
        pseudo[34] = (udpLength ushr 8).toByte()
        pseudo[35] = (udpLength and 0xFF).toByte()
        // Next header
        pseudo[36] = 0
        pseudo[37] = 0
        pseudo[38] = 0
        pseudo[39] = PROTOCOL_UDP.toByte()

        var sum = 0L
        for (i in 0 until 40 step 2) {
            sum += ((pseudo[i].toInt() and 0xFF) shl 8) or (pseudo[i + 1].toInt() and 0xFF)
        }

        val udpOffset = IPV6_HEADER_SIZE
        var i = udpOffset
        val end = udpOffset + udpLength
        while (i < end - 1) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (packet[i].toInt() and 0xFF) shl 8
        }

        while (sum > 0xFFFF) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }

        val result = sum.toInt().inv() and 0xFFFF
        return if (result == 0) 0xFFFF else result
    }

    // -------------------------------------------------------------------------
    // Byte helpers
    // -------------------------------------------------------------------------

    /** Reads an unsigned 16-bit big-endian value at [offset]. */
    private fun readUint16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    /** Writes an unsigned 16-bit big-endian value at [offset]. */
    private fun writeUint16(data: ByteArray, offset: Int, value: Int) {
        data[offset]     = (value ushr 8).toByte()
        data[offset + 1] = (value and 0xFF).toByte()
    }
}
