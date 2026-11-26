package com.aura.mobiledefense.domain.vpn

import java.net.InetAddress
import java.nio.ByteBuffer

data class ParsedIpPacket(
    val version: Int,
    val ihlBytes: Int,
    val totalLength: Int,
    val protocol: Int,
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val srcIpString: String,
    val dstIpString: String,
    val srcPort: Int,
    val dstPort: Int,
    val payloadOffset: Int,
    val payloadLength: Int
)

/**
 * Pure Kotlin wire-format IPv4 / UDP / TCP / DNS packet codec for the real Android TUN interface.
 */
object PacketCodec {
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    fun parseIpv4Packet(packet: ByteArray, length: Int): ParsedIpPacket? {
        if (length < 20) return null
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null
        val ihlBytes = (packet[0].toInt() and 0x0F) * 4
        if (ihlBytes < 20 || length < ihlBytes) return null

        val totalLen = ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)
        val actualLen = minOf(length, totalLen)
        val protocol = packet[9].toInt() and 0xFF

        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)
        val srcIpStr = formatIpv4(srcIp)
        val dstIpStr = formatIpv4(dstIp)

        var srcPort = 0
        var dstPort = 0
        var payloadOffset = ihlBytes
        var payloadLength = (actualLen - ihlBytes).coerceAtLeast(0)

        if (protocol == PROTO_UDP && actualLen >= ihlBytes + 8) {
            srcPort = ((packet[ihlBytes].toInt() and 0xFF) shl 8) or (packet[ihlBytes + 1].toInt() and 0xFF)
            dstPort = ((packet[ihlBytes + 2].toInt() and 0xFF) shl 8) or (packet[ihlBytes + 3].toInt() and 0xFF)
            val udpLen = ((packet[ihlBytes + 4].toInt() and 0xFF) shl 8) or (packet[ihlBytes + 5].toInt() and 0xFF)
            payloadOffset = ihlBytes + 8
            payloadLength = minOf(actualLen - payloadOffset, (udpLen - 8).coerceAtLeast(0)).coerceAtLeast(0)
        } else if (protocol == PROTO_TCP && actualLen >= ihlBytes + 20) {
            srcPort = ((packet[ihlBytes].toInt() and 0xFF) shl 8) or (packet[ihlBytes + 1].toInt() and 0xFF)
            dstPort = ((packet[ihlBytes + 2].toInt() and 0xFF) shl 8) or (packet[ihlBytes + 3].toInt() and 0xFF)
            val dataOffset = ((packet[ihlBytes + 12].toInt() ushr 4) and 0x0F) * 4
            payloadOffset = minOf(actualLen, ihlBytes + dataOffset)
            payloadLength = (actualLen - payloadOffset).coerceAtLeast(0)
        }

        return ParsedIpPacket(
            version = version,
            ihlBytes = ihlBytes,
            totalLength = actualLen,
            protocol = protocol,
            srcIp = srcIp,
            dstIp = dstIp,
            srcIpString = srcIpStr,
            dstIpString = dstIpStr,
            srcPort = srcPort,
            dstPort = dstPort,
            payloadOffset = payloadOffset,
            payloadLength = payloadLength
        )
    }

    /**
     * Parses the first QNAME from a DNS wire-format query.
     */
    fun extractDnsQueryDomain(packet: ByteArray, dnsOffset: Int, dnsLength: Int): String? {
        if (dnsLength < 13 || dnsOffset + dnsLength > packet.size) return null
        var idx = dnsOffset + 12
        val end = dnsOffset + dnsLength
        val labels = mutableListOf<String>()
        var guard = 0
        while (idx < end && guard++ < 64) {
            val len = packet[idx].toInt() and 0xFF
            if (len == 0) break
            // Compression pointer not expected in standard question QNAME, stop cleanly if seen
            if ((len and 0xC0) == 0xC0) break
            idx++
            if (idx + len > end) return null
            labels.add(String(packet, idx, len, Charsets.US_ASCII))
            idx += len
        }
        return if (labels.isEmpty()) null else labels.joinToString(".").lowercase()
    }

    /**
     * Extrae las IPs de las respuestas A/AAAA de una respuesta DNS (soporta compresión de nombres).
     * Se usa para aprender dominio→IP y poder cortar ese dominio en el túnel.
     */
    fun extractDnsAnswerIps(response: ByteArray): List<String> {
        if (response.size < 12) return emptyList()
        val qdCount = u16(response, 4)
        val anCount = u16(response, 6)
        if (anCount == 0) return emptyList()
        var idx = 12
        repeat(qdCount) {
            val skipped = skipDnsName(response, idx) ?: return emptyList()
            idx = skipped + 4 // QTYPE + QCLASS
        }
        val ips = mutableListOf<String>()
        repeat(anCount) {
            val afterName = skipDnsName(response, idx) ?: return ips
            if (afterName + 10 > response.size) return ips
            val type = u16(response, afterName)
            val rdLength = u16(response, afterName + 8)
            val rdStart = afterName + 10
            if (rdStart + rdLength > response.size) return ips
            when (type) {
                1 -> if (rdLength == 4) {
                    ips.add(formatIpv4(response.copyOfRange(rdStart, rdStart + 4)))
                }
                28 -> if (rdLength == 16) {
                    ips.add(formatIpv6(response.copyOfRange(rdStart, rdStart + 16)))
                }
            }
            idx = rdStart + rdLength
        }
        return ips.distinct()
    }

    /** Salta un nombre DNS (con punteros de compresión) y devuelve el offset del byte siguiente. */
    private fun skipDnsName(buf: ByteArray, start: Int): Int? {
        var idx = start
        var guard = 0
        while (idx < buf.size && guard++ < 128) {
            val len = buf[idx].toInt() and 0xFF
            if (len == 0) return idx + 1
            if ((len and 0xC0) == 0xC0) return idx + 2 // puntero: 2 bytes y fin del nombre
            idx += 1 + len
        }
        return null
    }

    private fun formatIpv6(bytes: ByteArray): String {
        val groups = (0 until 8).map { i ->
            ((bytes[i * 2].toInt() and 0xFF) shl 8) or (bytes[i * 2 + 1].toInt() and 0xFF)
        }
        return groups.joinToString(":") { Integer.toHexString(it) }
    }

    private fun u16(b: ByteArray, i: Int): Int =
        ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)

    /**
     * Builds a valid DNS NXDOMAIN (RCODE=3) response payload for a blocked domain query.
     */
    fun buildDnsNxDomainResponse(queryPayload: ByteArray): ByteArray {
        if (queryPayload.size < 12) return queryPayload
        val resp = queryPayload.copyOf()
        // Set QR=1 (response), preserve RD, set RA=1 and RCODE=3 (NXDOMAIN)
        resp[2] = ((resp[2].toInt() and 0x01) or 0x81).toByte()
        resp[3] = 0x83.toByte()
        // Zero ANCOUNT, NSCOUNT, ARCOUNT
        resp[6] = 0
        resp[7] = 0
        resp[8] = 0
        resp[9] = 0
        resp[10] = 0
        resp[11] = 0
        return resp
    }

    /**
     * Builds a complete IPv4 + UDP packet with valid RFC 1071 IPv4 and UDP checksums.
     */
    fun buildIpv4UdpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val out = ByteArray(totalLen)

        // IPv4 Header (20 bytes)
        out[0] = 0x45.toByte() // Version 4, IHL 5 (20 bytes)
        out[1] = 0x00.toByte() // TOS
        out[2] = ((totalLen ushr 8) and 0xFF).toByte()
        out[3] = (totalLen and 0xFF).toByte()
        out[4] = 0x00.toByte()
        out[5] = 0x01.toByte()
        out[6] = 0x40.toByte() // Don't Fragment
        out[7] = 0x00.toByte()
        out[8] = 64.toByte()   // TTL
        out[9] = PROTO_UDP.toByte()
        // Checksum [10..11] computed below
        System.arraycopy(srcIp, 0, out, 12, 4)
        System.arraycopy(dstIp, 0, out, 16, 4)

        val ipChecksum = computeIpChecksum(out, 0, 20)
        out[10] = ((ipChecksum ushr 8) and 0xFF).toByte()
        out[11] = (ipChecksum and 0xFF).toByte()

        // UDP Header (8 bytes)
        out[20] = ((srcPort ushr 8) and 0xFF).toByte()
        out[21] = (srcPort and 0xFF).toByte()
        out[22] = ((dstPort ushr 8) and 0xFF).toByte()
        out[23] = (dstPort and 0xFF).toByte()
        out[24] = ((udpLen ushr 8) and 0xFF).toByte()
        out[25] = (udpLen and 0xFF).toByte()
        // UDP checksum [26..27] computed below
        System.arraycopy(payload, 0, out, 28, payload.size)

        val udpChecksum = computeUdpChecksum(srcIp, dstIp, out, 20, udpLen)
        out[26] = ((udpChecksum ushr 8) and 0xFF).toByte()
        out[27] = (udpChecksum and 0xFF).toByte()

        return out
    }

    /**
     * Recalcula el checksum IPv4 de un paquete **en el sitio** (bytes 10-11).
     * Se usa cada vez que el proxy reescribe la cabecera de un paquete capturado del TUN.
     */
    fun applyIpv4Checksum(packet: ByteArray, headerLen: Int) {
        packet[10] = 0
        packet[11] = 0
        val checksum = computeIpChecksum(packet, 0, headerLen)
        packet[10] = ((checksum ushr 8) and 0xFF).toByte()
        packet[11] = (checksum and 0xFF).toByte()
    }

    /** Checksum de un segmento TCP (pseudo-cabecera IPv4 + cabecera + payload). */
    fun tcpChecksum(segment: ByteArray, srcIp: ByteArray, dstIp: ByteArray): Int {
        var sum = 0L
        sum += ((srcIp[0].toInt() and 0xFF) shl 8) or (srcIp[1].toInt() and 0xFF)
        sum += ((srcIp[2].toInt() and 0xFF) shl 8) or (srcIp[3].toInt() and 0xFF)
        sum += ((dstIp[0].toInt() and 0xFF) shl 8) or (dstIp[1].toInt() and 0xFF)
        sum += ((dstIp[2].toInt() and 0xFF) shl 8) or (dstIp[3].toInt() and 0xFF)
        sum += PROTO_TCP.toLong()
        sum += segment.size.toLong()
        var i = 0
        while (i < segment.size) {
            val hi = segment[i].toInt() and 0xFF
            val lo = if (i + 1 < segment.size) segment[i + 1].toInt() and 0xFF else 0
            sum += (hi shl 8) or lo
            i += 2
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }

    /**
     * Construye un paquete IPv4 + TCP completo y con checksums válidos.
     *
     * `seq`/`ack` van en espacio de 32 bits sin signo; el desbordamiento natural de la suma de
     * secuencias es correcto por diseño del protocolo.
     */
    fun buildIpv4TcpPacket(
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray = ByteArray(0),
        window: Int = 65535
    ): ByteArray {
        val tcpLen = 20 + payload.size
        val totalLen = 20 + tcpLen
        val out = ByteArray(totalLen)

        // ── IPv4 ──
        out[0] = 0x45
        out[1] = 0
        out[2] = ((totalLen ushr 8) and 0xFF).toByte()
        out[3] = (totalLen and 0xFF).toByte()
        out[4] = 0
        out[5] = 0
        out[6] = 0x40          // Don't Fragment
        out[7] = 0
        out[8] = 64            // TTL
        out[9] = PROTO_TCP.toByte()
        System.arraycopy(srcIp, 0, out, 12, 4)
        System.arraycopy(dstIp, 0, out, 16, 4)
        applyIpv4Checksum(out, 20)

        // ── TCP ──
        val t = 20
        out[t] = ((srcPort ushr 8) and 0xFF).toByte()
        out[t + 1] = (srcPort and 0xFF).toByte()
        out[t + 2] = ((dstPort ushr 8) and 0xFF).toByte()
        out[t + 3] = (dstPort and 0xFF).toByte()
        out[t + 4] = ((seq ushr 24) and 0xFF).toByte()
        out[t + 5] = ((seq ushr 16) and 0xFF).toByte()
        out[t + 6] = ((seq ushr 8) and 0xFF).toByte()
        out[t + 7] = (seq and 0xFF).toByte()
        out[t + 8] = ((ack ushr 24) and 0xFF).toByte()
        out[t + 9] = ((ack ushr 16) and 0xFF).toByte()
        out[t + 10] = ((ack ushr 8) and 0xFF).toByte()
        out[t + 11] = (ack and 0xFF).toByte()
        out[t + 12] = 0x50      // data offset 5 (20 bytes), sin opciones
        out[t + 13] = flags.toByte()
        out[t + 14] = ((window ushr 8) and 0xFF).toByte()
        out[t + 15] = (window and 0xFF).toByte()
        // checksum en t+16..17 (se calcula abajo)
        // urgent pointer 0
        if (payload.isNotEmpty()) System.arraycopy(payload, 0, out, 40, payload.size)

        val checksum = tcpChecksum(out.copyOfRange(t, totalLen), srcIp, dstIp)
        out[t + 16] = ((checksum ushr 8) and 0xFF).toByte()
        out[t + 17] = (checksum and 0xFF).toByte()

        return out
    }

    private fun computeIpChecksum(buf: ByteArray, offset: Int, len: Int): Int {
        var sum = 0L
        var i = offset
        while (i < offset + len) {
            if (i != offset + 10) {
                val hi = buf[i].toInt() and 0xFF
                val lo = if (i + 1 < offset + len) buf[i + 1].toInt() and 0xFF else 0
                sum += (hi shl 8) or lo
            }
            i += 2
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }

    private fun computeUdpChecksum(
        srcIp: ByteArray,
        dstIp: ByteArray,
        udpSegment: ByteArray,
        udpOffset: Int,
        udpLen: Int
    ): Int {
        var sum = 0L
        // Pseudo-header
        sum += ((srcIp[0].toInt() and 0xFF) shl 8) or (srcIp[1].toInt() and 0xFF)
        sum += ((srcIp[2].toInt() and 0xFF) shl 8) or (srcIp[3].toInt() and 0xFF)
        sum += ((dstIp[0].toInt() and 0xFF) shl 8) or (dstIp[1].toInt() and 0xFF)
        sum += ((dstIp[2].toInt() and 0xFF) shl 8) or (dstIp[3].toInt() and 0xFF)
        sum += PROTO_UDP.toLong()
        sum += udpLen.toLong()

        var i = 0
        while (i < udpLen) {
            if (i != 6) {
                val hi = udpSegment[udpOffset + i].toInt() and 0xFF
                val lo = if (i + 1 < udpLen) udpSegment[udpOffset + i + 1].toInt() and 0xFF else 0
                sum += (hi shl 8) or lo
            }
            i += 2
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        val result = (sum.inv() and 0xFFFFL).toInt()
        return if (result == 0) 0xFFFF else result
    }

    fun formatIpv4(bytes: ByteArray): String {
        if (bytes.size < 4) return "0.0.0.0"
        return "${bytes[0].toInt() and 0xFF}.${bytes[1].toInt() and 0xFF}.${bytes[2].toInt() and 0xFF}.${bytes[3].toInt() and 0xFF}"
    }

    fun parseIpv4AddressBytes(ip: String): ByteArray? {
        return runCatching {
            val addr = InetAddress.getByName(ip)
            addr.address.takeIf { it.size == 4 }
        }.getOrNull()
    }
}
