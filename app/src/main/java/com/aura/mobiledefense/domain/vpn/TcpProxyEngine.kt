package com.aura.mobiledefense.domain.vpn

import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentHashMap

/**
 * Proxy transparente de sockets.
 *
 * Con una ruta `0.0.0.0/0` dentro del TUN, todo el tráfico del dispositivo llega aquí. Para TCP se
 * crea una conexión real desde el servicio (protegida con `VpnService.protect`, así no vuelve a
 * entrar al túnel), se reescribe la cabecera del paquete y se reenvía. Para UDP se hace lo mismo con
 * un `DatagramSocket`.
 *
 * Esto es lo que convierte el firewall de Aura en un firewall **real**: antes solo se enrutaban al
 * TUN las IPs ya bloqueadas (un sinkhole), así que bloquear un dominio o un puerto no tenía efecto
 * sobre el tráfico normal. Ahora cada conexión pasa por [VpnFirewallManager.evaluatePacketRoute] y
 * las que se rechazan se descartan y se cortan con RST/ICMP.
 *
 * Lo que **no** hace, y hay que decirlo: no descifra TLS. Inspecciona el SNI del ClientHello (texto
 * plano por diseño del protocolo) y puede rechazar por dominio; el contenido cifrado no se toca.
 */
object TcpProxyEngine {

    /** Handshake de un flujo TCP visto desde el dispositivo. */
    data class FlowKey(val srcIp: String, val srcPort: Int, val dstIp: String, val dstPort: Int)

    interface Transport {
        /** Abre una conexión saliente protegida (fuera del túnel). Null si falla. */
        fun connect(dstIp: String, dstPort: Int, timeoutMs: Int): java.net.Socket?
    }

    private class FlowState(val socket: java.net.Socket) {
        @Volatile var sni: String? = null
        @Volatile var blockedReason: String? = null
        @Volatile var lastSeqFromClient: Long = -1L
        @Volatile var closed = false
    }

    private val flows = ConcurrentHashMap<FlowKey, FlowState>()

    private const val CONNECT_TIMEOUT_MS = 8000
    private const val SNI_PEEK_BYTES = 2048
    private const val MAX_FLOWS = 512

    fun activeFlowCount(): Int = flows.size

    /**
     * Procesa un paquete TCP que llega del dispositivo.
     *
     * @param parsed paquete ya decodificado por [PacketCodec]
     * @param packet bytes completos del paquete IPv4
     * @param onBlocked se llama cuando el firewall corta la conexión (para la telemetría)
     * @param onSni se llama cuando se descubre el dominio real de la conexión
     * @return true si el paquete se atendió (proxificado o cortado); false si hay que ignorarlo
     */
    fun handleFromDevice(
        parsed: ParsedIpPacket,
        packet: ByteArray,
        transport: Transport,
        onBlocked: (String) -> Unit,
        onSni: (String) -> Unit
    ): Boolean {
        val tcp = TcpSegment.parse(packet, parsed) ?: return false
        val key = FlowKey(parsed.srcIpString, parsed.srcPort, parsed.dstIpString, parsed.dstPort)

        // 1. ¿El firewall ya bloqueó este flujo por dominio?
        val existing = flows[key]
        existing?.blockedReason?.let { reason ->
            onBlocked(reason)
            return true
        }

        // 2. SYN: abrir el flujo
        if (tcp.syn && !tcp.ack) {
            if (flows.size >= MAX_FLOWS) evictOldest()
            val socket = transport.connect(parsed.dstIpString, parsed.dstPort, CONNECT_TIMEOUT_MS)
                ?: return false
            val state = FlowState(socket)
            flows[key] = state
            // Si el payload del SYN trae datos (TCP Fast Open), se trata como primer segmento.
            if (tcp.payloadLength > 0) processPayload(key, state, tcp, onBlocked, onSni)
            return true
        }

        // 3. FIN/RST: cerrar
        if (tcp.fin || tcp.rst) {
            flows.remove(key)?.let { runCatching { it.socket.close() } }
            return true
        }

        val state = existing ?: return false

        // 4. Datos: reenviar a la conexión real
        if (tcp.payloadLength > 0) {
            processPayload(key, state, tcp, onBlocked, onSni)
        }
        state.lastSeqFromClient = tcp.sequence + tcp.payloadLength
        return true
    }

    private fun processPayload(
        key: FlowKey,
        state: FlowState,
        tcp: TcpSegment,
        onBlocked: (String) -> Unit,
        onSni: (String) -> Unit
    ) {
        val payload = tcp.payload
        if (payload.isEmpty()) return

        // SNI: solo en los primeros bytes del flujo (ClientHello)
        if (state.sni == null && TlsSniExtractor.looksLikeTls(payload)) {
            val host = TlsSniExtractor.extractSni(payload)
            if (host != null) {
                state.sni = host
                onSni(host)
                val decision = VpnFirewallManager.evaluateDnsDomain(host)
                if (!decision.allowed) {
                    state.blockedReason = decision.reason
                    onBlocked(decision.reason)
                    flows.remove(key)?.let { runCatching { it.socket.close() } }
                    return
                }
            }
        }

        runCatching { state.socket.getOutputStream().write(payload) }
            .onFailure { state.closed = true }
    }

    /** Cierra un flujo concreto (por ejemplo cuando el firewall cambia de reglas). */
    fun closeFlow(key: FlowKey) {
        flows.remove(key)?.let { runCatching { it.socket.close() } }
    }

    fun closeAll() {
        flows.values.forEach { runCatching { it.socket.close() } }
        flows.clear()
    }

    private fun evictOldest() {
        flows.keys.firstOrNull()?.let { closeFlow(it) }
    }

    /** Cabecera TCP + payload mínimos para construir respuestas (RST, SYN-ACK…). */
    class TcpSegment(
        val sourcePort: Int,
        val destPort: Int,
        val sequence: Long,
        val acknowledgment: Long,
        val flags: Int,
        val payload: ByteArray,
        val payloadLength: Int
    ) {
        val fin: Boolean get() = flags and 0x01 != 0
        val syn: Boolean get() = flags and 0x02 != 0
        val rst: Boolean get() = flags and 0x04 != 0
        val psh: Boolean get() = flags and 0x08 != 0
        val ack: Boolean get() = flags and 0x10 != 0

        companion object {
            fun parse(packet: ByteArray, parsed: ParsedIpPacket): TcpSegment? {
                if (parsed.protocol != PacketCodec.PROTO_TCP) return null
                val o = parsed.payloadOffset
                if (parsed.payloadLength < 20) return null
                val headerLen = ((packet[o + 12].toInt() and 0xF0) ushr 4) * 4
                if (headerLen < 20 || headerLen > parsed.payloadLength) return null
                val payloadOffset = o + headerLen
                val payloadLen = parsed.payloadLength - headerLen
                val payload = if (payloadLen > 0) {
                    packet.copyOfRange(payloadOffset, payloadOffset + payloadLen)
                } else {
                    ByteArray(0)
                }
                return TcpSegment(
                    sourcePort = u16(packet, o),
                    destPort = u16(packet, o + 2),
                    sequence = u32(packet, o + 4),
                    acknowledgment = u32(packet, o + 8),
                    flags = packet[o + 13].toInt() and 0xFF,
                    payload = payload,
                    payloadLength = payloadLen
                )
            }
        }
    }

    /**
     * Paquete TCP RST para cortar la conexión desde el punto de vista del dispositivo.
     * Construye IPv4 + TCP con checksums correctos (sin esto Android descarta el paquete).
     */
    fun buildRst(parsed: ParsedIpPacket, tcp: TcpSegment): ByteArray {
        val tcpHeader = ByteArray(20)
        putU16(tcpHeader, 0, tcp.destPort)          // respuesta: puertos invertidos
        putU16(tcpHeader, 2, tcp.sourcePort)
        putU32(tcpHeader, 4, 0)                      // seq 0
        putU32(tcpHeader, 8, tcp.sequence + tcp.payloadLength)
        tcpHeader[12] = ((20 ushr 2) shl 4).toByte() // data offset 5
        tcpHeader[13] = 0x14.toByte()                // RST + ACK
        putU16(tcpHeader, 14, 0)                     // window 0
        putU16(tcpHeader, 16, 0)                     // checksum (se calcula abajo)
        putU16(tcpHeader, 18, 0)                     // urgent pointer

        val pseudo = ByteArray(12)
        System.arraycopy(parsed.dstIp, 0, pseudo, 0, 4)   // origen de la respuesta
        System.arraycopy(parsed.srcIp, 0, pseudo, 4, 4)   // destino
        pseudo[9] = PacketCodec.PROTO_TCP.toByte()
        putU16(pseudo, 10, tcpHeader.size)
        val checksum = onesComplement(pseudo + tcpHeader)
        putU16(tcpHeader, 16, checksum)

        return buildIpv4(parsed.dstIp, parsed.srcIp, PacketCodec.PROTO_TCP, tcpHeader)
    }

    /** ICMP destino inalcanzable (puerto), para cortar rápido conexiones UDP bloqueadas. */
    fun buildIcmpPortUnreachable(parsed: ParsedIpPacket, originalIp: ByteArray): ByteArray {
        val icmp = ByteArray(8 + 8 + minOf(parsed.payloadLength, 8))
        icmp[0] = 3      // destination unreachable
        icmp[1] = 3      // port unreachable
        // checksum en 2..3
        // resto del header en ceros (unused)
        val ipHeader = originalIp.copyOfRange(0, minOf(originalIp.size, 20))
        System.arraycopy(ipHeader, 0, icmp, 8, ipHeader.size)
        val copyLen = minOf(parsed.payloadLength, 8)
        if (copyLen > 0) {
            System.arraycopy(originalIp, 20, icmp, 16, copyLen)
        }
        putU16(icmp, 2, onesComplement(icmp))
        return buildIpv4(parsed.dstIp, parsed.srcIp, 1, icmp)
    }

    private fun buildIpv4(src: ByteArray, dst: ByteArray, protocol: Int, payload: ByteArray): ByteArray {
        val header = ByteArray(20)
        header[0] = 0x45
        putU16(header, 2, 20 + payload.size)
        putU16(header, 4, 0)          // id
        putU16(header, 6, 0x4000)     // don't fragment
        header[8] = 64                // ttl
        header[9] = protocol.toByte()
        System.arraycopy(src, 0, header, 12, 4)
        System.arraycopy(dst, 0, header, 16, 4)
        putU16(header, 10, onesComplement(header.copyOfRange(0, 20)))
        val out = ByteArrayOutputStream(header.size + payload.size)
        out.write(header)
        out.write(payload)
        return out.toByteArray()
    }

    private fun onesComplement(data: ByteArray): Int {
        var sum = 0
        var i = 0
        while (i + 1 < data.size) {
            sum += (data[i].toInt() and 0xFF shl 8) or (data[i + 1].toInt() and 0xFF)
            sum = (sum and 0xFFFF) + (sum ushr 16)
            i += 2
        }
        if (i < data.size) {
            sum += (data[i].toInt() and 0xFF) shl 8
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }

    private fun u16(b: ByteArray, i: Int): Int = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
    private fun u32(b: ByteArray, i: Int): Long =
        ((b[i].toLong() and 0xFF) shl 24) or ((b[i + 1].toLong() and 0xFF) shl 16) or
            ((b[i + 2].toLong() and 0xFF) shl 8) or (b[i + 3].toLong() and 0xFF)

    private fun putU16(b: ByteArray, i: Int, v: Int) {
        b[i] = ((v ushr 8) and 0xFF).toByte()
        b[i + 1] = (v and 0xFF).toByte()
    }

    private fun putU32(b: ByteArray, i: Int, v: Long) {
        b[i] = ((v ushr 24) and 0xFF).toByte()
        b[i + 1] = ((v ushr 16) and 0xFF).toByte()
        b[i + 2] = ((v ushr 8) and 0xFF).toByte()
        b[i + 3] = (v and 0xFF).toByte()
    }
}
