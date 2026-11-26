package com.aura.mobiledefense.domain.vpn

import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Proxy transparente TCP **completo** para el TUN de Aura.
 *
 * Con la ruta `0.0.0.0/0` todo el TCP del dispositivo entra por aquí. Para cada flujo:
 *
 *  1. `SYN` del dispositivo  -> se abre el socket real (protegido con `VpnService.protect`, así no
 *     vuelve a entrar al túnel) y se responde un **SYN-ACK** sintético con un ISN aleatorio.
 *  2. `ACK` del handshake    -> el flujo queda establecido.
 *  3. Datos del dispositivo  -> se escriben al socket y se ACK-ean con el número de secuencia real.
 *  4. Datos del servidor     -> un hilo por flujo los empaqueta en IPv4/TCP y los inyecta en el TUN.
 *  5. `FIN`/`RST`            -> cierre ordenado de ambos lados.
 *  6. Regla de firewall      -> el flujo se contesta con **RST** y se corta de verdad.
 *
 * Esto es lo que convierte a Aura en un firewall real: sin el camino de vuelta (paso 4) la ruta
 * `0.0.0.0/0` deja al dispositivo sin datos. Lo que **no** hace: no descifra TLS; solo inspecciona
 * el SNI del ClientHello, que viaja en claro por diseño del protocolo.
 */
object TcpProxyEngine {

    /** Handshake de un flujo TCP visto desde el dispositivo. */
    data class FlowKey(val srcIp: String, val srcPort: Int, val dstIp: String, val dstPort: Int)

    fun interface Transport {
        /** Abre una conexión saliente protegida (fuera del túnel). Null si falla. */
        fun connect(dstIp: String, dstPort: Int, timeoutMs: Int): java.net.Socket?
    }

    /** Inyecta un paquete IPv4 ya construido en el TUN. */
    fun interface Downlink {
        fun write(packet: ByteArray)
    }

    /**
     * Decide si un dominio descubierto por SNI se permite. Por defecto consulta las reglas reales
     * de [VpnFirewallManager]; los tests JVM lo reemplazan para no arrastrar el framework Android.
     */
    fun interface DomainPolicy {
        fun evaluate(domain: String): RuleEvaluationDecision
    }

    @Volatile
    var domainPolicy: DomainPolicy = DomainPolicy { VpnFirewallManager.evaluateDnsDomain(it) }

    private const val TCP_FIN = 0x01
    private const val TCP_SYN = 0x02
    private const val TCP_RST = 0x04
    private const val TCP_PSH = 0x08
    private const val TCP_ACK = 0x10
    private const val TCP_FIN_ACK = 0x11
    private const val TCP_SYN_ACK = 0x12
    private const val TCP_PSH_ACK = 0x18
    private const val TCP_RST_ACK = 0x14
    const val TCP_FLAG_FIN = TCP_FIN
    const val TCP_FLAG_SYN = TCP_SYN
    const val TCP_FLAG_RST = TCP_RST
    const val TCP_FLAG_PSH = TCP_PSH
    const val TCP_FLAG_ACK = TCP_ACK

    private class FlowState(
        val key: FlowKey,
        val socket: java.net.Socket,
        val srcIpBytes: ByteArray,
        val dstIpBytes: ByteArray
    ) {
        // Secuencias en nombres del dispositivo: seq del cliente -> lo que esperamos del cliente;
        // sndNxt -> nuestro siguiente byte hacia el dispositivo.
        @Volatile var rcvNxt: Long = 0L
        @Volatile var sndNxt: Long = 0L
        @Volatile var synAcked: Boolean = false
        @Volatile var sni: String? = null
        /** Acumula los primeros bytes del flujo hasta poder leer un ClientHello completo. */
        val sniProbe = java.io.ByteArrayOutputStream(4096)
        @Volatile var blockedReason: String? = null
        @Volatile var closed = false
        @Volatile var downlinkThread: Thread? = null
    }

    private val flows = ConcurrentHashMap<FlowKey, FlowState>()
    private val nextIsn = AtomicInteger(0x1000_0000)

    private const val CONNECT_TIMEOUT_MS = 8000
    private const val MAX_FLOWS = 512
    private const val MAX_REPLY_PAYLOAD = 1400
    private const val SNI_PROBE_LIMIT = 6144

    fun activeFlowCount(): Int = flows.size

    /**
     * Procesa un paquete TCP que llega del dispositivo.
     *
     * @param onBlocked se llama cuando el firewall corta la conexión (para la telemetría)
     * @param onSni se llama cuando se descubre el dominio real de la conexión
     * @param downlink escriba al TUN las respuestas (SYN-ACK, datos, FIN, RST)
     * @return true si el paquete se atendió (proxificado o cortado); false si hay que ignorarlo
     */
    fun handleFromDevice(
        parsed: ParsedIpPacket,
        packet: ByteArray,
        transport: Transport,
        onBlocked: (String) -> Unit,
        onSni: (String) -> Unit,
        downlink: Downlink
    ): Boolean {
        val tcp = TcpSegment.parse(packet, parsed) ?: return false
        val key = FlowKey(parsed.srcIpString, parsed.srcPort, parsed.dstIpString, parsed.dstPort)

        // 1. ¿El firewall ya bloqueó este flujo? Se contesta RST y se descarta todo.
        flows[key]?.blockedReason?.let { reason ->
            downlink.write(buildRstPacket(parsed, tcp))
            onBlocked(reason)
            return true
        }

        // 2. SYN sin ACK: abrir el flujo real y responder SYN-ACK.
        if (tcp.syn && !tcp.ack) {
            if (flows.size >= MAX_FLOWS) evictOldest()
            val socket = transport.connect(parsed.dstIpString, parsed.dstPort, CONNECT_TIMEOUT_MS)
            if (socket == null) {
                downlink.write(buildRstPacket(parsed, tcp))
                onBlocked("Conexión rechazada por el proxy: ${parsed.dstIpString}:${parsed.dstPort}")
                return true
            }
            val isn = (nextIsn.getAndAdd(64_000).toLong()) and 0xFFFF_FFFFL
            val state = FlowState(
                key = key,
                socket = socket,
                srcIpBytes = parsed.srcIp.copyOf(),
                dstIpBytes = parsed.dstIp.copyOf()
            )
            state.rcvNxt = (tcp.sequence + 1) and 0xFFFF_FFFFL
            state.sndNxt = (isn + 1) and 0xFFFF_FFFFL
            flows[key] = state

            downlink.write(
                PacketCodec.buildIpv4TcpPacket(
                    srcIp = parsed.dstIp,
                    srcPort = parsed.dstPort,
                    dstIp = parsed.srcIp,
                    dstPort = parsed.srcPort,
                    seq = isn,
                    ack = state.rcvNxt,
                    flags = TCP_SYN_ACK
                )
            )
            return true
        }

        val state = flows[key] ?: run {
            // Paquete de un flujo desconocido (p. ej. tras un reinicio): cortar rápido.
            if (!tcp.rst) downlink.write(buildRstPacket(parsed, tcp))
            return true
        }

        // 3. FIN/RST: cerrar el flujo.
        if (tcp.rst) {
            closeFlow(key)
            return true
        }
        if (tcp.fin) {
            state.rcvNxt = (tcp.sequence + tcp.payloadLength + 1) and 0xFFFF_FFFFL
            runCatching {
                downlink.write(
                    PacketCodec.buildIpv4TcpPacket(
                        srcIp = state.dstIpBytes, srcPort = key.dstPort,
                        dstIp = state.srcIpBytes, dstPort = key.srcPort,
                        seq = state.sndNxt, ack = state.rcvNxt, flags = TCP_FIN_ACK
                    )
                )
            }
            runCatching { state.socket.shutdownOutput() }
            closeFlow(key)
            return true
        }

        // 4. ACK del handshake: arrancar el hilo que devuelve los datos del servidor.
        if (!state.synAcked) {
            state.synAcked = true
            startDownlinkReader(state, downlink)
        }

        // 5. Datos del dispositivo -> socket real.
        if (tcp.payloadLength > 0) {
            processPayload(state, tcp, onBlocked, onSni, downlink)
            state.rcvNxt = (tcp.sequence + tcp.payloadLength) and 0xFFFF_FFFFL
            downlink.write(
                PacketCodec.buildIpv4TcpPacket(
                    srcIp = state.dstIpBytes, srcPort = key.dstPort,
                    dstIp = state.srcIpBytes, dstPort = key.srcPort,
                    seq = state.sndNxt, ack = state.rcvNxt, flags = TCP_ACK
                )
            )
        }
        return true
    }

    /** Bucle de retorno: lee el socket real y empaqueta cada bloque hacia el dispositivo. */
    private fun startDownlinkReader(state: FlowState, downlink: Downlink) {
        val thread = Thread {
            val buffer = ByteArray(MAX_REPLY_PAYLOAD)
            try {
                val input = state.socket.getInputStream()
                while (!state.closed) {
                    val n = input.read(buffer)
                    if (n <= 0) break
                    val payload = buffer.copyOf(n)
                    val key = state.key
                    // El seq del paquete es el de INICIO del bloque; sndNxt avanza después. Si no, el
                    // dispositivo recibiría un hueco de `n` bytes y descartaría los datos.
                    val segSeq = state.sndNxt
                    downlink.write(
                        PacketCodec.buildIpv4TcpPacket(
                            srcIp = state.dstIpBytes, srcPort = key.dstPort,
                            dstIp = state.srcIpBytes, dstPort = key.srcPort,
                            seq = segSeq,
                            ack = state.rcvNxt,
                            flags = TCP_PSH_ACK,
                            payload = payload
                        )
                    )
                    state.sndNxt = (state.sndNxt + n) and 0xFFFF_FFFFL
                }
                // Fin del flujo desde el servidor: FIN-ACK con nuestro siguiente seq.
                val key = state.key
                downlink.write(
                    PacketCodec.buildIpv4TcpPacket(
                        srcIp = state.dstIpBytes, srcPort = key.dstPort,
                        dstIp = state.srcIpBytes, dstPort = key.srcPort,
                        seq = state.sndNxt, ack = state.rcvNxt, flags = TCP_FIN_ACK
                    )
                )
            } catch (_: Exception) {
                // socket cerrado o error de red: se limpia el flujo abajo
            } finally {
                closeFlow(state.key)
            }
        }
        thread.name = "aura-tcp-downlink"
        thread.isDaemon = true
        state.downlinkThread = thread
        thread.start()
    }

    private fun processPayload(
        state: FlowState,
        tcp: TcpSegment,
        onBlocked: (String) -> Unit,
        onSni: (String) -> Unit,
        downlink: Downlink
    ) {
        val payload = tcp.payload
        if (payload.isEmpty()) return

        // SNI: solo en los primeros bytes del flujo (ClientHello). El ClientHello puede venir
        // partido en varios segmentos TCP (TLS 1.3 con extensiones grandes lo hace a menudo), así
        // que se acumulan los primeros bytes y se reintenta: devolver null no es un error, es
        // "todavía no sé a qué dominio se conecta".
        if (state.sni == null && state.sniProbe.size() < SNI_PROBE_LIMIT &&
            (state.sniProbe.size() > 0 || TlsSniExtractor.looksLikeTls(payload))
        ) {
            runCatching { state.sniProbe.write(payload) }
            val host = TlsSniExtractor.extractSni(state.sniProbe.toByteArray())
            if (host != null) {
                state.sni = host
                onSni(host)
                val decision = domainPolicy.evaluate(host)
                if (!decision.allowed) {
                    // Corte real: RST hacia el dispositivo y socket cerrado. Sin el RST la app
                    // seguiría esperando el handshake TLS hasta su propio timeout.
                    state.blockedReason = decision.reason
                    state.closed = true
                    onBlocked(decision.reason)
                    downlink.write(buildRstPacketForState(state, tcp))
                    runCatching { state.socket.close() }
                    return
                }
            }
        }

        runCatching { state.socket.getOutputStream().write(payload) }
            .onFailure { state.closed = true }
    }

    /** Cierra un flujo concreto (por ejemplo cuando el firewall cambia de reglas). */
    fun closeFlow(key: FlowKey) {
        val state = flows.remove(key) ?: return
        state.closed = true
        runCatching { state.socket.close() }
    }

    fun closeAll() {
        flows.values.forEach {
            it.closed = true
            runCatching { it.socket.close() }
        }
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
                // OJO: `parsed.payloadLength` es la longitud *después de la cabecera TCP*, no la del
                // segmento. Un SYN de handshake no lleva datos (payloadLength = 0) y aun así hay que
                // procesarlo: por eso aquí se mide el segmento completo desde el final de la IP.
                val o = parsed.ihlBytes
                val segmentLen = parsed.totalLength - o
                if (segmentLen < 20 || o + 20 > packet.size) return null
                val headerLen = ((packet[o + 12].toInt() and 0xF0) ushr 4) * 4
                if (headerLen < 20 || headerLen > segmentLen) return null
                val payloadOffset = o + headerLen
                val payloadLen = segmentLen - headerLen
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

    private fun buildRstPacketForState(state: FlowState, tcp: TcpSegment): ByteArray =
        PacketCodec.buildIpv4TcpPacket(
            srcIp = state.dstIpBytes,
            srcPort = state.key.dstPort,
            dstIp = state.srcIpBytes,
            dstPort = state.key.srcPort,
            seq = state.sndNxt,
            ack = (tcp.sequence + tcp.payloadLength) and 0xFFFF_FFFFL,
            flags = TCP_RST_ACK
        )

    /**
     * RST completo (IPv4+TCP con checksums válidos) a partir del paquete que envió el dispositivo.
     * Es lo que corta de verdad una conexión bloqueada por dominio/puerto/IP.
     */
    fun buildRstPacket(parsed: ParsedIpPacket, tcp: TcpSegment): ByteArray =
        PacketCodec.buildIpv4TcpPacket(
            srcIp = parsed.dstIp,
            srcPort = parsed.dstPort,
            dstIp = parsed.srcIp,
            dstPort = parsed.srcPort,
            seq = tcp.acknowledgment,
            ack = (tcp.sequence + tcp.payloadLength + 1) and 0xFFFF_FFFFL,
            flags = TCP_RST_ACK
        )

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
