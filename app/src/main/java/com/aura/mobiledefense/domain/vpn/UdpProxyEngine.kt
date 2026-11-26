package com.aura.mobiledefense.domain.vpn

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Proxy UDP real para todo el tráfico que no es DNS.
 *
 * El TUN de Android solo transporta IPv4; el DNS que apunta al gateway virtual lo atiende el
 * servicio. Todo lo demás (QUIC en 443/udp, VoIP, WebRTC, WireGuard, juegos…) quedaba
 * **descartado en silencio** con la VPN puesta: no era un firewall, era un agujero negro.
 *
 * Qué hace de verdad este motor:
 *  1. Decide la ruta con la misma política que el resto del TUN (IP/puerto vía [VpnFirewallManager]).
 *  2. Reenvía por un socket real **protegido** (`VpnService.protect`) para que el tráfico no
 *     vuelva a entrar al túnel en bucle.
 *  3. Reescribe las respuestas (IP/puertos intercambiados, checksums válidos) y las inyecta al TUN.
 *  4. Expira flujos inactivos (30 s) y no acumula sockets ni memoria ([DEFAULT_MAX_FLOWS]).
 *
 * DNS va por su propio camino; aquí nunca entra. ICMP devuelve false para que el servicio lo
 * descarte explícitamente. QUIC no se filtra por dominio aquí: sin descifrado solo aplican las
 * reglas por IP/puerto (los dominios bloqueados ya están aprendidos en [DomainSinkhole] vía DNS).
 */
object UdpProxyEngine {

    /** Un flujo hacia un destino concreto. Lo implementan el servicio VPN (socket real) y los tests. */
    interface UdpFlow {
        val destinationIp: String
        val destinationPort: Int
        val devicePort: Int
        fun send(payload: ByteArray)
        /** Espera hasta [timeoutMs] por un datagrama; null si no llegó nada o el socket murió. */
        fun receive(timeoutMs: Int): ByteArray?
        fun close()
    }

    /** Fábrica de flujos: el servicio crea sockets reales protegidos; los tests, falsos en memoria. */
    fun interface FlowFactory {
        /** null cuando el socket no se puede crear o proteger. */
        fun create(destinationIp: String, destinationPort: Int, devicePort: Int): UdpFlow?
    }

    /** Política de ruta. La sustituyen los tests JVM para no arrastrar Android. */
    fun interface RoutePolicy {
        fun evaluate(ip: String, port: Int): RuleEvaluationDecision
    }

    @Volatile
    var routePolicy: RoutePolicy = RoutePolicy { ip, port -> VpnFirewallManager.evaluatePacketRoute(ip, port) }

    const val DEFAULT_MAX_FLOWS = 256
    const val FLOW_IDLE_TIMEOUT_MS = 30_000L
    private const val RECEIVE_PULSE_MS = 250
    private const val MAX_PAYLOAD_BYTES = 65_507

    /** Techo de flujos concurrentes; ajustable solo para tests. */
    internal var maxFlows: Int = DEFAULT_MAX_FLOWS

    data class Stats(
        val forwarded: AtomicLong = AtomicLong(),
        val blocked: AtomicLong = AtomicLong(),
        val drops: AtomicLong = AtomicLong(),
        val expired: AtomicLong = AtomicLong()
    )

    val stats = Stats()

    private data class FlowKey(val destinationIp: String, val destinationPort: Int, val devicePort: Int)

    private class ManagedFlow(
        val flow: UdpFlow,
        val key: FlowKey,
        private val srcIpBytes: ByteArray,
        private val downlink: (ByteArray) -> Unit,
        private val onExpired: (ManagedFlow) -> Unit
    ) {
        @Volatile private var running = true
        @Volatile var lastActivity: Long = System.currentTimeMillis()

        fun start() {
            Thread({ loop() }, "udp-proxy-${flow.destinationIp}:${flow.destinationPort}").apply {
                isDaemon = true
                start()
            }
        }

        internal fun close() {
            running = false
        }

        private fun loop() {
            try {
                while (running) {
                    if (System.currentTimeMillis() - lastActivity > FLOW_IDLE_TIMEOUT_MS) {
                        onExpired(this)
                        return
                    }
                    val data = flow.receive(RECEIVE_PULSE_MS) ?: continue
                    lastActivity = System.currentTimeMillis()
                    if (data.size > MAX_PAYLOAD_BYTES) continue
                    val srcBytes = PacketCodec.parseIpv4AddressBytes(flow.destinationIp) ?: continue
                    // Destino del paquete reescrito = IP del dispositivo (10.8.0.2 en el túnel).
                    downlink(PacketCodec.buildIpv4UdpPacket(srcBytes, srcIpBytes, flow.destinationPort, key.devicePort, data))
                }
            } finally {
                runCatching { flow.close() }
            }
        }
    }

    private val flows = ConcurrentHashMap<FlowKey, ManagedFlow>()

    /** Pareja dispositivo→destino, o null si no se pudo crear/proteger el socket. */
    fun openFlow(
        destinationIp: String,
        destinationPort: Int,
        devicePort: Int,
        deviceIp: ByteArray,
        flowFactory: FlowFactory,
        downlink: (ByteArray) -> Unit
    ): Boolean {
        if (flows.size >= maxFlows) evictOldest()
        val key = FlowKey(destinationIp, destinationPort, devicePort)
        val created = runCatching { flowFactory.create(destinationIp, destinationPort, devicePort) }.getOrNull()
        if (created == null) return false
        val managed = ManagedFlow(created, key, deviceIp.copyOf(), downlink) { self ->
            flows.remove(key, self)
            stats.expired.incrementAndGet()
        }
        val existing = flows.putIfAbsent(key, managed)
        if (existing != null) {
            managed.close()
            runCatching { created.close() }
            return true
        }
        managed.start()
        return true
    }

    /** true si el paquete era UDP y quedó atendido (reenviado o bloqueado). */
    fun handleFromDevice(
        parsed: ParsedIpPacket,
        packet: ByteArray,
        flowFactory: FlowFactory,
        onBlocked: (reason: String) -> Unit,
        downlink: (ByteArray) -> Unit
    ): Boolean {
        if (parsed.protocol != PacketCodec.PROTO_UDP) return false
        if (parsed.payloadLength <= 0) return false

        val decision = routePolicy.evaluate(parsed.dstIpString, parsed.dstPort)
        if (!decision.allowed) {
            stats.blocked.incrementAndGet()
            onBlocked(decision.reason)
            return true
        }

        val key = FlowKey(parsed.dstIpString, parsed.dstPort, parsed.srcPort)
        var managed = flows[key]
        if (managed == null) {
            val opened = openFlow(parsed.dstIpString, parsed.dstPort, parsed.srcPort, parsed.srcIp, flowFactory, downlink)
            if (!opened) {
                stats.drops.incrementAndGet()
                onBlocked("No se pudo abrir/proteger el socket UDP hacia ${parsed.dstIpString}:${parsed.dstPort}")
                return true
            }
            managed = flows[key] ?: return true
        }

        managed.lastActivity = System.currentTimeMillis()
        val payload = packet.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength)
        runCatching { managed.flow.send(payload) }
            .onSuccess { stats.forwarded.incrementAndGet() }
            .onFailure {
                stats.drops.incrementAndGet()
                onBlocked("Fallo de envío UDP: ${it.message ?: it.javaClass.simpleName}")
            }
        return true
    }

    internal fun evictOldest() {
        val oldest = flows.values.minByOrNull { it.lastActivity } ?: return
        flows.remove(oldest.key, oldest)
        runCatching { oldest.close() }
    }

    /** Cierra todos los flujos (parada del servicio VPN). */
    fun closeAll() {
        flows.values.forEach { runCatching { it.close() } }
        flows.clear()
    }

    /** Solo para tests: flujos abiertos ahora mismo. */
    internal fun flowCount(): Int = flows.size

    /** Solo para tests: reemplaza el techo y limpia estado. */
    internal fun resetForTest(maxFlowsOverride: Int? = null) {
        closeAll()
        stats.forwarded.set(0); stats.blocked.set(0); stats.drops.set(0); stats.expired.set(0)
        maxFlows = maxFlowsOverride ?: DEFAULT_MAX_FLOWS
    }
}
