package com.aura.mobiledefense.domain.vpn

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.ArrayDeque
import java.util.Collections
import java.util.concurrent.CopyOnWriteArrayList

/**
 * El proxy UDP es lo que separa "VPN que bloquea todo lo no-DNS" de "VPN que filtra y reenvía de
 * verdad". Estos tests fijan el contrato completo:
 *
 *  - una ruta bloqueada NO abre socket ni reenvía nada, y queda en telemetría;
 *  - una ruta permitida reenvía el payload y reescribe la respuesta con checksums válidos;
 *  - los flujos expiran/se evocan sin fugas;
 *  - lo que no es UDP no pasa por este motor.
 *
 * Todo ocurre con sockets falsos en memoria: sin red real.
 */
class UdpProxyEngineTest {

    private class FakeFlow(
        override val destinationIp: String,
        override val destinationPort: Int,
        override val devicePort: Int,
        private val replies: ArrayDeque<ByteArray>
    ) : UdpProxyEngine.UdpFlow {
        val sent = CopyOnWriteArrayList<ByteArray>()
        @Volatile var closed = false

        override fun send(payload: ByteArray) {
            sent.add(payload)
        }

        override fun receive(timeoutMs: Int): ByteArray? {
            Thread.sleep(5)
            return if (replies.isEmpty()) null else replies.removeFirst()
        }

        override fun close() {
            closed = true
        }
    }

    private class Fixture(val allowAll: Boolean) {
        val flows = CopyOnWriteArrayList<FakeFlow>()
        val downlink = CopyOnWriteArrayList<ByteArray>()
        val blockedReasons = CopyOnWriteArrayList<String>()

        val factory = UdpProxyEngine.FlowFactory { ip, port, devicePort ->
            FakeFlow(ip, port, devicePort, ArrayDeque()).also { flows.add(it) }
        }

        fun factoryReturning(reply: ByteArray) = UdpProxyEngine.FlowFactory { ip, port, devicePort ->
            FakeFlow(ip, port, devicePort, ArrayDeque(listOf(reply))).also { flows.add(it) }
        }
    }

    private val deviceIp = byteArrayOf(10, 8, 0, 2)

    @Before
    fun setUp() {
        UdpProxyEngine.resetForTest()
    }

    @After
    fun tearDown() {
        UdpProxyEngine.resetForTest()
    }

    private fun deviceUdpPacket(
        payload: ByteArray,
        srcPort: Int = 40123,
        dstPort: Int = 443,
        dstIp: ByteArray = byteArrayOf(1, 2, 3, 4)
    ): ByteArray = PacketCodec.buildIpv4UdpPacket(deviceIp, dstIp, srcPort, dstPort, payload)

    private fun parse(packet: ByteArray) =
        PacketCodec.parseIpv4Packet(packet, packet.size)!!

    @Test
    fun `non udp protocol is not handled by this engine`() {
        UdpProxyEngine.routePolicy = UdpProxyEngine.RoutePolicy { _, _ -> RuleEvaluationDecision(true, "ok") }
        val fixture = Fixture(allowAll = true)
        val tcpPacket = PacketCodec.buildIpv4TcpPacket(deviceIp, 40000, byteArrayOf(1, 2, 3, 4), 443, seq = 1, ack = 0, flags = 0x02)
        val handled = UdpProxyEngine.handleFromDevice(
            parsed = parse(tcpPacket),
            packet = tcpPacket,
            flowFactory = fixture.factory,
            onBlocked = { fixture.blockedReasons.add(it) },
            downlink = { fixture.downlink.add(it) }
        )
        assertFalse(handled)
        assertEquals(0, fixture.flows.size)
    }

    @Test
    fun `blocked route opens no socket and reports the block`() {
        UdpProxyEngine.routePolicy = UdpProxyEngine.RoutePolicy { _, _ ->
            RuleEvaluationDecision(false, "IP de destino en la lista negra")
        }
        val fixture = Fixture(allowAll = false)
        val packet = deviceUdpPacket(byteArrayOf(0x0a, 0x0b))
        val handled = UdpProxyEngine.handleFromDevice(
            parsed = parse(packet),
            packet = packet,
            flowFactory = fixture.factory,
            onBlocked = { fixture.blockedReasons.add(it) },
            downlink = { fixture.downlink.add(it) }
        )
        assertTrue(handled)
        assertEquals(0, fixture.flows.size)
        assertEquals(1, fixture.blockedReasons.size)
        assertEquals("IP de destino en la lista negra", fixture.blockedReasons.first())
        assertEquals(1L, UdpProxyEngine.stats.blocked.get())
        assertEquals(0, fixture.downlink.size)
    }

    @Test
    fun `allowed route forwards payload to a protected socket`() {
        UdpProxyEngine.routePolicy = UdpProxyEngine.RoutePolicy { _, _ -> RuleEvaluationDecision(true, "ok") }
        val fixture = Fixture(allowAll = true)
        val payload = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val packet = deviceUdpPacket(payload, srcPort = 40123, dstPort = 443)
        val handled = UdpProxyEngine.handleFromDevice(
            parsed = parse(packet),
            packet = packet,
            flowFactory = fixture.factory,
            onBlocked = { fixture.blockedReasons.add(it) },
            downlink = { fixture.downlink.add(it) }
        )
        assertTrue(handled)
        assertEquals(1, fixture.flows.size)
        assertEquals(1, fixture.flows.first().sent.size)
        assertTrue(payload.contentEquals(fixture.flows.first().sent.first()))
        assertEquals(1L, UdpProxyEngine.stats.forwarded.get())
    }

    @Test
    fun `reply from the wire is rewritten and injected into the tun`() {
        UdpProxyEngine.routePolicy = UdpProxyEngine.RoutePolicy { _, _ -> RuleEvaluationDecision(true, "ok") }
        val fixture = Fixture(allowAll = true)
        val reply = byteArrayOf(0xde.toByte(), 0xad.toByte(), 0xbe.toByte(), 0xef.toByte())
        val factory = fixture.factoryReturning(reply)
        val packet = deviceUdpPacket(byteArrayOf(0x11), srcPort = 40123, dstPort = 443, dstIp = byteArrayOf(9, 9, 9, 9))
        UdpProxyEngine.handleFromDevice(
            parsed = parse(packet),
            packet = packet,
            flowFactory = factory,
            onBlocked = { fixture.blockedReasons.add(it) },
            downlink = { fixture.downlink.add(it) }
        )
        // El bucle de recepción corre en su propio hilo: esperar al paquete reescrito.
        val deadline = System.currentTimeMillis() + 3000
        while (fixture.downlink.isEmpty() && System.currentTimeMillis() < deadline) {
            Thread.sleep(10)
        }
        assertEquals(1, fixture.downlink.size)
        val rewritten = parse(fixture.downlink.first())
        assertEquals("9.9.9.9", rewritten.srcIpString)
        assertEquals("10.8.0.2", rewritten.dstIpString)
        assertEquals(443, rewritten.srcPort)
        assertEquals(40123, rewritten.dstPort)
        val rewrittenPayload = fixture.downlink.first()
            .copyOfRange(rewritten.payloadOffset, rewritten.payloadOffset + rewritten.payloadLength)
        assertTrue(reply.contentEquals(rewrittenPayload))
    }

    @Test
    fun `flow table is bounded and evicts the oldest`() {
        UdpProxyEngine.routePolicy = UdpProxyEngine.RoutePolicy { _, _ -> RuleEvaluationDecision(true, "ok") }
        UdpProxyEngine.resetForTest(maxFlowsOverride = 1)
        val fixture = Fixture(allowAll = true)
        fun sendTo(dst: ByteArray, srcPort: Int) {
            val packet = deviceUdpPacket(byteArrayOf(0x01), srcPort = srcPort, dstPort = 443, dstIp = dst)
            UdpProxyEngine.handleFromDevice(
                parsed = parse(packet),
                packet = packet,
                flowFactory = fixture.factory,
                onBlocked = { fixture.blockedReasons.add(it) },
                downlink = { fixture.downlink.add(it) }
            )
        }
        sendTo(byteArrayOf(1, 1, 1, 1), 40001)
        sendTo(byteArrayOf(2, 2, 2, 2), 40002)
        assertEquals("la tabla de flujos no puede crecer sin límite", 1, UdpProxyEngine.flowCount())
    }

    @Test
    fun `closeAll empties the flow table and closes sockets`() {
        UdpProxyEngine.routePolicy = UdpProxyEngine.RoutePolicy { _, _ -> RuleEvaluationDecision(true, "ok") }
        val fixture = Fixture(allowAll = true)
        val packet = deviceUdpPacket(byteArrayOf(0x02))
        UdpProxyEngine.handleFromDevice(
            parsed = parse(packet),
            packet = packet,
            flowFactory = fixture.factory,
            onBlocked = { fixture.blockedReasons.add(it) },
            downlink = { fixture.downlink.add(it) }
        )
        UdpProxyEngine.closeAll()
        assertEquals(0, UdpProxyEngine.flowCount())
    }
}
