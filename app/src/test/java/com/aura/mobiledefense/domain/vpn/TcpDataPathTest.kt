package com.aura.mobiledefense.domain.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket

/**
 * El camino de datos TCP completo del proxy: handshake, datos en ambos sentidos y corte por firewall.
 *
 * Esto es lo que faltaba: con `addRoute("0.0.0.0", 0)` todo el TCP del dispositivo pasa por el TUN y,
 * si el proxy no responde SYN-ACK ni devuelve los bytes del servidor, activar la VPN deja al teléfono
 * sin datos. Estos tests fijan ese contrato byte a byte: checksums válidos, secuencias correctas y
 * RST real cuando el firewall bloquea.
 */
class TcpDataPathTest {

    // ── Socket falso: todo en memoria, sin red ───────────────────────────────────────────────

    private class FakeSocket(private val serverPayload: ByteArray) : Socket() {
        val written = ByteArrayOutputStream()
        override fun getOutputStream(): OutputStream = object : OutputStream() {
            override fun write(b: Int) { written.write(b) }
            override fun write(b: ByteArray, off: Int, len: Int) = written.write(b, off, len)
        }
        override fun getInputStream(): InputStream = java.io.ByteArrayInputStream(serverPayload)
        override fun close() { /* no-op */ }
        override fun shutdownOutput() { /* no-op */ }
    }

    private class Captured {
        var socket: FakeSocket? = null
        val sent = mutableListOf<ByteArray>()
    }

    private fun transportFor(captured: Captured, serverPayload: ByteArray = ByteArray(0)) =
        TcpProxyEngine.Transport { _, _, _ ->
            FakeSocket(serverPayload).also { captured.socket = it }
        }

    private fun downlinkFor(captured: Captured) = TcpProxyEngine.Downlink { packet ->
        synchronized(captured.sent) { captured.sent.add(packet) }
    }

    // ── Paquetes del dispositivo ─────────────────────────────────────────────────────────────

    private fun devicePacket(
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray = ByteArray(0),
        srcPort: Int = 40123,
        dstPort: Int = 443
    ): ByteArray = PacketCodec.buildIpv4TcpPacket(
        srcIp = byteArrayOf(10, 8, 0, 2),
        srcPort = srcPort,
        dstIp = byteArrayOf(203, 0, 113, 9),
        dstPort = dstPort,
        seq = seq,
        ack = ack,
        flags = flags,
        payload = payload
    )

    private fun feed(captured: Captured, packet: ByteArray, transport: TcpProxyEngine.Transport) {
        val parsed = PacketCodec.parseIpv4Packet(packet, packet.size)!!
        TcpProxyEngine.handleFromDevice(
            parsed = parsed,
            packet = packet,
            transport = transport,
            onBlocked = { },
            onSni = { },
            downlink = downlinkFor(captured)
        )
    }

    private fun waitFor(count: Int, captured: Captured, timeoutMs: Long = 2000): List<ByteArray> {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            synchronized(captured.sent) {
                if (captured.sent.size >= count) return captured.sent.toList()
            }
            Thread.sleep(10)
        }
        synchronized(captured.sent) { return captured.sent.toList() }
    }

    /** Suma de complemento a uno de un bloque: debe dar 0xFFFF si el checksum es correcto. */
    private fun checksumOk(vararg parts: ByteArray): Boolean {
        var sum = 0
        for (part in parts) {
            var i = 0
            while (i + 1 < part.size) {
                sum += ((part[i].toInt() and 0xFF) shl 8) or (part[i + 1].toInt() and 0xFF)
                sum = (sum and 0xFFFF) + (sum ushr 16)
                i += 2
            }
            if (i < part.size) {
                sum += (part[i].toInt() and 0xFF) shl 8
                sum = (sum and 0xFFFF) + (sum ushr 16)
            }
        }
        return (sum and 0xFFFF) == 0xFFFF
    }

    private fun ipChecksumOk(packet: ByteArray) = checksumOk(packet.copyOfRange(0, 20))

    private fun tcpChecksumOk(packet: ByteArray): Boolean {
        val parsed = PacketCodec.parseIpv4Packet(packet, packet.size)!!
        val pseudo = byteArrayOf(
            parsed.srcIp[0], parsed.srcIp[1], parsed.srcIp[2], parsed.srcIp[3],
            parsed.dstIp[0], parsed.dstIp[1], parsed.dstIp[2], parsed.dstIp[3],
            0, PacketCodec.PROTO_TCP.toByte(),
            ((packet.size - 20) ushr 8).toByte(), ((packet.size - 20) and 0xFF).toByte()
        )
        return checksumOk(pseudo, packet.copyOfRange(20, packet.size))
    }

    // ── Tests ───────────────────────────────────────────────────────────────────────────────

    @Test
    fun `syn is answered with a valid syn ack for the reverse direction`() {
        TcpProxyEngine.closeAll()
        val captured = Captured()
        feed(captured, devicePacket(seq = 1000, ack = 0, flags = TcpProxyEngine.TCP_FLAG_SYN), transportFor(captured))

        val replies = waitFor(1, captured)
        assertEquals("el proxy debe responder al SYN", 1, replies.size)
        val reply = replies[0]
        val parsed = PacketCodec.parseIpv4Packet(reply, reply.size)!!

        assertEquals("203.0.113.9", parsed.srcIpString)
        assertEquals("10.8.0.2", parsed.dstIpString)
        assertEquals(443, parsed.srcPort)
        assertEquals(40123, parsed.dstPort)
        assertEquals(0x12, reply[33].toInt() and 0xFF)          // SYN+ACK
        assertEquals(1001L, TcpSegmentOf(reply).ack)             // ACK al seq+1 del cliente
        assertTrue("checksum IPv4 inválido", ipChecksumOk(reply))
        assertTrue("checksum TCP inválido: el dispositivo descartaría el SYN-ACK", tcpChecksumOk(reply))
        TcpProxyEngine.closeAll()
    }

    @Test
    fun `server bytes are delivered back to the device with correct sequence`() {
        TcpProxyEngine.closeAll()
        val captured = Captured()
        val transport = transportFor(captured, serverPayload = "HTTP/1.1 200 OK\r\n\r\nhola".toByteArray())

        feed(captured, devicePacket(seq = 5000, ack = 0, flags = TcpProxyEngine.TCP_FLAG_SYN), transport)
        val synAck = waitFor(1, captured).first()
        val serverIsn = TcpSegmentOf(synAck).seq

        // ACK del handshake + una petición real del dispositivo
        feed(captured, devicePacket(seq = 5001, ack = serverIsn + 1, flags = TcpProxyEngine.TCP_FLAG_ACK), transport)
        feed(
            captured,
            devicePacket(
                seq = 5001, ack = serverIsn + 1, flags = TcpProxyEngine.TCP_FLAG_PSH or TcpProxyEngine.TCP_FLAG_ACK,
                payload = "GET / HTTP/1.0\r\n\r\n".toByteArray()
            ),
            transport
        )

        val replies = waitFor(3, captured)
        // Se espera: SYN-ACK, ACK de datos y el bloque de respuesta del servidor.
        val dataReplies = replies.drop(1).mapNotNull { pkt ->
            val parsed = PacketCodec.parseIpv4Packet(pkt, pkt.size) ?: return@mapNotNull null
            if (parsed.payloadLength > 0) pkt else null
        }
        assertEquals("debe llegar exactamente un bloque de datos del servidor", 1, dataReplies.size)
        val dataPacket = dataReplies.first()
        assertTrue("checksum TCP del bloque de datos inválido", tcpChecksumOk(dataPacket))
        val payloadText = String(dataPacket.copyOfRange(40, dataPacket.size))
        assertEquals("HTTP/1.1 200 OK\r\n\r\nhola", payloadText)
        assertEquals("el bloque debe empezar en el ISN+1 del servidor", serverIsn + 1, TcpSegmentOf(dataPacket).seq)

        // Y lo que el dispositivo envió llegó intacto al socket real.
        assertEquals("GET / HTTP/1.0\r\n\r\n", captured.socket!!.written.toString(Charsets.UTF_8))
        TcpProxyEngine.closeAll()
    }

    @Test
    fun `blocked domain is answered with a real rst and no socket is opened`() {
        TcpProxyEngine.closeAll()
        VpnFirewallManager.setEncryptedDnsPolicy(false)
        VpnFirewallManager.replaceRulesForTest(
            listOf(
                com.aura.mobiledefense.data.local.FirewallRuleEntity(
                    id = "test-criteo",
                    pattern = "criteo.com",
                    ruleType = "DOMAIN",
                    action = "BLOCK",
                    reason = "rastreador de prueba",
                    enabled = true,
                    createdAt = 0L
                )
            )
        )

        val captured = Captured()
        val transport = transportFor(captured)
        feed(captured, devicePacket(seq = 9000, ack = 0, flags = TcpProxyEngine.TCP_FLAG_SYN), transport)
        val synAck = waitFor(1, captured).first()
        val serverIsn = TcpSegmentOf(synAck).seq

        // ClientHello con SNI de un dominio bloqueado
        feed(
            captured,
            devicePacket(
                seq = 9001, ack = serverIsn + 1,
                flags = TcpProxyEngine.TCP_FLAG_PSH or TcpProxyEngine.TCP_FLAG_ACK,
                payload = clientHello("api.criteo.com")
            ),
            transport
        )

        // SYN-ACK y RST son las dos únicas respuestas: el ClientHello no se reenvía.
        val replies = waitFor(2, captured)
        val rst = replies.lastOrNull { pkt ->
            pkt.size >= 34 && (pkt[33].toInt() and 0xFF) and TcpProxyEngine.TCP_FLAG_RST != 0
        }
        assertNotNull("el firewall debe cortar con RST", rst)
        assertTrue("checksum TCP del RST inválido", tcpChecksumOk(rst!!))
        assertEquals(
            "el ClientHello de un dominio bloqueado no debe reenviarse al servidor",
            0,
            captured.socket!!.written.size()
        )
        VpnFirewallManager.replaceRulesForTest(emptyList())
        TcpProxyEngine.closeAll()
    }

    @Test
    fun `fin from the device closes the flow cleanly`() {
        TcpProxyEngine.closeAll()
        val captured = Captured()
        val transport = transportFor(captured)
        feed(captured, devicePacket(seq = 100, ack = 0, flags = TcpProxyEngine.TCP_FLAG_SYN), transport)
        val synAck = waitFor(1, captured).first()
        val serverIsn = TcpSegmentOf(synAck).seq
        feed(captured, devicePacket(seq = 101, ack = serverIsn + 1, flags = TcpProxyEngine.TCP_FLAG_ACK), transport)
        feed(captured, devicePacket(seq = 101, ack = serverIsn + 1, flags = TcpProxyEngine.TCP_FLAG_FIN), transport)

        val replies = waitFor(2, captured)
        val finAck = replies.lastOrNull { pkt -> pkt.size >= 34 && (pkt[33].toInt() and 0xFF) and TcpProxyEngine.TCP_FLAG_FIN != 0 }
        assertNotNull("debe cerrarse el flujo con FIN-ACK", finAck)
        assertEquals("el flujo debe desaparecer del mapa", 0, TcpProxyEngine.activeFlowCount())
    }

    // ── Utilidades ──────────────────────────────────────────────────────────────────────────

    private fun TcpSegmentOf(packet: ByteArray): ParsedTcp {
        fun u32(i: Int): Long =
            ((packet[i].toLong() and 0xFF) shl 24) or ((packet[i + 1].toLong() and 0xFF) shl 16) or
                ((packet[i + 2].toLong() and 0xFF) shl 8) or (packet[i + 3].toLong() and 0xFF)
        return ParsedTcp(seq = u32(24), ack = u32(28))
    }

    private data class ParsedTcp(val seq: Long, val ack: Long)

    /** ClientHello mínimo pero **válido**: longitudes de 2 bytes en todos los campos. */
    private fun clientHello(host: String): ByteArray {
        val sni = host.toByteArray(Charsets.US_ASCII)
        fun stream(block: java.io.OutputStream.() -> Unit): ByteArray =
            java.io.ByteArrayOutputStream().also { it.block() }.toByteArray()
        fun java.io.OutputStream.u16(v: Int) { write((v shr 8) and 0xFF); write(v and 0xFF) }
        fun java.io.OutputStream.u24(v: Int) { write((v shr 16) and 0xFF); write((v shr 8) and 0xFF); write(v and 0xFF) }

        val serverName = stream {
            u16(sni.size + 3)              // longitud de la lista de nombres
            write(0x00)                     // name_type = host_name
            u16(sni.size)
            write(sni, 0, sni.size)
        }
        val extension = stream {
            u16(0x0000)                     // extensión server_name
            u16(serverName.size)
            write(serverName, 0, serverName.size)
        }
        val hello = stream {
            u16(0x0303)                     // legacy_version TLS 1.2
            write(ByteArray(32), 0, 32)     // random
            write(0x00)                     // session id vacío
            u16(2); u16(0x1301)             // un cipher suite (TLS_AES_128_GCM_SHA256)
            write(0x01); write(0x00)        // compresión: null
            u16(extension.size)
            write(extension, 0, extension.size)
        }
        val handshake = stream { write(0x01); u24(hello.size); write(hello, 0, hello.size) }
        return stream { write(0x16); u16(0x0301); u16(handshake.size); write(handshake, 0, handshake.size) }
    }
}
