package com.aura.mobiledefense.domain.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Paquetes malformados.
 *
 * `PacketCodec` parsea bytes que vienen de la red: cualquier app, cualquier servidor y cualquier
 * atacante en la misma wifi puede mandar basura. Un parser que lanza una excepción o que lee fuera
 * del buffer tumba el servicio VPN; uno que devuelve datos inventados puede hacer que el firewall
 * bloquee al vecino equivocado. Aquí se fija que devuelva `null` y nunca reviente.
 */
class PacketCodecMalformedTest {

    private fun ipv4Packet(): ByteArray {
        val packet = ByteArray(20 + 8 + 4)
        packet[0] = 0x45                       // v4, IHL 5
        packet[2] = ((packet.size shr 8) and 0xFF).toByte()
        packet[3] = (packet.size and 0xFF).toByte()
        packet[8] = 64                         // ttl
        packet[9] = PacketCodec.PROTO_UDP.toByte()
        packet[12] = 10; packet[15] = 2        // 10.0.0.2
        packet[16] = 203.toByte(); packet[18] = 113; packet[19] = 9
        return packet
    }

    @Test
    fun `empty and short buffers are rejected without throwing`() {
        assertNull(PacketCodec.parseIpv4Packet(ByteArray(0), 0))
        assertNull(PacketCodec.parseIpv4Packet(ByteArray(19), 19))
        assertNull(PacketCodec.parseIpv4Packet(ByteArray(20), 10))   // length miente
        assertNull(PacketCodec.parseIpv4Packet(ByteArray(64), 0))
    }

    @Test
    fun `ipv6 and bogus versions are rejected`() {
        val v6 = ByteArray(40).also { it[0] = 0x60.toByte() }
        assertNull(PacketCodec.parseIpv4Packet(v6, v6.size))
        val bogus = ByteArray(40).also { it[0] = 0x00 }
        assertNull(PacketCodec.parseIpv4Packet(bogus, bogus.size))
    }

    @Test
    fun `ihl larger than the buffer is rejected`() {
        val packet = ipv4Packet()
        packet[0] = 0x4F.toByte()              // IHL = 15 -> 60 bytes de cabecera en un paquete de 32
        assertNull(PacketCodec.parseIpv4Packet(packet, packet.size))
    }

    @Test
    fun `total length larger than the buffer is rejected`() {
        val packet = ipv4Packet()
        packet[2] = 0x7F; packet[3] = 0xFF.toByte()   // dice 32767 bytes
        assertNull(PacketCodec.parseIpv4Packet(packet, packet.size))
    }

    @Test
    fun `fragmented packet does not expose a fake port`() {
        val packet = ipv4Packet()
        packet[6] = 0x20                       // MF flag: fragmento, no primer segmento
        val parsed = PacketCodec.parseIpv4Packet(packet, packet.size)
        // Si el parser lo acepta, no debe inventarse puertos: el firewall decide por IP.
        if (parsed != null) {
            assertEquals(0, parsed.srcPort)
            assertEquals(0, parsed.dstPort)
        }
    }

    @Test
    fun `dns query parser survives truncated and hostile names`() {
        assertNull(PacketCodec.extractDnsQueryDomain(ByteArray(0), 0, 0))
        assertNull(PacketCodec.extractDnsQueryDomain(ByteArray(12), 0, 12))     // sin pregunta
        // Etiqueta que se declara más larga que el buffer
        val hostile = ByteArray(32)
        hostile[12] = 0x3F
        assertNull(PacketCodec.extractDnsQueryDomain(hostile, 12, 20))
        // Puntero de compresión en la pregunta: no debe seguirse ni colgarse
        val pointer = ByteArray(32)
        pointer[12] = 0xC0.toByte(); pointer[13] = 0x0C
        assertNull(PacketCodec.extractDnsQueryDomain(pointer, 12, 20))
    }

    @Test
    fun `dns answer parser ignores answers that run past the buffer`() {
        val response = ByteArray(40)
        response[4] = 0x00; response[5] = 0x01   // qdcount 1
        response[6] = 0x00; response[7] = 0x05   // ancount 5 (mentira)
        response[12] = 0x00                      // nombre raíz
        // La pregunta sigue en 13..17 y luego basura: no debe lanzar.
        val ips = PacketCodec.extractDnsAnswerIps(response)
        assertTrue("no debe inventar IPs", ips.isEmpty())
    }

    @Test
    fun `nxdomain response keeps the query id and flags`() {
        val query = ByteArray(29)
        query[0] = 0xAB.toByte(); query[1] = 0xCD.toByte()   // id
        query[2] = 0x01                                       // RD
        query[5] = 0x01                                       // qdcount 1
        val reply = PacketCodec.buildDnsNxDomainResponse(query)
        assertEquals(0xAB, reply[0].toInt() and 0xFF)
        assertEquals(0xCD, reply[1].toInt() and 0xFF)
        assertEquals(0x01, reply[2].toInt() and 0x01)         // RD preservado
        assertEquals(0x80, reply[2].toInt() and 0x80)         // QR = respuesta
        assertEquals(3, reply[3].toInt() and 0x0F)            // NXDOMAIN
        assertEquals(0, reply[7].toInt())                     // sin respuestas
    }

    @Test
    fun `ipv4 address helpers round trip`() {
        val bytes = PacketCodec.parseIpv4AddressBytes("203.0.113.9")
        assertNotNull(bytes)
        assertEquals("203.0.113.9", PacketCodec.formatIpv4(bytes!!))
        assertNull(PacketCodec.parseIpv4AddressBytes("300.1.1.1"))
        assertNull(PacketCodec.parseIpv4AddressBytes("no-es-ip"))
        assertNull(PacketCodec.parseIpv4AddressBytes("1.2.3"))
    }

    @Test
    fun `udp builder produces a parseable packet`() {
        val src = PacketCodec.parseIpv4AddressBytes("10.0.0.2")!!
        val dst = PacketCodec.parseIpv4AddressBytes("203.0.113.9")!!
        val packet = PacketCodec.buildIpv4UdpPacket(src, dst, 1234, 53, "hola".toByteArray())
        val parsed = PacketCodec.parseIpv4Packet(packet, packet.size)
        assertNotNull(parsed)
        assertEquals(1234, parsed!!.srcPort)
        assertEquals(53, parsed.dstPort)
        assertEquals(PacketCodec.PROTO_UDP, parsed.protocol)
        assertEquals("10.0.0.2", parsed.srcIpString)
    }
}
