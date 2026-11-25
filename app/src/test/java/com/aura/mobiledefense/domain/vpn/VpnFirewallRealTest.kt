package com.aura.mobiledefense.domain.vpn

import com.aura.mobiledefense.data.model.PrivilegeMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * Pruebas del firewall real: SNI de TLS, memoria dominio→IP y construcción de paquetes.
 *
 * Sin estas piezas el "bloqueo por dominio" era cosmético: el TUN solo enrutaba las IPs ya
 * bloqueadas, así que bloquear `criteo.com` no cortaba nada. Aquí se comprueba lo que de verdad
 * decide el corte.
 */
class VpnFirewallRealTest {

    // ── TlsSniExtractor ─────────────────────────────────────────────────────────────────────────

    /** ClientHello mínimo pero válido (versión, random, 1 suite, 1 compresión, extensión SNI). */
    private fun clientHello(host: String): ByteArray {
        val sni = host.toByteArray(Charsets.US_ASCII)
        val serverName = ByteArrayOutputStream().apply {
            write(byteArrayOf(0x00, ((sni.size + 3) shr 8).toByte(), ((sni.size + 3) and 0xFF).toByte()))
            write(0x00)                                     // host_name
            write((sni.size shr 8).toByte())
            write((sni.size and 0xFF).toByte())
            write(sni)
        }.toByteArray()
        val extension = ByteArrayOutputStream().apply {
            write(byteArrayOf(0x00, 0x00))                  // ext type: server_name
            write(((serverName.size shr 8) and 0xFF).toByte())
            write((serverName.size and 0xFF).toByte())
            write(serverName)
        }.toByteArray()
        val hello = ByteArrayOutputStream().apply {
            write(byteArrayOf(0x03, 0x03))                  // legacy_version TLS 1.2
            write(ByteArray(32))                            // random
            write(0x00)                                     // session id len
            write(byteArrayOf(0x00, 0x02, 0x13, 0x01))      // cipher suites
            write(byteArrayOf(0x01, 0x00))                  // compression
            write((extension.size shr 8).toByte())
            write((extension.size and 0xFF).toByte())
            write(extension)
        }.toByteArray()
        return ByteArrayOutputStream().apply {
            write(0x16)                                     // handshake record
            write(byteArrayOf(0x03, 0x01))
            write((hello.size shr 8).toByte())
            write((hello.size and 0xFF).toByte())
            write(hello)
        }.toByteArray()
    }

    @Test
    fun `sni is extracted from a client hello`() {
        assertEquals("criteo.com", TlsSniExtractor.extractSni(clientHello("criteo.com")))
        assertEquals("api.miempresa.com", TlsSniExtractor.extractSni(clientHello("api.miempresa.com")))
    }

    @Test
    fun `split client hello returns null until complete`() {
        val full = clientHello("midominio.com")
        val half = full.copyOf(full.size / 2)
        assertNull("un ClientHello partido debe pedir más bytes, no fallar", TlsSniExtractor.extractSni(half))
        assertNotNull(TlsSniExtractor.extractSni(full))
    }

    @Test
    fun `non tls traffic is not mistaken for a client hello`() {
        assertTrue(!TlsSniExtractor.looksLikeTls("GET / HTTP/1.1\r\n".toByteArray()))
        assertNull(TlsSniExtractor.extractSni("GET / HTTP/1.1\r\n".toByteArray()))
    }

    // ── DomainSinkhole ─────────────────────────────────────────────────────────────────────────

    @Test
    fun `blocked domain teaches the firewall its ips`() {
        DomainSinkhole.reset()
        DomainSinkhole.rememberResolution("criteo.com", listOf("203.0.113.50"), blocked = true)
        assertTrue(DomainSinkhole.isBlockedIp("203.0.113.50").blocked)
        assertTrue(DomainSinkhole.isBlockedIp("203.0.113.50").reason.contains("criteo.com"))
        assertTrue(!DomainSinkhole.isBlockedIp("198.51.100.7").blocked)
    }

    @Test
    fun `allowed domain does not block its ips`() {
        DomainSinkhole.reset()
        DomainSinkhole.rememberResolution("midominio.com", listOf("203.0.113.60"), blocked = false)
        assertTrue(!DomainSinkhole.isBlockedIp("203.0.113.60").blocked)
    }

    @Test
    fun `forgetting a domain unblocks it`() {
        DomainSinkhole.reset()
        DomainSinkhole.rememberResolution("taboola.com", listOf("203.0.113.70"), blocked = true)
        DomainSinkhole.forgetDomain("taboola.com")
        assertTrue(!DomainSinkhole.isBlockedIp("203.0.113.70").blocked)
    }

    // ── PacketCodec: DNS answers ───────────────────────────────────────────────────────────────

    @Test
    fun `dns answer ips are parsed with name compression`() {
        val response = ByteArrayOutputStream().apply {
            write(byteArrayOf(0x12, 0x34))                  // id
            write(byteArrayOf(0x81.toByte(), 0x80.toByte())) // flags: response, no error
            write(byteArrayOf(0x00, 0x01, 0x00, 0x02))      // qd=1, an=2
            write(ByteArray(6))                             // ns, ar
            write(byteArrayOf(0x04)); write("aura".toByteArray())
            write(byteArrayOf(0x03)); write("com".toByteArray())
            write(0x00)
            write(byteArrayOf(0x00, 0x01, 0x00, 0x01))      // A, IN
            // answer 1: puntero a la pregunta
            write(byteArrayOf(0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01))
            write(byteArrayOf(0x00, 0x00, 0x00, 0x3C))      // ttl
            write(byteArrayOf(0x00, 0x04, 203.toByte(), 0, 113, 9))
            // answer 2: puntero + AAAA
            write(byteArrayOf(0xC0.toByte(), 0x0C, 0x00, 0x1C, 0x00, 0x01))
            write(byteArrayOf(0x00, 0x00, 0x00, 0x3C))
            write(byteArrayOf(0x00, 0x10))
            write(ByteArray(15) { 0x00 })
            write(0x01)
        }.toByteArray()

        val ips = PacketCodec.extractDnsAnswerIps(response)
        assertEquals(listOf("203.0.113.9", "0:0:0:0:0:0:0:1"), ips)
    }

    // ── TcpProxyEngine: paquetes de corte ──────────────────────────────────────────────────────

    private fun ipv4TcpPacket(seq: Long, flags: Int): Pair<ByteArray, PacketCodec.ParsedIpPacket> {
        val packet = ByteArray(20 + 20)
        packet[0] = 0x45
        packet[2] = ((packet.size shr 8) and 0xFF).toByte()
        packet[3] = (packet.size and 0xFF).toByte()
        packet[8] = 64
        packet[9] = PacketCodec.PROTO_TCP.toByte()
        // src 10.0.0.2 (dispositivo) -> dst 203.0.113.9
        packet[12] = 10; packet[15] = 2
        packet[16] = 203.toByte(); packet[18] = 113; packet[19] = 9
        val tcp = 20
        packet[tcp] = 0x1F.toByte(); packet[tcp + 1] = 0x90.toByte()   // src port 8080
        packet[tcp + 2] = 0x01; packet[tcp + 3] = 0xBB.toByte()        // dst port 443
        packet[tcp + 4] = ((seq shr 24) and 0xFF).toByte()
        packet[tcp + 7] = (seq and 0xFF).toByte()
        packet[tcp + 12] = 0x50
        packet[tcp + 13] = flags.toByte()
        val parsed = PacketCodec.parseIpv4Packet(packet, packet.size)!!
        return packet to parsed
    }

    @Test
    fun `rst packet swaps endpoints and keeps checksums valid`() {
        val (packet, parsed) = ipv4TcpPacket(seq = 1000, flags = 0x02)
        val segment = TcpProxyEngine.TcpSegment.parse(packet, parsed)!!
        val rst = TcpProxyEngine.buildRst(parsed, segment)

        val out = PacketCodec.parseIpv4Packet(rst, rst.size)!!
        assertEquals("203.0.113.9", out.srcIpString)
        assertEquals("10.0.0.2", out.dstIpString)
        assertEquals(443, out.srcPort)
        assertEquals(8080, out.dstPort)
        // Flags RST+ACK
        assertEquals(0x14, rst[20 + 13].toInt() and 0xFF)

        // Checksum IPv4: la suma de complemento a uno debe dar 0xFFFF. Un RST con checksum
        // incorrecto lo descarta Android y la conexión no se corta.
        fun onesComplementSum(vararg parts: ByteArray): Int {
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
            return sum
        }

        assertEquals(0xFFFF, onesComplementSum(rst.copyOfRange(0, 20)))
        val pseudo = byteArrayOf(203.toByte(), 0, 113, 9, 10, 0, 0, 2, 0, PacketCodec.PROTO_TCP.toByte(), 0, 20)
        assertEquals(0xFFFF, onesComplementSum(pseudo, rst.copyOfRange(20, rst.size)))
    }

    @Test
    fun `tcp segment parser reads flags and sequence`() {
        val (packet, parsed) = ipv4TcpPacket(seq = 424242, flags = 0x18)
        val segment = TcpProxyEngine.TcpSegment.parse(packet, parsed)!!
        assertTrue(segment.psh && segment.ack)
        assertTrue(!segment.syn && !segment.rst)
        assertEquals(424242L, segment.sequence)
        assertEquals(0, segment.payloadLength)
    }

    // ── VpnFirewallManager: política DoH ──────────────────────────────────────────────────────

    @Test
    fun `encrypted dns is blocked only when policy is on`() {
        VpnFirewallManager.setEncryptedDnsPolicy(false)
        assertTrue(VpnFirewallManager.evaluateDnsDomain("dns.google").allowed)
        VpnFirewallManager.setEncryptedDnsPolicy(true)
        assertTrue(!VpnFirewallManager.evaluateDnsDomain("dns.google").allowed)
        assertTrue(!VpnFirewallManager.evaluateDnsDomain("mozilla.cloudflare-dns.com").allowed)
        assertTrue("un dominio normal sigue permitido", VpnFirewallManager.evaluateDnsDomain("midominio.com").allowed)
        VpnFirewallManager.setEncryptedDnsPolicy(false)
    }

    // ── PrivilegeMode import guard (evita unused import en builds estrictos) ───────────────────
    @Test
    fun `privilege mode enum is available for firewall policy`() {
        assertNotNull(PrivilegeMode.LOCAL)
    }
}
