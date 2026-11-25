package com.aura.mobiledefense.domain.vpn

/**
 * Prefijos SNI de TLS (RFC 6066). Son los 9 primeros bytes del ClientHello que se usan para saber
 * a qué dominio se conecta una app antes de que el certificado llegue.
 */
object TlsSniExtractor {

    const val TLS_RECORD_HANDSHAKE = 0x16
    const val TLS_HANDSHAKE_CLIENT_HELLO = 0x01
    private const val EXT_SERVER_NAME = 0x0000
    private const val SNI_HOST_NAME = 0x00

    /**
     * Extrae el SNI de un ClientHello dentro de [payload] (los bytes TCP de la conexión, en orden).
     *
     * Devuelve null si el buffer aún no contiene el ClientHello completo: el llamador debe pedir más
     * bytes. Un ClientHello partido en varios segmentos es lo normal, así que devolver null no es un
     * error, es "todavía no sé".
     */
    fun extractSni(payload: ByteArray, length: Int = payload.size): String? {
        if (length < 5) return null
        if (u8(payload, 0) != TLS_RECORD_HANDSHAKE) return null
        val recordLength = u16(payload, 3)
        if (length < 5 + recordLength) return null

        var p = 5
        if (u8(payload, p) != TLS_HANDSHAKE_CLIENT_HELLO) return null
        val helloLength = u24(payload, p + 1)
        val helloEnd = p + 4 + helloLength
        if (length < helloEnd) return null

        p += 4
        p += 2                                  // legacy_version
        p += 32                                 // random
        val sessionIdLen = u8(payload, p); p += 1 + sessionIdLen
        val cipherSuitesLen = u16(payload, p); p += 2 + cipherSuitesLen
        val compressionLen = u8(payload, p); p += 1 + compressionLen
        if (p + 2 > helloEnd) return null
        val extensionsLen = u16(payload, p)
        p += 2
        val extensionsEnd = minOf(p + extensionsLen, helloEnd)

        while (p + 4 <= extensionsEnd) {
            val type = u16(payload, p)
            val extLen = u16(payload, p + 2)
            val extStart = p + 4
            val extEnd = extStart + extLen
            if (extEnd > extensionsEnd) return null
            if (type == EXT_SERVER_NAME) {
                if (extEnd - extStart < 2) return null
                val listLen = u16(payload, extStart)
                var q = extStart + 2
                val listEnd = minOf(q + listLen, extEnd)
                while (q + 3 <= listEnd) {
                    val nameType = u8(payload, q)
                    val nameLen = u16(payload, q + 1)
                    val nameStart = q + 3
                    val nameEnd = nameStart + nameLen
                    if (nameEnd > listEnd) return null
                    if (nameType == SNI_HOST_NAME) {
                        val host = String(payload, nameStart, nameLen, Charsets.US_ASCII)
                            .trim().lowercase().trimEnd('.')
                        return host.ifBlank { null }
                    }
                    q = nameEnd
                }
                return null
            }
            p = extEnd
        }
        return null
    }

    /** ¿Los bytes son ya un intento de TLS? Sirve para descartar tráfico que no lo es. */
    fun looksLikeTls(payload: ByteArray): Boolean =
        payload.isNotEmpty() && u8(payload, 0) == TLS_RECORD_HANDSHAKE

    private fun u8(b: ByteArray, i: Int): Int = b[i].toInt() and 0xFF
    private fun u16(b: ByteArray, i: Int): Int = (u8(b, i) shl 8) or u8(b, i + 1)
    private fun u24(b: ByteArray, i: Int): Int = (u8(b, i) shl 16) or (u8(b, i + 1) shl 8) or u8(b, i + 2)
}
