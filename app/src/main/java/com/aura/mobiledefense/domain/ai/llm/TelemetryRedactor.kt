package com.aura.mobiledefense.domain.ai.llm

/**
 * Removes identifying data from telemetry before it ever leaves the device.
 *
 * Aura's privacy promise ("sin cuentas, sin analytics, sin telemetría propia") only survives an
 * LLM integration if what we send is evidence, not a fingerprint of the user. Everything that can
 * identify a person, a home network or a specific installed app is replaced by a stable token so
 * the model can still reason about *relationships* (`<IP_PRIVADA_1` talks to `>IP_PRIVADA_2`) without
 * knowing the real values.
 *
 * Stable tokens (same input → same token) are essential: if `192.168.1.10` becomes
 * `<IP_PRIVADA_1>` in every line, the model can still say "el mismo host aparece en 4 conexiones".
 */
object TelemetryRedactor {

    private val ipv4 = Regex("\\b(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\b")
    private val mac = Regex("\\b([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\\b")
    private val email = Regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")
    private val publicIpv6 = Regex("\\b(([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})\\b")

    /** Personal app packages: keep the vendor, drop the per-user suffix. */
    private val userPackage = Regex("\\b(com|org|net|io)\\.([a-z0-9_]+)\\.[a-z0-9_]{6,}\\b")

    // Captura "Bearer <t>", "Authorization: Bearer <t>", "Authorization: <t>" y "api_key=<t>".
    // El secreto va en el grupo 3 para sustituir SOLO el secreto, nunca el prefijo.
    private val bearerToken = Regex("(?i)(bearer\\s+|authorization\\s*:\\s*(bearer\\s+)?|api[-_]?key\\s*[:=]\\s*)([A-Za-z0-9._\\-]{12,})")
    private val jwt = Regex("eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]*")
    private val serial = Regex("(?i)\\b(serial(no)?|imei|android_id|ssaid)\\s*[:=]\\s*[A-Za-z0-9._\\-]{6,}")

    private val privateRanges = listOf(
        "10." to true,
        "192.168." to true,
        "127." to true
    )

    /**
     * @param text raw telemetry
     * @param keepHosts hosts the user explicitly asked to audit. Those are the user's own targets and
     *   the model needs them verbatim to say something useful about them.
     */
    fun redact(text: String, keepHosts: Set<String> = emptySet()): String {
        if (text.isBlank()) return text
        val tokens = linkedMapOf<String, String>()
        var out = text

        out = bearerToken.replace(out) { m ->
            // Conserva el prefijo (p.ej. "Authorization: Bearer ") y sustituye solo el secreto.
            val prefix = m.value.substring(0, m.value.length - m.groupValues[3].length)
            "$prefix<CREDENCIAL>"
        }
        out = jwt.replace(out, "<JWT>")
        out = serial.replace(out) { m ->
            val match = m.value
            val sep = if (':' in match) ':' else '='
            val head = match.substringBefore(sep).trim()
            "$head: <IDENTIFICADOR>"
        }
        out = email.replace(out, "<EMAIL>")
        out = mac.replace(out, "<MAC>")

        out = ipv4.replace(out) { m ->
            val a = m.groupValues[1].toIntOrNull() ?: 0
            val b = m.groupValues[2].toIntOrNull() ?: 0
            val isPrivate = privateRanges.any { (prefix, _) -> m.value.startsWith(prefix) } ||
                (a == 172 && b in 16..31) ||
                (a == 169 && b == 254)
            val isLoopback = a == 127
            val keep = keepHosts.any { it.equals(m.value, ignoreCase = true) }
            when {
                keep -> m.value
                isLoopback -> "<LOCALHOST>"
                isPrivate -> tokenFor(tokens, m.value, "<IP_PRIVADA_", ">")
                else -> tokenFor(tokens, m.value, "<IP_PUBLICA_", ">")
            }
        }

        out = publicIpv6.replace(out) { m ->
            val keep = keepHosts.any { it.equals(m.value, ignoreCase = true) }
            if (keep) m.value else tokenFor(tokens, m.value, "<IPV6_", ">")
        }

        out = userPackage.replace(out) { m ->
            val pkg = m.value
            val keep = keepHosts.any { it.equals(pkg, ignoreCase = true) }
            if (keep) pkg else "${m.groupValues[1]}.${m.groupValues[2]}.<PAQUETE>"
        }

        return out
    }

    private fun tokenFor(tokens: MutableMap<String, String>, value: String, prefix: String, suffix: String): String {
        tokens[value]?.let { return it }
        val token = "$prefix${tokens.size + 1}$suffix"
        tokens[value] = token
        return token
    }

    /** True when the redacted text still carries something that looks like a secret. */
    fun looksLeaky(text: String): Boolean =
        jwt.containsMatchIn(text) || bearerToken.containsMatchIn(text) || serial.containsMatchIn(text)
}
