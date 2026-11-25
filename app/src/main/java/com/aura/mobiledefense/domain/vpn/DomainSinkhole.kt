package com.aura.mobiledefense.domain.vpn

import java.util.concurrent.ConcurrentHashMap

/**
 * Decisiones del firewall por dominio, con memoria.
 *
 * El TUN de Android solo enruta por IP. Para bloquear un **dominio** hay que hacerlo en el momento
 * en que el nombre aparece en el tráfico: en la consulta DNS (interceptada) o en el SNI del
 * ClientHello de TLS. Una vez aprendido `dominio -> IP`, esa IP se bloquea de verdad en el túnel
 * (se descartan sus paquetes y se responde TCP RST), incluido el tráfico de apps que usan su propio
 * resolvedor y nunca pasan por nuestro DNS.
 *
 * Es puro Kotlin y sin estado de Android, para poder probarlo.
 */
object DomainSinkhole {

    /** Cuánto tiempo se recuerda una asociación dominio→IP aprendida por el firewall. */
    private const val IP_TTL_MS = 30 * 60 * 1000L
    private const val MAX_LEARNED_IPS = 2048

    data class Decision(val blocked: Boolean, val reason: String)

    private class LearnedIp(val domain: String, val blocked: Boolean, val expiresAt: Long)

    private val learned = ConcurrentHashMap<String, LearnedIp>()

    /** `dominio -> lista de IPs` observadas (para diagnóstico y para el informe). */
    private val observed = ConcurrentHashMap<String, MutableSet<String>>()

    /** Registra lo que devolvió el DNS upstream. */
    fun rememberResolution(domain: String, ips: List<String>, blocked: Boolean) {
        if (domain.isBlank()) return
        val host = domain.trim().lowercase().trimEnd('.')
        if (ips.isEmpty()) return
        val now = System.currentTimeMillis()
        observed.getOrPut(host) { java.util.Collections.synchronizedSet(mutableSetOf()) }
            .apply { ips.forEach { add(it) } }
        if (blocked) {
            if (learned.size > MAX_LEARNED_IPS) prune(now)
            ips.forEach { ip -> learned[ip] = LearnedIp(host, true, now + IP_TTL_MS) }
        }
    }

    /** ¿Esta IP pertenece a un dominio que acabamos de resolver y bloquear? */
    fun isBlockedIp(ip: String): Decision {
        val entry = learned[ip] ?: return Decision(false, "")
        if (entry.expiresAt < System.currentTimeMillis()) {
            learned.remove(ip)
            return Decision(false, "")
        }
        return if (entry.blocked) {
            Decision(true, "Dominio bloqueado por firewall: ${entry.domain}")
        } else {
            Decision(false, "")
        }
    }

    /** Olvida todo (al reiniciar el túnel o al quitar una regla). */
    fun reset() {
        learned.clear()
        observed.clear()
    }

    fun forgetDomain(domain: String) {
        val host = domain.trim().lowercase().trimEnd('.')
        learned.entries.removeIf { it.value.domain == host }
        observed.remove(host)
    }

    fun learnedIpCount(): Int = learned.size

    private fun prune(now: Long) {
        learned.entries.removeIf { it.value.expiresAt < now }
        if (learned.size > MAX_LEARNED_IPS) {
            learned.entries.sortedBy { it.value.expiresAt }
                .take(learned.size - MAX_LEARNED_IPS)
                .forEach { learned.remove(it.key) }
        }
    }
}
