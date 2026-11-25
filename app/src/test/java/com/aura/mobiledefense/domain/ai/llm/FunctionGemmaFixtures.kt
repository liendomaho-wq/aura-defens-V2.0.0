package com.aura.mobiledefense.domain.ai.llm

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Muestras congeladas del dataset de entrenamiento (aura-train/train.jsonl).
 *
 * Garantizan que [FunctionGemmaToolProvider] siga hablando el formato exacto con el que se
 * entrenó el modelo y que la app despache la herramienta esperada. Si el catálogo o el prompt
 * cambian, estas pruebas fallan: es intencional.
 */
class FunctionGemmaFixtures {

    data class Case(val user: String, val toolId: String, val target: String)

    companion object {
        val cases: List<Case> = listOf(
            Case("resuelvas 8.8.8.8 please", "DNS_RECON", "8.8.8.8"),
            Case("haz un escaneo TCP a app.minegocio.io", "PORT_PROBE", "app.minegocio.io"),
            Case("porfa el certificado de sitio.miproyecto.dev es válido? cuando puedas", "TLS_INSPECT", "sitio.miproyecto.dev"),
            Case("añade una regla para bloquear 192.168.1.10 ya", "FIREWALL_BLOCK", "192.168.1.10"),
            Case("quita el bloqueo de 172.16.5.20", "FIREWALL_ALLOW", "172.16.5.20"),
            Case("che /su id && getenforce gracias", "ROOT_SHELL", ""),
            Case("qué riesgos tiene usar wifi público gracias", "AI_THEORETICAL", ""),
            Case("bueno activa la protección de red rapidito", "VPN_START", ""),
            Case("hace falta que apliques los parches generados cuando puedas", "EXECUTE_SOLUTIONS", ""),
            Case("oye oye auditoría de superficie de apps", "APP_SURFACE_AUDIT", ""),
            Case("comprueba latencia y estado de app.minegocio.io ahora", "SERVER_MONITOR", "app.minegocio.io"),
            Case("ahora está bien configurado el servidor de cloudflare-demo.com? ahora", "HTTP_HEADERS", "cloudflare-demo.com"),
        )
    }
}
