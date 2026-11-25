package com.aura.mobiledefense.domain.ai.llm

import com.aura.mobiledefense.data.model.ForensicToolPlan
import com.aura.mobiledefense.data.model.PrivilegeMode

/**
 * Closed catalogue of every capability Aura can actually execute.
 *
 * This is the security boundary of the LLM integration: a language model may *propose* any
 * [toolId] it wants, but only the ids listed here are ever turned into a [ForensicToolPlan].
 * Anything else falls back to the deterministic heuristic classifier.
 *
 * The ids must stay in sync with the `when (plan.toolId)` dispatch in `NyxViewModel` and with
 * [LlmToolSpec.dispatch]. If you add a tool there, add it here too.
 */
object AuraToolCatalog {

    data class LlmToolSpec(
        val id: String,
        val dispatch: String,
        val requiresTarget: Boolean,
        val targetKind: TargetKind,
        val prefersRoot: Boolean,
        val summary: String,
        val examples: List<String> = emptyList()
    )

    enum class TargetKind {
        NONE,
        HOST,
        PATTERN,
        FREETEXT
    }

    val tools: List<LlmToolSpec> = listOf(
        LlmToolSpec(
            id = "FULL_AUTONOMOUS_AUDIT",
            dispatch = "runFullAutonomousAudit",
            requiresTarget = false,
            targetKind = TargetKind.HOST,
            prefersRoot = false,
            summary = "Auditoría integral del dispositivo y la red: integridad propia, postura del kernel, " +
                "sockets, superficie de apps, correlación contra la base de amenazas y generación de parches.",
            examples = listOf("audita todo", "revisa la seguridad del sistema completo", "hazme un diagnóstico general")
        ),
        LlmToolSpec(
            id = "SERVER_MONITOR",
            dispatch = "probeAndMonitorTarget",
            requiresTarget = true,
            targetKind = TargetKind.HOST,
            prefersRoot = false,
            summary = "Vigila un host remoto comparando RTT, TLS y estado HTTP contra su línea base para detectar anomalías.",
            examples = listOf("monitorea midominio.com", "vigila si mi servidor se cae")
        ),
        LlmToolSpec(
            id = "SELF_TRAIN_KEV",
            dispatch = "trainFromInternet",
            requiresTarget = false,
            targetKind = TargetKind.NONE,
            prefersRoot = false,
            summary = "Sincroniza el catálogo CISA KEV de vulnerabilidades explotadas para ampliar las firmas locales.",
            examples = listOf("entrénala con CISA", "actualiza las firmas de amenazas")
        ),
        LlmToolSpec(
            id = "SELF_INTEGRITY",
            dispatch = "inspectSelfIntegrity",
            requiresTarget = false,
            targetKind = TargetKind.NONE,
            prefersRoot = false,
            summary = "Autoverificación anti-manipulación de la propia app: firma del APK, debuggable, TracerPid y hooks.",
            examples = listOf("comprueba que no te hayan manipulado", "verifica tu integridad")
        ),
        LlmToolSpec(
            id = "DEVICE_INTEGRITY",
            dispatch = "collectDeviceIntegrityAudit",
            requiresTarget = false,
            targetKind = TargetKind.NONE,
            prefersRoot = false,
            summary = "Postura del dispositivo: SELinux, verified boot, ADB, cifrado, TEE/StrongBox y propiedades del kernel.",
            examples = listOf("cómo está el dispositivo", "revisa el estado del kernel")
        ),
        LlmToolSpec(
            id = "NETWORK_SOCKETS",
            dispatch = "inspectLocalNetworkAndSockets",
            requiresTarget = false,
            targetKind = TargetKind.NONE,
            prefersRoot = false,
            summary = "Topología de red local: interfaces, tabla TCP, sockets, ARP y capacidades de red.",
            examples = listOf("muéstrame los sockets abiertos", "qué conexiones tengo activas")
        ),
        LlmToolSpec(
            id = "PORT_PROBE",
            dispatch = "probePorts",
            requiresTarget = true,
            targetKind = TargetKind.HOST,
            prefersRoot = false,
            summary = "Sondeo TCP de puertos comunes con banner sobre un host autorizado.",
            examples = listOf("escanea los puertos de mi servidor", "mira si el 22 está abierto en 10.0.0.5")
        ),
        LlmToolSpec(
            id = "TLS_INSPECT",
            dispatch = "inspectTlsCertificate",
            requiresTarget = true,
            targetKind = TargetKind.HOST,
            prefersRoot = false,
            summary = "Inspección del certificado X.509: emisor, caducidad, protocolo y huella SHA-256 anti-MITM.",
            examples = listOf("revisa el certificado de midominio.com", "mira si el TLS es válido")
        ),
        LlmToolSpec(
            id = "DNS_RECON",
            dispatch = "inspectDnsRecon",
            requiresTarget = true,
            targetKind = TargetKind.HOST,
            prefersRoot = false,
            summary = "Resolución DNS over HTTPS: registros A, AAAA, MX, TXT y NS.",
            examples = listOf("resuelve el DNS de midominio.com", "qué registros MX tiene")
        ),
        LlmToolSpec(
            id = "HTTP_HEADERS",
            dispatch = "inspectHttpSecurityHeaders",
            requiresTarget = true,
            targetKind = TargetKind.HOST,
            prefersRoot = false,
            summary = "Cabeceras defensivas HTTP: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.",
            examples = listOf("mira las cabeceras de mi web", "tiene HSTS mi sitio")
        ),
        LlmToolSpec(
            id = "APP_SURFACE_AUDIT",
            dispatch = "auditInstalledAppSurface",
            requiresTarget = false,
            targetKind = TargetKind.FREETEXT,
            prefersRoot = false,
            summary = "Superficie de apps instaladas: componentes exportados, debuggable, allowBackup, cleartext y firma.",
            examples = listOf("audita las apps instaladas", "qué apps tienen debuggable")
        ),
        LlmToolSpec(
            id = "CRYPTO_JWT",
            dispatch = "analyzeCryptoOrJwt",
            requiresTarget = false,
            targetKind = TargetKind.FREETEXT,
            prefersRoot = false,
            summary = "Análisis criptográfico local de un JWT, hash o token pegado por el usuario.",
            examples = listOf("analiza este JWT eyJ...", "qué algoritmo usa este token")
        ),
        LlmToolSpec(
            id = "ROOT_SHELL",
            dispatch = "executeRootShellInspection",
            requiresTarget = true,
            targetKind = TargetKind.FREETEXT,
            prefersRoot = true,
            summary = "Inspección shell sujeta a RootCommandPolicy (deny por defecto). Solo lectura y mitigaciones firmadas.",
            examples = listOf("/su id && getenforce", "mira los procesos con selinux")
        ),
        LlmToolSpec(
            id = "VPN_START",
            dispatch = "startLocalVpnIfPrepared",
            requiresTarget = false,
            targetKind = TargetKind.NONE,
            prefersRoot = false,
            summary = "Activa el túnel VPN local con DNS sinkhole y firewall a nivel de paquete.",
            examples = listOf("activa la vpn", "enciende el firewall")
        ),
        LlmToolSpec(
            id = "VPN_STOP",
            dispatch = "stopLocalVpn",
            requiresTarget = false,
            targetKind = TargetKind.NONE,
            prefersRoot = false,
            summary = "Detiene el túnel VPN local conservando las reglas guardadas.",
            examples = listOf("apaga la vpn", "desactiva el firewall")
        ),
        LlmToolSpec(
            id = "VPN_TELEMETRY",
            dispatch = "buildTelemetryReport",
            requiresTarget = false,
            targetKind = TargetKind.NONE,
            prefersRoot = false,
            summary = "Telemetría del firewall: paquetes inspeccionados, bloqueos, bytes y estado del TUN.",
            examples = listOf("cuántos paquetes has bloqueado", "muéstrame la telemetría de la vpn")
        ),
        LlmToolSpec(
            id = "FIREWALL_BLOCK",
            dispatch = "addBlockRule",
            requiresTarget = true,
            targetKind = TargetKind.PATTERN,
            prefersRoot = false,
            summary = "Añade una regla de bloqueo por dominio, IP o puerto en el firewall VPN.",
            examples = listOf("bloquea doubleclick.net", "bloquea el puerto 6379")
        ),
        LlmToolSpec(
            id = "FIREWALL_ALLOW",
            dispatch = "removeRule",
            requiresTarget = true,
            targetKind = TargetKind.PATTERN,
            prefersRoot = false,
            summary = "Retira una regla de bloqueo existente del firewall VPN.",
            examples = listOf("permite otra vez doubleclick.net", "quita el bloqueo del 6379")
        ),
        LlmToolSpec(
            id = "EXECUTE_SOLUTIONS",
            dispatch = "executeSolutionsLive",
            requiresTarget = false,
            targetKind = TargetKind.NONE,
            prefersRoot = false,
            summary = "Aplica en vivo los parches y mitigaciones generados en el último análisis.",
            examples = listOf("aplica las soluciones", "ejecuta los parches")
        ),
        LlmToolSpec(
            id = "AI_THEORETICAL",
            dispatch = "theoreticalAnswer",
            requiresTarget = false,
            targetKind = TargetKind.FREETEXT,
            prefersRoot = false,
            summary = "Respuesta conversacional sin ejecutar herramientas: dudas, explicaciones, estrategia defensiva.",
            examples = listOf("cómo me protejo de un MITM", "qué es SELinux")
        )
    )

    private val byId: Map<String, LlmToolSpec> = tools.associateBy { it.id }

    /** Ids the model is allowed to return. */
    val allowedIds: Set<String> = tools.map { it.id }.toSet()

    fun spec(toolId: String): LlmToolSpec? = byId[toolId.trim().uppercase()]

    fun isAllowed(toolId: String): Boolean = byId.containsKey(toolId.trim().uppercase())

    /** Renders the catalogue as a compact prompt block. */
    fun promptBlock(): String = buildString {
        tools.forEach { t ->
            append("- ").append(t.id)
            append(" | target=").append(
                when (t.targetKind) {
                    TargetKind.NONE -> "no"
                    TargetKind.HOST -> "dominio|ip"
                    TargetKind.PATTERN -> "dominio|ip|puerto"
                    TargetKind.FREETEXT -> "texto|comando"
                }
            )
            if (t.prefersRoot) append(" | root")
            append(": ").append(t.summary)
            append('\n')
        }
    }

    /**
     * Builds a plan from a validated tool id, or null when the id is outside the catalogue.
     * `prefersRoot` is clamped: a model can never *raise* privileges on its own; the caller
     * still has to go through `PrivilegeAndDeviceEngine.probeRootCapability`.
     */
    fun buildPlan(
        toolId: String,
        target: String,
        reason: String,
        mode: PrivilegeMode
    ): ForensicToolPlan? {
        val spec = spec(toolId) ?: return null
        return ForensicToolPlan(
            toolId = spec.id,
            target = target.trim(),
            extraArg = "",
            prefersRoot = spec.prefersRoot && mode == PrivilegeMode.ROOT,
            analysisFocus = reason.ifBlank { spec.summary }
        )
    }
}
