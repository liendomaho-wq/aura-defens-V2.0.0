package com.aura.mobiledefense.domain.engines

import com.aura.mobiledefense.data.model.CompleteAuditReport
import com.aura.mobiledefense.data.model.GeneratedPatch
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.data.model.ToolExecutionResult
import com.aura.mobiledefense.data.model.VisualTopologyKind
import java.util.UUID

class PatchAndReportEngine(
    private val integrityEngine: AppSelfIntegrityEngine,
    private val privilegeEngine: PrivilegeAndDeviceEngine,
    private val networkEngine: NetworkForensicsEngine,
    private val binaryCryptoEngine: BinaryCryptoEngine,
    private val threatKnowledgeEngine: ThreatKnowledgeEngine
) {
    suspend fun runFullAutonomousAudit(
        targetHost: String,
        mode: PrivilegeMode
    ): ToolExecutionResult {
        val selfPair = integrityEngine.inspectSelfIntegrity(mode)
        val deviceRes = privilegeEngine.collectDeviceIntegrityAudit(mode)
        val netRes = networkEngine.inspectLocalNetworkAndSockets(mode)
        val appRes = binaryCryptoEngine.auditInstalledAppSurface("", mode)

        val remoteResults = mutableListOf<ToolExecutionResult>()
        val cleanHost = targetHost.trim()
            .removePrefix("https://")
            .removePrefix("http://")
            .substringBefore("/")
            .trim()
        if (cleanHost.isNotBlank()) {
            remoteResults.add(networkEngine.inspectTlsCertificate(cleanHost, mode))
            remoteResults.add(networkEngine.inspectHttpSecurityHeaders(cleanHost, mode))
            remoteResults.add(networkEngine.probePorts(cleanHost, mode))
        }

        val combinedTelemetry = buildString {
            appendLine(selfPair.second.rawTelemetry)
            appendLine()
            appendLine(deviceRes.rawTelemetry)
            appendLine()
            appendLine(netRes.rawTelemetry)
            appendLine()
            appendLine(appRes.rawTelemetry.take(2800))
            remoteResults.forEach {
                appendLine()
                appendLine(it.rawTelemetry.take(2200))
            }
        }

        val matchedRules = threatKnowledgeEngine.matchTelemetryAgainstRules(combinedTelemetry)
        val patches = generatePatchesFromTelemetry(combinedTelemetry, cleanHost, mode)

        val findingsSummary = buildString {
            appendLine("• Integridad propia: ${(selfPair.first.integrityScore * 100).toInt()}% (TracerPid=${selfPair.first.tracerPid}, hooking=${selfPair.first.hookingArtifacts.size})")
            if (matchedRules.isNotEmpty()) {
                matchedRules.forEach { r ->
                    appendLine("• [${r.ruleId}] ${r.title} (${r.vendorOrCategory})")
                }
            } else {
                appendLine("• Se evaluaron configuración de plataforma, SELinux, interfaces de red, sockets y superficie de aplicaciones.")
            }
            if (cleanHost.isNotBlank()) {
                appendLine("• Se auditó endpoint remoto $cleanHost (TLS X.509, cabeceras HTTP y puertos TCP).")
            }
        }

        val report = CompleteAuditReport(
            whatWasDone = buildString {
                append("Auditoría autónoma en plano ${mode.name}: verificación anti-manipulación propia, ")
                append("inspección de kernel/SELinux/props, enumeración de red y sockets, análisis de superficie ")
                append("de paquetes instalados y correlación con base de amenazas aprendida.")
                if (cleanHost.isNotBlank()) {
                    append(" Adicionalmente se ejecutó sondeo TLS, HTTP y TCP contra $cleanHost.")
                }
            },
            whatWasFound = findingsSummary.trim(),
            measuresAndPatchesTaken = if (patches.isEmpty()) {
                "No se requirieron parches críticos inmediatos sobre la telemetría inspeccionada; se mantuvo la línea base defensiva."
            } else {
                "Se generaron ${patches.size} parche(s) de mitigación y endurecimiento listos para aplicar: " +
                    patches.joinToString("; ") { "${it.title} (${it.targetArtifact})" }
            },
            improvementRecommendations = buildString {
                append("1) Mantener SELinux en Enforcing y verificación de arranque en estado 'green'. ")
                append("2) Habilitar monitoreo continuo sobre endpoints críticos para detectar cambios de certificado TLS o picos de latencia. ")
                append("3) Sincronizar el catálogo CISA KEV periódicamente para mantener actualizado el motor offline.")
            }
        )

        val fullTelemetry = buildString {
            appendLine(combinedTelemetry)
            if (matchedRules.isNotEmpty()) {
                appendLine()
                appendLine("=== CORRELACIÓN CON REGLAS APRENDIDAS (${matchedRules.size}) ===")
                matchedRules.forEach { r ->
                    appendLine("• [${r.ruleId}] ${r.title} -> ${r.remediationHint}")
                }
            }
        }

        val combinedSpectrum = (selfPair.second.measuredSpectrum +
            deviceRes.measuredSpectrum +
            netRes.measuredSpectrum.take(8) +
            appRes.measuredSpectrum.take(8)).take(32)

        return ToolExecutionResult(
            toolId = "FULL_AUTONOMOUS_AUDIT",
            target = cleanHost.ifBlank { "Sistema Integral + Red" },
            privilegeUsed = mode,
            rawTelemetry = fullTelemetry,
            measuredSpectrum = combinedSpectrum,
            suggestedVisual = VisualTopologyKind.NEURAL_SYNAPTIC_LATTICE,
            generatedPatches = patches,
            reportDraft = report
        )
    }

    fun generatePatchesFromTelemetry(
        telemetry: String,
        targetHost: String,
        mode: PrivilegeMode
    ): List<GeneratedPatch> {
        val lower = telemetry.lowercase()
        val patches = mutableListOf<GeneratedPatch>()

        if (lower.contains("cleartext=true") || lower.contains("http://")) {
            patches.add(
                GeneratedPatch(
                    id = UUID.randomUUID().toString(),
                    title = "Bloqueo estricto de tráfico en texto claro",
                    targetArtifact = "res/xml/network_security_config.xml",
                    severity = "ALTA",
                    rationale = "Se detectaron aplicaciones o referencias con tráfico HTTP sin cifrar susceptible a interceptación MITM.",
                    patchContent = """
                        <?xml version="1.0" encoding="utf-8"?>
                        <network-security-config>
                            <base-config cleartextTrafficPermitted="false">
                                <trust-anchors>
                                    <certificates src="system" />
                                </trust-anchors>
                            </base-config>
                        </network-security-config>
                    """.trimIndent()
                )
            )
        }

        if (lower.contains("debuggable=true") || lower.contains("allowbackup=true")) {
            patches.add(
                GeneratedPatch(
                    id = UUID.randomUUID().toString(),
                    title = "Endurecimiento de AndroidManifest (producción)",
                    targetArtifact = "AndroidManifest.xml",
                    severity = "ALTA",
                    rationale = "Aplicaciones con allowBackup o debuggable permiten extracción de datos locales o depuración no autorizada.",
                    patchContent = """
                        <application
                            android:allowBackup="false"
                            android:debuggable="false"
                            android:usesCleartextTraffic="false"
                            android:networkSecurityConfig="@xml/network_security_config">
                    """.trimIndent()
                )
            )
        }

        if (lower.contains("[ausente]  strict-transport-security") ||
            lower.contains("[ausente]  content-security-policy") ||
            lower.contains("[ausente]  x-frame-options")
        ) {
            val hostLabel = targetHost.ifBlank { "servidor-web" }
            patches.add(
                GeneratedPatch(
                    id = UUID.randomUUID().toString(),
                    title = "Cabeceras de defensa HTTP & TLS 1.3 ($hostLabel)",
                    targetArtifact = "/etc/nginx/conf.d/security-headers.conf",
                    severity = "MEDIA",
                    rationale = "Faltan cabeceras críticas (HSTS/CSP/XFO) en las respuestas HTTP del servidor auditado.",
                    patchContent = """
                        ssl_protocols TLSv1.2 TLSv1.3;
                        ssl_prefer_server_ciphers on;
                        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
                        add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'; object-src 'none';" always;
                        add_header X-Frame-Options "DENY" always;
                        add_header X-Content-Type-Options "nosniff" always;
                        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
                    """.trimIndent()
                )
            )
        }

        if (lower.contains("5555/tcp") || lower.contains("23/tcp") || lower.contains("6379/tcp") || lower.contains("adb debugging: habilitado")) {
            patches.add(
                GeneratedPatch(
                    id = UUID.randomUUID().toString(),
                    title = "Contención defensiva de puertos administrativos expuestos",
                    targetArtifact = if (mode == PrivilegeMode.ROOT) "iptables / nftables (Kernel)" else "Regla de Firewall / Perímetro",
                    severity = "CRITICA",
                    rationale = "Puertos sensibles (ADB 5555, Telnet 23 o Redis 6379) o depuración ADB activa amplían la superficie de intrusión.",
                    patchContent = """
                        # Contención defensiva inmediata (ejecutar solo en entorno autorizado)
                        iptables -A INPUT -p tcp --dport 5555 -j DROP
                        iptables -A INPUT -p tcp --dport 23 -j DROP
                        iptables -A INPUT -p tcp --dport 6379 -s 127.0.0.1 -j ACCEPT
                        iptables -A INPUT -p tcp --dport 6379 -j DROP
                        # En Android sin root: desactivar Depuración USB / ADB inalámbrico en Opciones de desarrollador
                    """.trimIndent()
                )
            )
        }

        if (lower.contains("algoritmo declarado: none") || lower.contains("expirado")) {
            patches.add(
                GeneratedPatch(
                    id = UUID.randomUUID().toString(),
                    title = "Validación criptográfica estricta de tokens JWT",
                    targetArtifact = "AuthJwtVerifier.kt / Middleware",
                    severity = "CRITICA",
                    rationale = "El token analizado presenta algoritmo 'none' o expiración vencida, vulnerable a falsificación de identidad.",
                    patchContent = """
                        // Rechazar explícitamente alg=none y validar firma + exp + iss
                        val allowedAlgorithms = setOf("RS256", "ES256")
                        require(header.alg in allowedAlgorithms) { "Algoritmo JWT no permitido" }
                        require(claims.expEpochSec > Instant.now().epochSecond) { "Token JWT expirado" }
                    """.trimIndent()
                )
            )
        }

        return patches
    }
}
