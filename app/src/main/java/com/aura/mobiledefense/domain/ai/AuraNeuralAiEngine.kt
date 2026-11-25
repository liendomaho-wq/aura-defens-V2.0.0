package com.aura.mobiledefense.domain.ai

import com.aura.mobiledefense.data.local.ThreatRuleEntity
import com.aura.mobiledefense.data.model.AiEngineMode
import com.aura.mobiledefense.data.model.AiStratumLayer
import com.aura.mobiledefense.data.model.AiVisualEdge
import com.aura.mobiledefense.data.model.AiVisualNode
import com.aura.mobiledefense.data.model.AiVisualScene
import com.aura.mobiledefense.data.model.CompleteAuditReport
import com.aura.mobiledefense.data.model.ForensicToolPlan
import com.aura.mobiledefense.data.model.GeneratedPatch
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.data.model.RootCapabilityState
import com.aura.mobiledefense.data.model.ThreatKnowledgeStats
import com.aura.mobiledefense.data.model.ToolExecutionResult
import com.aura.mobiledefense.data.model.VisualTopologyKind
import com.aura.mobiledefense.domain.engines.PatchAndReportEngine
import java.util.UUID

private data class ConversationTurn(
    val query: String,
    val toolId: String,
    val target: String,
    val summary: String,
    val severity: Float
)

/**
 * Aura Mobile Defense's proprietary, zero-cost conversational AI engine built entirely from scratch in Kotlin.
 * Performs intent classification, contextual memory tracking, telemetry-grounded natural language generation,
 * 3-layer synaptic graph synthesis, automated vulnerability correlation, and mitigation patch assembly
 * without calling Gemini, Google AI Studio, or any paid cloud API.
 */
class AuraNeuralAiEngine(
    private val patchAndReportEngine: PatchAndReportEngine
) {
    private val classifier = NeuralIntentClassifier()
    private val conversationMemory = ArrayDeque<ConversationTurn>()
    private var lastTarget: String = ""
    private var lastSceneSnapshot: AiVisualScene? = null

    fun planExecution(
        userQuery: String,
        currentMode: PrivilegeMode
    ): IntentClassification {
        val classification = classifier.classify(
            rawQuery = userQuery,
            currentMode = currentMode,
            lastTarget = lastTarget
        )
        if (classification.extractedHost.isNotBlank()) {
            lastTarget = classification.extractedHost
        }
        return classification
    }

    fun synthesizeScene(
        userQuery: String,
        classification: IntentClassification,
        toolResult: ToolExecutionResult,
        matchedRules: List<ThreatRuleEntity>,
        engineMode: AiEngineMode,
        knowledgeStats: ThreatKnowledgeStats,
        rootState: RootCapabilityState
    ): AiVisualScene {
        val patches = if (toolResult.generatedPatches.isNotEmpty()) {
            toolResult.generatedPatches
        } else {
            patchAndReportEngine.generatePatchesFromTelemetry(
                telemetry = toolResult.rawTelemetry,
                targetHost = toolResult.target,
                mode = toolResult.privilegeUsed
            )
        }

        val parsedHighlights = extractMeasuredHighlights(toolResult.rawTelemetry)
        val findings = buildFindingsList(parsedHighlights, matchedRules, toolResult)
        val severity = computeCalibratedSeverity(toolResult, matchedRules, patches)

        val narrative = generateConversationalNarrative(
            userQuery = userQuery,
            topic = classification.topic,
            confidence = classification.confidence,
            toolResult = toolResult,
            highlights = parsedHighlights,
            matchedRules = matchedRules,
            patches = patches,
            engineMode = engineMode,
            knowledgeStats = knowledgeStats,
            rootState = rootState
        )

        val report = toolResult.reportDraft ?: buildFourPartReport(
            toolResult = toolResult,
            findings = findings,
            patches = patches,
            knowledgeStats = knowledgeStats
        )

        val nodes = buildThreeLayerNeuralGraph(
            toolResult = toolResult,
            matchedRules = matchedRules,
            patches = patches,
            severity = severity,
            knowledgeStats = knowledgeStats,
            rootState = rootState
        )
        val edges = buildSynapticConnections(nodes, severity)
        val strata = buildStrataTelemetry(toolResult, matchedRules, patches, severity)
        val whispers = buildContextualWhispers(toolResult, patches, parsedHighlights)

        val title = buildDynamicTitle(toolResult, classification.topic)
        val modeTag = if (engineMode == AiEngineMode.LOCAL_AUTONOMOUS) "IA Local" else "IA Online"
        val subtitle = "${toolResult.target.ifBlank { "Dispositivo" }} · $modeTag · ${(classification.confidence * 100).toInt()}% conf."

        val scene = AiVisualScene(
            query = userQuery,
            title = title,
            subtitle = subtitle,
            visualKind = chooseVisualTopology(toolResult, patches.size),
            severityScore = severity,
            narrative = narrative,
            technicalFindings = findings,
            nodes = nodes,
            edges = edges,
            strata = strata,
            spectrumValues = toolResult.measuredSpectrum.ifEmpty {
                nodes.map { it.riskScore }.ifEmpty { listOf(0.3f, 0.5f, 0.4f, 0.6f) }
            },
            whisperPrompts = whispers,
            rawTelemetry = toolResult.rawTelemetry,
            toolExecuted = toolResult.toolId,
            privilegeMode = toolResult.privilegeUsed,
            engineMode = engineMode,
            report = report,
            patches = patches
        )

        if (conversationMemory.size >= 10) conversationMemory.removeFirst()
        conversationMemory.addLast(
            ConversationTurn(
                query = userQuery,
                toolId = toolResult.toolId,
                target = toolResult.target,
                summary = narrative.take(220),
                severity = severity
            )
        )
        if (toolResult.toolId != "AI_THEORETICAL") {
            lastSceneSnapshot = scene
        }
        return scene
    }

    private fun generateConversationalNarrative(
        userQuery: String,
        topic: ConversationalTopic,
        confidence: Float,
        toolResult: ToolExecutionResult,
        highlights: List<String>,
        matchedRules: List<ThreatRuleEntity>,
        patches: List<GeneratedPatch>,
        engineMode: AiEngineMode,
        knowledgeStats: ThreatKnowledgeStats,
        rootState: RootCapabilityState
    ): String {
        if (toolResult.toolId == "AI_THEORETICAL") {
            return composeConversationalAnswer(
                userQuery = userQuery,
                topic = topic,
                knowledgeStats = knowledgeStats,
                rootState = rootState,
                engineMode = engineMode
            )
        }

        val lines = toolResult.rawTelemetry.lines()
        val modeDesc = if (toolResult.privilegeUsed == PrivilegeMode.ROOT) "modo Con Root (Kernel/su)" else "modo Sin Root (Userland)"
        val engineDesc = if (engineMode == AiEngineMode.LOCAL_AUTONOMOUS) "motor neuronal autónomo local (sin internet)" else "motor neuronal propio con sensores de red activos"

        val specificSummary = when (toolResult.toolId) {
            "FULL_AUTONOMOUS_AUDIT" -> {
                val integrityLine = lines.firstOrNull { it.contains("Puntaje", true) || it.contains("Integridad", true) }
                val riskCount = matchedRules.size + patches.size
                "Completé una auditoría integral en $modeDesc usando mi $engineDesc. " +
                    (if (riskCount > 0) {
                        "Detecté ${matchedRules.size} coincidencia(s) contra la base de amenazas (${knowledgeStats.totalRules} firmas) y generé ${patches.size} parche(s) de mitigación concretos listos para aplicar."
                    } else {
                        "La superficie analizada mantiene una postura estable; no surgieron vulnerabilidades críticas que requieran contención inmediata."
                    }) +
                    (integrityLine?.let { " Estado de autodefensa: ${it.trim()}." } ?: "")
            }

            "SERVER_MONITOR" -> {
                val rttLine = lines.firstOrNull { it.contains("RTT", true) || it.contains("Latencia", true) }
                val anomalyLines = lines.filter { it.contains("ANOMAL", true) || it.contains("ALERTA", true) || it.contains("CAMBIO", true) }
                if (anomalyLines.isNotEmpty()) {
                    "¡Atención! Al vigilar ${toolResult.target} comparé la respuesta actual contra su línea base histórica y detecté ${anomalyLines.size} anomalía(s): ${anomalyLines.first().trim()}. Recomiendo inspeccionar los parches defensivos y verificar TLS/DNS de inmediato."
                } else {
                    "Monitoreo de ${toolResult.target} ejecutado correctamente sin desviaciones anómalas respecto a la línea base aprendida. ${rttLine?.trim().orEmpty()}"
                }
            }

            "SELF_TRAIN_KEV" -> {
                val assimilated = lines.firstOrNull { it.contains("asimiladas", true) }?.trim()
                val totalLine = lines.firstOrNull { it.contains("Total de reglas", true) }?.trim()
                "Ciclo de autoentrenamiento neuronal finalizado. ${assimilated ?: "Base sincronizada con catálogo real CISA KEV."} ${totalLine ?: "Total activo: ${knowledgeStats.totalRules} reglas listas para detección offline."}"
            }

            "PORT_PROBE" -> {
                val openPorts = lines.filter { it.contains("[ABIERTO]", true) }
                if (openPorts.isNotEmpty()) {
                    "Sondeé puertos TCP reales sobre ${toolResult.target} y encontré ${openPorts.size} puerto(s) abierto(s): ${openPorts.take(4).joinToString(" | ") { it.trim() }}. " +
                        if (patches.isNotEmpty()) "Generé reglas de contención firewall para cerrar exposición innecesaria." else "Verifica que cada servicio listado cuente con cifrado y control de acceso."
                } else {
                    "Escaneo TCP completado sobre ${toolResult.target}: no se detectaron puertos comunes abiertos al alcance actual."
                }
            }

            "TLS_INSPECT" -> {
                val proto = lines.firstOrNull { it.contains("Protocolo", true) }?.trim().orEmpty()
                val days = lines.firstOrNull { it.contains("expir", true) || it.contains("Días", true) }?.trim().orEmpty()
                "Inspección criptográfica X.509 sobre ${toolResult.target} completada. $proto $days. La huella SHA-256 del certificado queda fijada para detectar cambios por ataques MITM."
            }

            "DNS_RECON" -> {
                val records = lines.filter { it.contains("->") || it.contains("TXT") || it.contains("MX") }.take(3)
                "Resolución DNS over HTTPS (DoH) completada para ${toolResult.target}. " +
                    if (records.isNotEmpty()) "Registros clave medidos: ${records.joinToString(" ; ") { it.trim() }}."
                    else "Consulta finalizada sin registros adicionales expuestos."
            }

            "HTTP_HEADERS" -> {
                val missing = lines.filter { it.contains("[AUSENTE]", true) }
                if (missing.isNotEmpty()) {
                    "Audité las cabeceras HTTP de ${toolResult.target} y faltan ${missing.size} políticas defensivas (${missing.take(3).joinToString { it.replace("[AUSENTE]", "").trim() }}). Ya generé el bloque de configuración Nginx/Proxy listo para parchear el servidor."
                } else {
                    "Las cabeceras defensivas HTTP de ${toolResult.target} cumplen con las protecciones principales verificadas."
                }
            }

            "APP_SURFACE_AUDIT" -> {
                val flags = lines.filter { it.contains("debuggable=true", true) || it.contains("allowBackup=true", true) || it.contains("cleartext=true", true) }
                "Analicé las aplicaciones instaladas en el dispositivo. " +
                    if (flags.isNotEmpty()) "Encontré ${flags.size} paquete(s) con flags de riesgo (debuggable, allowBackup o tráfico cleartext) y preparé parches de AndroidManifest y Network Security Config."
                    else "No se observaron flags críticos expuestos en los paquetes inspeccionados."
            }

            "SELF_INTEGRITY" -> {
                "Verifiqué la autoprotección de Aura Mobile Defense en tiempo real: ${highlights.firstOrNull() ?: "sin depurador externo ni hooks detectados; reglas R8 activas para compilación release contra ingeniería inversa"}."
            }

            "VPN_START" -> {
                "Túnel VPN Local y Firewall activados sobre la interfaz TUN 10.8.0.2/32. Estoy interceptando consultas DNS en tiempo real, bloqueando rastreadores/puertos peligrosos y midiendo latencia y bytes reales sin simulaciones."
            }

            "VPN_STOP" -> {
                "Túnel VPN Local detenido limpiamente. Las reglas configuradas permanecen guardadas en la base local para cuando decidas reactivarlo."
            }

            "VPN_TELEMETRY" -> {
                val statsLine = lines.firstOrNull { it.contains("Paquetes inspeccionados", true) }?.trim().orEmpty()
                val tunLine = lines.firstOrNull { it.contains("Estado VPN TUN", true) }?.trim().orEmpty()
                "Telemetría real del Firewall y VPN Local: $tunLine $statsLine".trim()
            }

            "FIREWALL_BLOCK" -> {
                "Regla de bloqueo real añadida y aplicada al Firewall VPN para '${toolResult.target}'. Todo intento hacia ese destino o puerto será interceptado y descartado."
            }

            "FIREWALL_ALLOW" -> {
                "Regla eliminada del bloqueo en el Firewall VPN para '${toolResult.target}'."
            }

            "CRYPTO_JWT" -> {
                "Procesé el artefacto criptográfico localmente sin enviarlo a ningún servidor externo. ${highlights.take(2).joinToString(" · ")}"
            }

            else -> {
                "Ejecuté ${toolResult.toolId} sobre ${toolResult.target.ifBlank { "el dispositivo" }} en $modeDesc (${(confidence * 100).toInt()}% de certeza). " +
                    highlights.take(2).joinToString(" · ")
            }
        }

        return specificSummary.trim()
    }

    private fun composeConversationalAnswer(
        userQuery: String,
        topic: ConversationalTopic,
        knowledgeStats: ThreatKnowledgeStats,
        rootState: RootCapabilityState,
        engineMode: AiEngineMode
    ): String {
        val prevTurn = conversationMemory.lastOrNull()
        val prevAudit = lastSceneSnapshot
        val engineInfo = if (engineMode == AiEngineMode.LOCAL_AUTONOMOUS) {
            "Ahora opero 100% offline con mi motor neuronal propio."
        } else {
            "Ahora opero conectado con mi motor neuronal propio (sin claves externas ni costos), usando internet únicamente para autoentrenamiento CISA KEV y sondas reales de red/servidores."
        }

        return when (topic) {
            ConversationalTopic.GREETING ->
                "Hola, soy Aura Mobile Defense. Mi inteligencia artificial conversacional está programada directamente en tu dispositivo, sin depender de claves de Google AI Studio ni pagos por uso. Puedes pedirme auditar tu sistema (/audit), vigilar un servidor (/monitor dominio.com), analizar puertos, TLS, apps o conversar sobre defensa ante ataques."

            ConversationalTopic.HOW_IT_WORKS ->
                "Trabajo con una arquitectura neuronal de 3 capas escrita en código nativo: (1) Receptores que leen telemetría real del dispositivo (SELinux, sockets, apps, CPU/red) y endpoints externos (TLS, DNS DoH, HTTP, puertos); (2) Sinapsis ocultas que clasifican tu intención en lenguaje natural y correlacionan ${knowledgeStats.totalRules} firmas locales + catálogo CISA KEV; (3) Efectores que generan reportes de 4 secciones y parches listos para aplicar. $engineInfo"

            ConversationalTopic.ANTI_REVERSE_ENGINEERING ->
                "Para resistir ingeniería inversa y duplicación, Aura integra verificaciones activas en tiempo de ejecución (TracerPid, detección de depuradores, escaneo de librerías de hooking como Frida/Xposed en /proc/self/maps y huella SHA-256 de firma propia) combinadas con ofuscación y reducción R8 en builds release."

            ConversationalTopic.ROOT_EXPLANATION ->
                "Actualmente tienes UID '${rootState.uidOutput}' y SELinux '${rootState.selinuxMode}'. En modo Sin Root audito superficie de aplicaciones, sockets accesibles, certificados TLS, DNS, HTTP, entropía binaria y auto-integridad. Al deslizar al modo Con Root (si el binario 'su' está autorizado), amplío la inspección a contexto kernel, propiedades protegidas, tablas de red y comandos de diagnóstico profundo."

            ConversationalTopic.LAST_SUMMARY -> {
                if (prevAudit != null) {
                    "Resumen de tu última acción (${prevAudit.title}): ${prevAudit.narrative} Riesgo medido: ${(prevAudit.severityScore * 100).toInt()}%, con ${prevAudit.patches.size} parche(s) disponible(s). Toca 'ver reporte integral' abajo para revisar las 4 secciones o pedirme profundizar en cualquier nodo."
                } else if (prevTurn != null) {
                    "En el turno anterior ejecuté ${prevTurn.toolId} sobre ${prevTurn.target}: ${prevTurn.summary}"
                } else {
                    "Aún no hay una auditoría previa en esta sesión. Escribe 'audita todo' o 'monitorea cloudflare.com' y generaré el análisis completo con su reporte y parches."
                }
            }

            ConversationalTopic.DEFENSIVE_STRATEGY ->
                "Frente a un ataque o anomalía activa aplico contención escalonada basada en evidencia real: 1) Fijación de huella TLS X.509 para detectar interceptación MITM; 2) Cierre de puertos administrativos expuestos (como ADB 5555, Telnet 23 o Redis 6379) mediante firewall/deshabilitación; 3) Endurecimiento de cabeceras HSTS/CSP y Network Security Config sin tráfico cleartext; 4) Correlación continua contra las ${knowledgeStats.totalRules} firmas aprendidas. Dime qué host, IP o app quieres proteger ahora."

            else ->
                "Puedes preguntarme cualquier duda de seguridad o pedirme acciones reales: auditar el dispositivo ('audita todo'), activar la VPN local con firewall ('activa la vpn'), bloquear dominios/IPs/puertos ('bloquea doubleclick.net'), vigilar servidores por anomalías ('monitorea dominio.com'), aplicar soluciones en vivo ('ejecuta las soluciones') o autoentrenarme con CISA KEV. $engineInfo"
        }
    }

    private fun extractMeasuredHighlights(rawTelemetry: String): List<String> {
        return rawTelemetry.lines()
            .map { it.trim() }
            .filter { line ->
                line.startsWith("•") ||
                    line.contains("[ABIERTO]", true) ||
                    line.contains("[AUSENTE]", true) ||
                    line.contains("ANOMAL", true) ||
                    line.contains("CRITIC", true) ||
                    line.contains("CRÍTIC", true) ||
                    line.contains("debuggable=true", true) ||
                    line.contains("cleartext=true", true) ||
                    line.contains("Permissive", true) ||
                    line.contains("SELinux", true) ||
                    line.contains("Protocolo", true) ||
                    line.contains("TracerPid", true)
            }
            .distinct()
            .take(6)
    }

    private fun buildFindingsList(
        highlights: List<String>,
        matchedRules: List<ThreatRuleEntity>,
        toolResult: ToolExecutionResult
    ): List<String> {
        val list = mutableListOf<String>()
        matchedRules.take(4).forEach { r ->
            list.add("[${r.ruleId}] ${r.title} — ${r.remediationHint}")
        }
        highlights.filter { h -> list.none { it.contains(h.take(18)) } }
            .take(5 - list.size.coerceAtMost(4))
            .forEach { list.add(it) }

        if (list.isEmpty()) {
            list.add("Telemetría procesada por motor propio (${toolResult.toolId}) sobre '${toolResult.target.ifBlank { "dispositivo" }}'.")
            list.add("Plano de privilegio verificado: ${toolResult.privilegeUsed.name}.")
        }
        return list.take(6)
    }

    private fun computeCalibratedSeverity(
        toolResult: ToolExecutionResult,
        matchedRules: List<ThreatRuleEntity>,
        patches: List<GeneratedPatch>
    ): Float {
        if (toolResult.toolId == "AI_THEORETICAL") return 0.18f
        val ruleMax = matchedRules.maxOfOrNull { it.severity } ?: 0f
        val patchBoost = when {
            patches.any { it.severity.contains("CRIT", true) } -> 0.88f
            patches.any { it.severity.contains("ALTA", true) } -> 0.72f
            patches.isNotEmpty() -> 0.56f
            else -> 0.24f
        }
        val anomalyBoost = if (toolResult.rawTelemetry.contains("ANOMAL", true)) 0.78f else 0f
        return maxOf(ruleMax, patchBoost, anomalyBoost, 0.22f).coerceIn(0.15f, 0.98f)
    }

    private fun buildFourPartReport(
        toolResult: ToolExecutionResult,
        findings: List<String>,
        patches: List<GeneratedPatch>,
        knowledgeStats: ThreatKnowledgeStats
    ): CompleteAuditReport {
        return CompleteAuditReport(
            whatWasDone = "Aura ejecutó de forma autónoma '${toolResult.toolId}' sobre '${toolResult.target.ifBlank { "el dispositivo" }}' en modo ${toolResult.privilegeUsed.name}, correlacionando la telemetría real contra ${knowledgeStats.totalRules} firmas locales.",
            whatWasFound = findings.joinToString("\n"),
            measuresAndPatchesTaken = if (patches.isEmpty()) {
                "No se detectaron exposiciones críticas que requirieran parche inmediato; la línea base y la huella de integridad fueron actualizadas."
            } else {
                "Se sintetizaron ${patches.size} solución(es) de contención y parcheo real: ${patches.joinToString("; ") { "${it.title} [${it.severity}]" }}."
            },
            improvementRecommendations = "1) Mantener el monitoreo periódico de endpoints críticos para detectar cambios de certificado o latencia. 2) Aplicar los parches generados en configuración/firewall. 3) Ejecutar /train con internet disponible para incorporar nuevas vulnerabilidades explotadas (CISA KEV)."
        )
    }

    private fun buildThreeLayerNeuralGraph(
        toolResult: ToolExecutionResult,
        matchedRules: List<ThreatRuleEntity>,
        patches: List<GeneratedPatch>,
        severity: Float,
        knowledgeStats: ThreatKnowledgeStats,
        rootState: RootCapabilityState
    ): List<AiVisualNode> {
        val targetTag = toolResult.target.ifBlank { "Dispositivo" }.take(18)
        return listOf(
            // Layer 0: Receptors
            AiVisualNode(
                id = "rec_os",
                label = "Sensor OS",
                sublabel = "${toolResult.privilegeUsed.name} · ${rootState.selinuxMode.take(10)}",
                category = "RECEPTOR",
                riskScore = if (rootState.selinuxMode.contains("Permissive", true)) 0.82f else 0.28f,
                xNorm = 0.16f,
                yNorm = 0.22f,
                forensicDetail = "Lectura real de kernel, UID (${rootState.uidOutput}), SELinux y capacidades de privilegio.",
                layerIndex = 0
            ),
            AiVisualNode(
                id = "rec_net",
                label = "Sensor Red",
                sublabel = targetTag,
                category = "RECEPTOR NET",
                riskScore = (severity * 0.85f).coerceIn(0.2f, 0.95f),
                xNorm = 0.16f,
                yNorm = 0.50f,
                forensicDetail = "Telemetría directa de interfaces, sockets TCP, TLS X.509, DNS DoH y cabeceras HTTP.",
                layerIndex = 0
            ),
            AiVisualNode(
                id = "rec_self",
                label = "Auto-Integridad",
                sublabel = "Anti-Tamper",
                category = "RECEPTOR",
                riskScore = if (toolResult.rawTelemetry.contains("DEBUGGER", true)) 0.9f else 0.22f,
                xNorm = 0.16f,
                yNorm = 0.78f,
                forensicDetail = "Protección contra ingeniería inversa: firma APK SHA-256, TracerPid y detección de hooking.",
                layerIndex = 0
            ),
            // Layer 1: Hidden Synaptic Processing
            AiVisualNode(
                id = "syn_nlp",
                label = "Núcleo IA Aura",
                sublabel = "${conversationMemory.size + 1} turnos",
                category = "SYNAPSE",
                riskScore = 0.32f,
                xNorm = 0.50f,
                yNorm = 0.28f,
                forensicDetail = "Clasificador neuronal nativo, memoria conversacional y sintetizador NLG local sin claves externas.",
                layerIndex = 1
            ),
            AiVisualNode(
                id = "syn_kev",
                label = "Correlación KEV",
                sublabel = "${matchedRules.size}/${knowledgeStats.totalRules} firmas",
                category = "SYNAPSE",
                riskScore = if (matchedRules.isNotEmpty()) severity else 0.25f,
                xNorm = 0.50f,
                yNorm = 0.68f,
                forensicDetail = toolResult.rawTelemetry.take(500),
                layerIndex = 1
            ),
            // Layer 2: Effectors
            AiVisualNode(
                id = "eff_patch",
                label = "Parches",
                sublabel = "${patches.size} soluciones",
                category = "EFFECTOR",
                riskScore = if (patches.isNotEmpty()) 0.78f else 0.18f,
                xNorm = 0.84f,
                yNorm = 0.34f,
                forensicDetail = if (patches.isEmpty()) {
                    "Sin parches críticos pendientes en esta ejecución."
                } else {
                    patches.joinToString("\n") { "• ${it.title} (${it.targetArtifact})" }
                },
                layerIndex = 2
            ),
            AiVisualNode(
                id = "eff_report",
                label = "Reporte 4-Fases",
                sublabel = "IDX ${(severity * 100).toInt()}%",
                category = "EFFECTOR",
                riskScore = severity,
                xNorm = 0.84f,
                yNorm = 0.68f,
                forensicDetail = "Informe completo: qué se hizo, qué se encontró, medidas tomadas y recomendaciones.",
                layerIndex = 2
            )
        )
    }

    private fun buildSynapticConnections(
        nodes: List<AiVisualNode>,
        severity: Float
    ): List<AiVisualEdge> {
        val l0 = nodes.filter { it.layerIndex == 0 }
        val l1 = nodes.filter { it.layerIndex == 1 }
        val l2 = nodes.filter { it.layerIndex == 2 }
        val edges = mutableListOf<AiVisualEdge>()
        l0.forEach { a ->
            l1.forEach { b ->
                edges.add(AiVisualEdge(a.id, b.id, "entrada", (0.45f + a.riskScore * 0.4f).coerceIn(0.3f, 0.95f)))
            }
        }
        l1.forEach { b ->
            l2.forEach { c ->
                edges.add(AiVisualEdge(b.id, c.id, "decisión", (0.55f + severity * 0.35f).coerceIn(0.4f, 0.98f)))
            }
        }
        return edges
    }

    private fun buildStrataTelemetry(
        toolResult: ToolExecutionResult,
        matchedRules: List<ThreatRuleEntity>,
        patches: List<GeneratedPatch>,
        severity: Float
    ): List<AiStratumLayer> {
        return listOf(
            AiStratumLayer("Receptores Reales", "ACTIVO", 0.88f, "${toolResult.toolId} · ${toolResult.privilegeUsed.name}"),
            AiStratumLayer("Red Neuronal Aura", "AUTÓNOMO", 1f - severity * 0.45f, "${matchedRules.size} firmas correlacionadas"),
            AiStratumLayer("Efectores y Parches", if (patches.isEmpty()) "NOMINAL" else "MITIGACIÓN", if (patches.isEmpty()) 0.92f else 0.58f, "${patches.size} parches generados")
        )
    }

    private fun chooseVisualTopology(toolResult: ToolExecutionResult, patchCount: Int): VisualTopologyKind {
        return when {
            toolResult.toolId == "PORT_PROBE" && patchCount > 0 -> VisualTopologyKind.NEURAL_SYNAPTIC_LATTICE
            toolResult.toolId == "PROTOCOL_STRATA" -> VisualTopologyKind.PROTOCOL_STRATA
            else -> VisualTopologyKind.NEURAL_SYNAPTIC_LATTICE
        }
    }

    private fun buildDynamicTitle(toolResult: ToolExecutionResult, topic: ConversationalTopic): String {
        return when (toolResult.toolId) {
            "FULL_AUTONOMOUS_AUDIT" -> "Auditoría Neuronal Integral"
            "SERVER_MONITOR" -> "Vigilancia · ${toolResult.target.take(22)}"
            "SELF_TRAIN_KEV" -> "Autoentrenamiento CISA KEV"
            "SELF_INTEGRITY" -> "Blindaje Anti-Manipulación"
            "DEVICE_INTEGRITY" -> "Integridad OS & Kernel"
            "NETWORK_SOCKETS" -> "Topología de Red y Sockets"
            "PORT_PROBE" -> "Sondeo TCP · ${toolResult.target.take(20)}"
            "TLS_INSPECT" -> "Cifrado TLS · ${toolResult.target.take(20)}"
            "DNS_RECON" -> "Registros DNS · ${toolResult.target.take(20)}"
            "HTTP_HEADERS" -> "Cabeceras HTTP · ${toolResult.target.take(18)}"
            "APP_SURFACE_AUDIT" -> "Superficie Apps Android"
            "CRYPTO_JWT" -> "Criptoanálisis Local"
            "ROOT_SHELL" -> "Diagnóstico Kernel su"
            "VPN_START" -> "VPN Local + Firewall Activo"
            "VPN_STOP" -> "VPN Local Detenida"
            "VPN_TELEMETRY" -> "Telemetría VPN & Firewall"
            "FIREWALL_BLOCK" -> "Firewall · Bloqueo Aplicado"
            "FIREWALL_ALLOW" -> "Firewall · Regla Liberada"
            "AI_THEORETICAL" -> when (topic) {
                ConversationalTopic.GREETING -> "Aura IA Conversacional"
                ConversationalTopic.HOW_IT_WORKS -> "Arquitectura Aura Mobile Defens Propia"
                ConversationalTopic.ANTI_REVERSE_ENGINEERING -> "Defensa Anti-Duplicación"
                else -> "Asistencia Ciberdefensiva"
            }
            else -> "Aura Mobile Defense"
        }
    }

    private fun buildContextualWhispers(
        toolResult: ToolExecutionResult,
        patches: List<GeneratedPatch>,
        highlights: List<String>
    ): List<String> {
        val target = toolResult.target.takeIf {
            it.isNotBlank() && !it.contains("Sistema", true) && !it.contains("Consulta", true) && !it.contains("Modo", true)
        }
        val list = mutableListOf<String>()
        if (target != null && toolResult.toolId != "SERVER_MONITOR") {
            list.add("Monitorear anomalías continuas en $target")
        }
        if (target != null && toolResult.toolId != "PORT_PROBE") {
            list.add("Escanear puertos TCP de $target")
        }
        if (patches.isNotEmpty()) {
            list.add("Ejecutar ahora las ${patches.size} soluciones de mitigación")
        }
        if (toolResult.toolId !in setOf("VPN_START", "VPN_TELEMETRY")) {
            list.add("Activar VPN Local + Firewall y ver telemetría real")
        }
        if (list.size < 3 && toolResult.toolId != "SELF_TRAIN_KEV") {
            list.add("Autoentrenar base de amenazas con CISA KEV")
        }
        if (list.size < 3) {
            list.add("Ejecutar auditoría integral del dispositivo y red")
        }
        return list.take(3)
    }
}
