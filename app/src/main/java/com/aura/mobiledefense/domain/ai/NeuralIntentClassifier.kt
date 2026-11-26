package com.aura.mobiledefense.domain.ai

import com.aura.mobiledefense.data.model.ForensicToolPlan
import com.aura.mobiledefense.data.model.PrivilegeMode
import java.text.Normalizer
import kotlin.math.exp

enum class ConversationalTopic {
    NONE,
    GREETING,
    CAPABILITIES,
    HOW_IT_WORKS,
    ANTI_REVERSE_ENGINEERING,
    ROOT_EXPLANATION,
    DEFENSIVE_STRATEGY,
    LAST_SUMMARY
}

data class IntentClassification(
    val plan: ForensicToolPlan,
    val topic: ConversationalTopic,
    val confidence: Float,
    val extractedHost: String
)

/**
 * Self-contained neural intent classifier built from scratch in Kotlin.
 * Uses diacritic-folded unigram/bigram weights, entity extraction, and multi-turn context bias
 * with zero external LLM APIs or paid keys.
 */
class NeuralIntentClassifier {

    private data class IntentRuleSet(
        val toolId: String,
        val focus: String,
        val prefersRoot: Boolean = false,
        val weights: Map<String, Float>
    )

    private val intentNeurons = listOf(
        IntentRuleSet(
            toolId = "FULL_AUTONOMOUS_AUDIT",
            focus = "Auditoría integral autónoma y generación de parches",
            weights = mapOf(
                "audita" to 3.4f, "auditoria" to 3.6f, "audit" to 3.4f,
                "vulnerabilidad" to 3.0f, "vulnerabilidades" to 3.2f, "revisa" to 1.8f,
                "analiza" to 1.6f, "sistema" to 1.9f, "completo" to 2.2f, "completa" to 2.2f,
                "parche" to 2.6f, "parches" to 2.8f, "solucion" to 2.2f, "soluciones" to 2.2f,
                "reporte" to 2.5f, "informe" to 2.5f, "diagnostico" to 2.2f,
                "seguridad" to 1.6f, "todo" to 1.8f, "protege" to 2.1f, "escaneo" to 1.9f
            )
        ),
        IntentRuleSet(
            toolId = "SERVER_MONITOR",
            focus = "Monitoreo continuo de red y detección de anomalías",
            weights = mapOf(
                "monitorea" to 3.8f, "monitoreo" to 3.8f, "monitor" to 3.6f,
                "vigila" to 3.5f, "vigilancia" to 3.4f, "servidor" to 3.1f, "servidores" to 3.1f,
                "anomalia" to 3.6f, "anomalias" to 3.6f, "anormal" to 3.2f,
                "latencia" to 2.7f, "caida" to 2.4f, "linea" to 1.8f, "base" to 1.6f,
                "continuo" to 2.4f, "alerta" to 2.3f, "endpoint" to 2.4f
            )
        ),
        IntentRuleSet(
            toolId = "SELF_TRAIN_KEV",
            focus = "Autoentrenamiento desde catálogo de amenazas en internet",
            weights = mapOf(
                "autoentrena" to 4.2f, "autoentrenar" to 4.2f, "autoentrenamiento" to 4.2f,
                "entrena" to 3.8f, "entrenar" to 3.8f, "entrenamiento" to 3.8f,
                "aprende" to 3.2f, "actualizar" to 2.3f, "actualiza" to 2.5f,
                "kev" to 4.0f, "cisa" to 4.0f, "cve" to 3.0f, "firmas" to 2.8f,
                "amenazas" to 2.2f, "internet" to 2.4f, "feed" to 2.8f
            )
        ),
        IntentRuleSet(
            toolId = "SELF_INTEGRITY",
            focus = "Auto-integridad y protección anti-ingeniería inversa",
            weights = mapOf(
                "integridad" to 3.4f, "ingenieria" to 3.5f, "inversa" to 3.5f,
                "duplicacion" to 3.3f, "clonacion" to 3.1f, "ofuscacion" to 3.2f,
                "tamper" to 3.4f, "debugger" to 3.2f, "depurador" to 3.1f,
                "frida" to 3.6f, "xposed" to 3.6f, "hook" to 3.0f, "hooking" to 3.2f,
                "firma" to 2.4f, "tracerpid" to 3.5f, "autoproteccion" to 3.3f
            )
        ),
        IntentRuleSet(
            toolId = "DEVICE_INTEGRITY",
            focus = "Auditoría de kernel, SELinux, propiedades OS y Keystore",
            weights = mapOf(
                "dispositivo" to 3.0f, "telefono" to 2.8f, "movil" to 2.4f,
                "kernel" to 3.6f, "selinux" to 3.8f, "enforcing" to 3.2f,
                "permissive" to 3.2f, "bootloader" to 3.4f, "keystore" to 3.2f,
                "android" to 2.0f, "propiedades" to 2.8f, "getprop" to 3.5f,
                "entorno" to 2.6f, "hardware" to 2.4f, "compilacion" to 2.3f
            )
        ),
        IntentRuleSet(
            toolId = "NETWORK_SOCKETS",
            focus = "Inspección de interfaces, DNS, VPN y sockets TCP",
            weights = mapOf(
                "red" to 2.9f, "redes" to 2.9f, "socket" to 3.7f, "sockets" to 3.7f,
                "wifi" to 3.1f, "vpn" to 3.2f, "interfaz" to 2.9f, "interfaces" to 2.9f,
                "conexiones" to 3.1f, "trafico" to 2.8f, "arp" to 3.4f, "iptables" to 3.4f,
                "ip" to 2.0f, "enlaces" to 2.3f, "abiertas" to 1.9f
            )
        ),
        IntentRuleSet(
            toolId = "PORT_PROBE",
            focus = "Sondeo concurrente de puertos TCP y banners",
            weights = mapOf(
                "puerto" to 4.0f, "puertos" to 4.0f, "port" to 3.8f, "ports" to 3.8f,
                "banner" to 3.4f, "banners" to 3.4f, "tcp" to 2.8f, "escanea" to 2.7f,
                "escanear" to 2.7f, "adb" to 2.8f, "5555" to 3.2f, "ssh" to 2.7f
            )
        ),
        IntentRuleSet(
            toolId = "TLS_INSPECT",
            focus = "Inspección de certificados X.509 y cifrado TLS",
            weights = mapOf(
                "tls" to 4.2f, "ssl" to 4.0f, "certificado" to 3.9f, "certificados" to 3.9f,
                "x509" to 3.9f, "https" to 2.7f, "caduca" to 2.9f, "expira" to 2.8f,
                "emisor" to 2.7f, "mitm" to 2.6f, "cifrado" to 2.1f, "handshake" to 3.5f
            )
        ),
        IntentRuleSet(
            toolId = "DNS_RECON",
            focus = "Resolución y auditoría de registros DNS DoH",
            weights = mapOf(
                "dns" to 4.3f, "mx" to 3.4f, "txt" to 3.2f, "spf" to 3.6f,
                "dmarc" to 3.6f, "aaaa" to 3.3f, "ns" to 2.9f, "dominio" to 2.4f,
                "subdominio" to 2.7f, "registros" to 2.5f, "doh" to 3.8f
            )
        ),
        IntentRuleSet(
            toolId = "HTTP_HEADERS",
            focus = "Auditoría de cabeceras de seguridad HTTP",
            weights = mapOf(
                "http" to 3.1f, "cabecera" to 4.0f, "cabeceras" to 4.0f,
                "header" to 3.9f, "headers" to 3.9f, "hsts" to 3.8f,
                "csp" to 3.8f, "xfo" to 3.5f, "cors" to 3.4f, "web" to 2.2f
            )
        ),
        IntentRuleSet(
            toolId = "APP_SURFACE_AUDIT",
            focus = "Auditoría de superficie en aplicaciones instaladas",
            weights = mapOf(
                "app" to 3.2f, "apps" to 3.4f, "aplicacion" to 2.8f, "aplicaciones" to 3.2f,
                "paquete" to 3.3f, "paquetes" to 3.3f, "apk" to 3.2f, "instaladas" to 3.4f,
                "debuggable" to 3.6f, "allowbackup" to 3.6f, "cleartext" to 3.2f, "permisos" to 2.5f
            )
        ),
        IntentRuleSet(
            toolId = "CRYPTO_JWT",
            focus = "Decodificación JWT e identificación criptográfica",
            weights = mapOf(
                "jwt" to 4.5f, "token" to 3.8f, "hash" to 3.9f, "sha256" to 3.8f,
                "md5" to 3.6f, "base64" to 3.4f, "entropia" to 3.4f, "cripto" to 3.5f,
                "criptografia" to 3.5f, "algoritmo" to 2.8f, "decodifica" to 3.5f
            )
        ),
        IntentRuleSet(
            toolId = "ROOT_SHELL",
            focus = "Inspección de diagnóstico kernel con privilegio su",
            prefersRoot = true,
            weights = mapOf(
                "su" to 3.6f, "shell" to 3.8f, "dmesg" to 4.0f, "netstat" to 3.6f,
                "lsmod" to 3.9f, "ps" to 3.0f, "comando" to 2.9f
            )
        ),
        IntentRuleSet(
            toolId = "VPN_START",
            focus = "Activación de VPN Local 100% real y Firewall TUN",
            weights = mapOf(
                "vpn" to 3.4f, "activa" to 2.8f, "enciende" to 2.9f, "inicia" to 2.6f,
                "tunel" to 3.2f, "conecta" to 2.5f, "proteccion" to 1.8f, "tun" to 3.0f
            )
        ),
        IntentRuleSet(
            toolId = "VPN_STOP",
            focus = "Desactivación controlada de VPN Local",
            weights = mapOf(
                "vpn" to 2.9f, "apaga" to 3.4f, "desactiva" to 3.5f, "deten" to 3.3f,
                "cierra" to 2.8f, "desconecta" to 3.3f
            )
        ),
        IntentRuleSet(
            toolId = "VPN_TELEMETRY",
            focus = "Telemetría en tiempo real de VPN Local y Firewall",
            weights = mapOf(
                "vpn" to 3.2f, "firewall" to 3.6f, "cortafuegos" to 3.6f,
                "telemetria" to 3.5f, "paquetes" to 3.3f, "trafico" to 2.8f,
                "bloqueados" to 3.1f, "reglas" to 2.9f, "estado" to 2.3f
            )
        ),
        IntentRuleSet(
            toolId = "FIREWALL_BLOCK",
            focus = "Regla de bloqueo en Firewall Local VPN",
            weights = mapOf(
                "bloquea" to 4.2f, "bloquear" to 4.2f, "drop" to 3.5f,
                "deniega" to 3.8f, "impide" to 3.4f, "firewall" to 2.2f
            )
        ),
        IntentRuleSet(
            toolId = "FIREWALL_ALLOW",
            focus = "Eliminar bloqueo en Firewall Local VPN",
            weights = mapOf(
                "desbloquea" to 4.2f, "permite" to 3.8f, "permitir" to 3.8f,
                "libera" to 3.4f, "quita" to 2.5f
            )
        ),
        IntentRuleSet(
            toolId = "APP_FIREWALL_BLOCK",
            focus = "Bloqueo de una aplicación concreta a nivel de kernel (uid owner DROP)",
            weights = mapOf(
                "app" to 2.6f, "aplicacion" to 2.6f, "aplicaciones" to 1.8f,
                "paquete" to 3.2f, "bloquea" to 3.0f, "bloquear" to 3.0f,
                "corta" to 2.6f, "impide" to 2.2f
            ),
            prefersRoot = true
        ),
        IntentRuleSet(
            toolId = "APP_FIREWALL_ALLOW",
            focus = "Retirar el bloqueo de una aplicación concreta (kernel)",
            weights = mapOf(
                "app" to 2.6f, "aplicacion" to 2.6f, "paquete" to 3.2f,
                "desbloquea" to 4.0f, "permite" to 3.0f, "libera" to 2.8f
            ),
            prefersRoot = true
        ),
        IntentRuleSet(
            toolId = "APP_FIREWALL_LIST",
            focus = "Listar apps instaladas y reglas de bloqueo por app activas",
            weights = mapOf(
                "apps" to 3.4f, "aplicaciones" to 3.2f, "lista" to 3.2f,
                "listar" to 3.2f, "bloqueadas" to 3.8f, "instaladas" to 2.6f
            )
        ),
        IntentRuleSet(
            toolId = "INTEL_OSV_QUERY",
            focus = "Consulta de vulnerabilidades por paquete y versión exacta en OSV",
            weights = mapOf(
                "osv" to 5.0f, "vulnerabilidad" to 2.6f, "vulnerables" to 2.6f,
                "cve" to 2.4f, "paquete" to 2.0f, "version" to 1.6f
            )
        ),
        IntentRuleSet(
            toolId = "INTEL_URLHAUS_CHECK",
            focus = "Reputación de un host/URL en URLhaus (abuse.ch)",
            weights = mapOf(
                "urlhaus" to 5.0f, "malicioso" to 3.2f, "reputacion" to 3.4f,
                "abuse" to 3.0f, "malware" to 2.4f
            )
        ),
        IntentRuleSet(
            toolId = "EXECUTE_SOLUTIONS",
            focus = "Ejecución en vivo de soluciones y mitigaciones de vulnerabilidades",
            weights = mapOf(
                "ejecuta" to 4.0f, "ejecutar" to 4.0f, "aplica" to 3.8f, "aplicar" to 3.8f,
                "corrige" to 3.8f, "corregir" to 3.8f, "soluciona" to 3.9f, "solucionar" to 3.9f,
                "remedia" to 3.7f, "parchea" to 3.8f, "arregla" to 3.5f, "hazlo" to 3.6f,
                "soluciones" to 2.8f
            )
        ),
        IntentRuleSet(
            toolId = "AI_THEORETICAL",
            focus = "Asistencia conversacional autónoma de ciberdefensa",
            weights = mapOf(
                "hola" to 3.6f, "buenos" to 2.8f, "buenas" to 2.8f, "saludos" to 3.4f,
                "quien" to 3.1f, "eres" to 3.0f, "que" to 1.3f, "como" to 1.8f,
                "funcionas" to 3.8f, "funciona" to 3.4f, "puedes" to 2.6f, "haces" to 3.0f,
                "ayuda" to 3.2f, "explica" to 3.4f, "explicame" to 3.6f, "significa" to 3.3f,
                "porque" to 2.4f, "estrategia" to 3.0f, "recomiendas" to 2.9f,
                "recomendacion" to 2.9f, "resumen" to 3.2f, "resume" to 3.2f,
                "hiciste" to 3.1f, "encontraste" to 3.3f, "gratis" to 2.6f, "sin" to 1.1f,
                "pagar" to 2.8f, "gracias" to 3.4f
            )
        )
    )

    fun classify(
        rawQuery: String,
        currentMode: PrivilegeMode,
        lastTarget: String = ""
    ): IntentClassification {
        val trimmed = rawQuery.trim()
        val normalized = foldDiacritics(trimmed.lowercase())
        val tokens = tokenize(normalized)
        val extractedHost = extractHostOrIp(trimmed)
        val hasJwt = Regex("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*").containsMatchIn(trimmed)
        val hasHexHash = Regex("\\b[a-fA-F0-9]{32,128}\\b").containsMatchIn(trimmed)
        val packageMention = Regex("\\b[a-z][a-z0-9_]*(\\.[a-z0-9_]+){2,}\\b").find(trimmed)?.value.orEmpty()

        // 1. Explicit slash commands
        fastPath(trimmed, normalized, currentMode, extractedHost, lastTarget)?.let { plan ->
            return IntentClassification(plan, ConversationalTopic.NONE, 1.0f, extractedHost.ifBlank { lastTarget })
        }

        // 2. Direct cryptographic artifacts always trigger CRYPTO_JWT
        if (hasJwt || hasHexHash) {
            return IntentClassification(
                plan = ForensicToolPlan("CRYPTO_JWT", trimmed, "", false, "Análisis criptográfico y JWT"),
                topic = ConversationalTopic.NONE,
                confidence = 0.99f,
                extractedHost = extractedHost
            )
        }

        val portMention = Regex("\\b(\\d{2,5})\\b").find(normalized)?.groupValues?.getOrNull(1).orEmpty()
        val hasRuleTarget = extractedHost.isNotBlank() || portMention.isNotBlank()
        // 3. Feed-forward weighted neural scoring over token features
        val scores = mutableMapOf<String, Float>()
        intentNeurons.forEach { neuron ->
            var z = 0.05f
            tokens.forEach { tok ->
                neuron.weights[tok]?.let { w -> z += w }
                // Prefix stem matching for Spanish verb conjugations
                neuron.weights.forEach { (key, w) ->
                    if (tok.length >= 5 && key.length >= 5 && tok != key &&
                        (tok.startsWith(key.take(5)) || key.startsWith(tok.take(5)))
                    ) {
                        z += w * 0.55f
                    }
                }
            }
            // Contextual entity feature boosts
            if (extractedHost.isNotBlank()) {
                when (neuron.toolId) {
                    "SERVER_MONITOR", "PORT_PROBE", "TLS_INSPECT", "DNS_RECON", "HTTP_HEADERS", "FULL_AUTONOMOUS_AUDIT", "FIREWALL_BLOCK", "FIREWALL_ALLOW" -> z += 1.4f
                    "AI_THEORETICAL" -> z -= 1.2f
                }
            }
            if (hasRuleTarget && (neuron.toolId == "FIREWALL_BLOCK" || neuron.toolId == "FIREWALL_ALLOW")) {
                z += 1.2f
            }
            if (packageMention.isNotBlank() && neuron.toolId == "APP_SURFACE_AUDIT") {
                z += 3.2f
            }
            if (packageMention.isNotBlank() &&
                (neuron.toolId == "APP_FIREWALL_BLOCK" || neuron.toolId == "APP_FIREWALL_ALLOW")
            ) {
                z += 3.6f
            }
            if (tokens.contains("atacando") || tokens.contains("ataque") || tokens.contains("intrusion")) {
                if (neuron.toolId == "FULL_AUTONOMOUS_AUDIT" || neuron.toolId == "NETWORK_SOCKETS" || neuron.toolId == "VPN_START") z += 1.6f
            }
            scores[neuron.toolId] = z
        }

        // Softmax normalization for real confidence score
        val maxZ = scores.values.maxOrNull() ?: 1f
        val expSum = scores.values.sumOf { exp((it - maxZ).toDouble()) }.toFloat().coerceAtLeast(1e-5f)
        val bestEntry = scores.maxByOrNull { it.value }!!
        val confidence = (exp((bestEntry.value - maxZ).toDouble()).toFloat() / expSum).coerceIn(0.15f, 0.99f)

        val chosenTool = if (bestEntry.value < 1.5f && extractedHost.isNotBlank()) {
            "FULL_AUTONOMOUS_AUDIT"
        } else {
            bestEntry.key
        }

        val resolvedTarget = when {
            extractedHost.isNotBlank() -> extractedHost
            (chosenTool == "FIREWALL_BLOCK" || chosenTool == "FIREWALL_ALLOW") && portMention.isNotBlank() -> portMention
            packageMention.isNotBlank() -> packageMention
            chosenTool in setOf("PORT_PROBE", "TLS_INSPECT", "DNS_RECON", "HTTP_HEADERS", "SERVER_MONITOR") && lastTarget.isNotBlank() -> lastTarget
            chosenTool == "PORT_PROBE" -> "127.0.0.1"
            chosenTool == "ROOT_SHELL" -> trimmed
            else -> ""
        }

        val neuronMeta = intentNeurons.first { it.toolId == chosenTool }
        val topic = if (chosenTool == "AI_THEORETICAL") detectConversationalTopic(tokens, normalized) else ConversationalTopic.NONE
        val wantsRoot = neuronMeta.prefersRoot || currentMode == PrivilegeMode.ROOT ||
            tokens.any { it == "root" || it == "kernel" || it == "iptables" }

        return IntentClassification(
            plan = ForensicToolPlan(
                toolId = chosenTool,
                target = resolvedTarget,
                extraArg = "",
                prefersRoot = wantsRoot,
                analysisFocus = neuronMeta.focus
            ),
            topic = topic,
            confidence = confidence,
            extractedHost = resolvedTarget
        )
    }

    private fun detectConversationalTopic(tokens: List<String>, norm: String): ConversationalTopic {
        return when {
            tokens.any { it in setOf("hola", "buenos", "buenas", "saludos", "hey") } && tokens.size <= 5 ->
                ConversationalTopic.GREETING
            norm.contains("ingenieria inversa") || norm.contains("duplica") || norm.contains("clona") ->
                ConversationalTopic.ANTI_REVERSE_ENGINEERING
            norm.contains("como funciona") || norm.contains("como trab") || norm.contains("arquitectura") || norm.contains("red neuronal") ->
                ConversationalTopic.HOW_IT_WORKS
            norm.contains("root") && (norm.contains("diferencia") || norm.contains("sin root") || norm.contains("por que")) ->
                ConversationalTopic.ROOT_EXPLANATION
            tokens.any { it in setOf("encontraste", "hiciste", "resumen", "resume", "ultimo", "ultima", "resultado") } ->
                ConversationalTopic.LAST_SUMMARY
            tokens.any { it in setOf("ataque", "atacan", "mitm", "defender", "defiendo", "recomiendas", "mejora", "parche") } ->
                ConversationalTopic.DEFENSIVE_STRATEGY
            else -> ConversationalTopic.CAPABILITIES
        }
    }

    private fun fastPath(
        trimmed: String,
        lowerNorm: String,
        mode: PrivilegeMode,
        extractedHost: String,
        lastTarget: String
    ): ForensicToolPlan? {
        val fallbackHost = extractedHost.ifBlank { lastTarget }
        return when {
            lowerNorm.startsWith("/audit") ->
                ForensicToolPlan("FULL_AUTONOMOUS_AUDIT", trimmed.removePrefix("/audit").trim().ifBlank { fallbackHost }, "", mode == PrivilegeMode.ROOT, "Auditoría integral autónoma")
            lowerNorm.startsWith("/monitor") ->
                ForensicToolPlan("SERVER_MONITOR", trimmed.removePrefix("/monitor").trim().ifBlank { fallbackHost }, "", false, "Monitoreo de servidor y anomalías")
            lowerNorm.startsWith("/train") ->
                ForensicToolPlan("SELF_TRAIN_KEV", "", "", false, "Autoentrenamiento desde feed CISA KEV")
            lowerNorm.startsWith("/integrity") ->
                ForensicToolPlan("SELF_INTEGRITY", "", "", mode == PrivilegeMode.ROOT, "Verificación anti-manipulación propia")
            lowerNorm.startsWith("/tls") ->
                ForensicToolPlan("TLS_INSPECT", trimmed.removePrefix("/tls").trim().ifBlank { fallbackHost }, "", false, "Inspección de certificado TLS X.509")
            lowerNorm.startsWith("/dns") ->
                ForensicToolPlan("DNS_RECON", trimmed.removePrefix("/dns").trim().ifBlank { fallbackHost }, "", false, "Reconocimiento DNS DoH")
            lowerNorm.startsWith("/http") ->
                ForensicToolPlan("HTTP_HEADERS", trimmed.removePrefix("/http").trim().ifBlank { fallbackHost }, "", false, "Cabeceras defensivas HTTP")
            lowerNorm.startsWith("/ports") ->
                ForensicToolPlan("PORT_PROBE", trimmed.removePrefix("/ports").trim().ifBlank { fallbackHost.ifBlank { "127.0.0.1" } }, "", false, "Sondeo de puertos TCP")
            lowerNorm.startsWith("/sockets") || lowerNorm.startsWith("/net") ->
                ForensicToolPlan("NETWORK_SOCKETS", "", "", mode == PrivilegeMode.ROOT, "Topología de red y sockets")
            lowerNorm.startsWith("/apps") ->
                ForensicToolPlan("APP_SURFACE_AUDIT", trimmed.removePrefix("/apps").trim(), "", mode == PrivilegeMode.ROOT, "Superficie de aplicaciones")
            lowerNorm.startsWith("/jwt") || lowerNorm.startsWith("/hash") || lowerNorm.startsWith("/crypto") ->
                ForensicToolPlan("CRYPTO_JWT", trimmed, "", false, "Análisis criptográfico y JWT")
            lowerNorm.startsWith("/block-app ") || lowerNorm.startsWith("/blockapp ") ->
                ForensicToolPlan("APP_FIREWALL_BLOCK", trimmed.substringAfter("app ").trim(), "", true, "Bloqueo por app (kernel, requiere root)")
            lowerNorm.startsWith("/allow-app ") || lowerNorm.startsWith("/unblock-app ") || lowerNorm.startsWith("/allowapp ") ->
                ForensicToolPlan("APP_FIREWALL_ALLOW", trimmed.substringAfter("app ").trim(), "", true, "Retirar bloqueo por app")
            lowerNorm == "/apps-blocked" || lowerNorm == "/bloqueadas" ->
                ForensicToolPlan("APP_FIREWALL_LIST", "", "", false, "Listar apps bloqueadas")
            lowerNorm.startsWith("/osv ") ->
                ForensicToolPlan("INTEL_OSV_QUERY", trimmed.removePrefix("/osv").trim(), "", false, "Consulta de vulnerabilidades en OSV")
            lowerNorm.startsWith("/urlhaus ") ->
                ForensicToolPlan("INTEL_URLHAUS_CHECK", trimmed.removePrefix("/urlhaus").trim(), "", false, "Reputación de host/URL en URLhaus")
            lowerNorm.startsWith("/vpn on") || lowerNorm == "/vpn start" || lowerNorm == "/vpn activar" ->
                ForensicToolPlan("VPN_START", "", "", false, "Activar VPN Local y Firewall")
            lowerNorm.startsWith("/vpn off") || lowerNorm == "/vpn stop" ->
                ForensicToolPlan("VPN_STOP", "", "", false, "Detener VPN Local")
            lowerNorm.startsWith("/vpn") || lowerNorm.startsWith("/firewall") ->
                ForensicToolPlan("VPN_TELEMETRY", "", "", false, "Telemetría VPN Local y Firewall")
            lowerNorm.startsWith("/block ") ->
                ForensicToolPlan("FIREWALL_BLOCK", trimmed.removePrefix("/block ").trim(), "", false, "Bloquear dominio/IP/puerto en Firewall")
            lowerNorm.startsWith("/allow ") ->
                ForensicToolPlan("FIREWALL_ALLOW", trimmed.removePrefix("/allow ").trim(), "", false, "Permitir en Firewall")
            lowerNorm.startsWith("/fix") || lowerNorm.startsWith("/apply") ->
                ForensicToolPlan("EXECUTE_SOLUTIONS", fallbackHost, "", mode == PrivilegeMode.ROOT, "Ejecutar soluciones y mitigaciones")
            lowerNorm.startsWith("/su") ->
                ForensicToolPlan("ROOT_SHELL", trimmed, "", true, "Inspección shell su")
            lowerNorm.startsWith("/env") || lowerNorm.startsWith("/device") ->
                ForensicToolPlan("DEVICE_INTEGRITY", "", "", mode == PrivilegeMode.ROOT, "Integridad kernel y dispositivo")
            else -> null
        }
    }

    private fun extractHostOrIp(input: String): String {
        val match = Regex("(https?://)?([a-zA-Z0-9-]+\\.[a-zA-Z0-9.-]+|\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b)(:\\d+)?")
            .find(input) ?: return ""
        val candidate = match.groupValues[2]
        // Ignore Android package prefixes like com.aura.mobiledefense.app unless user isn't mentioning app packages
        val parts = candidate.split(".")
        return if (parts.size >= 3 && parts[0] in setOf("com", "org", "net", "io") && !input.contains("http", true)) {
            ""
        } else {
            candidate
        }
    }

    private fun foldDiacritics(input: String): String {
        val decomposed = Normalizer.normalize(input, Normalizer.Form.NFD)
        return decomposed.replace(Regex("\\p{InCombiningDiacriticalMarks}+"), "")
    }

    private fun tokenize(input: String): List<String> {
        return input.split(Regex("[^a-z0-9._/]+")).filter { it.isNotBlank() }
    }
}
