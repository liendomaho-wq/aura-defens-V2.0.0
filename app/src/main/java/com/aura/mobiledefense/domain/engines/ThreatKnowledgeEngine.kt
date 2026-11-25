package com.aura.mobiledefense.domain.engines

import com.aura.mobiledefense.data.local.ForensicSessionDao
import com.aura.mobiledefense.data.local.ThreatRuleEntity
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.data.model.ThreatKnowledgeStats
import com.aura.mobiledefense.data.model.ToolExecutionResult
import com.aura.mobiledefense.data.model.VisualTopologyKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class ThreatKnowledgeEngine(
    private val dao: ForensicSessionDao
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(12, TimeUnit.SECONDS)
        .readTimeout(25, TimeUnit.SECONDS)
        .build()

    private val cisaKevFeedUrl =
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    suspend fun ensureBaselineKnowledgeSeeded() = withContext(Dispatchers.IO) {
        if (dao.countThreatRules() > 0) return@withContext
        val now = System.currentTimeMillis()
        val baselineRules = listOf(
            ThreatRuleEntity(
                ruleId = "AURA-BASE-01",
                source = "LOCAL_BASELINE",
                vendorOrCategory = "Android Sandbox",
                title = "Aplicación compilada con FLAG_DEBUGGABLE",
                keywords = "debuggable=true,ro.debuggable = 1",
                severity = 0.85f,
                remediationHint = "Desactivar android:debuggable en builds de producción y habilitar R8.",
                updatedAt = now
            ),
            ThreatRuleEntity(
                ruleId = "AURA-BASE-02",
                source = "LOCAL_BASELINE",
                vendorOrCategory = "Transporte",
                title = "Tráfico HTTP en texto claro habilitado",
                keywords = "cleartext=true,http://",
                severity = 0.78f,
                remediationHint = "Definir network_security_config.xml con cleartextTrafficPermitted=\"false\".",
                updatedAt = now
            ),
            ThreatRuleEntity(
                ruleId = "AURA-BASE-03",
                source = "LOCAL_BASELINE",
                vendorOrCategory = "Criptografía / JWT",
                title = "Token JWT con algoritmo 'none' o expirado",
                keywords = "algoritmo 'none',algoritmo declarado: none,EXPIRADO",
                severity = 0.92f,
                remediationHint = "Exigir verificación asimétrica RS256/ES256 y rechazar alg=none en el backend.",
                updatedAt = now
            ),
            ThreatRuleEntity(
                ruleId = "AURA-BASE-04",
                source = "LOCAL_BASELINE",
                vendorOrCategory = "Red / ADB",
                title = "Puerto ADB TCP (5555) o servicios DB sin cifrado expuestos",
                keywords = "5555/tcp,6379/tcp,27017/tcp,23/tcp,ADB-TCP",
                severity = 0.90f,
                remediationHint = "Bloquear puertos administrativos en firewall local (iptables/nftables) y deshabilitar ADB sobre red.",
                updatedAt = now
            ),
            ThreatRuleEntity(
                ruleId = "AURA-BASE-05",
                source = "LOCAL_BASELINE",
                vendorOrCategory = "HTTP / TLS",
                title = "Ausencia de cabeceras HSTS o Content-Security-Policy",
                keywords = "[AUSENTE]  Strict-Transport-Security,[AUSENTE]  Content-Security-Policy",
                severity = 0.65f,
                remediationHint = "Agregar Strict-Transport-Security y Content-Security-Policy en el proxy/servidor web.",
                updatedAt = now
            ),
            ThreatRuleEntity(
                ruleId = "AURA-BASE-06",
                source = "LOCAL_BASELINE",
                vendorOrCategory = "Kernel / SELinux",
                title = "SELinux en modo Permissive o Bootloader desbloqueado",
                keywords = "Permissive,ro.boot.flash.locked = 0,ro.boot.verifiedbootstate = orange",
                severity = 0.80f,
                remediationHint = "Restaurar SELinux a Enforcing (setenforce 1) y verificar integridad de arranque.",
                updatedAt = now
            )
        )
        dao.upsertThreatRules(baselineRules)
    }

    suspend fun getKnowledgeStats(): ThreatKnowledgeStats = withContext(Dispatchers.IO) {
        ensureBaselineKnowledgeSeeded()
        val total = dao.countThreatRules()
        val kev = dao.countCisaKevRules()
        val lastAt = dao.getLastTrainedTimestamp() ?: 0L
        ThreatKnowledgeStats(
            totalRules = total,
            cisaKevCount = kev,
            localBaselineCount = total - kev,
            lastTrainedAt = lastAt,
            lastTrainingSummary = if (kev > 0) {
                "$total reglas activas ($kev firmas reales CISA KEV sincronizadas)"
            } else {
                "$total reglas heurísticas locales activas"
            }
        )
    }

    suspend fun trainFromInternet(mode: PrivilegeMode): ToolExecutionResult =
        withContext(Dispatchers.IO) {
            ensureBaselineKnowledgeSeeded()
            val sb = StringBuilder()
            sb.appendLine("=== AUTOENTRENAMIENTO CON FEED REAL DE AMENAZAS (CISA KEV) ===")
            sb.appendLine("Fuente: $cisaKevFeedUrl")

            try {
                val request = Request.Builder()
                    .url(cisaKevFeedUrl)
                    .header("User-Agent", "AuraMobileDefense/1.0")
                    .header("Accept", "application/json")
                    .get()
                    .build()

                val ingestedRules = mutableListOf<ThreatRuleEntity>()
                val now = System.currentTimeMillis()
                var catalogVersion = "desconocida"
                var totalCatalogCount = 0

                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        throw IllegalStateException("HTTP ${response.code} al consultar CISA KEV")
                    }
                    val bodyStr = response.body?.string()
                        ?: throw IllegalStateException("Respuesta vacía del catálogo CISA KEV")

                    val json = JSONObject(bodyStr)
                    catalogVersion = json.optString("catalogVersion", "actual")
                    totalCatalogCount = json.optInt("count", 0)
                    val vulns = json.optJSONArray("vulnerabilities")
                        ?: throw IllegalStateException("Formato inesperado en catálogo CISA KEV")

                    val priorityVendors = listOf(
                        "google", "android", "linux", "openssl", "nginx",
                        "apache", "openssh", "qualcomm", "mediatek", "arm", "curl"
                    )

                    // Collect up to 140 high-relevance + newest real CVEs into local Room knowledge base
                    for (i in (vulns.length() - 1) downTo 0) {
                        if (ingestedRules.size >= 140) break
                        val v = vulns.getJSONObject(i)
                        val cveId = v.optString("cveID", "")
                        val vendor = v.optString("vendorProject", "")
                        val product = v.optString("product", "")
                        val name = v.optString("vulnerabilityName", "")
                        val action = v.optString("requiredAction", "")
                        val combined = "$vendor $product $name".lowercase()
                        val isRelevant = priorityVendors.any { combined.contains(it) } ||
                            ingestedRules.size < 45

                        if (cveId.isNotBlank() && isRelevant) {
                            ingestedRules.add(
                                ThreatRuleEntity(
                                    ruleId = cveId,
                                    source = "CISA_KEV",
                                    vendorOrCategory = "$vendor / $product".trim(' ', '/'),
                                    title = name.ifBlank { cveId },
                                    keywords = listOf(vendor, product, cveId)
                                        .filter { it.isNotBlank() }
                                        .joinToString(",")
                                        .lowercase(),
                                    severity = if (combined.contains("remote") || combined.contains("execution")) 0.92f else 0.76f,
                                    remediationHint = action.ifBlank { "Aplicar actualización de seguridad del proveedor." },
                                    updatedAt = now
                                )
                            )
                        }
                    }
                }

                if (ingestedRules.isNotEmpty()) {
                    dao.upsertThreatRules(ingestedRules)
                }

                val totalStored = dao.countThreatRules()
                sb.appendLine("Catálogo CISA KEV versión: $catalogVersion ($totalCatalogCount CVEs publicados)")
                sb.appendLine("Nuevas firmas asimiladas en red local Room: ${ingestedRules.size}")
                sb.appendLine("Total de reglas neuronales locales activas: $totalStored")
                sb.appendLine()
                sb.appendLine("--- Muestra de firmas recién aprendidas ---")
                ingestedRules.take(8).forEach { r ->
                    sb.appendLine("• [${r.ruleId}] ${r.vendorOrCategory}: ${r.title.take(90)}")
                }

                val spectrum = ingestedRules.take(24).map { it.severity }
                ToolExecutionResult(
                    toolId = "SELF_TRAIN_KEV",
                    target = "CISA KEV $catalogVersion",
                    privilegeUsed = mode,
                    rawTelemetry = sb.toString(),
                    measuredSpectrum = spectrum.ifEmpty { listOf(0.8f, 0.7f, 0.9f) },
                    suggestedVisual = VisualTopologyKind.NEURAL_SYNAPTIC_LATTICE
                )
            } catch (e: Exception) {
                val existing = dao.countThreatRules()
                sb.appendLine("Sincronización online interrumpida: ${e.javaClass.simpleName} (${e.message})")
                sb.appendLine("El motor local conserva $existing reglas activas para detección offline.")
                ToolExecutionResult(
                    toolId = "SELF_TRAIN_KEV",
                    target = "Modo Local ($existing reglas)",
                    privilegeUsed = mode,
                    rawTelemetry = sb.toString(),
                    measuredSpectrum = listOf(0.35f, 0.45f, 0.3f, 0.5f),
                    suggestedVisual = VisualTopologyKind.NEURAL_SYNAPTIC_LATTICE
                )
            }
        }

    suspend fun matchTelemetryAgainstRules(telemetry: String): List<ThreatRuleEntity> =
        withContext(Dispatchers.IO) {
            ensureBaselineKnowledgeSeeded()
            val lower = telemetry.lowercase()
            dao.getAllThreatRules().filter { rule ->
                val keys = rule.keywords.split(",").map { it.trim().lowercase() }.filter { it.length >= 3 }
                keys.any { kw -> lower.contains(kw) }
            }.take(12)
        }
}
