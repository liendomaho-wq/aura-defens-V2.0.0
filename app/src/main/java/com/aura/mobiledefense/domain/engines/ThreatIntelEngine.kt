package com.aura.mobiledefense.domain.engines

import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.data.model.ToolExecutionResult
import com.aura.mobiledefense.data.model.VisualTopologyKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Inteligencia de amenazas bajo demanda: OSV (vulnerabilidades por paquete) y URLhaus
 * (URLs/dominios maliciosos conocidos). Fuentes abiertas, sin clave ni cuenta.
 *
 * Reglas de diseño (las mismas que KEV):
 *  - Solo se ejecuta cuando el usuario lo pide en la conversación. No hay sincronización
 *    silenciosa en segundo plano: cualquier petición de red es explícita y visible.
 *  - Lectura acotada (tope duro de bytes) para que un feed hostil o roto no cuelgue la app.
 *  - Respuesta real o error honesto: nunca "parece vulnerable" inventado.
 */
class ThreatIntelEngine {

    private val client = OkHttpClient.Builder()
        .connectTimeout(12, TimeUnit.SECONDS)
        .readTimeout(25, TimeUnit.SECONDS)
        .build()

    private val maxResponseBytes = 4 * 1024 * 1024

    private fun executeCapped(request: Request): String {
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw IllegalStateException("HTTP ${response.code} de ${request.url.host}")
            }
            val body = response.body?.byteStream()
                ?: throw IllegalStateException("Respuesta vacía de ${request.url.host}")
            val out = java.io.ByteArrayOutputStream(1 shl 16)
            val buffer = ByteArray(64 * 1024)
            var total = 0
            body.use { stream ->
                while (total < maxResponseBytes) {
                    val read = stream.read(buffer)
                    if (read <= 0) break
                    val allowed = minOf(read, maxResponseBytes - total)
                    out.write(buffer, 0, allowed)
                    total += allowed
                }
            }
            return out.toString("UTF-8")
        }
    }

    // ── OSV ──────────────────────────────────────────────────────────────────────────────

    suspend fun checkOsv(target: String, mode: PrivilegeMode): ToolExecutionResult =
        withContext(Dispatchers.IO) {
            val parsed = ThreatIntelParsers.parseOsvTarget(target)
            if (parsed == null) {
                return@withContext failure(
                    toolId = "INTEL_OSV_QUERY",
                    target = target,
                    mode = mode,
                    detail = "Formato esperado: ecosistema:paquete:versión — por ejemplo " +
                        "PyPI:django:3.2.1 · npm:lodash:4.17.20 · Go:golang.org/x/text:v0.3.0 · " +
                        "Maven:org.apache.struts:struts2-core:2.5.10 · crates.io:openssl:0.10.55 · " +
                        "Android:android-13:TQ2A.230505.002"
                )
            }
            val body = JSONObject().apply {
                put("package", JSONObject().apply {
                    put("name", parsed.name)
                    put("ecosystem", parsed.ecosystem)
                })
                put("version", parsed.version)
            }.toString()
            val result = try {
                val request = Request.Builder()
                    .url("https://api.osv.dev/v1/query")
                    .header("User-Agent", "AuraMobileDefense/1.0")
                    .header("Accept", "application/json")
                    .post(body.toRequestBody("application/json; charset=utf-8".toMediaType()))
                    .build()
                ThreatIntelParsers.parseOsvResponse(executeCapped(request))
            } catch (e: Exception) {
                return@withContext failure(
                    "INTEL_OSV_QUERY", target, mode,
                    "No se pudo consultar OSV (api.osv.dev): ${e.message ?: e.javaClass.simpleName}"
                )
            }
            ToolExecutionResult(
                toolId = "INTEL_OSV_QUERY",
                target = target,
                privilegeUsed = mode,
                rawTelemetry = buildString {
                    appendLine("=== INTEL OSV (osv.dev) ===")
                    appendLine("Consulta: ${parsed.ecosystem} · ${parsed.name} · ${parsed.version}")
                    appendLine("Vulnerabilidades conocidas: ${result.total}")
                    result.entries.forEach { appendLine("  $it") }
                    if (result.total > result.entries.size) {
                        appendLine("  … y ${result.total - result.entries.size} más (consulta el detalle en osv.dev)")
                    }
                    appendLine()
                    appendLine(
                        if (result.total > 0)
                            "Acción sugerida: actualiza el componente y revisa si alguna CVE está en CISA KEV (herramienta SELF_TRAIN_KEV)."
                        else
                            "Sin vulnerabilidades conocidas para esa versión exacta en OSV. No equivale a garantía de ausencia."
                    )
                },
                measuredSpectrum = if (result.total > 0) listOf(0.85f, 0.8f, 0.9f) else listOf(0.2f, 0.25f, 0.15f),
                suggestedVisual = VisualTopologyKind.ATTACK_VECTOR_FLOW
            )
        }

    // ── URLhaus ──────────────────────────────────────────────────────────────────────────

    suspend fun checkUrlhaus(target: String, mode: PrivilegeMode): ToolExecutionResult =
        withContext(Dispatchers.IO) {
            val host = ThreatIntelParsers.extractHost(target)
            if (host == null) {
                return@withContext failure(
                    "INTEL_URLHAUS_CHECK", target, mode,
                    "Indica un dominio o una URL válida (por ejemplo evil.example o https://evil.example/a)."
                )
            }
            val result = try {
                val form = "host=${java.net.URLEncoder.encode(host, "UTF-8")}"
                val request = Request.Builder()
                    .url("https://urlhaus.abuse.ch/api/v1/host/")
                    .header("User-Agent", "AuraMobileDefense/1.0")
                    .header("Accept", "application/json")
                    .post(form.toRequestBody("application/x-www-form-urlencoded".toMediaType()))
                    .build()
                ThreatIntelParsers.parseUrlhausResponse(executeCapped(request))
            } catch (e: Exception) {
                return@withContext failure(
                    "INTEL_URLHAUS_CHECK", target, mode,
                    "No se pudo consultar URLhaus (urlhaus.abuse.ch): ${e.message ?: e.javaClass.simpleName}"
                )
            }
            val malicious = result.queryStatus == "ok" && result.urlCount > 0
            ToolExecutionResult(
                toolId = "INTEL_URLHAUS_CHECK",
                target = target,
                privilegeUsed = mode,
                rawTelemetry = buildString {
                    appendLine("=== INTEL URLHAUS (abuse.ch) ===")
                    appendLine("Host consultado: $host")
                    appendLine("Estado de la consulta: ${result.queryStatus}")
                    if (result.queryStatus == "ok") {
                        appendLine("URLs maliciosas conocidas en este host: ${result.urlCount}")
                        result.entries.forEach { appendLine("  $it") }
                        if (result.urlCount > result.entries.size) {
                            appendLine("  … y ${result.urlCount - result.entries.size} más (ver urlhaus.abuse.ch)")
                        }
                        if (malicious) {
                            appendLine()
                            appendLine("Host MALICIOSO según URLhaus. Para cortarlo en el túnel di: bloquea $host")
                        }
                    } else {
                        appendLine("Sin entradas para este host en URLhaus (esto no demuestra que sea seguro).")
                    }
                },
                measuredSpectrum = if (malicious) listOf(0.95f, 0.92f, 0.97f) else listOf(0.25f, 0.3f, 0.2f),
                suggestedVisual = VisualTopologyKind.ATTACK_VECTOR_FLOW
            )
        }

    private fun failure(toolId: String, target: String, mode: PrivilegeMode, detail: String) =
        ToolExecutionResult(
            toolId = toolId,
            target = target,
            privilegeUsed = mode,
            rawTelemetry = "=== INTEL NO DISPONIBLE ===\n$detail",
            measuredSpectrum = listOf(0.3f, 0.3f, 0.3f),
            suggestedVisual = VisualTopologyKind.ATTACK_VECTOR_FLOW
        )
}

/** Parseo puro: sin red, sin Android, testeable en JVM. */
internal object ThreatIntelParsers {

    data class OsvTarget(val ecosystem: String, val name: String, val version: String)
    data class OsvSummary(val total: Int, val entries: List<String>)
    data class UrlhausSummary(val queryStatus: String, val urlCount: Int, val entries: List<String>)

    /** Ecosistemas que acepta OSV (osv.dev) + alias frecuentes. */
    private val ecosystemAliases = mapOf(
        "pypi" to "PyPI", "python" to "PyPI",
        "npm" to "npm", "node" to "npm",
        "go" to "Go", "golang" to "Go",
        "maven" to "Maven",
        "crates.io" to "crates.io", "crates" to "crates.io", "cargo" to "crates.io", "rust" to "crates.io",
        "rubygems" to "RubyGems", "gem" to "RubyGems",
        "nuget" to "NuGet",
        "packagist" to "Packagist", "composer" to "Packagist",
        "hex" to "Hex",
        "pub" to "Pub",
        "debian" to "Debian",
        "alpine" to "Alpine",
        "ubuntu" to "Ubuntu",
        "android" to "Android"
    )

    /**
     * `ecosistema:paquete:versión`. La versión es el segmento tras el ÚLTIMO ':' (los nombres Maven
     * llevan ':' ellos mismos: Maven:org.apache.struts:struts2-core:2.5.10).
     */
    fun parseOsvTarget(raw: String): OsvTarget? {
        val clean = raw.trim()
        val first = clean.indexOf(':')
        val last = clean.lastIndexOf(':')
        if (first <= 0 || last <= first || last == clean.length - 1) return null
        val ecosystem = ecosystemAliases[clean.substring(0, first).trim().lowercase()] ?: return null
        val name = clean.substring(first + 1, last).trim()
        val version = clean.substring(last + 1).trim()
        if (name.isBlank() || version.isBlank() || name.length > 300 || version.length > 100) return null
        return OsvTarget(ecosystem, name, version)
    }

    /** Extrae el host de una URL o acepta un host desnudo. */
    fun extractHost(raw: String): String? {
        val clean = raw.trim().lowercase()
        if (clean.isBlank()) return null
        val host = if (clean.contains("://")) {
            runCatching { java.net.URI(clean).host }.getOrNull()
        } else {
            clean.substringBefore('/').substringBefore('?').substringBefore('#').substringBefore(':')
        } ?: return null
        val h = host.trimEnd('.')
        val ok = Regex("^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
        return if (ok.matches(h)) h else null
    }

    /** Respuesta real de POST /v1/query de OSV. Tolera campos ausentes. */
    fun parseOsvResponse(body: String): OsvSummary {
        val json = JSONObject(body)
        val vulns = json.optJSONArray("vulns") ?: return OsvSummary(0, emptyList())
        val entries = mutableListOf<String>()
        for (i in 0 until vulns.length()) {
            if (entries.size >= 12) break
            val v = vulns.optJSONObject(i) ?: continue
            val id = v.optString("id", "OSV-?")
            val aliases = v.optJSONArray("aliases")
            val aliasList = (0 until (aliases?.length() ?: 0)).map { aliases!!.optString(it) }.filter { it.isNotBlank() }
            val alias = if (aliasList.isEmpty()) "" else " (${aliasList.take(3).joinToString(", ")}${if (aliasList.size > 3) "…" else ""})"
            val summary = v.optString("summary", "").replace('\n', ' ').trim()
            val summaryShort = if (summary.length > 110) summary.take(110) + "…" else summary
            entries.add("$id$alias — $summaryShort")
        }
        return OsvSummary(vulns.length(), entries)
    }

    /** Respuesta real de POST /api/v1/host/ de URLhaus. Tolera campos ausentes. */
    fun parseUrlhausResponse(body: String): UrlhausSummary {
        val json = JSONObject(body)
        val status = json.optString("query_status", "error")
        if (status != "ok") return UrlhausSummary(status, 0, emptyList())
        val urls = json.optJSONArray("urls") ?: return UrlhausSummary(status, 0, emptyList())
        val entries = mutableListOf<String>()
        for (i in 0 until urls.length()) {
            if (entries.size >= 10) break
            val u = urls.optJSONObject(i) ?: continue
            val url = u.optString("url", "?")
            val threat = u.optString("threat", "malware")
            val date = u.optString("date_added", "?")
            entries.add("[$date] $threat — ${if (url.length > 120) url.take(120) + "…" else url}")
        }
        return UrlhausSummary(status, urls.length(), entries)
    }
}
