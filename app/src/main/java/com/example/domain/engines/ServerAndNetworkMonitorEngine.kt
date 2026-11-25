package com.example.domain.engines

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.example.data.local.AnomalyEventEntity
import com.example.data.local.ForensicSessionDao
import com.example.data.local.MonitorTargetEntity
import com.example.data.model.PrivilegeMode
import com.example.data.model.ToolExecutionResult
import com.example.data.model.VisualTopologyKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.TimeUnit

class ServerAndNetworkMonitorEngine(
    private val context: Context,
    private val dao: ForensicSessionDao
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(7, TimeUnit.SECONDS)
        .readTimeout(9, TimeUnit.SECONDS)
        .followRedirects(false)
        .build()

    private val securityHeaderNames = listOf(
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy"
    )

    suspend fun probeAndMonitorTarget(
        rawTarget: String,
        mode: PrivilegeMode
    ): ToolExecutionResult = withContext(Dispatchers.IO) {
        val normalizedUrl = normalizeEndpoint(rawTarget)
        val existing = dao.getMonitorTarget(normalizedUrl)
        val now = System.currentTimeMillis()
        val sb = StringBuilder()
        sb.appendLine("=== MONITOREO ACTIVO DE SERVIDOR Y DETECCIÓN DE ANOMALÍAS ===")
        sb.appendLine("Endpoint vigilado: $normalizedUrl")

        val anomaliesDetected = mutableListOf<AnomalyEventEntity>()
        var measuredRtt = 0L
        var measuredStatus = -1
        var measuredTlsSha = ""
        var measuredHeaderCount = 0

        try {
            val start = System.currentTimeMillis()
            val req = Request.Builder()
                .url(normalizedUrl)
                .header("User-Agent", "AuraMobileDefense-Monitor/1.0")
                .get()
                .build()

            client.newCall(req).execute().use { resp ->
                measuredRtt = (System.currentTimeMillis() - start).coerceAtLeast(1L)
                measuredStatus = resp.code
                measuredHeaderCount = securityHeaderNames.count { resp.header(it) != null }
                val leafCert = resp.handshake?.peerCertificates
                    ?.filterIsInstance<X509Certificate>()
                    ?.firstOrNull()
                measuredTlsSha = if (leafCert != null) {
                    MessageDigest.getInstance("SHA-256")
                        .digest(leafCert.encoded)
                        .joinToString(":") { "%02X".format(it) }
                } else ""
            }

            if (existing == null) {
                val initial = MonitorTargetEntity(
                    target = normalizedUrl,
                    baselineRttMs = measuredRtt,
                    lastRttMs = measuredRtt,
                    baselineStatusCode = measuredStatus,
                    lastStatusCode = measuredStatus,
                    baselineTlsSha256 = measuredTlsSha,
                    lastTlsSha256 = measuredTlsSha,
                    baselineHeaderCount = measuredHeaderCount,
                    lastHeaderCount = measuredHeaderCount,
                    checkCount = 1,
                    anomalyCount = 0,
                    lastCheckedAt = now,
                    isActive = true
                )
                dao.upsertMonitorTarget(initial)
                sb.appendLine("Línea base aprendida: HTTP $measuredStatus | RTT ${measuredRtt}ms | Cabeceras seguras: $measuredHeaderCount/5")
                if (measuredTlsSha.isNotBlank()) {
                    sb.appendLine("Huella TLS X.509 base: ${measuredTlsSha.take(35)}…")
                }
            } else {
                // Compare against learned baseline
                if (measuredRtt > (existing.baselineRttMs * 2.5).toLong() + 180L) {
                    anomaliesDetected.add(
                        AnomalyEventEntity(
                            id = UUID.randomUUID().toString(),
                            target = normalizedUrl,
                            kind = "LATENCY_SPIKE",
                            severity = "MEDIA",
                            description = "Latencia anómala: ${measuredRtt}ms vs base aprendida ${existing.baselineRttMs}ms",
                            timestamp = now
                        )
                    )
                }
                if (existing.baselineTlsSha256.isNotBlank() &&
                    measuredTlsSha.isNotBlank() &&
                    existing.baselineTlsSha256 != measuredTlsSha
                ) {
                    anomaliesDetected.add(
                        AnomalyEventEntity(
                            id = UUID.randomUUID().toString(),
                            target = normalizedUrl,
                            kind = "TLS_CERT_DRIFT",
                            severity = "CRITICA",
                            description = "Cambio inesperado en huella TLS SHA-256 (posible MITM o rotación no prevista)",
                            timestamp = now
                        )
                    )
                }
                if (measuredStatus != existing.baselineStatusCode && measuredStatus >= 400) {
                    anomaliesDetected.add(
                        AnomalyEventEntity(
                            id = UUID.randomUUID().toString(),
                            target = normalizedUrl,
                            kind = "HTTP_STATUS_ANOMALY",
                            severity = "ALTA",
                            description = "Código HTTP cambió de ${existing.baselineStatusCode} a $measuredStatus",
                            timestamp = now
                        )
                    )
                }
                if (measuredHeaderCount < existing.baselineHeaderCount) {
                    anomaliesDetected.add(
                        AnomalyEventEntity(
                            id = UUID.randomUUID().toString(),
                            target = normalizedUrl,
                            kind = "HEADER_REGRESSION",
                            severity = "ALTA",
                            description = "Degradación de cabeceras de seguridad: $measuredHeaderCount/5 (base ${existing.baselineHeaderCount}/5)",
                            timestamp = now
                        )
                    )
                }

                anomaliesDetected.forEach { dao.insertAnomaly(it) }

                // Adaptive EMA update on nominal samples
                val nextBaselineRtt = if (anomaliesDetected.isEmpty()) {
                    ((existing.baselineRttMs * 0.75) + (measuredRtt * 0.25)).toLong().coerceAtLeast(1L)
                } else existing.baselineRttMs

                dao.upsertMonitorTarget(
                    existing.copy(
                        baselineRttMs = nextBaselineRtt,
                        lastRttMs = measuredRtt,
                        lastStatusCode = measuredStatus,
                        lastTlsSha256 = measuredTlsSha,
                        lastHeaderCount = measuredHeaderCount,
                        checkCount = existing.checkCount + 1,
                        anomalyCount = existing.anomalyCount + anomaliesDetected.size,
                        lastCheckedAt = now,
                        isActive = true
                    )
                )

                sb.appendLine("Muestra #${existing.checkCount + 1}: HTTP $measuredStatus | RTT ${measuredRtt}ms (base ${existing.baselineRttMs}ms)")
                sb.appendLine("Cabeceras seguras: $measuredHeaderCount/5 | TLS: ${measuredTlsSha.take(26)}…")
            }
        } catch (e: Exception) {
            val alert = AnomalyEventEntity(
                id = UUID.randomUUID().toString(),
                target = normalizedUrl,
                kind = "ENDPOINT_UNREACHABLE",
                severity = "ALTA",
                description = "Fallo al sondear servidor: ${e.javaClass.simpleName} (${e.message?.take(100)})",
                timestamp = now
            )
            anomaliesDetected.add(alert)
            dao.insertAnomaly(alert)
            sb.appendLine("[ANOMALÍA] Endpoint inalcanzable: ${e.message}")
        }

        // Local device network health snapshot
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNet = cm.activeNetwork
        val caps = activeNet?.let { cm.getNetworkCapabilities(it) }
        val linkProps = activeNet?.let { cm.getLinkProperties(it) }
        val hasProxy = linkProps?.httpProxy != null
        val hasVpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        sb.appendLine()
        sb.appendLine("=== ESTADO DE RED LOCAL DEL DISPOSITIVO ===")
        sb.appendLine("Interfaz: ${linkProps?.interfaceName ?: "Sin red"} | VPN: $hasVpn | Proxy HTTP: ${if (hasProxy) "ACTIVO (${linkProps?.httpProxy?.host})" else "Ninguno"}")
        sb.appendLine("DNS locales: ${linkProps?.dnsServers?.joinToString { it.hostAddress ?: "" } ?: "N/D"}")

        if (anomaliesDetected.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("--- ANOMALÍAS DETECTADAS (${anomaliesDetected.size}) ---")
            anomaliesDetected.forEach { sb.appendLine("• [${it.severity}] ${it.kind}: ${it.description}") }
        } else {
            sb.appendLine("Sin desviaciones anormales respecto a la línea base.")
        }

        val spectrum = listOf(
            (measuredRtt.coerceAtMost(1000L) / 1000f).coerceIn(0.1f, 1f),
            if (measuredStatus in 200..399) 0.88f else 0.2f,
            (measuredHeaderCount / 5f).coerceIn(0.15f, 1f),
            if (anomaliesDetected.isEmpty()) 0.92f else 0.18f,
            if (hasVpn) 0.9f else 0.5f,
            if (!hasProxy) 0.9f else 0.3f
        )

        ToolExecutionResult(
            toolId = "SERVER_MONITOR",
            target = normalizedUrl,
            privilegeUsed = mode,
            rawTelemetry = sb.toString(),
            measuredSpectrum = spectrum + spectrum,
            suggestedVisual = VisualTopologyKind.SPECTRUM_INTERFERENCE
        )
    }

    suspend fun runBackgroundMonitorCycle(): List<AnomalyAlertSummary> = withContext(Dispatchers.IO) {
        val active = dao.getActiveMonitorTargets().take(4)
        val newAlerts = mutableListOf<AnomalyAlertSummary>()
        active.forEach { target ->
            val before = target.anomalyCount
            probeAndMonitorTarget(target.target, PrivilegeMode.USERLAND)
            val updated = dao.getMonitorTarget(target.target)
            if (updated != null && updated.anomalyCount > before) {
                newAlerts.add(
                    AnomalyAlertSummary(
                        target = target.target,
                        newAnomalies = updated.anomalyCount - before
                    )
                )
            }
        }
        newAlerts
    }

    private fun normalizeEndpoint(raw: String): String {
        val clean = raw.trim()
            .removePrefix("/monitor")
            .trim()
        return when {
            clean.isBlank() -> "https://cloudflare.com"
            clean.startsWith("http://") || clean.startsWith("https://") -> clean
            else -> "https://$clean"
        }
    }

    data class AnomalyAlertSummary(val target: String, val newAnomalies: Int)
}
