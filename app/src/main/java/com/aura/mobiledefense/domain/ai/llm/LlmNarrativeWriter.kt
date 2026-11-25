package com.aura.mobiledefense.domain.ai.llm

import com.aura.mobiledefense.data.local.ThreatRuleEntity
import com.aura.mobiledefense.data.model.ToolExecutionResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Writes the chat narrative with an LLM, grounded on the telemetry that was just measured.
 *
 * The contract that makes this safe: [write] returns `null` on any failure, and the caller keeps
 * the deterministic template. There is no path where a model outage produces an empty message.
 *
 * Privacy: telemetry is passed through [TelemetryRedactor] before it leaves the device, and the
 * hosts the user explicitly asked to audit are kept verbatim so the answer stays useful.
 */
class LlmNarrativeWriter(
    private val provider: LlmProvider,
    private val timeoutMs: Long = 20_000L,
    private val maxTelemetryChars: Int = 6_000
) {

    suspend fun write(
        userQuery: String,
        result: ToolExecutionResult,
        matchedRules: List<ThreatRuleEntity>,
        extraContext: String = ""
    ): String? = withContext(Dispatchers.IO) {
        if (result.toolId == "AI_THEORETICAL") {
            return@withContext writeTheoretical(userQuery, extraContext)
        }

        val keepHosts = buildSet {
            if (result.target.isNotBlank()) {
                add(result.target)
                add(result.target.substringBefore(':'))
            }
        }
        val redacted = TelemetryRedactor.redact(
            text = result.rawTelemetry.take(maxTelemetryChars),
            keepHosts = keepHosts
        )
        if (TelemetryRedactor.looksLeaky(redacted)) return@withContext null

        val user = buildString {
            appendLine("Petición del usuario: ${userQuery.take(300)}")
            appendLine("Herramienta ejecutada: ${result.toolId}")
            appendLine("Objetivo: ${result.target.ifBlank { "el dispositivo" }}")
            appendLine("Plano de privilegios: ${result.privilegeUsed.name}")
            if (matchedRules.isNotEmpty()) {
                appendLine("Reglas de amenaza coincidentes:")
                matchedRules.take(6).forEach { appendLine("- [${it.source}] ${it.title}") }
            }
            if (extraContext.isNotBlank()) appendLine("Contexto: ${extraContext.take(400)}")
            appendLine()
            appendLine("TELEMETRÍA MEDIDA (datos reales, no inventar nada fuera de esto):")
            appendLine(redacted)
        }

        val reply = withTimeoutOrNull(timeoutMs) {
            provider.complete(
                system = AuraSystemPrompt.narrative,
                user = user,
                jsonMode = false,
                maxTokens = 420
            )
        }
        reply?.let(::sanitize)
    }

    suspend fun writeTheoretical(userQuery: String, extraContext: String): String? =
        withContext(Dispatchers.IO) {
            val user = buildString {
                appendLine("Pregunta: ${userQuery.take(400)}")
                if (extraContext.isNotBlank()) appendLine("Estado del dispositivo: ${extraContext.take(600)}")
            }
            val reply = withTimeoutOrNull(timeoutMs) {
                provider.complete(
                    system = AuraSystemPrompt.theoretical,
                    user = user,
                    jsonMode = false,
                    maxTokens = 380
                )
            }
            reply?.let(::sanitize)
        }

    /** Strips fences, control chars and runaway length so the chat panel never breaks. */
    private fun sanitize(raw: String): String? {
        val cleaned = raw
            .replace("```", "")
            .replace("\r", "")
            .trim()
            .take(1_600)
        return cleaned.ifBlank { null }
    }
}
