package com.aura.mobiledefense.domain.ai.llm

import android.util.Log
import com.aura.mobiledefense.data.model.ForensicToolPlan
import com.aura.mobiledefense.data.model.PrivilegeMode
import org.json.JSONObject

private const val TAG = "LlmIntentResolver"

data class LlmIntentOutcome(
    val plan: ForensicToolPlan?,
    val needsTarget: Boolean,
    val reason: String,
    val rawModelOutput: String?,
    val failure: LlmFailure?
)

enum class LlmFailure {
    NOT_CONFIGURED,
    NETWORK,
    UNPARSEABLE,
    TOOL_NOT_ALLOWED,
    INJECTION_SUSPECTED,
    NEEDS_TARGET
}

/**
 * Turns a natural-language request into one of Aura's real tools using an LLM.
 *
 * The model never executes anything. It returns JSON that is parsed and validated here against the
 * closed [AuraToolCatalog]; anything unexpected is discarded and the caller falls back to the
 * deterministic [HeuristicIntentResolver].
 *
 * Defences applied, in order:
 *  1. Prompt-injection marker scan on the raw user text.
 *  2. Hard cap on input length.
 *  3. JSON-only response, parsed with org.json (no lenient parsing).
 *  4. toolId must exist in [AuraToolCatalog.allowedIds].
 *  5. Target must pass [TargetValidator] for that tool's target kind.
 *  6. `prefersRoot` can only be honoured when the user is already in ROOT mode.
 */
class LlmIntentResolver(
    private val provider: LlmProvider,
    private val maxInputChars: Int = 600
) {

    suspend fun resolve(query: String, mode: PrivilegeMode): LlmIntentOutcome {
        val trimmed = query.trim()
        if (trimmed.isBlank()) {
            return LlmIntentOutcome(null, false, "", null, LlmFailure.NOT_CONFIGURED)
        }
        if (AuraSystemPrompt.isInjectionAttempt(trimmed)) {
            Log.w(TAG, "Prompt injection markers detected, refusing LLM routing")
            return LlmIntentOutcome(null, false, "", null, LlmFailure.INJECTION_SUSPECTED)
        }

        val userContent = trimmed.take(maxInputChars)
        val raw = provider.complete(
            system = AuraSystemPrompt.intent,
            user = userContent,
            jsonMode = true,
            maxTokens = 300
        ) ?: return LlmIntentOutcome(null, false, "", null, LlmFailure.NETWORK)

        val json = extractJson(raw)
        if (json == null) {
            Log.w(TAG, "Model returned non-JSON output: ${raw.take(120)}")
            return LlmIntentOutcome(null, false, "", raw, LlmFailure.UNPARSEABLE)
        }

        val toolId = json.optString("toolId").trim().uppercase()
        if (!AuraToolCatalog.isAllowed(toolId)) {
            Log.w(TAG, "Model proposed a tool outside the catalogue: $toolId")
            return LlmIntentOutcome(null, false, "", raw, LlmFailure.TOOL_NOT_ALLOWED)
        }

        val spec = AuraToolCatalog.spec(toolId)!!
        val rawTarget = json.optString("target").trim()
        val needsTargetFlag = json.optBoolean("needsTarget", false)
        val reason = json.optString("reason").trim().take(200)

        val target = TargetValidator.normalize(rawTarget, spec.targetKind)
        if (spec.requiresTarget && target.isBlank()) {
            return LlmIntentOutcome(null, true, reason, raw, LlmFailure.NEEDS_TARGET)
        }
        if (!TargetValidator.isValid(target, spec.targetKind)) {
            Log.w(TAG, "Model returned an invalid target for $toolId: $rawTarget")
            return LlmIntentOutcome(null, needsTargetFlag, reason, raw, LlmFailure.UNPARSEABLE)
        }

        val plan = AuraToolCatalog.buildPlan(toolId, target, reason, mode)
            ?: return LlmIntentOutcome(null, false, reason, raw, LlmFailure.TOOL_NOT_ALLOWED)

        return LlmIntentOutcome(plan, needsTargetFlag, reason, raw, null)
    }

    /**
     * Accepts both a bare JSON object and one wrapped in ```json fences, which some models still
     * emit despite `responseMimeType`. Never tries to repair malformed JSON.
     */
    private fun extractJson(raw: String): JSONObject? {
        val cleaned = raw
            .replace("```json", "")
            .replace("```", "")
            .trim()
        val start = cleaned.indexOf('{')
        val end = cleaned.lastIndexOf('}')
        if (start < 0 || end <= start) return null
        return runCatching { JSONObject(cleaned.substring(start, end + 1)) }.getOrNull()
    }
}
