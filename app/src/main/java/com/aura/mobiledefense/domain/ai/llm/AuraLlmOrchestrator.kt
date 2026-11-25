package com.aura.mobiledefense.domain.ai.llm

import com.aura.mobiledefense.data.model.AiEngineMode
import com.aura.mobiledefense.data.local.ThreatRuleEntity
import com.aura.mobiledefense.data.model.AiVisualScene
import com.aura.mobiledefense.data.model.RootCapabilityState
import com.aura.mobiledefense.data.model.ThreatKnowledgeStats
import com.aura.mobiledefense.data.model.ToolExecutionResult
import com.aura.mobiledefense.domain.ai.AuraNeuralAiEngine
import com.aura.mobiledefense.domain.ai.ConversationalTopic
import com.aura.mobiledefense.domain.ai.IntentClassification
import com.aura.mobiledefense.data.model.ForensicToolPlan
import com.aura.mobiledefense.data.model.PrivilegeMode

/**
 * Single entry point the ViewModel talks to.
 *
 * It owns the LLM-versus-heuristic decision so the rest of the app never has to know whether a
 * model is configured:
 *
 *   explicit slash command   → heuristic (always, deterministic)
 *   LLM configured + healthy → LLM tool choice, validated against the catalogue
 *   LLM down / invalid       → heuristic
 *
 * The narrative follows the same shape: LLM when available, template otherwise. A failure never
 * reaches the UI as an error.
 */
class AuraLlmOrchestrator(
    private val engine: AuraNeuralAiEngine,
    private val settingsStore: LlmSettingsStore,
    private val heuristic: HeuristicIntentResolver = HeuristicIntentResolver()
) {

    data class Resolution(
        val classification: IntentClassification,
        val source: ResolutionSource,
        val modelReason: String = "",
        val needsTarget: Boolean = false,
        val modelOutput: String? = null,
        val failure: LlmFailure? = null
    )

    enum class ResolutionSource {
        SLASH_COMMAND,
        HEURISTIC,
        LLM
    }

    private var lastTarget: String = ""

    suspend fun plan(query: String, mode: PrivilegeMode): Resolution {
        val trimmed = query.trim()

        // 1. Explicit commands are sacred: never routed through a model.
        if (trimmed.startsWith("/")) {
            val plan = heuristic.resolve(trimmed, mode, lastTarget)
            rememberTarget(plan)
            return Resolution(
                classification = wrap(plan),
                source = ResolutionSource.SLASH_COMMAND
            )
        }

        // 2. Try the model.
        val settings = settingsStore.settings.value
        val provider = if (settings.enabled && settings.useForIntent) settingsStore.buildProvider(settings) else null
        if (provider != null) {
            val outcome = LlmIntentResolver(provider).resolve(trimmed, mode)
            val plan = outcome.plan
            if (plan != null) {
                rememberTarget(plan)
                return Resolution(
                    classification = wrap(plan),
                    source = ResolutionSource.LLM,
                    modelReason = outcome.reason,
                    modelOutput = outcome.rawModelOutput
                )
            }
            val fallbackPlan = heuristic.resolve(trimmed, mode, lastTarget)
            rememberTarget(fallbackPlan)
            return Resolution(
                classification = wrap(fallbackPlan),
                source = ResolutionSource.HEURISTIC,
                modelReason = outcome.reason,
                needsTarget = outcome.needsTarget,
                modelOutput = outcome.rawModelOutput,
                failure = outcome.failure
            )
        }

        // 3. No model: deterministic only.
        val plan = heuristic.resolve(trimmed, mode, lastTarget)
        rememberTarget(plan)
        return Resolution(
            classification = wrap(plan),
            source = ResolutionSource.HEURISTIC,
            failure = if (settings.enabled) LlmFailure.NOT_CONFIGURED else null
        )
    }

    /**
     * Builds the scene with the template engine, then swaps in a model-written narrative when one
     * is available. Nodes, edges, severity and patches always come from the measured telemetry.
     */
    suspend fun synthesize(
        userQuery: String,
        resolution: Resolution,
        toolResult: ToolExecutionResult,
        matchedRules: List<ThreatRuleEntity>,
        knowledgeStats: ThreatKnowledgeStats,
        rootState: RootCapabilityState,
        engineMode: AiEngineMode
    ): AiVisualScene {
        val base = engine.synthesizeScene(
            userQuery = userQuery,
            classification = resolution.classification,
            toolResult = toolResult,
            matchedRules = matchedRules,
            engineMode = engineMode,
            knowledgeStats = knowledgeStats,
            rootState = rootState
        )

        val settings = settingsStore.settings.value
        val provider = if (settings.enabled && settings.useForNarrative) {
            settingsStore.buildProvider(settings)
        } else null

        val extra = buildString {
            if (resolution.modelReason.isNotBlank()) {
                append("Motivo de la herramienta elegida: ${resolution.modelReason}. ")
            }
            append("Firmas de amenaza activas: ${knowledgeStats.totalRules}. ")
            append("SELinux: ${rootState.selinuxMode}.")
        }

        val llmText = if (provider != null) {
            LlmNarrativeWriter(provider).write(
                userQuery = userQuery,
                result = toolResult,
                matchedRules = matchedRules,
                extraContext = extra
            )
        } else null

        val scene = engine.withNarrative(base, llmText)
        return if (llmText != null) {
            scene.copy(subtitle = scene.subtitle.replace("IA Local", "IA Online"))
        } else scene
    }

    fun resetContext() {
        lastTarget = ""
    }

    private fun rememberTarget(plan: ForensicToolPlan) {
        if (plan.target.isNotBlank()) lastTarget = plan.target
    }

    private fun wrap(plan: ForensicToolPlan): IntentClassification = IntentClassification(
        plan = plan,
        topic = ConversationalTopic.NONE,
        confidence = 1.0f,
        extractedHost = plan.target
    )
}
