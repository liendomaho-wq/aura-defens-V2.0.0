package com.aura.mobiledefense.domain.ai

import com.aura.mobiledefense.data.local.ThreatRuleEntity
import com.aura.mobiledefense.data.model.AiEngineMode
import com.aura.mobiledefense.data.model.AiVisualScene
import com.aura.mobiledefense.data.model.ForensicToolPlan
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.data.model.RootCapabilityState
import com.aura.mobiledefense.data.model.ThreatKnowledgeStats
import com.aura.mobiledefense.data.model.ToolExecutionResult
import com.aura.mobiledefense.domain.engines.PatchAndReportEngine

/**
 * Facade over [AuraNeuralAiEngine] for strictly local/offline invocations and unit verification.
 */
class LocalAutonomousEngine(
    patchAndReportEngine: PatchAndReportEngine
) {
    private val neuralEngine = AuraNeuralAiEngine(patchAndReportEngine)

    fun planLocally(query: String, mode: PrivilegeMode): ForensicToolPlan {
        return neuralEngine.planExecution(query, mode).plan
    }

    fun synthesizeLocally(
        userQuery: String,
        toolResult: ToolExecutionResult,
        matchedRules: List<ThreatRuleEntity>
    ): AiVisualScene {
        val classification = neuralEngine.planExecution(userQuery, toolResult.privilegeUsed)
        return neuralEngine.synthesizeScene(
            userQuery = userQuery,
            classification = classification,
            toolResult = toolResult,
            matchedRules = matchedRules,
            engineMode = AiEngineMode.LOCAL_AUTONOMOUS,
            knowledgeStats = ThreatKnowledgeStats(totalRules = matchedRules.size.coerceAtLeast(6)),
            rootState = RootCapabilityState(verified = toolResult.privilegeUsed == PrivilegeMode.ROOT)
        )
    }
}
