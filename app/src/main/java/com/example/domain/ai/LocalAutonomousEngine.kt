package com.example.domain.ai

import com.example.data.local.ThreatRuleEntity
import com.example.data.model.AiEngineMode
import com.example.data.model.AiVisualScene
import com.example.data.model.ForensicToolPlan
import com.example.data.model.PrivilegeMode
import com.example.data.model.RootCapabilityState
import com.example.data.model.ThreatKnowledgeStats
import com.example.data.model.ToolExecutionResult
import com.example.domain.engines.PatchAndReportEngine

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
