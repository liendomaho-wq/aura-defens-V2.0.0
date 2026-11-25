package com.aura.mobiledefense.domain.ai.llm

import com.aura.mobiledefense.data.model.ForensicToolPlan
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.domain.ai.NeuralIntentClassifier

/**
 * The deterministic resolver: Aura's original hand-weighted classifier.
 *
 * It is the fallback for every LLM failure (no key, no network, timeout, unparseable output, a
 * tool outside the catalogue, a suspected injection). It is also the only path for explicit slash
 * commands, which must never depend on a model.
 */
class HeuristicIntentResolver(
    private val classifier: NeuralIntentClassifier = NeuralIntentClassifier()
) {

    fun resolve(query: String, mode: PrivilegeMode, lastTarget: String = ""): ForensicToolPlan {
        val classification = classifier.classify(
            rawQuery = query,
            currentMode = mode,
            lastTarget = lastTarget
        )
        val plan = classification.plan
        // Never let the heuristic emit an id the ViewModel does not dispatch.
        return if (AuraToolCatalog.isAllowed(plan.toolId)) plan
        else AuraToolCatalog.buildPlan("AI_THEORETICAL", plan.target, plan.analysisFocus, mode) ?: plan
    }
}
