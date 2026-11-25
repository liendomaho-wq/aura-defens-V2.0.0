package com.aura.mobiledefense.domain.ai.llm

/**
 * On-device backend slot.
 *
 * Aura already ships the heuristic engine as the true on-device "brain". This class exists so the
 * on-device *generative* model (Gemini Nano via ML Kit GenAI, or a MediaPipe/llama.cpp GGUF bundle)
 * can be dropped in later without touching the ViewModel: implement [complete] and set
 * [available] to true from the model's own availability check.
 *
 * Until then it reports unavailable and every call returns null, so the caller falls back to the
 * deterministic templates and the heuristic classifier. No behaviour change, no crash, no fake AI.
 */
class OnDeviceProvider(
    private val delegate: (suspend (system: String, user: String, jsonMode: Boolean, maxTokens: Int) -> String?)? = null
) : LlmProvider {

    override val displayName: String = "Modelo local en el dispositivo"

    /** Set this to true from the platform check once a real on-device model is bundled. */
    @Volatile
    var available: Boolean = delegate != null

    override fun isConfigured(): Boolean = available && delegate != null

    override suspend fun complete(
        system: String,
        user: String,
        jsonMode: Boolean,
        maxTokens: Int
    ): String? {
        val d = delegate ?: return null
        if (!available) return null
        return runCatching { d(system, user, jsonMode, maxTokens) }.getOrNull()
    }
}
