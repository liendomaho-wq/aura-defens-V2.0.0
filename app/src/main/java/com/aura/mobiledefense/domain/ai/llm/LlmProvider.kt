package com.aura.mobiledefense.domain.ai.llm

/**
 * Contract every model backend implements. Three implementations ship with Aura:
 *
 *  - [GeminiProvider]          Google AI Studio / Gemini API (cloud)
 *  - [OpenAiCompatibleProvider] OpenAI, Groq, DeepSeek, Mistral, Ollama, LM Studio, vLLM, or any
 *                              gateway that speaks /v1/chat/completions
 *  - [OnDeviceProvider]        reserved slot for Gemini Nano / MediaPipe; returns null until wired
 *
 * Every method returns `null` on failure instead of throwing: the caller always has a deterministic
 * fallback and the app must never show an empty screen because a model was unreachable.
 */
interface LlmProvider {

    /** Human readable name shown in the UI, e.g. "Gemini · gemini-2.5-flash". */
    val displayName: String

    /** Cheap availability check (key present, endpoint configured). No network call. */
    fun isConfigured(): Boolean

    /**
     * @param system system prompt (Aura's cyberdefence rules)
     * @param user user content, already redacted
     * @param jsonMode ask the backend for strict JSON output when supported
     * @param maxTokens output cap
     */
    suspend fun complete(
        system: String,
        user: String,
        jsonMode: Boolean = false,
        maxTokens: Int = 1024
    ): String?
}

/** Where the user's model runs. Drives the privacy banner in the UI. */
enum class LlmBackendKind {
    /** On-device model: telemetry never leaves the phone. */
    ON_DEVICE,

    /** Third-party API: redacted telemetry is sent to the provider. */
    CLOUD,

    /** The user's own server / gateway on the LAN (Ollama, LM Studio, vLLM). */
    SELF_HOSTED
}

data class LlmSettings(
    val enabled: Boolean = false,
    val backend: LlmBackendKind = LlmBackendKind.CLOUD,
    val provider: LlmProviderId = LlmProviderId.GEMINI,
    val apiKey: String = "",
    val model: String = "",
    val baseUrl: String = "",
    val temperature: Float = 0.2f,
    val maxOutputTokens: Int = 1024,
    /** The user accepted the cloud-privacy notice. */
    val cloudConsentGiven: Boolean = false,
    /** Use the model for tool selection, not only for prose. */
    val useForIntent: Boolean = true,
    /** Use the model for the narrative shown in the chat. */
    val useForNarrative: Boolean = true
)

enum class LlmProviderId {
    GEMINI,
    OPENAI_COMPATIBLE,
    ON_DEVICE;

    val label: String
        get() = when (this) {
            GEMINI -> "Google Gemini"
            OPENAI_COMPATIBLE -> "OpenAI / compatible"
            ON_DEVICE -> "En el dispositivo"
        }
}
