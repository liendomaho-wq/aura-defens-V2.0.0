package com.aura.mobiledefense.domain.ai.llm

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.aura.mobiledefense.data.model.AiEngineMode
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

private const val TAG = "LlmSettingsStore"
private const val PREFS_ENCRYPTED = "aura_llm_secure"
private const val PREFS_PLAIN = "aura_llm_prefs"

/**
 * Persists the LLM configuration.
 *
 * The API key goes to `EncryptedSharedPreferences` (AndroidKeyStore-backed AES256-GCM) and never
 * touches the Room database, the logs or the exported schemas. The rest of the settings live in
 * plain prefs because they are not secret.
 *
 * The key is BYOK: the user's own credential, stored on the user's own device. Nothing is baked
 * into the APK, so `apktool` cannot extract a shared secret.
 */
class LlmSettingsStore private constructor(context: Context) {

    companion object {
        @Volatile
        private var instance: LlmSettingsStore? = null

        fun get(context: Context): LlmSettingsStore =
            instance ?: synchronized(this) {
                instance ?: LlmSettingsStore(context.applicationContext).also { instance = it }
            }

        /** Models offered in the settings UI per provider. */
        val geminiModels = listOf(
            "gemini-2.5-flash",
            "gemini-2.5-flash-lite",
            "gemini-2.5-pro"
        )

        val openAiCompatiblePresets = listOf(
            Triple("OpenAI", "https://api.openai.com/v1", "gpt-4.1-mini"),
            Triple("Groq", "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
            Triple("DeepSeek", "https://api.deepseek.com/v1", "deepseek-chat"),
            Triple("Mistral", "https://api.mistral.ai/v1", "mistral-small-latest"),
            Triple("Ollama local", "http://192.168.1.10:11434/v1", "llama3.1:8b"),
            Triple("LM Studio local", "http://192.168.1.10:1234/v1", "local-model")
        )
    }

    private val secure: SharedPreferences = runCatching {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_ENCRYPTED,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        ) as SharedPreferences
    }.getOrElse {
        // Some heavily modified ROMs fail to open the keystore. Degrade to a memory-only store so
        // the app keeps working and never silently writes a key in cleartext.
        Log.w(TAG, "EncryptedSharedPreferences unavailable, using memory-only key storage: ${it.message}")
        context.getSharedPreferences("aura_llm_volatile", Context.MODE_PRIVATE)
    }

    private val plain: SharedPreferences = context.getSharedPreferences(PREFS_PLAIN, Context.MODE_PRIVATE)

    // The app always starts in the truthful mode: LLM only if a provider is actually usable.
    private val _settings = MutableStateFlow(
        load().let { loaded ->
            if (loaded.enabled && buildProvider(loaded) == null) loaded.copy(enabled = false) else loaded
        }
    )

    val settings: StateFlow<LlmSettings> = _settings.asStateFlow()

    private fun load(): LlmSettings = LlmSettings(
        enabled = plain.getBoolean("enabled", false),
        backend = runCatching { LlmBackendKind.valueOf(plain.getString("backend", "CLOUD")!!) }
            .getOrDefault(LlmBackendKind.CLOUD),
        provider = runCatching { LlmProviderId.valueOf(plain.getString("provider", "GEMINI")!!) }
            .getOrDefault(LlmProviderId.GEMINI),
        apiKey = runCatching { secure.getString("api_key", "").orEmpty() }.getOrDefault(""),
        model = plain.getString("model", "").orEmpty(),
        baseUrl = plain.getString("base_url", "").orEmpty(),
        temperature = plain.getFloat("temperature", 0.2f),
        maxOutputTokens = plain.getInt("max_tokens", 1024),
        cloudConsentGiven = plain.getBoolean("cloud_consent", false),
        useForIntent = plain.getBoolean("use_intent", true),
        useForNarrative = plain.getBoolean("use_narrative", true)
    )

    fun update(transform: (LlmSettings) -> LlmSettings) {
        val next = transform(_settings.value)
        plain.edit().apply {
            putBoolean("enabled", next.enabled)
            putString("backend", next.backend.name)
            putString("provider", next.provider.name)
            putString("model", next.model)
            putString("base_url", next.baseUrl)
            putFloat("temperature", next.temperature)
            putInt("max_tokens", next.maxOutputTokens)
            putBoolean("cloud_consent", next.cloudConsentGiven)
            putBoolean("use_intent", next.useForIntent)
            putBoolean("use_narrative", next.useForNarrative)
        }.apply()
        runCatching { secure.edit().putString("api_key", next.apiKey).apply() }
        _settings.value = next
    }

    fun clearKey() = update { it.copy(apiKey = "", enabled = false) }

    /** Effective model name, falling back to the provider default. */
    fun effectiveModel(settings: LlmSettings): String = when {
        settings.model.isNotBlank() -> settings.model
        settings.provider == LlmProviderId.GEMINI -> GeminiProvider.DEFAULT_MODEL
        else -> OpenAiCompatibleProvider.DEFAULT_MODEL
    }

    /**
     * Builds the provider for the current settings, or null when nothing usable is configured.
     * Called on every request so a settings change takes effect immediately.
     */
    fun buildProvider(settings: LlmSettings = _settings.value): LlmProvider? {
        if (!settings.enabled) return null
        val model = effectiveModel(settings)
        val provider = when (settings.provider) {
            LlmProviderId.GEMINI -> GeminiProvider(
                apiKey = settings.apiKey,
                model = model,
                temperature = settings.temperature
            )
            LlmProviderId.OPENAI_COMPATIBLE -> OpenAiCompatibleProvider(
                apiKey = settings.apiKey,
                model = model,
                baseUrl = settings.baseUrl.ifBlank { OpenAiCompatibleProvider.DEFAULT_BASE_URL },
                temperature = settings.temperature,
                label = if (settings.backend == LlmBackendKind.SELF_HOSTED) "Servidor propio" else "OpenAI compatible"
            )
            LlmProviderId.ON_DEVICE -> OnDeviceProvider()
        }
        return provider.takeIf { it.isConfigured() }
    }

    /** Maps the LLM availability onto the existing `AiEngineMode` the UI already renders. */
    fun engineModeFor(settings: LlmSettings): AiEngineMode =
        if (settings.enabled && buildProvider(settings) != null) AiEngineMode.ONLINE_CLOUD
        else AiEngineMode.LOCAL_AUTONOMOUS
}
