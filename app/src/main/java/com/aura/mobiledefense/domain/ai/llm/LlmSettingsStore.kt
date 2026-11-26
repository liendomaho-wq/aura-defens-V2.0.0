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

        /**
         * Presets del proveedor OpenAI-compatible. Los de LAN usan `localhost`, que **sí** está
         * exento en network_security_config para cleartext. El usuario debe cambiar la IP o, mejor,
         * exponer Ollama/LM Studio con `adb reverse tcp:11434 tcp:11434` (así `localhost:11434`
         * funciona desde el teléfono sin abrir HTTP en la red).
         */
        val openAiCompatiblePresets = listOf(
            Triple("OpenAI", "https://api.openai.com/v1", "gpt-4.1-mini"),
            Triple("Groq", "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
            Triple("DeepSeek", "https://api.deepseek.com/v1", "deepseek-chat"),
            Triple("Mistral", "https://api.mistral.ai/v1", "mistral-small-latest"),
            Triple("Ollama (adb reverse)", "http://localhost:11434/v1", "llama3.1:8b"),
            Triple("LM Studio (adb reverse)", "http://localhost:1234/v1", "local-model")
        )

        /** Aviso legible cuando el endpoint es HTTP y no está exento por la política de red. */
        fun cleartextWarning(baseUrl: String): String? {
            val url = baseUrl.trim().lowercase()
            if (!url.startsWith("http://")) return null
            val host = url.removePrefix("http://").substringBefore('/').substringBefore(':')
            val exempt = host == "localhost" || host == "127.0.0.1" || host == "10.0.2.2" || host == "10.8.0.2"
            return if (exempt) null else
                "HTTP en claro hacia $host está bloqueado por android:usesCleartextTraffic=false. " +
                    "Usa HTTPS, localhost con `adb reverse`, o sirve el modelo tras un proxy TLS."
        }
    }

    /** true cuando la clave API vive en un almacén cifrado por el AndroidKeyStore. */
    @Volatile
    var secureStorageAvailable: Boolean = false
        private set

    /**
     * Clave API en memoria. Es el **único** respaldo cuando el KeyStore no está disponible: si no
     * se puede cifrar, no se escribe en disco. Antes este camino caía a SharedPreferences normales,
     * que dejan la clave en texto claro en /data/data/.../shared_prefs.
     */
    @Volatile
    private var volatileApiKey: String = ""

    private val secure: SharedPreferences? = runCatching {
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
    }.onFailure {
        Log.w(TAG, "EncryptedSharedPreferences no disponible: clave solo en memoria (${it.message})")
    }.getOrNull()

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
        apiKey = secure?.let { prefs ->
            runCatching { prefs.getString("api_key", "").orEmpty() }.getOrDefault("")
        } ?: volatileApiKey,
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
        val encryptedStore = secure
        if (encryptedStore != null) {
            // La clave se cifra con una clave AES-GCM que nunca sale del AndroidKeyStore.
            runCatching { encryptedStore.edit().putString("api_key", next.apiKey).apply() }
                .onSuccess { secureStorageAvailable = true }
                .onFailure {
                    // Si no se puede escribir, no se debe cargar luego la clave ANTERIOR: la vieja
                    // sería distinta de la que el usuario acaba de teclear. Se borra la entrada y
                    // la clave vive solo en memoria, como cuando no hay KeyStore.
                    runCatching { encryptedStore.edit().remove("api_key").apply() }
                    volatileApiKey = next.apiKey
                    secureStorageAvailable = false
                }
        } else {
            // Sin KeyStore: la clave NO toca el disco, se queda en memoria. Aura lo avisa en /ia.
            volatileApiKey = next.apiKey
            secureStorageAvailable = false
        }
        _settings.value = next
    }

    fun clearKey() {
        volatileApiKey = ""
        runCatching { secure?.edit()?.remove("api_key")?.apply() }
        update { it.copy(apiKey = "", enabled = false) }
    }

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
