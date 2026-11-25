package com.aura.mobiledefense.domain.ai.llm

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Any backend that speaks the OpenAI Chat Completions wire format:
 *
 *  - OpenAI            baseUrl = https://api.openai.com/v1
 *  - Groq              baseUrl = https://api.groq.com/openai/v1
 *  - DeepSeek          baseUrl = https://api.deepseek.com/v1
 *  - Mistral           baseUrl = https://api.mistral.ai/v1
 *  - Ollama (LAN)      baseUrl = http://192.168.1.x:11434/v1     (apiKey ignored)
 *  - LM Studio / vLLM  baseUrl = http://192.168.1.x:1234/v1
 *
 * Self-hosted endpoints run on the user's own hardware, so telemetry never reaches a third party.
 */
class OpenAiCompatibleProvider(
    private val apiKey: String,
    private val model: String,
    private val baseUrl: String,
    private val temperature: Float = 0.2f,
    private val label: String = "OpenAI compatible"
) : LlmProvider {

    companion object {
        const val DEFAULT_BASE_URL = "https://api.openai.com/v1"
        const val DEFAULT_MODEL = "gpt-4.1-mini"
    }

    override val displayName: String = "$label · $model"

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .callTimeout(75, TimeUnit.SECONDS)
        .build()

    private val jsonMedia = "application/json; charset=utf-8".toMediaType()

    private fun endpoint(): String {
        val trimmed = baseUrl.trimEnd('/')
        return if (trimmed.endsWith("/chat/completions")) trimmed else "$trimmed/chat/completions"
    }

    override fun isConfigured(): Boolean =
        model.isNotBlank() && baseUrl.isNotBlank() && (apiKey.isNotBlank() || isLocalEndpoint())

    /** Local Ollama/LM Studio accept no key. */
    private fun isLocalEndpoint(): Boolean {
        val host = runCatching { java.net.URI(baseUrl).host.orEmpty() }.getOrDefault("")
        return host == "localhost" || host == "127.0.0.1" || host.startsWith("192.168.") ||
            host.startsWith("10.") || host.startsWith("172.") || host.endsWith(".local")
    }

    override suspend fun complete(
        system: String,
        user: String,
        jsonMode: Boolean,
        maxTokens: Int
    ): String? = withContext(Dispatchers.IO) {
        if (!isConfigured()) return@withContext null
        runCatching {
            val body = JSONObject().apply {
                put("model", model)
                put("temperature", temperature.toDouble())
                put("max_tokens", maxTokens)
                put(
                    "messages",
                    JSONArray().apply {
                        put(JSONObject().put("role", "system").put("content", system))
                        put(JSONObject().put("role", "user").put("content", user))
                    }
                )
                if (jsonMode) {
                    // Supported by OpenAI, Groq, DeepSeek, Mistral and recent Ollama builds.
                    put("response_format", JSONObject().put("type", "json_object"))
                }
            }

            val builder = Request.Builder()
                .url(endpoint())
                .addHeader("Content-Type", "application/json")
                .post(body.toString().toRequestBody(jsonMedia))
            if (apiKey.isNotBlank()) builder.addHeader("Authorization", "Bearer $apiKey")

            client.newCall(builder.build()).execute().use { response ->
                val raw = response.body?.string().orEmpty()
                if (!response.isSuccessful) return@runCatching null
                extractText(raw)
            }
        }.getOrNull()
    }

    private fun extractText(raw: String): String? {
        val root = runCatching { JSONObject(raw) }.getOrNull() ?: return null
        val choices = root.optJSONArray("choices") ?: return null
        if (choices.length() == 0) return null
        val message = choices.optJSONObject(0)?.optJSONObject("message") ?: return null
        return message.optString("content").trim().ifBlank { null }
    }
}
