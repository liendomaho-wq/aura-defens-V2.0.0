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
 * Google Gemini (AI Studio / Vertex-compatible REST) backend.
 *
 * Uses generateContent with `responseMimeType: application/json` when [jsonMode] is set, which is
 * the documented way to get parseable output from Gemini 1.5/2.x.
 */
class GeminiProvider(
    private val apiKey: String,
    private val model: String = DEFAULT_MODEL,
    private val baseUrl: String = DEFAULT_BASE_URL,
    private val temperature: Float = 0.2f
) : LlmProvider {

    companion object {
        const val DEFAULT_MODEL = "gemini-2.5-flash"
        const val DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
    }

    override val displayName: String = "Gemini · $model"

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(45, TimeUnit.SECONDS)
        .callTimeout(60, TimeUnit.SECONDS)
        .build()

    private val jsonMedia = "application/json; charset=utf-8".toMediaType()

    override fun isConfigured(): Boolean = apiKey.isNotBlank() && model.isNotBlank()

    override suspend fun complete(
        system: String,
        user: String,
        jsonMode: Boolean,
        maxTokens: Int
    ): String? = withContext(Dispatchers.IO) {
        if (!isConfigured()) return@withContext null
        runCatching {
            val body = JSONObject().apply {
                put(
                    "systemInstruction",
                    JSONObject().put("parts", JSONArray().put(JSONObject().put("text", system)))
                )
                put(
                    "contents",
                    JSONArray().put(
                        JSONObject().apply {
                            put("role", "user")
                            put("parts", JSONArray().put(JSONObject().put("text", user)))
                        }
                    )
                )
                put(
                    "generationConfig",
                    JSONObject().apply {
                        put("temperature", temperature.toDouble())
                        put("maxOutputTokens", maxTokens)
                        put("topP", 0.95)
                        if (jsonMode) put("responseMimeType", "application/json")
                    }
                )
                put(
                    "safetySettings",
                    JSONArray().apply {
                        listOf(
                            "HARM_CATEGORY_HARASSMENT",
                            "HARM_CATEGORY_HATE_SPEECH",
                            "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                            "HARM_CATEGORY_DANGEROUS_CONTENT"
                        ).forEach { cat ->
                            put(
                                JSONObject()
                                    .put("category", cat)
                                    .put("threshold", "BLOCK_ONLY_HIGH")
                            )
                        }
                    }
                )
            }

            val request = Request.Builder()
                .url("$baseUrl/models/$model:generateContent")
                .addHeader("x-goog-api-key", apiKey)
                .addHeader("Content-Type", "application/json")
                .post(body.toString().toRequestBody(jsonMedia))
                .build()

            client.newCall(request).execute().use { response ->
                val raw = response.body?.string().orEmpty()
                if (!response.isSuccessful) return@runCatching null
                extractText(raw)
            }
        }.getOrNull()
    }

    private fun extractText(raw: String): String? {
        val root = runCatching { JSONObject(raw) }.getOrNull() ?: return null
        val candidates = root.optJSONArray("candidates") ?: return null
        if (candidates.length() == 0) return null
        val parts = candidates.optJSONObject(0)
            ?.optJSONObject("content")
            ?.optJSONArray("parts") ?: return null
        val sb = StringBuilder()
        for (i in 0 until parts.length()) {
            parts.optJSONObject(i)?.optString("text")?.let { sb.append(it) }
        }
        return sb.toString().trim().ifBlank { null }
    }
}
