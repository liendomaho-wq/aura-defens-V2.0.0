package com.aura.mobiledefense.domain.ai.llm

import org.json.JSONArray
import org.json.JSONObject

/**
 * Adapta el clasificador de intenciones fine-tuneado (FunctionGemma 270M, formato de *function
 * calling* nativo de Gemma) al contrato [LlmProvider] que ya usa [LlmIntentResolver].
 *
 * Flujo:
 *   user (texto en español) + catálogo cerrado de 20 herramientas
 *     -> `<start_function_call>call:PORT_PROBE{reason:<escape>…<escape>,target:<escape>…<escape>}<end_function_call>`
 *     -> [toJson] lo convierte al JSON `{toolId, target, needsTarget, reason}` que espera el resolver
 *     -> [LlmIntentResolver] valida contra [AuraToolCatalog] y [TargetValidator].
 *
 * El modelo **nunca** emite comandos de shell: solo elige un `toolId` de la lista. Si devuelve una
 * herramienta fuera del catálogo, texto basura o nada, [LlmIntentResolver] lo descarta y la app cae
 * al motor heurístico. Esta clase no decide, solo traduce.
 *
 * `inference` es el motor real (MediaPipe LLM Inference, llama.cpp JNI, etc.). Mientras sea null el
 * proveedor no está configurado y no se usa.
 */
class FunctionGemmaToolProvider(
    private val inference: (suspend (prompt: String, maxTokens: Int) -> String?)? = null,
    private val maxTokens: Int = 64
) : LlmProvider {

    override val displayName: String = "FunctionGemma 270M (local, fine-tune Aura)"

    override fun isConfigured(): Boolean = inference != null

    override suspend fun complete(
        system: String,
        user: String,
        jsonMode: Boolean,
        maxTokens: Int
    ): String? {
        val engine = inference ?: return null
        val prompt = buildPrompt(user)
        val raw = runCatching { engine(prompt, maxTokens.coerceAtMost(this.maxTokens)) }.getOrNull()
            ?: return null
        return toJson(raw)
    }

    /** Prompt completo en el formato exacto con el que se entrenó (ver aura-train/render_dataset.py). */
    fun buildPrompt(userText: String): String = buildString {
        append("<bos><start_of_turn>developer\n")
        append(AuraSystemPrompt.intent.trim())
        for (tool in AuraToolCatalog.tools) {
            append("<start_function_declaration>")
            append(declaration(tool))
            append("<end_function_declaration>")
        }
        append("<end_of_turn>\n")
        append("<start_of_turn>user\n")
        append(userText.trim().take(MAX_INPUT_CHARS))
        append("<start_of_turn>model\n")
    }

    private fun declaration(tool: LlmToolSpec): String = buildString {
        append("declaration:").append(tool.id).append("{description:<escape>")
        append(tool.summary).append("<escape>")
        val properties = when (tool.targetKind) {
            TargetKind.HOST -> "target:{description:<escape>dominio o IP del objetivo autorizado<escape>}"
            TargetKind.PATTERN -> "target:{description:<escape>dominio, IP o puerto a aplicar<escape>}"
            TargetKind.FREETEXT -> "target:{description:<escape>texto libre, token o comando de inspección<escape>}"
            TargetKind.NONE -> ""
        }
        if (properties.isNotEmpty()) {
            append(",parameters:{properties:{")
            append(properties)
            append(",reason:{description:<escape>motivo breve en español<escape>}}")
            if (tool.requiresTarget) append(",required:[<escape>target<escape>]")
            append("}")
        }
        append("}")
    }

    companion object {
        private const val MAX_INPUT_CHARS = 600
        private val CALL = Regex(
            "call:([A-Za-z_][A-Za-z0-9_]*)\\{(.*?)}<end_function_call>",
            RegexOption.DOT_MATCHES_ALL
        )
        private val TARGET = Regex("target:<escape>(.*?)<escape>", RegexOption.DOT_MATCHES_ALL)
        private val REASON = Regex("reason:<escape>(.*?)<escape>", RegexOption.DOT_MATCHES_ALL)

        /**
         * Traduce la salida nativa del modelo al JSON del resolver. Devuelve null si no hay ninguna
         * llamada reconocible, para que el llamador use el fallback heurístico.
         */
        fun toJson(raw: String): String? {
            val match = CALL.find(raw) ?: return null
            val toolId = match.groupValues[1].trim().uppercase()
            val body = match.groupValues[2]
            val target = TARGET.find(body)?.groupValues?.get(1)?.trim().orEmpty()
            val reason = REASON.find(body)?.groupValues?.get(1)?.trim()?.take(200).orEmpty()
            val spec = AuraToolCatalog.spec(toolId)
            val needsTarget = spec?.requiresTarget == true && target.isBlank()
            return JSONObject()
                .put("toolId", toolId)
                .put("target", target)
                .put("needsTarget", needsTarget)
                .put("reason", reason)
                .toString()
        }

        /** Utilidad para las pruebas: herramientas declaradas en el prompt, en orden. */
        fun declaredToolIds(): JSONArray =
            JSONArray().apply { AuraToolCatalog.tools.forEach { put(it.id) } }
    }
}
