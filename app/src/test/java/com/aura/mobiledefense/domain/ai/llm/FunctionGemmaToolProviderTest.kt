package com.aura.mobiledefense.domain.ai.llm
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Contrato del adaptador FunctionGemma ↔ AuraToolCatalog.
 *
 * Lo que se protege aquí:
 *  1. El prompt que se manda al modelo es idéntico en forma al que se usó para entrenar
 *     (aura-train/render_dataset.py): tokens de control de Gemma, `<escape>` y 20 declaraciones.
 *  2. La salida nativa del modelo (`call:TOOL{...}<end_function_call>`) se traduce a un JSON que
 *     [LlmIntentResolver] acepta, y una herramienta fuera del catálogo NUNCA llega a un plan.
 *  3. Los casos congelados del dataset siguen despachando la herramienta esperada.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class FunctionGemmaToolProviderTest {

    private fun renderedModelOutput(toolId: String, target: String, reason: String = "motivo"): String =
        "<start_function_call>call:$toolId{" +
            "reason:<escape>$reason<escape>,target:<escape>$target<escape>}" +
            "<end_function_call>"

    @Test
    fun `prompt uses the exact FunctionGemma control tokens`() {
        val prompt = FunctionGemmaToolProvider().buildPrompt("escanea los puertos de miempresa.com")
        assertTrue(prompt.startsWith("<bos><start_of_turn>developer\n"))
        assertTrue(prompt.contains("<end_of_turn>\n<start_of_turn>user\n"))
        assertTrue(prompt.contains("escanea los puertos de miempresa.com"))
        assertTrue(prompt.endsWith("<start_of_turn>model\n"))
        // Un turno `model` abierto sin cerrar: el modelo continúa con la llamada.
        assertEquals(1, Regex("<start_of_turn>model").findAll(prompt).count())
    }

    @Test
    fun `prompt declares every catalogued tool once`() {
        val prompt = FunctionGemmaToolProvider().buildPrompt("hola")
        val declared = Regex("<start_function_declaration>declaration:([A-Z_]+)\\{")
            .findAll(prompt).map { it.groupValues[1] }.toList()
        assertEquals(AuraToolCatalog.allowedIds.toList(), declared)
        // 20 herramientas del dataset congelado + APP_FIREWALL_* (firewall por app) e
        // INTEL_* (OSV/URLhaus bajo demanda). El modelo local no las vio en entrenamiento;
        // los proveedores API sí las reciben como contrato real. Sincronía con AuraToolCatalog.
        assertEquals(25, declared.size)
        assertEquals(25, Regex("<end_function_declaration>").findAll(prompt).count())
    }

    @Test
    fun `prompt marks required target only for tools that need one`() {
        val prompt = FunctionGemmaToolProvider().buildPrompt("hola")
        val portBlock = prompt.substringAfter("declaration:PORT_PROBE{").substringBefore("<end_function_declaration>")
        val selfIntegrity = prompt.substringAfter("declaration:SELF_INTEGRITY{")
            .substringBefore("<end_function_declaration>")
        assertTrue(portBlock.contains("required:[<escape>target<escape>]"))
        assertTrue(!selfIntegrity.contains("required:"))
    }

    @Test
    fun `native call is translated to the resolver json`() {
        val json = FunctionGemmaToolProvider.toJson(
            renderedModelOutput("PORT_PROBE", "miempresa.com", "Sondear puertos TCP")
        )
        requireNotNull(json)
        assertTrue(json.contains("\"toolId\":\"PORT_PROBE\""))
        assertTrue(json.contains("\"target\":\"miempresa.com\""))
        assertTrue(json.contains("\"needsTarget\":false"))
    }

    @Test
    fun `missing target is flagged instead of invented`() {
        val json = FunctionGemmaToolProvider.toJson(renderedModelOutput("TLS_INSPECT", ""))
        requireNotNull(json)
        assertTrue(json.contains("\"needsTarget\":true"))
        assertTrue(json.contains("\"target\":\"\""))
    }

    @Test
    fun `tool outside the catalogue never becomes a plan`() {
        val raw = "<start_function_call>call:rm_rf_everything{target:<escape>/<escape>}" +
            "<end_function_call>"
        val json = FunctionGemmaToolProvider.toJson(raw)
        requireNotNull(json)
        assertTrue(json.contains("\"toolId\":\"RM_RF_EVERYTHING\""))
        // El catálogo lo rechaza: aquí es donde se corta.
        assertTrue(!AuraToolCatalog.isAllowed("RM_RF_EVERYTHING"))
        assertNull(AuraToolCatalog.buildPlan("RM_RF_EVERYTHING", "/", "", com.aura.mobiledefense.data.model.PrivilegeMode.USERLAND))
    }

    @Test
    fun `garbage output falls back to null`() {
        assertNull(FunctionGemmaToolProvider.toJson("no sé qué hacer con eso"))
        assertNull(FunctionGemmaToolProvider.toJson(""))
        assertNull(FunctionGemmaToolProvider.toJson("call:PORT_PROBE{target:<escape>x<escape>}"))
    }

    @Test
    fun `lowercase tool id is normalised`() {
        val json = FunctionGemmaToolProvider.toJson(renderedModelOutput("dns_recon", "midominio.com"))
        requireNotNull(json)
        assertTrue(json.contains("\"toolId\":\"DNS_RECON\""))
    }

    @Test
    fun `every frozen dataset case still maps to its tool`() {
        for (case in FunctionGemmaFixtures.cases) {
            val json = FunctionGemmaToolProvider.toJson(
                renderedModelOutput(case.toolId, case.target)
            )
            requireNotNull(json) { "sin llamada para ${case.user}" }
            assertTrue(
                "el catálogo rechazó ${case.toolId}",
                AuraToolCatalog.isAllowed(case.toolId)
            )
            assertTrue(json.contains("\"toolId\":\"${case.toolId}\""))
            if (case.target.isNotEmpty()) {
                assertTrue(json.contains("\"target\":\"${case.target}\""))
            }
        }
    }

    @Test
    fun `provider without engine is not configured`() {
        val provider = FunctionGemmaToolProvider()
        assertTrue(!provider.isConfigured())
    }
}
