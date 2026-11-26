package com.aura.mobiledefense

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.aura.mobiledefense.data.model.AiEngineMode
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.data.model.ToolExecutionResult
import com.aura.mobiledefense.data.model.VisualTopologyKind
import com.aura.mobiledefense.domain.ai.LocalAutonomousEngine
import com.aura.mobiledefense.domain.engines.AppSelfIntegrityEngine
import com.aura.mobiledefense.domain.engines.BinaryCryptoEngine
import com.aura.mobiledefense.domain.engines.NetworkForensicsEngine
import com.aura.mobiledefense.domain.engines.PatchAndReportEngine
import com.aura.mobiledefense.domain.engines.PrivilegeAndDeviceEngine
import com.aura.mobiledefense.domain.engines.ThreatKnowledgeEngine
import com.aura.mobiledefense.data.local.NyxDatabase
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class WorkspaceIntegrationTest {

    @Test
    fun `read string from context matches Aura Mobile Defense`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val appName = context.getString(R.string.app_name)
        assertEquals("Aura Mobile Defense", appName)
    }

    @Test
    fun `crypto engine decodes JWT and detects none algorithm`() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val engine = BinaryCryptoEngine(context)
        val jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0."
        val result = engine.analyzeCryptoOrJwt(jwt, PrivilegeMode.USERLAND)

        assertEquals("CRYPTO_JWT", result.toolId)
        assertTrue(result.rawTelemetry.contains("none"))
        assertTrue(result.rawTelemetry.contains("admin"))
    }

    @Test
    fun `local autonomous engine synthesizes neural lattice, patches, and 4-part report offline`() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val db = NyxDatabase.getInMemory(context)
        val dao = db.forensicSessionDao()
        val knowledge = ThreatKnowledgeEngine(dao)
        val patchEngine = PatchAndReportEngine(
            integrityEngine = AppSelfIntegrityEngine(context),
            privilegeEngine = PrivilegeAndDeviceEngine(context),
            networkEngine = NetworkForensicsEngine(context),
            binaryCryptoEngine = BinaryCryptoEngine(context),
            threatKnowledgeEngine = knowledge
        )
        val localEngine = LocalAutonomousEngine(patchEngine)

        val simulatedMeasuredTelemetry = ToolExecutionResult(
            toolId = "FULL_AUTONOMOUS_AUDIT",
            target = "example.com",
            privilegeUsed = PrivilegeMode.USERLAND,
            rawTelemetry = "Flags: debuggable=true, allowBackup=true, cleartext=true\n[AUSENTE]  Strict-Transport-Security\n[ABIERTO] 5555/tcp (ADB-TCP)"
        )

        val scene = localEngine.synthesizeLocally("audita todo", simulatedMeasuredTelemetry, emptyList())
        assertEquals(AiEngineMode.LOCAL_AUTONOMOUS, scene.engineMode)
        assertEquals(VisualTopologyKind.NEURAL_SYNAPTIC_LATTICE, scene.visualKind)
        assertTrue(scene.nodes.size >= 6)
        assertNotNull(scene.report)
        assertTrue(scene.patches.size >= 3)
        db.close()
    }

    @Test
    fun `system activity monitor emits valid CPU and network load snapshot`() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val monitor = com.aura.mobiledefense.domain.engines.SystemActivityMonitor(context)
        val snapshot = monitor.observeSystemLoad(intervalMs = 20L).first()
        assertTrue(snapshot.cpuLoad in 0.05f..1.0f)
        assertTrue(snapshot.networkLoad in 0.05f..1.0f)
        assertTrue(snapshot.memoryPressure in 0.05f..1.0f)
    }

    @Test
    fun `custom neural conversational engine classifies intents and remembers target context without API keys`() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val db = NyxDatabase.getInMemory(context)
        val dao = db.forensicSessionDao()
        val knowledge = ThreatKnowledgeEngine(dao)
        val patchEngine = PatchAndReportEngine(
            integrityEngine = AppSelfIntegrityEngine(context),
            privilegeEngine = PrivilegeAndDeviceEngine(context),
            networkEngine = NetworkForensicsEngine(context),
            binaryCryptoEngine = BinaryCryptoEngine(context),
            threatKnowledgeEngine = knowledge
        )
        val ai = com.aura.mobiledefense.domain.ai.AuraNeuralAiEngine(patchEngine)

        // Turn 1: greet / ask how it works without external keys
        val greetingPlan = ai.planExecution("Hola, cómo funcionas?", PrivilegeMode.USERLAND)
        assertEquals("AI_THEORETICAL", greetingPlan.plan.toolId)

        // Turn 2: mention server for monitoring
        val monitorPlan = ai.planExecution("monitorea cloudflare.com por anomalías", PrivilegeMode.USERLAND)
        assertEquals("SERVER_MONITOR", monitorPlan.plan.toolId)
        assertEquals("cloudflare.com", monitorPlan.plan.target)

        // Turn 3: follow-up inherits target context automatically
        val followUpPorts = ai.planExecution("ahora escanea sus puertos", PrivilegeMode.USERLAND)
        assertEquals("PORT_PROBE", followUpPorts.plan.toolId)
        assertEquals("cloudflare.com", followUpPorts.plan.target)

        val scene = ai.synthesizeScene(
            userQuery = "Hola, cómo funcionas?",
            classification = greetingPlan,
            toolResult = ToolExecutionResult(
                toolId = "AI_THEORETICAL",
                target = "Asistencia Aura",
                privilegeUsed = PrivilegeMode.USERLAND,
                rawTelemetry = "Motor IA Propio"
            ),
            matchedRules = emptyList(),
            engineMode = AiEngineMode.ONLINE_CLOUD,
            knowledgeStats = com.aura.mobiledefense.data.model.ThreatKnowledgeStats(totalRules = 6),
            rootState = com.aura.mobiledefense.data.model.RootCapabilityState()
        )
        assertTrue(scene.narrative.contains("Aura"))
        assertEquals(7, scene.nodes.size)
        db.close()
    }
}
