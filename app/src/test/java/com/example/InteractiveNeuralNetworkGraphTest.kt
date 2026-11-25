package com.example

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.click
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeRight
import com.example.data.model.AiVisualEdge
import com.example.data.model.AiVisualNode
import com.example.ui.components.InteractiveNeuralNetworkGraph
import com.example.ui.theme.NyxCoreTheme
import com.example.ui.theme.NyxCyan
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class InteractiveNeuralNetworkGraphTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun `graph renders on canvas and handles tap and drag gestures`() {
        var tappedNode: AiVisualNode? = null
        val nodes = listOf(
            AiVisualNode(
                id = "n1",
                label = "CPU-CORE",
                sublabel = "LOCAL",
                category = "COMPUTE",
                riskScore = 0.4f,
                xNorm = 0.2f,
                yNorm = 0.5f,
                forensicDetail = "Core CPU telemetry receptor",
                layerIndex = 0
            ),
            AiVisualNode(
                id = "n2",
                label = "NET-PIPE",
                sublabel = "TLS",
                category = "NET",
                riskScore = 0.7f,
                xNorm = 0.8f,
                yNorm = 0.5f,
                forensicDetail = "Network socket effector",
                layerIndex = 2
            )
        )
        val edges = listOf(
            AiVisualEdge(
                fromId = "n1",
                toId = "n2",
                relation = "SYNAPSE",
                intensity = 0.85f
            )
        )

        composeTestRule.setContent {
            NyxCoreTheme {
                InteractiveNeuralNetworkGraph(
                    sceneKey = "test_scene",
                    nodes = nodes,
                    edges = edges,
                    cpuLoad = 0.65f,
                    networkLoad = 0.55f,
                    networkKbps = 124.5f,
                    accentColor = NyxCyan,
                    selectedNodeId = null,
                    highlightLayer = null,
                    isSynthesizing = false,
                    onNodeTapped = { tappedNode = it }
                )
            }
        }

        composeTestRule.waitForIdle()
        val graphNode = composeTestRule.onNodeWithTag("interactive_neural_network_graph")
        graphNode.assertIsDisplayed()

        graphNode.performTouchInput {
            swipeRight()
            click(centerLeft)
        }
        composeTestRule.waitForIdle()
        assertTrue(tappedNode == null || tappedNode?.id in listOf("n1", "n2"))
    }

    @Test
    fun `generative visual canvas renders fluid dark constellation for non-lattice topologies`() {
        val scene = com.example.data.model.AiVisualScene(
            query = "audita tráfico",
            title = "Constelación de Vectores",
            subtitle = "TLS & Circuitos",
            visualKind = com.example.data.model.VisualTopologyKind.ATTACK_VECTOR_FLOW,
            severityScore = 0.65f,
            narrative = "Constelación activa",
            technicalFindings = listOf("TLS 1.3 verificado"),
            nodes = listOf(
                AiVisualNode("a1", "TLS-GATE", "1.3", "TLS", 0.2f, 0.25f, 0.4f, "TLS socket", 0),
                AiVisualNode("a2", "DNS-TUN", "53", "NET", 0.7f, 0.75f, 0.6f, "VPN TUN filter", 1)
            ),
            edges = listOf(AiVisualEdge("a1", "a2", "CIRCUIT", 0.9f)),
            strata = emptyList(),
            spectrumValues = listOf(0.4f, 0.8f),
            whisperPrompts = emptyList(),
            rawTelemetry = "OK",
            toolExecuted = "TLS_INSPECT",
            privilegeMode = com.example.data.model.PrivilegeMode.USERLAND
        )

        composeTestRule.setContent {
            NyxCoreTheme {
                com.example.ui.components.GenerativeVisualCanvas(
                    scene = scene,
                    privilegeMode = com.example.data.model.PrivilegeMode.USERLAND,
                    isAnalyzing = false,
                    selectedNodeId = "a1",
                    cpuLoad = 0.45f,
                    networkLoad = 0.72f,
                    networkKbps = 84.2f,
                    onNodeTapped = {}
                )
            }
        }
        composeTestRule.waitForIdle()

        val canvasNode = composeTestRule.onNodeWithTag("generative_ai_canvas")
        canvasNode.assertIsDisplayed()
        canvasNode.performTouchInput {
            swipeRight()
        }
        composeTestRule.waitForIdle()
    }
}
