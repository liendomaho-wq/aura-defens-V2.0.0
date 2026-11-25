package com.example.ui.components

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import com.example.data.model.AiVisualEdge
import com.example.data.model.AiVisualNode
import com.example.data.model.VpnFirewallTelemetry

/**
 * Delegates the interactive graph surface to [AuraCircuitConstellationCanvas]
 * so the neural telemetry lattice renders as an Aura Mobile Defens integrated-circuit & constellation hologram.
 */
@Composable
fun InteractiveNeuralNetworkGraph(
    sceneKey: String,
    nodes: List<AiVisualNode>,
    edges: List<AiVisualEdge>,
    cpuLoad: Float,
    networkLoad: Float,
    networkKbps: Float,
    accentColor: Color,
    selectedNodeId: String?,
    highlightLayer: Int?,
    isSynthesizing: Boolean,
    onNodeTapped: (AiVisualNode?) -> Unit,
    modifier: Modifier = Modifier,
    vpnTelemetry: VpnFirewallTelemetry = VpnFirewallTelemetry()
) {
    AuraCircuitConstellationCanvas(
        sceneKey = sceneKey,
        nodes = nodes,
        edges = edges,
        cpuLoad = cpuLoad,
        networkLoad = networkLoad,
        networkKbps = networkKbps,
        vpnTelemetry = vpnTelemetry,
        accentColor = accentColor,
        selectedNodeId = selectedNodeId,
        highlightLayer = highlightLayer,
        isSynthesizing = isSynthesizing,
        onNodeTapped = onNodeTapped,
        modifier = modifier
    )
}
