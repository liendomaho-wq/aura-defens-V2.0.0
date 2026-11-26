package com.aura.mobiledefense.data.model

enum class PrivilegeMode {
    USERLAND,
    ROOT
}

enum class AiEngineMode {
    ONLINE_CLOUD,
    LOCAL_AUTONOMOUS
}

enum class VisualTopologyKind {
    NEURAL_SYNAPTIC_LATTICE,
    CONSTELLATION_MESH,
    SPECTRUM_INTERFERENCE,
    ENTROPY_MATRIX,
    PROTOCOL_STRATA,
    BINARY_HELIX,
    ATTACK_VECTOR_FLOW;

    companion object {
        fun fromWire(value: String): VisualTopologyKind {
            return entries.firstOrNull { it.name.equals(value.trim(), ignoreCase = true) }
                ?: NEURAL_SYNAPTIC_LATTICE
        }
    }
}

data class RootCapabilityState(
    val suAvailable: Boolean = false,
    val suPath: String? = null,
    val rootFlavor: String = "Ninguno detectado",
    val selinuxMode: String = "Desconocido",
    val uidOutput: String = "uid=${android.os.Process.myUid()}",
    val verified: Boolean = false,
    val lastProbeMessage: String = ""
)

data class AiVisualNode(
    val id: String,
    val label: String,
    val sublabel: String,
    val category: String,
    val riskScore: Float,
    val xNorm: Float,
    val yNorm: Float,
    val forensicDetail: String,
    val layerIndex: Int = 1
)

data class AiVisualEdge(
    val fromId: String,
    val toId: String,
    val relation: String,
    val intensity: Float
)

data class AiStratumLayer(
    val name: String,
    val status: String,
    val healthScore: Float,
    val summary: String
)

data class GeneratedPatch(
    val id: String,
    val title: String,
    val targetArtifact: String,
    val severity: String,
    val rationale: String,
    val patchContent: String
)

data class CompleteAuditReport(
    val whatWasDone: String,
    val whatWasFound: String,
    val measuresAndPatchesTaken: String,
    val improvementRecommendations: String
)

data class MonitorTargetSnapshot(
    val target: String,
    val lastStatusCode: Int,
    val baselineRttMs: Long,
    val lastRttMs: Long,
    val baselineTlsSha256: String,
    val lastTlsSha256: String,
    val checkCount: Int,
    val anomalyCount: Int,
    val lastCheckedAt: Long,
    val isActive: Boolean
)

data class AnomalyAlert(
    val id: String,
    val target: String,
    val kind: String,
    val severity: String,
    val description: String,
    val timestamp: Long
)

data class ThreatKnowledgeStats(
    val totalRules: Int = 0,
    val cisaKevCount: Int = 0,
    val localBaselineCount: Int = 0,
    val lastTrainedAt: Long = 0L,
    val lastTrainingSummary: String = "Base inicial local activa"
)

data class AiVisualScene(
    val id: String = java.util.UUID.randomUUID().toString(),
    val timestamp: Long = System.currentTimeMillis(),
    val query: String,
    val title: String,
    val subtitle: String,
    /** Objetivo estructurado que midió el engine (antes se reconstruía parseando el subtítulo). */
    val target: String = "",
    val visualKind: VisualTopologyKind,
    val severityScore: Float,
    val narrative: String,
    val technicalFindings: List<String>,
    val nodes: List<AiVisualNode>,
    val edges: List<AiVisualEdge>,
    val strata: List<AiStratumLayer>,
    val spectrumValues: List<Float>,
    val whisperPrompts: List<String>,
    val rawTelemetry: String,
    val toolExecuted: String,
    val privilegeMode: PrivilegeMode,
    val engineMode: AiEngineMode = AiEngineMode.ONLINE_CLOUD,
    val report: CompleteAuditReport? = null,
    val patches: List<GeneratedPatch> = emptyList()
)

sealed interface WorkspaceUiState {
    data object Booting : WorkspaceUiState
    data class Analyzing(
        val phase: String,
        val previousScene: AiVisualScene?
    ) : WorkspaceUiState

    data class Ready(
        val scene: AiVisualScene
    ) : WorkspaceUiState

    data class Error(
        val message: String,
        val previousScene: AiVisualScene?
    ) : WorkspaceUiState
}

data class ToolExecutionResult(
    val toolId: String,
    val target: String,
    val privilegeUsed: PrivilegeMode,
    val rawTelemetry: String,
    val measuredSpectrum: List<Float> = emptyList(),
    val suggestedVisual: VisualTopologyKind = VisualTopologyKind.NEURAL_SYNAPTIC_LATTICE,
    val generatedPatches: List<GeneratedPatch> = emptyList(),
    val reportDraft: CompleteAuditReport? = null
)

data class ForensicToolPlan(
    val toolId: String,
    val target: String,
    val extraArg: String,
    val prefersRoot: Boolean,
    val analysisFocus: String
)

enum class ChatSpeaker {
    USER,
    AURA
}

enum class ExecutionStepState {
    RUNNING,
    DONE,
    NEEDS_CONSENT,
    FAILED
}

data class SolutionExecutionStep(
    val stepNumber: Int,
    val title: String,
    val detail: String,
    val state: ExecutionStepState,
    val timestamp: Long = System.currentTimeMillis()
)

data class AuraChatMessage(
    val id: String = java.util.UUID.randomUUID().toString(),
    val speaker: ChatSpeaker,
    val text: String,
    val timestamp: Long = System.currentTimeMillis(),
    val subtitle: String = "",
    val suggestions: List<String> = emptyList(),
    val recommendations: List<String> = emptyList(),
    val patches: List<GeneratedPatch> = emptyList(),
    val executionSteps: List<SolutionExecutionStep> = emptyList(),
    val isExecuting: Boolean = false,
    val hasReport: Boolean = false
)

enum class FirewallRuleType {
    DOMAIN,
    IP,
    PORT
}

enum class FirewallPacketEventAction {
    ALLOWED,
    BLOCKED
}

data class FirewallPacketEvent(
    val id: String = java.util.UUID.randomUUID().toString(),
    val timestamp: Long = System.currentTimeMillis(),
    val protocol: String,
    val destination: String,
    val port: Int,
    val action: FirewallPacketEventAction,
    val reason: String,
    val rttMs: Long = 0L
)

data class VpnFirewallTelemetry(
    val isRunning: Boolean = false,
    val tunAddress: String = "10.8.0.2/32",
    val upstreamDns: String = "1.1.1.1:53",
    val startedAtMs: Long = 0L,
    val packetsInspected: Long = 0L,
    val packetsAllowed: Long = 0L,
    val packetsBlocked: Long = 0L,
    val bytesIn: Long = 0L,
    val bytesOut: Long = 0L,
    val lastDnsRttMs: Long = 0L,
    val activeRulesCount: Int = 0,
    val recentEvents: List<FirewallPacketEvent> = emptyList()
)

