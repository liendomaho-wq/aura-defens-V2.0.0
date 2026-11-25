package com.aura.mobiledefense.ui.screens

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aura.mobiledefense.data.model.WorkspaceUiState
import com.aura.mobiledefense.ui.components.BlackConversationalPanel
import com.aura.mobiledefense.ui.components.GenerativeVisualCanvas
import com.aura.mobiledefense.ui.components.LlmSettingsOverlay
import com.aura.mobiledefense.ui.components.MemoryTimelineOverlay
import com.aura.mobiledefense.ui.components.NeuralPromptBar
import com.aura.mobiledefense.ui.components.NodeDeepDiveOverlay
import com.aura.mobiledefense.ui.components.PrivilegeHorizonBar
import com.aura.mobiledefense.ui.components.ReportAndPatchOverlay
import com.aura.mobiledefense.ui.components.VisualWalkthroughOverlay
import com.aura.mobiledefense.ui.viewmodel.NyxViewModel

@Composable
fun NyxWorkspaceScreen(
    viewModel: NyxViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val showWalkthrough by viewModel.showWalkthrough.collectAsStateWithLifecycle()
    val walkthroughStep by viewModel.walkthroughStep.collectAsStateWithLifecycle()
    val privilegeMode by viewModel.privilegeMode.collectAsStateWithLifecycle()
    val engineMode by viewModel.engineMode.collectAsStateWithLifecycle()
    val rootState by viewModel.rootState.collectAsStateWithLifecycle()
    val knowledgeStats by viewModel.knowledgeStats.collectAsStateWithLifecycle()
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val selectedNode by viewModel.selectedNode.collectAsStateWithLifecycle()
    val showMemory by viewModel.showMemoryOverlay.collectAsStateWithLifecycle()
    val showReportPatch by viewModel.showReportPatchOverlay.collectAsStateWithLifecycle()
    val monitorBanner by viewModel.activeMonitorBanner.collectAsStateWithLifecycle()
    val savedSessions by viewModel.savedSessions.collectAsStateWithLifecycle()
    val monitorTargets by viewModel.monitorTargets.collectAsStateWithLifecycle()
    val anomalyAlerts by viewModel.anomalyAlerts.collectAsStateWithLifecycle()
    val systemLoad by viewModel.systemLoad.collectAsStateWithLifecycle()
    val vpnTelemetry by viewModel.vpnTelemetry.collectAsStateWithLifecycle()
    val chatMessages by viewModel.chatMessages.collectAsStateWithLifecycle()
    val showLlmSettings by viewModel.showLlmSettings.collectAsStateWithLifecycle()
    val llmSettings by viewModel.llmSettings.collectAsStateWithLifecycle()
    val llmStatus by viewModel.llmStatus.collectAsStateWithLifecycle()

    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
        onResult = { uri ->
            if (uri != null) viewModel.inspectFileUri(uri)
        }
    )

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult(),
        onResult = { result ->
            viewModel.onVpnConsentGranted(result.resultCode == Activity.RESULT_OK)
        }
    )

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
        onResult = { /* Foreground VPN works regardless; notification visibility is optional */ }
    )

    LaunchedEffect(Unit) {
        viewModel.requestFilePickerEvent.collect {
            filePickerLauncher.launch(arrayOf("*/*"))
        }
    }

    LaunchedEffect(Unit) {
        viewModel.requestVpnConsentEvent.collect {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val granted = ContextCompat.checkSelfPermission(
                    context,
                    Manifest.permission.POST_NOTIFICATIONS
                ) == PackageManager.PERMISSION_GRANTED
                if (!granted) {
                    notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                }
            }
            val prepIntent = VpnService.prepare(context)
            if (prepIntent != null) {
                vpnPermissionLauncher.launch(prepIntent)
            } else {
                viewModel.onVpnConsentGranted(true)
            }
        }
    }

    val activeScene = when (val state = uiState) {
        is WorkspaceUiState.Ready -> state.scene
        is WorkspaceUiState.Analyzing -> state.previousScene
        is WorkspaceUiState.Error -> state.previousScene
        WorkspaceUiState.Booting -> null
    }
    val analyzingPhase = when (val state = uiState) {
        is WorkspaceUiState.Analyzing -> state.phase
        WorkspaceUiState.Booting -> "Inicializando circuitos de Aura Mobile Defens…"
        else -> null
    }
    val errorMessage = (uiState as? WorkspaceUiState.Error)?.message

    Box(modifier = modifier.fillMaxSize()) {
        // 1. Living Aura Mobile Defens Integrated-Circuit & Constellation Canvas (zero shields/radars/buttons)
        GenerativeVisualCanvas(
            scene = activeScene,
            privilegeMode = privilegeMode,
            isAnalyzing = analyzingPhase != null,
            selectedNodeId = selectedNode?.id,
            highlightLayer = if (showWalkthrough) walkthroughStep else null,
            cpuLoad = systemLoad.cpuLoad,
            networkLoad = systemLoad.networkLoad,
            networkKbps = systemLoad.networkKbps,
            vpnTelemetry = vpnTelemetry,
            onNodeTapped = { node ->
                if (!showWalkthrough) viewModel.selectNode(node)
            },
            modifier = Modifier.fillMaxSize()
        )

        if (!showWalkthrough) {
            // 2. Top Magnetic Privilege & Connectivity Horizon
            PrivilegeHorizonBar(
                privilegeMode = privilegeMode,
                engineMode = engineMode,
                rootState = rootState,
                knowledgeStats = knowledgeStats,
                monitorBanner = monitorBanner,
                onSwitchPrivilegeMode = { next -> viewModel.switchPrivilegeMode(next) },
                onToggleEngineMode = { nextEngine -> viewModel.switchEngineMode(nextEngine) },
                onOpenLlmSettings = { viewModel.setLlmSettingsVisible(true) },
                onPullDownMemory = { viewModel.setMemoryOverlayVisible(true) },
                modifier = Modifier.align(Alignment.TopCenter)
            )

            // 3. Pure-Black Conversational AI Panel + Neural Prompt (zero buttons)
            Column(
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                BlackConversationalPanel(
                    messages = chatMessages,
                    activeScene = activeScene,
                    vpnTelemetry = vpnTelemetry,
                    privilegeMode = privilegeMode,
                    analyzingPhase = analyzingPhase,
                    errorMessage = errorMessage,
                    onExecuteWhisper = { whisper -> viewModel.submitQuery(whisper) },
                    onExecuteSolutionsNow = { viewModel.executeSolutionsLiveNow() },
                    onToggleVpn = { viewModel.toggleLocalVpn() },
                    onOpenReportAndPatches = { viewModel.setReportPatchOverlayVisible(true) }
                )

                NeuralPromptBar(
                    privilegeMode = privilegeMode,
                    isBusy = analyzingPhase != null,
                    onSubmitQuery = { query -> viewModel.submitQuery(query) },
                    onTriggerFileInspection = { viewModel.triggerFilePicker() }
                )
            }
        }

        // 4. First-Run / Revisit Interactive Visual Presentation Walkthrough
        AnimatedVisibility(
            visible = showWalkthrough,
            enter = fadeIn(),
            exit = fadeOut()
        ) {
            VisualWalkthroughOverlay(
                step = walkthroughStep,
                onStepChange = { delta -> viewModel.advanceWalkthrough(delta) },
                onComplete = { viewModel.completeWalkthrough() }
            )
        }

        // 5. IC / Constellation Node Deep-Dive Overlay
        AnimatedVisibility(
            visible = selectedNode != null && !showWalkthrough,
            enter = fadeIn() + slideInVertically { it / 2 },
            exit = fadeOut() + slideOutVertically { it / 2 }
        ) {
            selectedNode?.let { node ->
                NodeDeepDiveOverlay(
                    node = node,
                    onDismiss = { viewModel.selectNode(null) },
                    onPivotNode = { query ->
                        viewModel.selectNode(null)
                        viewModel.submitQuery(query)
                    }
                )
            }
        }

        // 6. Complete 4-Part Audit Report & Generated Patches Overlay
        AnimatedVisibility(
            visible = showReportPatch && activeScene != null,
            enter = fadeIn() + slideInVertically { it / 2 },
            exit = fadeOut() + slideOutVertically { it / 2 }
        ) {
            activeScene?.let { scene ->
                ReportAndPatchOverlay(
                    scene = scene,
                    onDismiss = { viewModel.setReportPatchOverlayVisible(false) }
                )
            }
        }

        // 7. LLM engine configuration (BYOK) — /ia
        AnimatedVisibility(
            visible = showLlmSettings,
            enter = fadeIn() + slideInVertically { it / 2 },
            exit = fadeOut() + slideOutVertically { it / 2 }
        ) {
            LlmSettingsOverlay(
                settings = llmSettings,
                status = llmStatus,
                onUpdate = { transform -> viewModel.updateLlmSettings(transform) },
                onTestConnection = { viewModel.testLlmConnection() },
                onClearKey = { viewModel.clearLlmKey() },
                onDismiss = { viewModel.setLlmSettingsVisible(false) }
            )
        }

        // 8. Local Forensic Memory, Monitored Servers & Anomaly Timeline
        AnimatedVisibility(
            visible = showMemory,
            enter = fadeIn() + slideInVertically { -it / 2 },
            exit = fadeOut() + slideOutVertically { -it / 2 }
        ) {
            MemoryTimelineOverlay(
                sessions = savedSessions,
                monitorTargets = monitorTargets,
                anomalies = anomalyAlerts,
                onRestoreSession = { scene -> viewModel.restoreSession(scene) },
                onDeleteSession = { id -> viewModel.deleteSession(id) },
                onDeleteMonitorTarget = { target -> viewModel.removeMonitorTarget(target) },
                onRunMonitorNow = { target ->
                    viewModel.setMemoryOverlayVisible(false)
                    viewModel.submitQuery("/monitor $target")
                },
                onDismiss = { viewModel.setMemoryOverlayVisible(false) }
            )
        }
    }
}
