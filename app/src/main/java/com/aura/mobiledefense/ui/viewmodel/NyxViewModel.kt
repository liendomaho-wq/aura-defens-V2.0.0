package com.aura.mobiledefense.ui.viewmodel

import android.app.Application
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aura.mobiledefense.data.local.ForensicSessionRepository
import com.aura.mobiledefense.data.local.NyxDatabase
import com.aura.mobiledefense.data.model.AiEngineMode
import com.aura.mobiledefense.data.model.AiVisualNode
import com.aura.mobiledefense.data.model.AiVisualScene
import com.aura.mobiledefense.data.model.AnomalyAlert
import com.aura.mobiledefense.data.model.AuraChatMessage
import com.aura.mobiledefense.data.model.ChatSpeaker
import com.aura.mobiledefense.data.model.ExecutionStepState
import com.aura.mobiledefense.data.model.FirewallRuleType
import com.aura.mobiledefense.data.model.MonitorTargetSnapshot
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.data.model.RootCapabilityState
import com.aura.mobiledefense.data.model.SolutionExecutionStep
import com.aura.mobiledefense.data.model.ThreatKnowledgeStats
import com.aura.mobiledefense.data.model.ToolExecutionResult
import com.aura.mobiledefense.data.model.VisualTopologyKind
import com.aura.mobiledefense.data.model.VpnFirewallTelemetry
import com.aura.mobiledefense.data.model.WorkspaceUiState
import com.aura.mobiledefense.domain.ai.AuraNeuralAiEngine
import com.aura.mobiledefense.domain.ai.llm.AuraLlmOrchestrator
import com.aura.mobiledefense.domain.ai.llm.AuraToolCatalog
import com.aura.mobiledefense.domain.ai.llm.LlmSettings
import com.aura.mobiledefense.domain.ai.llm.LlmSettingsStore
import com.aura.mobiledefense.domain.ai.llm.LlmFailure
import com.aura.mobiledefense.domain.engines.AppSelfIntegrityEngine
import com.aura.mobiledefense.domain.engines.BinaryCryptoEngine
import com.aura.mobiledefense.domain.engines.NetworkForensicsEngine
import com.aura.mobiledefense.domain.engines.PatchAndReportEngine
import com.aura.mobiledefense.domain.engines.PrivilegeAndDeviceEngine
import com.aura.mobiledefense.domain.engines.ServerAndNetworkMonitorEngine
import com.aura.mobiledefense.domain.engines.SolutionExecutionEngine
import com.aura.mobiledefense.domain.engines.SystemActivityMonitor
import com.aura.mobiledefense.domain.engines.SystemLoadSnapshot
import com.aura.mobiledefense.domain.engines.ThreatKnowledgeEngine
import com.aura.mobiledefense.domain.vpn.AppFirewallEngine
import com.aura.mobiledefense.domain.vpn.VpnFirewallManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

private const val TAG = "AuraViewModel"
private const val PREFS_NAME = "aura_defense_prefs"
private const val KEY_TOUR_DONE = "visual_tour_completed"

class NyxViewModel(application: Application) : AndroidViewModel(application) {

    /**
     * La base se abre de forma perezosa y protegida: si el AndroidKeyStore no puede descifrar la
     * clave de SQLCipher, el fallo debe llegar a la UI como un error legible y no como un crash en el
     * constructor del ViewModel (que ocurre antes de que exista cualquier pantalla).
     */
    private val databaseResult: Result<NyxDatabase> = runCatching { NyxDatabase.getInstance(application) }

    /** true cuando la base cifrada no se pudo abrir y se está usando una base volátil. */
    private var storageDegraded: Boolean = false

    private val db: NyxDatabase = databaseResult.getOrElse {
        storageDegraded = true
        Log.e(TAG, "Base cifrada no disponible; usando base en memoria", it)
        NyxDatabase.getInMemory(application)
    }

    private val dao = db.forensicSessionDao()
    private val sessionRepository = ForensicSessionRepository(dao)

    private val privilegeEngine = PrivilegeAndDeviceEngine(application)
    private val networkEngine = NetworkForensicsEngine(application)
    private val binaryCryptoEngine = BinaryCryptoEngine(application)
    private val selfIntegrityEngine = AppSelfIntegrityEngine(application)
    private val threatKnowledgeEngine = ThreatKnowledgeEngine(dao)
    private val serverMonitorEngine = ServerAndNetworkMonitorEngine(application, dao)
    private val patchAndReportEngine = PatchAndReportEngine(
        integrityEngine = selfIntegrityEngine,
        privilegeEngine = privilegeEngine,
        networkEngine = networkEngine,
        binaryCryptoEngine = binaryCryptoEngine,
        threatKnowledgeEngine = threatKnowledgeEngine
    )

    private val solutionExecutionEngine = SolutionExecutionEngine(application, privilegeEngine)
    private val auraAiEngine = AuraNeuralAiEngine(patchAndReportEngine)
    private val llmSettingsStore = LlmSettingsStore.get(application)
    private val llmOrchestrator = AuraLlmOrchestrator(auraAiEngine, llmSettingsStore)

    private val prefs = application.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val _showWalkthrough = MutableStateFlow(!prefs.getBoolean(KEY_TOUR_DONE, false))
    val showWalkthrough: StateFlow<Boolean> = _showWalkthrough.asStateFlow()

    private val _walkthroughStep = MutableStateFlow(0)
    val walkthroughStep: StateFlow<Int> = _walkthroughStep.asStateFlow()

    private val _privilegeMode = MutableStateFlow(PrivilegeMode.USERLAND)
    val privilegeMode: StateFlow<PrivilegeMode> = _privilegeMode.asStateFlow()

    private val _engineMode = MutableStateFlow(AiEngineMode.LOCAL_AUTONOMOUS)
    val engineMode: StateFlow<AiEngineMode> = _engineMode.asStateFlow()

    private val _rootState = MutableStateFlow(RootCapabilityState())
    val rootState: StateFlow<RootCapabilityState> = _rootState.asStateFlow()

    private val _knowledgeStats = MutableStateFlow(ThreatKnowledgeStats())
    val knowledgeStats: StateFlow<ThreatKnowledgeStats> = _knowledgeStats.asStateFlow()

    private val _uiState = MutableStateFlow<WorkspaceUiState>(WorkspaceUiState.Booting)
    val uiState: StateFlow<WorkspaceUiState> = _uiState.asStateFlow()

    private val _selectedNode = MutableStateFlow<AiVisualNode?>(null)
    val selectedNode: StateFlow<AiVisualNode?> = _selectedNode.asStateFlow()

    private val _showMemoryOverlay = MutableStateFlow(false)
    val showMemoryOverlay: StateFlow<Boolean> = _showMemoryOverlay.asStateFlow()

    private val _showReportPatchOverlay = MutableStateFlow(false)
    val showReportPatchOverlay: StateFlow<Boolean> = _showReportPatchOverlay.asStateFlow()

    private val _showLlmSettings = MutableStateFlow(false)
    val showLlmSettings: StateFlow<Boolean> = _showLlmSettings.asStateFlow()

    /** Last LLM routing diagnostic, shown in the settings sheet. */
    private val _llmStatus = MutableStateFlow("")
    val llmStatus: StateFlow<String> = _llmStatus.asStateFlow()

    private val _activeMonitorBanner = MutableStateFlow<String?>(null)
    val activeMonitorBanner: StateFlow<String?> = _activeMonitorBanner.asStateFlow()

    private val _requestFilePickerEvent = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val requestFilePickerEvent: SharedFlow<Unit> = _requestFilePickerEvent.asSharedFlow()

    private val _requestVpnConsentEvent = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val requestVpnConsentEvent: SharedFlow<Unit> = _requestVpnConsentEvent.asSharedFlow()

    private val _chatMessages = MutableStateFlow<List<AuraChatMessage>>(emptyList())
    val chatMessages: StateFlow<List<AuraChatMessage>> = _chatMessages.asStateFlow()

    val vpnTelemetry: StateFlow<VpnFirewallTelemetry> = VpnFirewallManager.telemetry

    /** true si la base forense está realmente cifrada con SQLCipher en este dispositivo. */
    val databaseEncrypted: Boolean get() = com.aura.mobiledefense.data.local.AuraDatabaseCipher.isEncrypted()

    /** Motivo por el que no está cifrada, si aplica. */
    val databaseEncryptionFault: String?
        get() = com.aura.mobiledefense.data.local.AuraDatabaseCipher.lastFaultReason

    /** LLM configuration (BYOK). Observable so the settings sheet reacts immediately. */
    val llmSettings: StateFlow<LlmSettings> = llmSettingsStore.settings

    private val systemActivityMonitor = SystemActivityMonitor(application)

    val systemLoad: StateFlow<SystemLoadSnapshot> = systemActivityMonitor.observeSystemLoad()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), SystemLoadSnapshot())

    val savedSessions: StateFlow<List<AiVisualScene>> = sessionRepository.sessions
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val monitorTargets: StateFlow<List<MonitorTargetSnapshot>> = sessionRepository.monitorTargets
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val anomalyAlerts: StateFlow<List<AnomalyAlert>> = sessionRepository.anomalies
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private var activeJob: Job? = null
    private var lastScene: AiVisualScene? = null

    init {
        bootstrapEnvironment()
        startBackgroundMonitorLoop()
    }

    fun advanceWalkthrough(delta: Int = 1) {
        val next = _walkthroughStep.value + delta
        if (next >= 3) {
            completeWalkthrough()
        } else if (next >= 0) {
            _walkthroughStep.value = next
        }
    }

    fun completeWalkthrough() {
        prefs.edit().putBoolean(KEY_TOUR_DONE, true).apply()
        _showWalkthrough.value = false
    }

    fun openWalkthrough() {
        _walkthroughStep.value = 0
        _showWalkthrough.value = true
    }

    fun switchEngineMode(mode: AiEngineMode) {
        if (mode == AiEngineMode.ONLINE_CLOUD && llmSettingsStore.buildProvider() == null) {
            // No model configured yet: open the BYOK sheet instead of pretending to be online.
            _llmStatus.value = "Configura una clave o un endpoint para activar el motor LLM."
            _showLlmSettings.value = true
            return
        }
        _engineMode.value = mode
        if (mode == AiEngineMode.LOCAL_AUTONOMOUS) {
            submitQuery("Auditoría de estado en modo local autónomo")
        } else {
            bootstrapEnvironment()
        }
    }

    fun bootstrapEnvironment() {
        activeJob?.cancel()
        activeJob = viewModelScope.launch {
            _uiState.value = WorkspaceUiState.Analyzing(
                phase = "Activando red neuronal y sondas de integridad…",
                previousScene = lastScene
            )
            if (storageDegraded) {
                _chatMessages.value = _chatMessages.value + AuraChatMessage(
                    speaker = ChatSpeaker.AURA,
                    subtitle = "ALMACENAMIENTO DEGRADADO",
                    text = "No se pudo abrir la base cifrada con el AndroidKeyStore de este dispositivo. " +
                        "Aura sigue operativa con una base volátil: la evidencia de esta sesión no se " +
                        "guardará. La base cifrada anterior NO se ha borrado."
                )
            }
            try {
                VpnFirewallManager.ensureInitialized(getApplication())
                threatKnowledgeEngine.ensureBaselineKnowledgeSeeded()
                _knowledgeStats.value = threatKnowledgeEngine.getKnowledgeStats()

                val cap = privilegeEngine.probeRootCapability(attemptElevation = false)
                _rootState.value = cap
                val mode = if (cap.suAvailable && cap.verified) PrivilegeMode.ROOT else PrivilegeMode.USERLAND
                _privilegeMode.value = mode

                val activeEngineMode = if (!hasNetworkConnectivity() || _engineMode.value == AiEngineMode.LOCAL_AUTONOMOUS) {
                    if (!hasNetworkConnectivity()) _engineMode.value = AiEngineMode.LOCAL_AUTONOMOUS
                    AiEngineMode.LOCAL_AUTONOMOUS
                } else {
                    AiEngineMode.ONLINE_CLOUD
                }

                val auditResult = patchAndReportEngine.runFullAutonomousAudit("", mode)
                val matched = threatKnowledgeEngine.matchTelemetryAgainstRules(auditResult.rawTelemetry)

                _uiState.value = WorkspaceUiState.Analyzing(
                    phase = "Sincronizando circuitos de Aura Mobile Defens y telemetría…",
                    previousScene = lastScene
                )

                val classification = auraAiEngine.planExecution("Auditoría inicial integral del sistema y red", mode)
                val scene = llmOrchestrator.synthesize(
                    userQuery = "Auditoría inicial integral del sistema, auto-protección y red",
                    resolution = AuraLlmOrchestrator.Resolution(
                        classification = classification,
                        source = AuraLlmOrchestrator.ResolutionSource.HEURISTIC
                    ),
                    toolResult = auditResult,
                    matchedRules = matched,
                    knowledgeStats = _knowledgeStats.value,
                    rootState = cap,
                    engineMode = activeEngineMode
                )

                lastScene = scene
                sessionRepository.saveScene(scene)
                appendAuraSceneMessage(scene)
                _uiState.value = WorkspaceUiState.Ready(scene)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Bootstrap failed", e)
                _uiState.value = WorkspaceUiState.Error(
                    message = e.localizedMessage ?: "Error al inicializar Aura Mobile Defense.",
                    previousScene = lastScene
                )
            }
        }
    }

    fun switchPrivilegeMode(targetMode: PrivilegeMode) {
        if (_privilegeMode.value == targetMode && _uiState.value is WorkspaceUiState.Ready) return
        _privilegeMode.value = targetMode
        activeJob?.cancel()
        activeJob = viewModelScope.launch {
            _selectedNode.value = null
            _uiState.value = WorkspaceUiState.Analyzing(
                phase = if (targetMode == PrivilegeMode.ROOT) {
                    "Verificando elevación su y contexto kernel…"
                } else {
                    "Cambiando a plano Sin Root (Userland)…"
                },
                previousScene = lastScene
            )
            try {
                val cap = privilegeEngine.probeRootCapability(
                    attemptElevation = targetMode == PrivilegeMode.ROOT
                )
                _rootState.value = cap

                val result = privilegeEngine.collectDeviceIntegrityAudit(targetMode)
                val matched = threatKnowledgeEngine.matchTelemetryAgainstRules(result.rawTelemetry)
                val activeEngine = if (_engineMode.value == AiEngineMode.LOCAL_AUTONOMOUS || !hasNetworkConnectivity()) {
                    AiEngineMode.LOCAL_AUTONOMOUS
                } else {
                    AiEngineMode.ONLINE_CLOUD
                }
                val classification = auraAiEngine.planExecution("Cambio a plano ${targetMode.name}", targetMode)
                val scene = llmOrchestrator.synthesize(
                    userQuery = "Cambio a plano ${targetMode.name}: verificar integridad y capacidades reales",
                    resolution = AuraLlmOrchestrator.Resolution(
                        classification = classification,
                        source = AuraLlmOrchestrator.ResolutionSource.HEURISTIC
                    ),
                    toolResult = result,
                    matchedRules = matched,
                    knowledgeStats = _knowledgeStats.value,
                    rootState = cap,
                    engineMode = activeEngine
                )
                lastScene = scene
                sessionRepository.saveScene(scene)
                appendAuraSceneMessage(scene)
                _uiState.value = WorkspaceUiState.Ready(scene)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Privilege switch failed", e)
                _uiState.value = WorkspaceUiState.Error(
                    message = e.localizedMessage ?: "Error al cambiar de privilegio.",
                    previousScene = lastScene
                )
            }
        }
    }

    fun submitQuery(rawInput: String) {
        val query = rawInput.trim()
        if (query.isBlank()) return

        val lower = query.lowercase()
        when {
            lower == "/intro" || lower == "/tour" -> {
                openWalkthrough()
                return
            }
            lower == "/root" || lower == "modo root" -> {
                switchPrivilegeMode(PrivilegeMode.ROOT)
                return
            }
            lower == "/user" || lower == "/nonroot" || lower == "modo sin root" -> {
                switchPrivilegeMode(PrivilegeMode.USERLAND)
                return
            }
            lower == "/local" || lower == "/offline" || lower.contains("modo local") -> {
                _engineMode.value = AiEngineMode.LOCAL_AUTONOMOUS
                submitQuery("/audit")
                return
            }
            lower == "/online" || lower.contains("modo online") -> {
                _engineMode.value = AiEngineMode.ONLINE_CLOUD
                bootstrapEnvironment()
                return
            }
            lower == "/ia" || lower == "/llm" || lower == "/modelo" || lower == "/ai" -> {
                _showLlmSettings.value = true
                return
            }
            lower == "/history" || lower == "/historial" -> {
                _showMemoryOverlay.value = true
                return
            }
            lower == "/report" || lower == "/reporte" || lower == "/patches" || lower == "/parches" -> {
                _showReportPatchOverlay.value = true
                return
            }
            lower == "/file" || lower == "/apk" -> {
                _requestFilePickerEvent.tryEmit(Unit)
                return
            }
            lower == "/clear" -> {
                viewModelScope.launch { sessionRepository.clearHistory() }
                return
            }
        }

        _chatMessages.value = _chatMessages.value + AuraChatMessage(
            speaker = ChatSpeaker.USER,
            text = query
        )

        activeJob?.cancel()
        activeJob = viewModelScope.launch {
            _selectedNode.value = null
            _showMemoryOverlay.value = false
            _showReportPatchOverlay.value = false

            val onlineAvailable = hasNetworkConnectivity()
            val llmReady = llmSettingsStore.buildProvider() != null
            val activeEngine = if (_engineMode.value == AiEngineMode.LOCAL_AUTONOMOUS || (!onlineAvailable && !llmReady)) {
                AiEngineMode.LOCAL_AUTONOMOUS
            } else {
                AiEngineMode.ONLINE_CLOUD
            }

            _uiState.value = WorkspaceUiState.Analyzing(
                phase = "Aura analizando intención…",
                previousScene = lastScene
            )

            try {
                val activeMode = _privilegeMode.value
                val resolution = llmOrchestrator.plan(query, activeMode)
                val classification = resolution.classification
                val plan = classification.plan

                if (plan.toolId == "EXECUTE_SOLUTIONS") {
                    runLiveSolutionExecution(activeMode)
                    return@launch
                }

                val effectiveMode = if (plan.prefersRoot && activeMode == PrivilegeMode.USERLAND) {
                    val cap = privilegeEngine.probeRootCapability(attemptElevation = true)
                    _rootState.value = cap
                    if (cap.verified) {
                        _privilegeMode.value = PrivilegeMode.ROOT
                        PrivilegeMode.ROOT
                    } else {
                        PrivilegeMode.USERLAND
                    }
                } else {
                    activeMode
                }

                // Si el modelo estaba configurado y falló (sin red, JSON inválido, herramienta fuera
                // del catálogo, inyección detectada), se dice en el panel. Antes el fallback era
                // completamente silencioso y parecía que el LLM no estaba haciendo nada.
                resolution.failure?.let { failure ->
                    _chatMessages.value = _chatMessages.value + AuraChatMessage(
                        speaker = ChatSpeaker.AURA,
                        subtitle = "MOTOR IA · FALLBACK LOCAL",
                        text = llmFallbackMessage(failure, resolution.modelReason)
                    )
                }

                _uiState.value = WorkspaceUiState.Analyzing(
                    phase = when (resolution.source) {
                        AuraLlmOrchestrator.ResolutionSource.LLM ->
                            "IA eligiendo herramienta: ${plan.toolId}…"
                        AuraLlmOrchestrator.ResolutionSource.SLASH_COMMAND ->
                            "Ejecutando comando: ${plan.toolId}…"
                        AuraLlmOrchestrator.ResolutionSource.HEURISTIC ->
                            "Ejecutando módulo real: ${plan.toolId}…"
                    },
                    previousScene = lastScene
                )

                val toolResult = when (plan.toolId) {
                    "FULL_AUTONOMOUS_AUDIT" -> patchAndReportEngine.runFullAutonomousAudit(plan.target, effectiveMode)
                    "SERVER_MONITOR" -> serverMonitorEngine.probeAndMonitorTarget(plan.target, effectiveMode)
                    "SELF_TRAIN_KEV" -> {
                        val res = threatKnowledgeEngine.trainFromInternet(effectiveMode)
                        _knowledgeStats.value = threatKnowledgeEngine.getKnowledgeStats()
                        res
                    }
                    "SELF_INTEGRITY" -> selfIntegrityEngine.inspectSelfIntegrity(effectiveMode).second
                    "DEVICE_INTEGRITY" -> privilegeEngine.collectDeviceIntegrityAudit(effectiveMode)
                    "NETWORK_SOCKETS" -> networkEngine.inspectLocalNetworkAndSockets(effectiveMode)
                    "PORT_PROBE" -> networkEngine.probePorts(plan.target, effectiveMode)
                    "TLS_INSPECT" -> networkEngine.inspectTlsCertificate(plan.target, effectiveMode)
                    "DNS_RECON" -> networkEngine.inspectDnsRecon(plan.target, effectiveMode)
                    "HTTP_HEADERS" -> networkEngine.inspectHttpSecurityHeaders(plan.target, effectiveMode)
                    "APP_SURFACE_AUDIT" -> binaryCryptoEngine.auditInstalledAppSurface(plan.target, effectiveMode)
                    "CRYPTO_JWT" -> binaryCryptoEngine.analyzeCryptoOrJwt(plan.target.ifBlank { query }, effectiveMode)
                    "ROOT_SHELL" -> privilegeEngine.executeRootShellInspection(plan.target.ifBlank { query }, effectiveMode)
                    "VPN_START" -> {
                        val started = VpnFirewallManager.startLocalVpnIfPrepared(getApplication())
                        if (!started) {
                            _requestVpnConsentEvent.tryEmit(Unit)
                        }
                        VpnFirewallManager.buildTelemetryReport(effectiveMode)
                    }
                    "VPN_STOP" -> {
                        VpnFirewallManager.stopLocalVpn(getApplication())
                        VpnFirewallManager.buildTelemetryReport(effectiveMode)
                    }
                    "VPN_TELEMETRY" -> VpnFirewallManager.buildTelemetryReport(effectiveMode)
                    "APP_FIREWALL_BLOCK" -> {
                        val pkg = plan.target.trim()
                        val result = AppFirewallEngine.setAppBlocked(getApplication(), pkg, blocked = true)
                        if (!vpnTelemetry.value.isRunning) {
                            val started = VpnFirewallManager.startLocalVpnIfPrepared(getApplication())
                            if (!started) _requestVpnConsentEvent.tryEmit(Unit)
                        }
                        ToolExecutionResult(
                            toolId = "APP_FIREWALL_BLOCK",
                            target = pkg,
                            privilegeUsed = effectiveMode,
                            rawTelemetry = buildString {
                                appendLine("=== FIREWALL POR APP ===")
                                appendLine("Paquete: ${result.packageName}")
                                appendLine("UID: ${result.uid ?: "desconocido"}")
                                appendLine("Kernel (iptables owner DROP): ${if (result.enforcedAtKernel) "APLICADO Y VERIFICADO" else "NO APLICADO"}")
                                appendLine(result.message)
                            },
                            measuredSpectrum = listOf(0.92f, 0.88f, 0.97f),
                            suggestedVisual = VisualTopologyKind.ATTACK_VECTOR_FLOW
                        )
                    }
                    "APP_FIREWALL_ALLOW" -> {
                        val pkg = plan.target.trim()
                        val result = AppFirewallEngine.setAppBlocked(getApplication(), pkg, blocked = false)
                        ToolExecutionResult(
                            toolId = "APP_FIREWALL_ALLOW",
                            target = pkg,
                            privilegeUsed = effectiveMode,
                            rawTelemetry = buildString {
                                appendLine("=== FIREWALL POR APP ===")
                                appendLine("Paquete: ${result.packageName}")
                                appendLine("UID: ${result.uid ?: "desconocido"}")
                                appendLine("Kernel: ${if (result.enforcedAtKernel) "REGLA RETIRADA Y VERIFICADA" else "SIN CAMBIOS EN KERNEL"}")
                                appendLine(result.message)
                            },
                            measuredSpectrum = listOf(0.5f, 0.6f, 0.5f),
                            suggestedVisual = VisualTopologyKind.ATTACK_VECTOR_FLOW
                        )
                    }
                    "APP_FIREWALL_LIST" -> {
                        val query = plan.target.trim().lowercase()
                        val rules = AppFirewallEngine.listPersistedRules(getApplication())
                        val apps = AppFirewallEngine.listInstalledApps(getApplication(), includeSystem = false)
                        val matches = if (query.isBlank()) emptyList()
                            else apps.filter { it.packageName.contains(query) || it.label.lowercase().contains(query) }
                        ToolExecutionResult(
                            toolId = "APP_FIREWALL_LIST",
                            target = plan.target,
                            privilegeUsed = effectiveMode,
                            rawTelemetry = buildString {
                                appendLine("=== FIREWALL POR APP ===")
                                appendLine("Apps de terceros instaladas: ${apps.size}")
                                appendLine("Reglas por app activas en Room: ${rules.size}")
                                rules.forEach { appendLine("  BLOQUEADA: ${it.pattern} (uid ${it.reason.substringAfter("uid ").substringBefore(")")})") }
                                if (query.isNotBlank()) {
                                    appendLine("Coincidencias con '$query':")
                                    if (matches.isEmpty()) appendLine("  (ninguna)")
                                    matches.forEach { appendLine("  ${it.label} — ${it.packageName} (uid ${it.uid})") }
                                }
                            },
                            measuredSpectrum = listOf(0.35f, 0.45f, 0.4f),
                            suggestedVisual = VisualTopologyKind.ATTACK_VECTOR_FLOW
                        )
                    }
                    "FIREWALL_BLOCK" -> {
                        val pattern = plan.target.trim()
                        if (pattern.isNotBlank()) {
                            val ruleType = when {
                                pattern.all { it.isDigit() } -> FirewallRuleType.PORT
                                Regex("^\\d{1,3}(?:\\.\\d{1,3}){3}$").matches(pattern) -> FirewallRuleType.IP
                                else -> FirewallRuleType.DOMAIN
                            }
                            VpnFirewallManager.addBlockRule(
                                getApplication(),
                                pattern,
                                ruleType,
                                "Bloqueo conversacional solicitado por usuario"
                            )
                            if (!vpnTelemetry.value.isRunning) {
                                val started = VpnFirewallManager.startLocalVpnIfPrepared(getApplication())
                                if (!started) _requestVpnConsentEvent.tryEmit(Unit)
                            }
                        }
                        VpnFirewallManager.buildTelemetryReport(effectiveMode)
                    }
                    "FIREWALL_ALLOW" -> {
                        if (plan.target.isNotBlank()) {
                            VpnFirewallManager.removeRule(getApplication(), plan.target)
                        }
                        VpnFirewallManager.buildTelemetryReport(effectiveMode)
                    }
                    else -> ToolExecutionResult(
                        toolId = "AI_THEORETICAL",
                        target = plan.target.ifBlank { "Asistencia Aura" },
                        privilegeUsed = effectiveMode,
                        rawTelemetry = "Motor IA Propio | Plano: ${effectiveMode.name} | SELinux: ${_rootState.value.selinuxMode} | Reglas aprendidas: ${_knowledgeStats.value.totalRules}",
                        measuredSpectrum = listOf(0.45f, 0.7f, 0.55f, 0.85f, 0.65f, 0.75f),
                        suggestedVisual = VisualTopologyKind.NEURAL_SYNAPTIC_LATTICE
                    )
                }

                val matched = threatKnowledgeEngine.matchTelemetryAgainstRules(toolResult.rawTelemetry)

                _uiState.value = WorkspaceUiState.Analyzing(
                    phase = "Actualizando circuitos de Aura Mobile Defens y soluciones…",
                    previousScene = lastScene
                )

                val scene = llmOrchestrator.synthesize(
                    userQuery = query,
                    resolution = resolution,
                    toolResult = toolResult,
                    matchedRules = matched,
                    knowledgeStats = _knowledgeStats.value,
                    rootState = _rootState.value,
                    engineMode = activeEngine
                )

                lastScene = scene
                sessionRepository.saveScene(scene)
                appendAuraSceneMessage(scene)
                _uiState.value = WorkspaceUiState.Ready(scene)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Query execution failed", e)
                _uiState.value = WorkspaceUiState.Error(
                    message = e.localizedMessage ?: "Error en ejecución o síntesis IA.",
                    previousScene = lastScene
                )
            }
        }
    }

    private fun llmFallbackMessage(failure: LlmFailure, modelReason: String): String = when (failure) {
        LlmFailure.NOT_CONFIGURED ->
            "No hay proveedor LLM configurado: he usado el clasificador heurístico local. " +
                "Configúralo con /ia si quieres el motor con modelo."
        LlmFailure.NETWORK ->
            "El proveedor LLM no respondió (red, timeout o clave inválida). He resuelto la petición " +
                "con el clasificador local para no dejarte sin respuesta."
        LlmFailure.UNPARSEABLE ->
            "El modelo devolvió una respuesta que no cumple el contrato JSON. He descartado su " +
                "elección y ejecutado el clasificador local."
        LlmFailure.TOOL_NOT_ALLOWED ->
            "El modelo propuso una herramienta que no existe en el catálogo cerrado de Aura. " +
                "Petición rechazada y reenrutada al clasificador local."
        LlmFailure.INJECTION_SUSPECTED ->
            "He detectado marcadores de prompt injection en tu mensaje, así que no he llamado al " +
                "modelo. El clasificador local ha resuelto la petición."
        LlmFailure.NEEDS_TARGET ->
            "El modelo identificó la herramienta pero falta el objetivo (dominio, IP o puerto). " +
                (modelReason.takeIf { it.isNotBlank() }?.let { "Motivo: $it. " } ?: "") +
                "Indícalo y repito la operación."
    }

    fun inspectFileUri(uri: Uri) {
        activeJob?.cancel()
        activeJob = viewModelScope.launch {
            _selectedNode.value = null
            _showMemoryOverlay.value = false
            _uiState.value = WorkspaceUiState.Analyzing(
                phase = "Analizando entropía, hashes y IOCs del archivo…",
                previousScene = lastScene
            )
            try {
                val result = binaryCryptoEngine.analyzeBinaryUri(uri, _privilegeMode.value)
                val matched = threatKnowledgeEngine.matchTelemetryAgainstRules(result.rawTelemetry)
                val activeEngine = if (_engineMode.value == AiEngineMode.LOCAL_AUTONOMOUS || !hasNetworkConnectivity()) {
                    AiEngineMode.LOCAL_AUTONOMOUS
                } else {
                    AiEngineMode.ONLINE_CLOUD
                }
                val classification = auraAiEngine.planExecution("Análisis binario ${result.target}", _privilegeMode.value)
                val scene = llmOrchestrator.synthesize(
                    userQuery = "Análisis estático de seguridad y entropía para ${result.target}",
                    resolution = AuraLlmOrchestrator.Resolution(
                        classification = classification,
                        source = AuraLlmOrchestrator.ResolutionSource.HEURISTIC
                    ),
                    toolResult = result,
                    matchedRules = matched,
                    knowledgeStats = _knowledgeStats.value,
                    rootState = _rootState.value,
                    engineMode = activeEngine
                )
                lastScene = scene
                sessionRepository.saveScene(scene)
                appendAuraSceneMessage(scene)
                _uiState.value = WorkspaceUiState.Ready(scene)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "File inspection failed", e)
                _uiState.value = WorkspaceUiState.Error(
                    message = e.localizedMessage ?: "Error al analizar archivo local.",
                    previousScene = lastScene
                )
            }
        }
    }

    fun executeSolutionsLiveNow() {
        activeJob?.cancel()
        activeJob = viewModelScope.launch {
            _chatMessages.value = _chatMessages.value + AuraChatMessage(
                speaker = ChatSpeaker.USER,
                text = "Ejecutar las soluciones para las vulnerabilidades detectadas"
            )
            runLiveSolutionExecution(_privilegeMode.value)
        }
    }

    fun toggleLocalVpn() {
        if (vpnTelemetry.value.isRunning) {
            VpnFirewallManager.stopLocalVpn(getApplication())
            _chatMessages.value = _chatMessages.value + AuraChatMessage(
                speaker = ChatSpeaker.AURA,
                subtitle = "VPN LOCAL + FIREWALL",
                text = "Túnel VPN Local detenido. Puedes reactivarlo en cualquier momento."
            )
        } else {
            val started = VpnFirewallManager.startLocalVpnIfPrepared(getApplication())
            if (!started) {
                _requestVpnConsentEvent.tryEmit(Unit)
            } else {
                _chatMessages.value = _chatMessages.value + AuraChatMessage(
                    speaker = ChatSpeaker.AURA,
                    subtitle = "VPN LOCAL + FIREWALL ACTIVO",
                    text = "VPN Local iniciada sobre 10.8.0.2/32 con filtrado DNS y firewall de puertos/IPs en vivo."
                )
            }
        }
    }

    fun onVpnConsentGranted(granted: Boolean) {
        if (granted) {
            VpnFirewallManager.sendVpnCommand(getApplication(), com.aura.mobiledefense.domain.vpn.AuraLocalVpnService.ACTION_START)
            // Mark any pending NEEDS_CONSENT step as DONE
            _chatMessages.value = _chatMessages.value.map { msg ->
                if (msg.executionSteps.any { it.state == ExecutionStepState.NEEDS_CONSENT }) {
                    msg.copy(
                        isExecuting = false,
                        executionSteps = msg.executionSteps.map { st ->
                            if (st.state == ExecutionStepState.NEEDS_CONSENT) {
                                st.copy(
                                    title = "VPN Local + Firewall operando en vivo",
                                    detail = "Autorización concedida. Túnel TUN 10.8.0.2/32 activo inspeccionando DNS y firewall.",
                                    state = ExecutionStepState.DONE
                                )
                            } else st
                        }
                    )
                } else msg
            }
        } else {
            _chatMessages.value = _chatMessages.value + AuraChatMessage(
                speaker = ChatSpeaker.AURA,
                subtitle = "PERMISO VPN REQUERIDO",
                text = "No se concedió permiso al sistema Android para crear la interfaz VPN local. Sin este permiso el firewall TUN no puede interceptar paquetes."
            )
        }
    }

    private suspend fun runLiveSolutionExecution(mode: PrivilegeMode) {
        val currentScene = lastScene
        val patches = currentScene?.patches.orEmpty()
        // Objetivo estructurado: antes se sacaba con substringBefore("·") del subtítulo, que se
        // rompía en cuanto el formato o el propio objetivo contenía el separador.
        val target = currentScene?.target?.trim().orEmpty()
        val telemetry = currentScene?.rawTelemetry.orEmpty()

        val execMsgId = java.util.UUID.randomUUID().toString()
        _chatMessages.value = _chatMessages.value + AuraChatMessage(
            id = execMsgId,
            speaker = ChatSpeaker.AURA,
            subtitle = "EJECUCIÓN REAL DE SOLUCIONES · ${mode.name}",
            text = "Iniciando aplicación real de mitigaciones en el panel:",
            isExecuting = true,
            suggestions = listOf(
                "Ver telemetría de VPN Local y Firewall (/vpn)",
                "Ejecutar nueva auditoría de verificación (/audit)"
            )
        )

        _uiState.value = WorkspaceUiState.Analyzing(
            phase = "Ejecutando soluciones y reglas de Firewall en vivo…",
            previousScene = currentScene
        )

        solutionExecutionEngine.executeSolutionsLive(
            patches = patches,
            targetHost = target,
            rawTelemetry = telemetry,
            mode = mode,
            onRequireVpnConsent = { _requestVpnConsentEvent.tryEmit(Unit) }
        ).collect { steps ->
            val stillRunning = steps.any { it.state == ExecutionStepState.RUNNING }
            _chatMessages.value = _chatMessages.value.map { m ->
                if (m.id == execMsgId) {
                    m.copy(
                        executionSteps = steps,
                        isExecuting = stillRunning,
                        text = if (stillRunning) {
                            "Ejecutando mitigaciones paso a paso sobre el sistema y firewall:"
                        } else {
                            "Soluciones procesadas (${steps.count { it.state == ExecutionStepState.DONE }}/${steps.size} completadas)."
                        }
                    )
                } else m
            }
        }

        lastScene?.let { _uiState.value = WorkspaceUiState.Ready(it) }
    }

    private fun appendAuraSceneMessage(scene: AiVisualScene) {
        val recs = scene.report?.improvementRecommendations
            ?.split(Regex("\\s*(?=\\d+\\))"))
            ?.map { it.trim() }
            ?.filter { it.isNotBlank() }
            ?: emptyList()

        val msg = AuraChatMessage(
            speaker = ChatSpeaker.AURA,
            subtitle = scene.title,
            text = scene.narrative,
            suggestions = scene.whisperPrompts,
            recommendations = recs.ifEmpty { scene.technicalFindings.take(3) },
            patches = scene.patches,
            hasReport = scene.report != null || scene.patches.isNotEmpty()
        )
        val updated = (_chatMessages.value + msg).takeLast(30)
        _chatMessages.value = updated
    }

    fun selectNode(node: AiVisualNode?) {
        _selectedNode.value = node
    }

    fun setMemoryOverlayVisible(visible: Boolean) {
        _showMemoryOverlay.value = visible
    }

    fun setReportPatchOverlayVisible(visible: Boolean) {
        _showReportPatchOverlay.value = visible
    }

    fun setLlmSettingsVisible(visible: Boolean) {
        _showLlmSettings.value = visible
    }

    // ── LLM settings (BYOK) ──────────────────────────────────────────────────────────────────

    fun updateLlmSettings(transform: (LlmSettings) -> LlmSettings) {
        llmSettingsStore.update(transform)
        syncEngineModeWithLlm()
    }

    fun acceptCloudConsent() = updateLlmSettings { it.copy(cloudConsentGiven = true) }

    fun clearLlmKey() {
        llmSettingsStore.clearKey()
        _llmStatus.value = "Clave eliminada. Aura vuelve al motor heurístico local."
        syncEngineModeWithLlm()
    }

    /** Sends a tiny probe to the configured model and reports what came back. */
    fun testLlmConnection() {
        viewModelScope.launch {
            val settings = llmSettingsStore.settings.value
            val provider = llmSettingsStore.buildProvider(settings)
            if (provider == null) {
                _llmStatus.value = "Sin configuración válida: revisa clave, modelo y endpoint."
                return@launch
            }
            val cleartextWarning = LlmSettingsStore.cleartextWarning(settings.baseUrl)
            if (cleartextWarning != null) {
                _llmStatus.value = cleartextWarning
                return@launch
            }
            if (!llmSettingsStore.secureStorageAvailable) {
                _llmStatus.value = "Aviso: el AndroidKeyStore no está disponible; la clave se queda " +
                    "solo en memoria y se perderá al cerrar la app."
            } else {
                _llmStatus.value = "Probando ${provider.displayName}…"
            }
            val reply = runCatching {
                provider.complete(
                    system = "Responde solo con la palabra OK.",
                    user = "ping",
                    jsonMode = false,
                    maxTokens = 16
                )
            }.getOrNull()
            val result = if (reply != null) {
                "Conexión correcta con ${provider.displayName}: ${reply.take(60)}"
            } else {
                "El modelo no respondió. Revisa la clave, el endpoint o tu conexión."
            }
            _llmStatus.value = if (llmSettingsStore.secureStorageAvailable) result
            else "Aviso: clave solo en memoria (KeyStore no disponible). $result"
        }
    }

    private fun syncEngineModeWithLlm() {
        val settings = llmSettingsStore.settings.value
        _engineMode.value = llmSettingsStore.engineModeFor(settings)
    }

    fun restoreSession(scene: AiVisualScene) {
        _showMemoryOverlay.value = false
        _selectedNode.value = null
        lastScene = scene
        _privilegeMode.value = scene.privilegeMode
        appendAuraSceneMessage(scene)
        _uiState.value = WorkspaceUiState.Ready(scene)
    }

    fun deleteSession(id: String) {
        viewModelScope.launch { sessionRepository.deleteSession(id) }
    }

    fun removeMonitorTarget(target: String) {
        viewModelScope.launch { dao.deleteMonitorTarget(target) }
    }

    fun triggerFilePicker() {
        _requestFilePickerEvent.tryEmit(Unit)
    }

    private fun startBackgroundMonitorLoop() {
        viewModelScope.launch {
            while (isActive) {
                delay(25_000L)
                if (hasNetworkConnectivity()) {
                    runCatching {
                        val alerts = serverMonitorEngine.runBackgroundMonitorCycle()
                        if (alerts.isNotEmpty()) {
                            val summary = alerts.joinToString { "${it.target} (+${it.newAnomalies})" }
                            _activeMonitorBanner.value = "Anomalía de red/servidor detectada: $summary"
                        }
                    }
                }
            }
        }
    }

    private fun hasNetworkConnectivity(): Boolean {
        val cm = getApplication<Application>().getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val net = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(net) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }
}
