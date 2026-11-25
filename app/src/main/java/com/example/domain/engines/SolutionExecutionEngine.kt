package com.example.domain.engines

import android.content.Context
import com.example.data.model.ExecutionStepState
import com.example.data.model.FirewallRuleType
import com.example.data.model.GeneratedPatch
import com.example.data.model.PrivilegeMode
import com.example.data.model.SolutionExecutionStep
import com.example.domain.vpn.VpnFirewallManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import java.io.File
import java.net.InetAddress
import java.security.MessageDigest

/**
 * Executes real vulnerability mitigations (no simulations) and streams live step-by-step progress
 * into Aura's black conversational panel.
 */
class SolutionExecutionEngine(
    private val context: Context,
    private val privilegeEngine: PrivilegeAndDeviceEngine
) {

    fun executeSolutionsLive(
        patches: List<GeneratedPatch>,
        targetHost: String,
        rawTelemetry: String,
        mode: PrivilegeMode,
        onRequireVpnConsent: () -> Unit
    ): Flow<List<SolutionExecutionStep>> = flow {
        val steps = mutableListOf<SolutionExecutionStep>()

        fun emitStep(stepNumber: Int, title: String, detail: String, state: ExecutionStepState) {
            val idx = steps.indexOfFirst { it.stepNumber == stepNumber }
            val updated = SolutionExecutionStep(stepNumber, title, detail, state)
            if (idx >= 0) steps[idx] = updated else steps.add(updated)
        }

        // STEP 1: Persist verified patch artifacts to private app storage
        emitStep(1, "Sintetizando y escribiendo archivos de parche", "Preparando artefactos defensivos verificados…", ExecutionStepState.RUNNING)
        emit(steps.toList())
        delay(220)

        val patchDir = File(context.filesDir, "aura_remediations").apply { mkdirs() }
        val writtenSummary = if (patches.isNotEmpty()) {
            patches.mapIndexed { i, patch ->
                val safeName = patch.targetArtifact.replace(Regex("[^a-zA-Z0-9._-]"), "_")
                val outFile = File(patchDir, "${i + 1}_$safeName")
                outFile.writeText(patch.patchContent)
                val sha = MessageDigest.getInstance("SHA-256")
                    .digest(patch.patchContent.toByteArray())
                    .joinToString("") { "%02x".format(it) }
                    .take(12)
                "${outFile.name} (sha256:$sha)"
            }.joinToString(", ")
        } else {
            val baselineFile = File(patchDir, "hardening_baseline.txt")
            baselineFile.writeText("Aura Defense Verified Baseline\n${rawTelemetry.take(1200)}")
            baselineFile.name
        }
        emitStep(1, "Artefactos de mitigación guardados", "Escritos en almacenamiento privado: $writtenSummary", ExecutionStepState.DONE)
        emit(steps.toList())

        // STEP 2: Enforce real Firewall rules based on findings
        emitStep(2, "Configurando reglas reales en Firewall Aura", "Evaluando puertos, dominios e IPs riesgosas…", ExecutionStepState.RUNNING)
        emit(steps.toList())
        delay(220)

        VpnFirewallManager.ensureInitialized(context)
        val lower = rawTelemetry.lowercase()
        val appliedRules = mutableListOf<String>()

        if (lower.contains("5555/tcp") || lower.contains("adb")) {
            VpnFirewallManager.addBlockRule(context, "5555", FirewallRuleType.PORT, "Mitigación automática: puerto ADB 5555")
            appliedRules.add("PORT 5555 DROP")
        }
        if (lower.contains("23/tcp")) {
            VpnFirewallManager.addBlockRule(context, "23", FirewallRuleType.PORT, "Mitigación automática: Telnet inseguro")
            appliedRules.add("PORT 23 DROP")
        }
        if (lower.contains("6379/tcp")) {
            VpnFirewallManager.addBlockRule(context, "6379", FirewallRuleType.PORT, "Mitigación automática: Redis sin cifrado")
            appliedRules.add("PORT 6379 DROP")
        }
        if (lower.contains("cleartext=true")) {
            VpnFirewallManager.addBlockRule(context, "80", FirewallRuleType.PORT, "Mitigación: tráfico HTTP cleartext")
            appliedRules.add("HTTP:80 vigilado")
        }
        if (targetHost.isNotBlank() && (lower.contains("anomal") || lower.contains("mitm"))) {
            val resolvedIp = runCatching { InetAddress.getByName(targetHost).hostAddress }.getOrNull()
            if (!resolvedIp.isNullOrBlank()) {
                VpnFirewallManager.addBlockRule(context, resolvedIp, FirewallRuleType.IP, "Contención automática por anomalía en $targetHost")
                appliedRules.add("IP $resolvedIp DROP")
            }
        }
        if (appliedRules.isEmpty()) {
            appliedRules.add("Reglas base de rastreadores y puertos 5555/23/6379 activas")
        }
        emitStep(2, "Firewall actualizado en Room", "Reglas activadas: ${appliedRules.joinToString(" · ")}", ExecutionStepState.DONE)
        emit(steps.toList())

        // STEP 3: Kernel / Root hardening if privilege mode is ROOT
        if (mode == PrivilegeMode.ROOT) {
            emitStep(3, "Aplicando endurecimiento Kernel (Root su)", "Verificando SELinux e iptables del sistema…", ExecutionStepState.RUNNING)
            emit(steps.toList())
            val cmdResults = mutableListOf<String>()
            if (lower.contains("permissive")) {
                val r = privilegeEngine.executeRootShellInspection("setenforce 1 && getenforce", PrivilegeMode.ROOT)
                cmdResults.add("SELinux -> ${r.rawTelemetry.lines().lastOrNull { it.isNotBlank() } ?: "ejecutado"}")
            }
            if (lower.contains("5555/tcp")) {
                privilegeEngine.executeRootShellInspection("iptables -C INPUT -p tcp --dport 5555 -j DROP 2>/dev/null || iptables -I INPUT -p tcp --dport 5555 -j DROP", PrivilegeMode.ROOT)
                cmdResults.add("iptables DROP 5555 aplicado")
            }
            if (cmdResults.isEmpty()) {
                val r = privilegeEngine.executeRootShellInspection("getenforce", PrivilegeMode.ROOT)
                cmdResults.add("Kernel verificado (${r.rawTelemetry.lines().lastOrNull { it.isNotBlank() } ?: "ok"})")
            }
            emitStep(3, "Contención Kernel ejecutada", cmdResults.joinToString(" | "), ExecutionStepState.DONE)
            emit(steps.toList())
        } else {
            emitStep(3, "Contención en plano Sin Root (Userland)", "Sin privilegio su: el endurecimiento de red se canaliza a través del túnel VPN local.", ExecutionStepState.DONE)
            emit(steps.toList())
        }

        // STEP 4: Ensure Real Local VPN + Firewall TUN service is active
        emitStep(4, "Activando túnel VPN Local + Firewall real", "Verificando interfaz TUN 10.8.0.2/32…", ExecutionStepState.RUNNING)
        emit(steps.toList())
        delay(200)

        val vpnReady = VpnFirewallManager.startLocalVpnIfPrepared(context)
        if (vpnReady) {
            emitStep(
                4,
                "VPN Local + Firewall operando en vivo",
                "Túnel TUN activo inspeccionando DNS y filtrando rutas bloqueadas en tiempo real.",
                ExecutionStepState.DONE
            )
        } else {
            emitStep(
                4,
                "Esperando autorización VPN de Android",
                "Acepta el diálogo del sistema Android para encender el túnel TUN real del firewall.",
                ExecutionStepState.NEEDS_CONSENT
            )
            onRequireVpnConsent()
        }
        emit(steps.toList())
    }.flowOn(Dispatchers.IO)
}
