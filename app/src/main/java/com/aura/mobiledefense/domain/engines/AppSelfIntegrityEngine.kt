package com.aura.mobiledefense.domain.engines

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.data.model.ToolExecutionResult
import com.aura.mobiledefense.data.model.VisualTopologyKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest

class AppSelfIntegrityEngine(private val context: Context) {

    data class IntegritySnapshot(
        val packageName: String,
        val signerSha256: String,
        val isDebuggableFlag: Boolean,
        val isDebuggerConnected: Boolean,
        val tracerPid: Int,
        val hookingArtifacts: List<String>,
        val integrityScore: Float,
        val summaryText: String
    )

    suspend fun inspectSelfIntegrity(mode: PrivilegeMode): Pair<IntegritySnapshot, ToolExecutionResult> =
        withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val pkg = context.packageName
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageManager.GET_SIGNING_CERTIFICATES
            } else {
                @Suppress("DEPRECATION")
                PackageManager.GET_SIGNATURES
            }
            val pkgInfo = runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(flags.toLong()))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(pkg, flags)
                }
            }.getOrNull()

            val signerBytes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkgInfo?.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
            } else {
                @Suppress("DEPRECATION")
                pkgInfo?.signatures?.firstOrNull()?.toByteArray()
            }

            val signerSha256 = if (signerBytes != null) {
                MessageDigest.getInstance("SHA-256")
                    .digest(signerBytes)
                    .joinToString(":") { "%02X".format(it) }
            } else "No verificable"

            val debuggableFlag = ((pkgInfo?.applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_DEBUGGABLE) != 0
            val debuggerConnected = Debug.isDebuggerConnected()

            val tracerPid = runCatching {
                File("/proc/self/status").readLines()
                    .firstOrNull { it.startsWith("TracerPid:") }
                    ?.substringAfter(":")
                    ?.trim()
                    ?.toIntOrNull() ?: 0
            }.getOrDefault(0)

            val suspiciousLibs = listOf("frida", "xposed", "lsposed", "substrate", "gadget")
            val hookingHits = runCatching {
                File("/proc/self/maps").useLines { lines ->
                    lines.filter { line ->
                        suspiciousLibs.any { lib -> line.contains(lib, ignoreCase = true) }
                    }.take(8).toList()
                }
            }.getOrDefault(emptyList())

            var score = 1.0f
            if (debuggerConnected) score -= 0.35f
            if (tracerPid > 0) score -= 0.30f
            if (hookingHits.isNotEmpty()) score -= 0.35f
            if (debuggableFlag) score -= 0.15f
            score = score.coerceIn(0.1f, 1.0f)

            val sb = StringBuilder().apply {
                appendLine("=== AUTO-PROTECCIÓN E INTEGRIDAD ANTI-MANIPULACIÓN ===")
                appendLine("Paquete: $pkg")
                appendLine("Firma APK SHA-256: $signerSha256")
                appendLine("Build Debuggable Flag: $debuggableFlag (Release habilita ofuscación R8)")
                appendLine("Debugger Activo: $debuggerConnected | TracerPid (/proc/self/status): $tracerPid")
                appendLine(
                    "Artefactos de instrumentación en memoria (/proc/self/maps): " +
                        if (hookingHits.isEmpty()) "Ninguno detectado" else "${hookingHits.size} coincidencia(s)"
                )
                hookingHits.forEach { appendLine("  • ${it.take(120)}") }
                appendLine("Índice de integridad en ejecución: ${(score * 100).toInt()}%")
            }

            val snap = IntegritySnapshot(
                packageName = pkg,
                signerSha256 = signerSha256,
                isDebuggableFlag = debuggableFlag,
                isDebuggerConnected = debuggerConnected,
                tracerPid = tracerPid,
                hookingArtifacts = hookingHits,
                integrityScore = score,
                summaryText = sb.toString()
            )

            val toolResult = ToolExecutionResult(
                toolId = "SELF_INTEGRITY",
                target = pkg,
                privilegeUsed = mode,
                rawTelemetry = sb.toString(),
                measuredSpectrum = listOf(
                    if (!debuggerConnected) 0.95f else 0.15f,
                    if (tracerPid == 0) 0.95f else 0.2f,
                    if (hookingHits.isEmpty()) 0.95f else 0.1f,
                    if (!debuggableFlag) 0.9f else 0.55f,
                    score
                ),
                suggestedVisual = VisualTopologyKind.NEURAL_SYNAPTIC_LATTICE
            )

            snap to toolResult
        }
}
