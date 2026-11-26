package com.aura.mobiledefense.domain.engines

import android.content.Context
import android.os.Build
import android.os.Process
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.data.model.RootCapabilityState
import com.aura.mobiledefense.data.model.ToolExecutionResult
import com.aura.mobiledefense.data.model.VisualTopologyKind
import com.aura.mobiledefense.domain.security.RootCommandPolicy
import com.aura.mobiledefense.domain.security.ShellRunner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.security.KeyFactory
import java.security.KeyStore
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.SecretKeySpec

class PrivilegeAndDeviceEngine(private val context: Context) {

    private val suCandidatePaths = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/su/bin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/debug_ramdisk/su",
        "/sbin/.magisk/busybox/su"
    )

    suspend fun probeRootCapability(attemptElevation: Boolean): RootCapabilityState =
        withContext(Dispatchers.IO) {
            val foundSuPath = suCandidatePaths.firstOrNull { File(it).exists() }
                ?: runCommand("which su", timeoutMs = 1500L).stdout.trim().takeIf {
                    it.isNotBlank() && File(it).exists()
                }

            val rootFlavor = detectRootFlavor(foundSuPath)
            val selinuxFromProc = readSmallFile("/sys/fs/selinux/enforce")?.let {
                when (it.trim()) {
                    "1" -> "Enforcing"
                    "0" -> "Permissive"
                    else -> it.trim()
                }
            } ?: runCommand("getenforce", timeoutMs = 1500L).stdout.trim().ifBlank { "Restringido (Userland)" }

            if (!attemptElevation) {
                return@withContext RootCapabilityState(
                    suAvailable = foundSuPath != null,
                    suPath = foundSuPath,
                    rootFlavor = rootFlavor,
                    selinuxMode = selinuxFromProc,
                    uidOutput = "uid=${Process.myUid()} (Userland Sandbox)",
                    verified = false,
                    lastProbeMessage = if (foundSuPath != null) {
                        "Binario su localizado en $foundSuPath (modo Userland activo)"
                    } else {
                        "Sin binario su accesible; operando con APIs de Userland"
                    }
                )
            }

            val suResult = runSuCommand("id && getenforce 2>/dev/null", timeoutMs = 4500L)
            val isRootVerified = suResult.exitCode == 0 && suResult.stdout.contains("uid=0")
            val selinuxAfterSu = suResult.stdout.lines()
                .drop(1)
                .firstOrNull { it.isNotBlank() }
                ?.trim()
                ?: selinuxFromProc

            RootCapabilityState(
                suAvailable = foundSuPath != null || isRootVerified,
                suPath = foundSuPath,
                rootFlavor = rootFlavor,
                selinuxMode = selinuxAfterSu,
                uidOutput = if (isRootVerified) {
                    suResult.stdout.lines().firstOrNull().orEmpty().ifBlank { "uid=0(root)" }
                } else {
                    "uid=${Process.myUid()} (Elevación su no concedida)"
                },
                verified = isRootVerified,
                lastProbeMessage = when {
                    isRootVerified -> "Elevación su confirmada: ${suResult.stdout.lines().firstOrNull().orEmpty()}"
                    suResult.stderr.isNotBlank() -> "su rechazado/inaccesible: ${suResult.stderr.take(140)}"
                    else -> "Binario su no disponible en este dispositivo"
                }
            )
        }

    suspend fun collectDeviceIntegrityAudit(mode: PrivilegeMode): ToolExecutionResult =
        withContext(Dispatchers.IO) {
            val sb = StringBuilder()
            val props = readKeySystemProps()
            val kernelVersion = readSmallFile("/proc/version")?.trim() ?: "No legible"
            val memInfo = readSmallFile("/proc/meminfo")?.lines()?.take(4)?.joinToString(" | ") ?: "N/D"
            val adbEnabled = runCatching {
                Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
            }.getOrDefault(false)
            val teeStatus = probeHardwareKeystore()
            val rootState = probeRootCapability(attemptElevation = mode == PrivilegeMode.ROOT)

            sb.appendLine("=== DISPOSITIVO & INTEGRIDAD DE PLATAFORMA ===")
            sb.appendLine("Modelo: ${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})")
            sb.appendLine("Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) | Patch: ${Build.VERSION.SECURITY_PATCH}")
            sb.appendLine("Build Tags: ${Build.TAGS} | Fingerprint: ${Build.FINGERPRINT}")
            sb.appendLine("Kernel: $kernelVersion")
            sb.appendLine("Memoria: $memInfo")
            sb.appendLine("ADB Debugging: ${if (adbEnabled) "HABILITADO" else "Deshabilitado"}")
            sb.appendLine("Hardware Keystore / TEE: $teeStatus")
            sb.appendLine("SELinux: ${rootState.selinuxMode}")
            sb.appendLine("Privilegio: ${rootState.uidOutput} | Root Flavor: ${rootState.rootFlavor}")
            sb.appendLine()
            sb.appendLine("=== PROPIEDADES DEL SISTEMA ===")
            props.forEach { (k, v) -> sb.appendLine("$k = $v") }

            if (mode == PrivilegeMode.ROOT) {
                sb.appendLine()
                sb.appendLine("=== TELEMETRÍA KERNEL / ROOT (su) ===")
                if (rootState.verified) {
                    val kernelTelemetry = runSuCommand(
                        "uname -a; echo '---lsmod---'; (lsmod 2>/dev/null || cat /proc/modules 2>/dev/null); echo '---mounts---'; mount; echo '---procs---'; ps -A -Z 2>/dev/null",
                        timeoutMs = 7000L
                    )
                    sb.appendLine(kernelTelemetry.stdout.ifBlank { kernelTelemetry.stderr })
                } else {
                    sb.appendLine("Nota real del sistema: ${rootState.lastProbeMessage}")
                }
            }

            // Calculate real normalized posture indicators for visual spectrum
            val indicators = listOf(
                if (props["ro.boot.verifiedbootstate"] == "green") 0.9f else 0.35f,
                if (props["ro.boot.flash.locked"] == "1") 0.9f else 0.25f,
                if (props["ro.debuggable"] == "0") 0.88f else 0.2f,
                if (!adbEnabled) 0.85f else 0.4f,
                if (rootState.selinuxMode.contains("Enforcing", ignoreCase = true)) 0.92f else 0.3f,
                if (teeStatus.contains("Hardware", ignoreCase = true)) 0.9f else 0.45f,
                if (props["ro.crypto.state"] == "encrypted") 0.95f else 0.3f,
                if (!rootState.suAvailable) 0.85f else 0.5f
            )

            ToolExecutionResult(
                toolId = "DEVICE_INTEGRITY",
                target = "${Build.MANUFACTURER} ${Build.MODEL}",
                privilegeUsed = mode,
                rawTelemetry = sb.toString(),
                measuredSpectrum = indicators,
                suggestedVisual = VisualTopologyKind.PROTOCOL_STRATA
            )
        }

    suspend fun executeRootShellInspection(
        command: String,
        mode: PrivilegeMode
    ): ToolExecutionResult = withContext(Dispatchers.IO) {
        val requestedCmd = command.trim().removePrefix("/su").trim()
        val cleanCmd = requestedCmd.ifBlank {
            "id && getenforce && uname -a && ps -A -Z"
        }

        // Default-deny gate: every shell string (free-form chat text included) must pass the policy
        // before it reaches `su -c` / `sh -c`.
        when (val decision = RootCommandPolicy.evaluate(cleanCmd, elevated = mode == PrivilegeMode.ROOT)) {
            is RootCommandPolicy.Decision.Denied -> {
                return@withContext ToolExecutionResult(
                    toolId = "ROOT_SHELL",
                    target = cleanCmd.take(200),
                    privilegeUsed = mode,
                    rawTelemetry = buildString {
                        appendLine("=== EJECUCIÓN BLOQUEADA POR POLÍTICA DE PRIVILEGIOS ===")
                        appendLine("Solicitud: ${cleanCmd.take(200)}")
                        appendLine("Motivo: ${decision.reason}")
                        appendLine()
                        appendLine("Aura solo ejecuta inspecciones de lectura (id, getenforce, ps, ss, iptables -L,")
                        appendLine("dumpsys, getprop…) y mitigaciones verificadas (setenforce 1, DROP de puertos")
                        appendLine("administrativos). Cualquier otra orden debe ejecutarse manualmente fuera de Aura.")
                    },
                    measuredSpectrum = listOf(0.95f, 0.95f, 0.95f),
                    suggestedVisual = VisualTopologyKind.ATTACK_VECTOR_FLOW
                )
            }
            is RootCommandPolicy.Decision.Allowed -> Unit
        }

        val res = if (mode == PrivilegeMode.ROOT) {
            runSuCommand(cleanCmd, timeoutMs = 9000L)
        } else {
            runCommand(cleanCmd, timeoutMs = 6000L)
        }

        val output = buildString {
            appendLine("=== EJECUCIÓN ${if (mode == PrivilegeMode.ROOT) "ROOT (su -c)" else "USERLAND (sh -c)"} ===")
            appendLine("Comando: $cleanCmd")
            appendLine("Exit Code: ${res.exitCode}")
            if (res.stdout.isNotBlank()) {
                appendLine("--- STDOUT ---")
                appendLine(res.stdout.take(6000))
            }
            if (res.stderr.isNotBlank()) {
                appendLine("--- STDERR ---")
                appendLine(res.stderr.take(2000))
            }
            if (res.stdout.isBlank() && res.stderr.isBlank()) {
                appendLine("(Sin salida estándar)")
            }
        }

        val lines = res.stdout.lines().filter { it.isNotBlank() }
        val spectrum = (0 until 16).map { idx ->
            val line = lines.getOrNull(idx) ?: ""
            (line.length.coerceAtMost(80) / 80f).coerceIn(0.12f, 0.98f)
        }

        ToolExecutionResult(
            toolId = "ROOT_SHELL",
            target = cleanCmd,
            privilegeUsed = mode,
            rawTelemetry = output,
            measuredSpectrum = spectrum,
            suggestedVisual = VisualTopologyKind.CONSTELLATION_MESH
        )
    }

    private fun detectRootFlavor(suPath: String?): String {
        val indicators = listOf(
            "/data/adb/magisk" to "Magisk",
            "/sbin/.magisk" to "Magisk",
            "/data/adb/ksu" to "KernelSU",
            "/data/adb/ksud" to "KernelSU",
            "/data/adb/ap" to "APatch"
        )
        indicators.firstOrNull { (path, _) -> File(path).exists() }?.let { return it.second }
        if (suPath != null) {
            return when {
                suPath.contains("magisk", ignoreCase = true) -> "Magisk"
                else -> "su binario ($suPath)"
            }
        }
        return "Ninguno detectado"
    }

    private suspend fun readKeySystemProps(): Map<String, String> {
        val keys = listOf(
            "ro.debuggable",
            "ro.secure",
            "ro.boot.verifiedbootstate",
            "ro.boot.flash.locked",
            "ro.crypto.state",
            "ro.build.selinux",
            "persist.sys.usb.config",
            "service.adb.root",
            "ro.product.cpu.abilist"
        )
        val result = linkedMapOf<String, String>()
        keys.forEach { key ->
            val v = runCommand("getprop $key", timeoutMs = 1000L).stdout.trim()
            result[key] = v.ifBlank { "(no definido)" }
        }
        return result
    }

    private fun probeHardwareKeystore(): String {
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore")
            ks.load(null)
            val alias = "nyxcore_tee_probe"
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val keyGen = javax.crypto.KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES,
                    "AndroidKeyStore"
                )
                keyGen.init(
                    KeyGenParameterSpec.Builder(
                        alias,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                    )
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build()
                )
                val key = keyGen.generateKey()
                val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
                val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
                ks.deleteEntry(alias)
                @Suppress("DEPRECATION")
                val hwBacked = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    info.securityLevel != KeyProperties.SECURITY_LEVEL_SOFTWARE
                } else {
                    info.isInsideSecureHardware
                }
                if (hwBacked) "Hardware-Backed (TEE / StrongBox)" else "Software Keystore"
            } else {
                "AndroidKeyStore disponible"
            }
        } catch (e: Exception) {
            "Keystore probe: ${e.javaClass.simpleName} (${e.message?.take(60)})"
        }
    }

    private fun readSmallFile(path: String): String? = try {
        val f = File(path)
        if (f.exists() && f.canRead()) f.readText().take(8000) else null
    } catch (_: Exception) {
        null
    }

    data class ShellOutput(val exitCode: Int, val stdout: String, val stderr: String)

    // Todo proceso pasa por ShellRunner: evalúa RootCommandPolicy y mata el proceso al vencer el
    // timeout. Antes se creaba con ProcessBuilder directamente y readText() podía colgarse.
    private suspend fun runSuCommand(cmd: String, timeoutMs: Long): ShellOutput =
        ShellRunner.run(cmd, elevated = true, timeoutMs = timeoutMs).toShellOutput()

    private suspend fun runCommand(cmd: String, timeoutMs: Long): ShellOutput =
        ShellRunner.run(cmd, elevated = false, timeoutMs = timeoutMs).toShellOutput()

    private fun ShellRunner.Output.toShellOutput() = ShellOutput(
        exitCode = exitCode,
        stdout = stdout,
        stderr = stderr.ifBlank { blockedReason ?: if (timedOut) "Timeout" else "" }
    )
}
