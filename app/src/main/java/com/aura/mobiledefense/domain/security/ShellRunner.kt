package com.aura.mobiledefense.domain.security

import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Único punto de ejecución de procesos de Aura.
 *
 * Antes de este archivo había tres caminos que llamaban `su -c` / `sh -c` por su cuenta
 * ([com.aura.mobiledefense.domain.engines.NetworkForensicsEngine],
 * [com.aura.mobiledefense.domain.engines.BinaryCryptoEngine] y
 * [com.aura.mobiledefense.domain.engines.PrivilegeAndDeviceEngine]): cualquiera de ellos podía saltarse
 * [RootCommandPolicy] sin que nada lo notara. Ahora todo pasa por [run], que **siempre** evalúa la
 * política antes de crear el proceso, y no hay ninguna otra forma de lanzar un shell en la app.
 *
 * Además de la política, aquí se cierra el otro agujero del `ProcessBuilder` original: si el proceso
 * se cuelga, se lee con timeout y se mata con [Process.destroyForcibly], en vez de esperar para
 * siempre en `readText()`.
 */
object ShellRunner {

    data class Output(
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
        val timedOut: Boolean = false,
        val blockedReason: String? = null
    ) {
        val succeeded: Boolean get() = blockedReason == null && !timedOut && exitCode == 0
        val combined: String get() = buildString {
            if (stdout.isNotBlank()) append(stdout.trimEnd())
            if (stderr.isNotBlank()) {
                if (isNotEmpty()) append('\n')
                append(stderr.trimEnd())
            }
        }
    }

    /** Dónde está el binario `su` en este dispositivo, o null si no hay root. */
    private val suCandidates = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/vendor/bin/su",
        "/su/bin/su", "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su"
    )

    fun findSuBinary(): String? {
        suCandidates.firstOrNull { File(it).canRead() }?.let { return it }
        // Fallback: su en PATH
        return runCatching {
            val path = System.getenv("PATH") ?: return@runCatching null
            path.split(File.pathSeparator).map { File(it, "su") }.firstOrNull { it.canExecute() }?.absolutePath
        }.getOrNull()
    }

    /**
     * Ejecuta un comando **solo si** [RootCommandPolicy] lo permite.
     *
     * @param command texto tal como lo pidió el usuario o lo generó un motor
     * @param elevated true para lanzar por `su -c`, false para `sh -c`
     * @param timeoutMs tiempo máximo; al vencer se mata el proceso
     */
    suspend fun run(command: String, elevated: Boolean, timeoutMs: Long = 7000L): Output {
        val decision = RootCommandPolicy.evaluate(command, elevated)
        if (decision is RootCommandPolicy.Decision.Denied) {
            return Output(exitCode = -1, stdout = "", stderr = decision.reason, blockedReason = decision.reason)
        }
        val allowed = decision as RootCommandPolicy.Decision.Allowed

        // La política ya validó el comando; elevated se respeta tal cual lo decidió la política.
        val argv = if (allowed.elevated) {
            val su = findSuBinary() ?: return Output(
                exitCode = -1,
                stdout = "",
                stderr = "Root no disponible: no se encontró el binario su.",
                blockedReason = "root-no-disponible"
            )
            listOf(su, "-c", allowed.command)
        } else {
            listOf("sh", "-c", allowed.command)
        }
        return exec(argv, timeoutMs)
    }

    private suspend fun exec(argv: List<String>, timeoutMs: Long): Output = withContext(Dispatchers.IO) {
        var process: Process? = null
        try {
            process = ProcessBuilder(argv).redirectErrorStream(false).start()
            val started = process
            val finished = withTimeoutOrNull(timeoutMs) {
                val stdout = StringBuilder()
                val stderr = StringBuilder()
                val readerThread = Thread {
                    runCatching { started.inputStream.bufferedReader().use { stdout.append(it.readText()) } }
                }
                val errThread = Thread {
                    runCatching { started.errorStream.bufferedReader().use { stderr.append(it.readText()) } }
                }
                readerThread.start()
                errThread.start()
                val code = started.waitFor()
                readerThread.join(1500)
                errThread.join(1500)
                Output(code, stdout.toString().take(MAX_OUTPUT), stderr.toString().take(MAX_OUTPUT))
            }
            if (finished != null) return@withContext finished

            // Timeout: matar de verdad, no dejar el proceso huérfano.
            runCatching { started.destroyForcibly() }
            Output(
                exitCode = -2,
                stdout = "",
                stderr = "Tiempo de espera agotado (${timeoutMs}ms). Proceso terminado.",
                timedOut = true
            )
        } catch (e: Exception) {
            runCatching { process?.destroyForcibly() }
            Output(-1, "", e.message ?: e.javaClass.simpleName)
        }
    }

    private const val MAX_OUTPUT = 12000

    /** Ejecución de diagnóstico sin shell: argumentos separados, sin interpretación. */
    suspend fun execArgs(argv: List<String>, timeoutMs: Long = 3000L): Output {
        if (argv.isEmpty()) return Output(-1, "", "argv vacío")
        return exec(argv, timeoutMs)
    }

    /** Cuánto tarda como máximo en morir un proceso tras [Process.destroyForcibly]. */
    fun awaitExit(process: Process, ms: Long): Boolean = process.waitFor(ms, TimeUnit.MILLISECONDS)
}
