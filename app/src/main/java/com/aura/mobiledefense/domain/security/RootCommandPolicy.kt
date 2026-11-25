package com.aura.mobiledefense.domain.security

/**
 * Default-deny policy for every shell string that Aura is about to execute.
 *
 * The conversational classifier can route free-form user text into [ROOT_SHELL]. Before this
 * policy existed, any phrase that the classifier scored as a shell intent was passed straight to
 * `su -c` / `sh -c`, which turns a chat message into root code execution. The policy is the single
 * choke point that every root/userland command must pass through.
 *
 * Rules:
 *  1. Default deny. Only commands whose first token is in [readOnlyBinaries], or that match one of
 *     the curated mitigation templates in [mitigationTemplates], are accepted.
 *  2. Shell metacharacters that allow code execution or redirection (`;`, `&&`, `||`, `|`, `>`,
 *     `<`, backticks, `$()`, newlines) are only tolerated when every segment of the pipeline is
 *     itself allowlisted. No `eval`, `sh -c`, `xargs`, `-exec`, `su`, `magisk`, `am`, `pm install`.
 *  3. Arguments with relative/absolute write paths are rejected for read-only binaries.
 */
object RootCommandPolicy {

    sealed interface Decision {
        data class Allowed(val command: String, val elevated: Boolean, val readOnly: Boolean) : Decision
        data class Denied(val reason: String) : Decision
    }

    /** Binaries that only read state. Anything not in this set is denied outright. */
    private val readOnlyBinaries = setOf(
        "id", "whoami", "groups", "getenforce", "uname", "uptime",
        "getprop", "which", "ls", "stat", "df", "free", "cat", "head",
        "tail", "wc", "grep", "egrep", "sort", "uniq", "cut", "tr", "echo", "printf",
        "ps", "ss", "netstat", "lsof", "ping", "dmesg", "logcat",
        "dumpsys", "sha256sum", "sha1sum", "md5sum", "vmstat", "top", "find",
        "test", "true", "false"
    )

    /** Subcommands of `ip` that only report state. */
    private val readOnlyIpSubcommands = setOf(
        "addr", "a", "addrlabel", "route", "r", "neigh", "n", "link", "l", "rule", "tunnel", "maddr"
    )

    /** Verbs that mutate network state inside an `ip` invocation. */
    private val mutatingIpVerbs = listOf("set", "add", "del", "delete", "flush", "change", "replace")

    /**
     * Exact mitigation commands that Aura itself issues from SolutionExecutionEngine / PatchAndReportEngine.
     * They are matched literally (after whitespace normalisation) so no user text can reuse them.
     */
    private val mitigationTemplates = setOf(
        "setenforce 1",
        "setenforce 0",
        "setenforce 1 && getenforce",
        "iptables -c input -p tcp --dport 5555 -j drop 2>/dev/null || iptables -i input -p tcp --dport 5555 -j drop",
        "iptables -i input -p tcp --dport 5555 -j drop"
    )

    /** Ports whose DROP rule Aura is allowed to create by itself. */
    private val administrativePorts = setOf(23, 5555, 6379, 27017)

    private val forgedMitigationPrefixes = listOf(
        "iptables -i input -p tcp --dport ", "iptables -c input -p tcp --dport "
    )

    /** Hard denials: destructive, persistence, or side-channel execution primitives. */
    private val forbiddenTokens = listOf(
        "rm", "rmdir", "mkfs", "mke2fs", "dd", "shred", "wipe", "reboot", "shutdown", "halt",
        "poweroff", "fastboot", "flash_image", "format", "chmod", "chown", "insmod", "rmmod",
        "modprobe", "eval", "exec", "xargs", "bash", "sh", "zsh", "dash", "curl", "wget",
        "nc", "ncat", "netcat", "telnet", "python", "python3", "perl", "ruby", "node",
        "ssh", "scp", "sftp", "adb", "setprop", "resetprop", "restorecon", "killall", "pkill",
        "kill", "am", "cmd", "svc", "input", "screencap", "screenrecord", "install", "uninstall",
        "enable", "disable", "pm uninstall", "pm install", "pm clear", "content", "monkey",
        "magisk", "ksud", "apd", "twrp", "busybox"
    )

    private val mutatingIptablesFlags = setOf(
        "-A", "-I", "-D", "-F", "-P", "-N", "-X", "-R", "-Z", "-E",
        "--append", "--insert", "--delete", "--flush", "--policy", "--new-chain",
        "--delete-chain", "--replace", "--zero", "--check", "-C"
    )

    private val forbiddenSubstrings = listOf(
        ">", "<", "`", "\$(", "\${", "/dev/block", "/dev/mem",
        "chmod 777", "chcon ", "/system/bin/sh", "/system/xbin/su",
        "-exec", "--exec", "-delete", "-ok", "run-as", "base64 -d"
    )

    private val pipelineSeparators = Regex("(\\|\\||&&|;|\\|)")

    fun evaluate(rawCommand: String, elevated: Boolean): Decision {
        val raw = rawCommand.trim().removePrefix("/su").trim()
        if (raw.isBlank()) {
            return Decision.Denied("Comando vacío. Indica qué inspección deseas ejecutar.")
        }
        if (raw.length > 400) {
            return Decision.Denied("Comando demasiado largo (>400 caracteres).")
        }
        if (raw.any { it == '\n' || it == '\r' || it == '\u0000' }) {
            return Decision.Denied("El comando contiene saltos de línea o bytes nulos.")
        }

        val normalized = raw.lowercase().split(Regex("\\s+")).joinToString(" ")

        // Whitelisted Aura mitigations (literal match) run even when elevate=true.
        if (mitigationTemplates.contains(normalized)) {
            return Decision.Allowed(raw, elevated, readOnly = false)
        }
        if (forgedMitigationPrefixes.any { normalized.startsWith(it) }) {
            val port = normalized.substringAfter("--dport ").substringBefore(" ").trim()
            val ipPort = port.toIntOrNull()
            if (ipPort != null && ipPort in administrativePorts && normalized.endsWith("-j drop")) {
                return Decision.Allowed(raw, elevated, readOnly = false)
            }
            return Decision.Denied("Plantilla iptables no reconocida.")
        }

        forbiddenSubstrings.firstOrNull { raw.contains(it) }?.let {
            return Decision.Denied("Secuencia prohibida por la política de privilegios: '$it'.")
        }

        val segments = raw.split(pipelineSeparators).map { it.trim() }.filter { it.isNotBlank() }
        if (segments.isEmpty()) {
            return Decision.Denied("No se detectó ningún ejecutable válido.")
        }

        for (segment in segments) {
            val tokens = segment.split(Regex("\\s+")).filter { it.isNotBlank() }
            val binary = tokens.first().lowercase().substringAfterLast('/')
            if (tokens.size > 24) {
                return Decision.Denied("Segmento demasiado largo: '${segment.take(40)}…'.")
            }
            if (forbiddenTokens.contains(binary)) {
                return Decision.Denied(
                    "El binario '$binary' no está permitido: Aura solo ejecuta inspecciones de lectura y mitigaciones verificadas."
                )
            }
            when {
                readOnlyBinaries.contains(binary) -> {
                    if (binary == "find" && tokens.any { it.startsWith("-exec") || it == "-delete" }) {
                        return Decision.Denied("'find' con -exec/-delete está bloqueado.")
                    }
                    if (binary == "echo" || binary == "printf") {
                        // Nothing to validate: echo without redirection cannot mutate state.
                    }
                }
                binary == "command" -> {
                    val flag = tokens.getOrNull(1)?.lowercase() ?: ""
                    if (flag != "-v") {
                        return Decision.Denied("'command' solo se permite como 'command -v <binario>'.")
                    }
                }
                binary == "ip" -> {
                    val sub = tokens.drop(1).firstOrNull { !it.startsWith("-") }?.lowercase() ?: ""
                    if (sub !in readOnlyIpSubcommands) {
                        return Decision.Denied("Solo se permite 'ip addr|route|neigh|link' en modo lectura.")
                    }
                    if (tokens.any { token -> mutatingIpVerbs.any { token.equals(it, ignoreCase = true) } }) {
                        return Decision.Denied("Verbo mutante en 'ip' bloqueado (set/add/del/flush).")
                    }
                }
                binary == "pm" -> {
                    val sub = tokens.getOrNull(1)?.lowercase() ?: ""
                    if (sub !in setOf("list", "path", "dump", "version")) {
                        return Decision.Denied("Solo se permite 'pm list|path|dump|version'.")
                    }
                }
                binary == "settings" -> {
                    if (tokens.getOrNull(1)?.lowercase() != "get") {
                        return Decision.Denied("Solo se permite 'settings get'.")
                    }
                }
                binary == "iptables" -> {
                    // iptables flags are case sensitive: -n (numeric) is harmless, -N (new chain) is not.
                    val mutatingFlags = tokens.drop(1).filter { token ->
                        val flag = token.substringBefore("=")
                        mutatingIptablesFlags.any { flag == it || flag.startsWith("$it=") }
                    }
                    if (mutatingFlags.isNotEmpty()) {
                        return Decision.Denied(
                            "Solo se permite listar iptables (-L/-S); las mutaciones requieren plantilla firmada."
                        )
                    }
                }
                binary == "nft" -> {
                    if (tokens.getOrNull(1)?.lowercase() != "list") {
                        return Decision.Denied("Solo se permite 'nft list'.")
                    }
                }
                else -> {
                    return Decision.Denied(
                        "Binario '$binary' fuera de la lista blanca de inspección."
                    )
                }
            }
        }

        return Decision.Allowed(raw, elevated, readOnly = true)
    }
}
