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
        // `setenforce 0` (SELinux a Permissive) queda fuera a propósito: Aura es una herramienta
        // defensiva y su propio motor de integridad penaliza Permissive. No puede existir un camino
        // firmado que reduzca la postura de seguridad del dispositivo.
        "setenforce 1",
        "setenforce 1 && getenforce"
        // Los DROPs de puertos administrativos viven en [administrativeDropTemplates]: una sola
        // fuente de verdad, sin duplicados.
    )

    /** Ports whose DROP rule Aura is allowed to create by itself. */
    private val administrativePorts = setOf(23, 5555, 6379, 27017)

    /**
     * Plantillas COMPLETAS de auto-mitigación: una entrada literal por puerto y forma, sin
     * matching por prefijo. Cualquier variación — orden de flags, flags extra, comillas raras,
     * redirecciones, encadenado — no casa y cae al resto de la política (o se deniega).
     * Antes se aceptaba por prefijo `iptables -i input -p tcp --dport ` + puerto en la lista,
     * algo frágil: este set cerrado lo elimina entero.
     */
    private val administrativeDropTemplates: Set<String> = buildSet {
        for (port in administrativePorts) {
            add("iptables -i input -p tcp --dport $port -j drop")
            add("iptables -c input -p tcp --dport $port -j drop 2>/dev/null || iptables -i input -p tcp --dport $port -j drop")
        }
    }

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

    // NB: las acciones estilo find (-exec/-delete/-ok) se validan a nivel de TOKEN más abajo.
    // Como substring rompían texto legítimo: "-ok" negaba el propio 'echo aura-ok'.
    private val forbiddenSubstrings = listOf(
        ">", "<", "`", "\$(", "\${", "/dev/block", "/dev/mem",
        "chmod 777", "chcon ", "/system/bin/sh", "/system/xbin/su",
        "run-as", "base64 -d"
    )

    /** Tokens exactos que ejecutan o borran (acciones de find y equivalentes). */
    private val dangerousActionTokens = setOf(
        "-exec", "-execdir", "--exec", "-ok", "-okdir", "-delete"
    )

    /**
     * Acciones de `find` que escriben en disco. `-fprint`, `-fprintf` y `-fls` crean ficheros y
     * `-execdir` / `-okdir` ejecutan binarios: la regla 3 los prohíbe igual que `-exec`/`-delete`.
     * Antes solo se miraban `-exec` y `-delete`, así que `find / -fprint /sdcard/x` pasaba.
     */
    private val findWriteActions = listOf(
        "-fprint", "-fprint0", "-fprintf", "-fls", "-delete", "-exec", "-execdir", "-ok", "-okdir"
    )

    /** Lo que cada motor le pide al kernel con root. Si no está aquí, no se ejecuta. */
    private val trustedInternalCommands = setOf(
        // NetworkForensicsEngine: sockets, vecinos ARP e iptables en modo lectura
        "ss -tulnpa 2>/dev/null || netstat -tulnpa 2>/dev/null; echo '---IP-NEIGH---'; " +
            "ip neigh show 2>/dev/null; echo '---IPTABLES---'; iptables -L -n 2>/dev/null",
        // BinaryCryptoEngine: inventario de paquetes de terceros
        "pm list packages -3 -f",
        // PrivilegeAndDeviceEngine: sondeo de root y auditoría del kernel
        "id && getenforce 2>/dev/null",
        "id && getenforce && uname -a && ps -A -Z",
        "uname -a; echo '---LSMOD---'; (lsmod 2>/dev/null || cat /proc/modules 2>/dev/null); " +
            "echo '---MOUNTS---'; mount; echo '---PROCS---'; ps -A -Z 2>/dev/null"
    )

    /**
     * Rutas del sistema que un comando de inspección no necesita leer ni escribir en crudo.
     * `/proc` y `/sys` quedan fuera a propósito: son la fuente real de la telemetría de Aura.
     */
    private val protectedPathPrefixes = listOf(
        "/system", "/vendor", "/product", "/oem", "/data/adb", "/data/system",
        "/data/data", "/data/misc", "/sbin", "/init.rc", "/dev/block", "/dev/mem",
        "/dev/kmem", "/dev/port", "/proc/kcore", "/proc/sysrq-trigger"
        // OJO: /proc/sys/kernel NO se bloquea — la anti-debug/anti-root de Aura lee
        // randomize_va_space y hosts. Escribir ahí sigue imposible: los binarios son de solo
        // lectura, las redirecciones están prohibidas y sysctl/setprop no están en la lista.
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

        // Comandos internos firmados por Aura: se comparan normalizados y literalmente, así que
        // un usuario no puede reutilizarlos con texto propio.
        if (trustedInternalCommands.contains(normalized)) {
            return Decision.Allowed(raw, elevated, readOnly = true)
        }

        // Whitelisted Aura mitigations (literal match) run even when elevate=true.
        if (mitigationTemplates.contains(normalized)) {
            return Decision.Allowed(raw, elevated, readOnly = false)
        }
        if (administrativeDropTemplates.contains(normalized)) {
            return Decision.Allowed(raw, elevated, readOnly = false)
        }

        forbiddenSubstrings.firstOrNull { raw.contains(it) }?.let {
            return Decision.Denied("Secuencia prohibida por la política de privilegios: '$it'.")
        }

        protectedPathPrefixes.firstOrNull { prefix ->
            raw.contains("$prefix/") || raw.endsWith(prefix)
        }?.let { prefix ->
            return Decision.Denied(
                "Ruta protegida por la política de privilegios: '$prefix'. " +
                    "Aura no lee ni escribe ahí, ni siquiera con root."
            )
        }

        val segments = raw.split(pipelineSeparators).map { it.trim() }.filter { it.isNotBlank() }
        if (segments.isEmpty()) {
            return Decision.Denied("No se detectó ningún ejecutable válido.")
        }

        for (segment in segments) {
            val tokens = segment.split(Regex("\\s+")).filter { it.isNotBlank() }
            val dangerous = tokens.drop(1).firstOrNull { dangerousActionTokens.contains(it.substringBefore("=").lowercase()) }
            if (dangerous != null) {
                return Decision.Denied("Acción '$dangerous' bloqueada: ejecuta o borra archivos.")
            }
            val binary = tokens.first().lowercase().substringAfterLast('/')
            if (tokens.size > 24) {
                return Decision.Denied("Segmento demasiado largo: '${segment.take(40)}…'.")
            }
            if (forbiddenTokens.contains(binary)) {
                return Decision.Denied(
                    "El binario '$binary' no está permitido: Aura solo ejecuta inspecciones de lectura y mitigaciones verificadas."
                )
            }
            // Regla 3: ninguna ruta protegida, ni como argumento ni tras redirección.
            protectedPathPrefixes.firstOrNull { prefix ->
                tokens.drop(1).any { token ->
                    val candidate = token.substringAfter("=", token).trim('"', '\'')
                    candidate == prefix || candidate.startsWith(prefix + "/")
                }
            }?.let { prefix ->
                return Decision.Denied(
                    "Ruta protegida por la política de privilegios: '$prefix'. " +
                        "Aura no lee ni escribe ahí, ni siquiera con root."
                )
            }

            when {
                readOnlyBinaries.contains(binary) -> {
                    if (binary == "find") {
                        val writeAction = tokens.firstOrNull { token ->
                            val flag = token.substringBefore("=")
                            findWriteActions.any { flag == it || flag.startsWith("$it ") }
                        }
                        if (writeAction != null) {
                            return Decision.Denied(
                                "'find' con '${writeAction.substringBefore("=")}' está bloqueado: " +
                                    "crea ficheros o ejecuta binarios."
                            )
                        }
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
