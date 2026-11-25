package com.aura.mobiledefense.domain.ai.llm

/**
 * Validates and normalises the `target` a language model proposes.
 *
 * A model can be talked into returning almost anything. Every string that will later reach an
 * engine — and, for ROOT_SHELL, `su -c` — passes through here first. Rules are deliberately
 * stricter than what the engines accept: a rejected target costs one heuristic fallback, an
 * accepted bad target costs a privilege boundary.
 */
object TargetValidator {

    private val hostname = Regex("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
    private val ipv4 = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$")
    private val port = Regex("^\\d{1,5}$")
    private val packageName = Regex("^[a-z][a-z0-9_]*(\\.[a-z0-9_]+){1,}$")
    private val ipv6 = Regex("^[0-9a-fA-F:]{3,45}$")

    private val shellMetachars = listOf(";", "|", "&", ">", "<", "`", "$", "\\", "\n", "\r", "\u0000")

    private val forbiddenShellWords = listOf(
        "rm ", "rmdir", "mkfs", "dd ", "reboot", "shutdown", "chmod", "chown", "wget", "curl",
        "nc ", "ncat", "telnet", "python", "perl", "ruby", "node ", "bash", "sh -c", "eval",
        "exec", "xargs", "base64 -d", "pm uninstall", "pm install", "pm clear", "am start",
        "am broadcast", "settings put", "setprop", "resetprop", "magisk", "insmod", "rmmod",
        "/dev/block", "/dev/mem", "/system/xbin/su", "run-as"
    )

    fun normalize(raw: String, kind: AuraToolCatalog.TargetKind): String {
        var value = raw.trim()
            .removePrefix("http://")
            .removePrefix("https://")
        // Drop credentials, path, query and fragment: only the host matters for the engines.
        value = value.substringBefore('/')
            .substringBefore('?')
            .substringBefore('#')
            .substringAfter('@')
        if (value.count { it == ':' } == 1) value = value.substringBefore(':')
        value = value.trim().removeSuffix(".")
        return when (kind) {
            AuraToolCatalog.TargetKind.NONE -> ""
            else -> value
        }
    }

    fun isValid(target: String, kind: AuraToolCatalog.TargetKind): Boolean {
        if (kind == AuraToolCatalog.TargetKind.NONE) return true
        if (target.isBlank()) return !requiresNonBlank(kind)

        if (shellMetachars.any { target.contains(it) }) return false
        if (target.length > 253) return false

        return when (kind) {
            AuraToolCatalog.TargetKind.HOST -> isHost(target)
            AuraToolCatalog.TargetKind.PATTERN ->
                isHost(target) || isIp(target) || port.matches(target) && target.toInt() in 1..65535
            AuraToolCatalog.TargetKind.FREETEXT -> isSafeFreeText(target)
            AuraToolCatalog.TargetKind.NONE -> true
        }
    }

    private fun requiresNonBlank(kind: AuraToolCatalog.TargetKind): Boolean =
        kind == AuraToolCatalog.TargetKind.HOST

    fun isIp(value: String): Boolean {
        val m = ipv4.find(value) ?: return false
        return m.groupValues.drop(1).all { it.toIntOrNull() in 0..255 }
    }

    fun isIpv6(value: String): Boolean = value.contains(':') && ipv6.matches(value)

    fun isHost(value: String): Boolean {
        if (isIp(value) || isIpv6(value)) return true
        if (!hostname.matches(value)) return false
        if (value.contains("..") || value.startsWith("-") || value.endsWith("-")) return false
        // Require at least one dot or a well-known single label; reject "abc" as a host.
        return value.contains('.') || value.equals("localhost", ignoreCase = true)
    }

    fun isPackageName(value: String): Boolean = packageName.matches(value)

    /**
     * Free text is the only kind that can reach `su -c` (ROOT_SHELL) or the crypto analyzer.
     * Reject anything that looks like an attempt at command chaining or a destructive binary.
     */
    fun isSafeFreeText(value: String): Boolean {
        if (value.length > 400) return false
        if (shellMetachars.any { value.contains(it) }) return false
        val lower = value.lowercase()
        return forbiddenShellWords.none { lower.contains(it) }
    }
}
