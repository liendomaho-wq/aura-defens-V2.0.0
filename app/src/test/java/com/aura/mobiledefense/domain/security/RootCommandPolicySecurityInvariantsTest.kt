package com.aura.mobiledefense.domain.security

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Invariantes de la política de privilegios.
 *
 * No son casos de uso: son propiedades que deben cumplirse siempre, aunque alguien añada mañana una
 * plantilla nueva a [RootCommandPolicy]. Si alguno falla, Aura ha dejado de ser una herramienta
 * defensiva o se ha abierto un camino de ejecución de código arbitrario.
 */
class RootCommandPolicySecurityInvariantsTest {

    private fun allowed(cmd: String, elevated: Boolean = true) =
        RootCommandPolicy.evaluate(cmd, elevated) is RootCommandPolicy.Decision.Allowed

    @Test
    fun `no trusted template mutates system state destructively`() {
        val dangerous = listOf(
            "setenforce 0",       // bajar SELinux a Permissive
            "mount -o remount",   // remontar /system
            "insmod", "rmmod",    // cargar/descargar módulos del kernel
            "chmod", "chown",     // permisos
            "dd if=", "mkfs",     // escritura en bloque
            "pm uninstall", "pm clear",
            "am start", "am broadcast",
            "settings put",
            "content insert", "content update"
        )
        dangerous.forEach { fragment ->
            assertTrue(
                "la política no puede permitir '$fragment'",
                !allowed(fragment)
            )
        }
    }

    @Test
    fun `free form text can never reach a shell beyond read only`() {
        val attacks = listOf(
            "id; rm -rf /data",
            "id && reboot",
            "grep x /proc/cpuinfo | tee /sdcard/x",
            "cat /proc/version > /data/local/tmp/x",
            "echo $(reboot)",
            "getprop `pm list packages`",
            "id\nreboot",
            "/system/bin/su -c id",
            "sh -c id",
            "eval id",
            "xargs -I{} id",
            "find / -exec id \\;",
            "find / -fprint /sdcard/x",
            "busybox sh",
            "magisk --install"
        )
        attacks.forEach { cmd ->
            assertTrue("no debería permitirse: '$cmd'", !allowed(cmd))
        }
    }

    @Test
    fun `every deny returns a human readable reason`() {
        val decision = RootCommandPolicy.evaluate("reboot", elevated = true)
        assertTrue(decision is RootCommandPolicy.Decision.Denied)
        val reason = (decision as RootCommandPolicy.Decision.Denied).reason
        assertTrue("el motivo debe explicarse en el panel", reason.length > 10)
    }

    @Test
    fun `empty and oversized input is rejected`() {
        assertTrue(!allowed(""))
        assertTrue(!allowed("   "))
        assertTrue(!allowed("id " + "a".repeat(500)))
    }

    @Test
    fun `the same command is evaluated identically with and without elevation`() {
        // La elevación no puede cambiar la decisión: solo cómo se lanza (su -c o sh -c).
        val cmds = listOf("id", "getenforce", "reboot", "ss -tulnpa")
        cmds.forEach { cmd ->
            val root = RootCommandPolicy.evaluate(cmd, elevated = true)::class.simpleName
            val user = RootCommandPolicy.evaluate(cmd, elevated = false)::class.simpleName
            assertTrue("'$cmd' decidió distinto según el modo", root == user)
        }
    }
}
