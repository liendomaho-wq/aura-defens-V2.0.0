package com.aura.mobiledefense.domain.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regla 3 de [RootCommandPolicy]: "Arguments with relative/absolute write paths are rejected for
 * read-only binaries" estaba documentada pero **no implementada**. Estas pruebas fijan lo que la
 * regla dice de verdad, y también que [ShellRunner] no sea una puerta trasera.
 */
class RootCommandPolicyWritePathTest {

    private fun allowed(cmd: String, elevated: Boolean = true) =
        RootCommandPolicy.evaluate(cmd, elevated) is RootCommandPolicy.Decision.Allowed

    private fun denied(cmd: String, elevated: Boolean = true) =
        RootCommandPolicy.evaluate(cmd, elevated) is RootCommandPolicy.Decision.Denied

    // ── find: acciones que escriben ───────────────────────────────────────────────────────────

    @Test
    fun `find with write actions is denied`() {
        assertTrue(denied("find / -fprint /sdcard/out.txt"))
        assertTrue(denied("find /data -fprintf /sdcard/log.txt %p"))
        assertTrue(denied("find / -fls /sdcard/ls.txt"))
        assertTrue(denied("find / -execdir id \\;"))
        assertTrue(denied("find / -okdir id \\;"))
        assertTrue(denied("find / -delete"))
        assertTrue(denied("find / -exec id \\;"))
        assertTrue(denied("find / -fprint0 /sdcard/out"))
    }

    @Test
    fun `find without write actions is still allowed`() {
        assertTrue(allowed("find /proc -name status -maxdepth 2"))
        assertTrue(allowed("find /data/local/tmp -type f -name '*.log'"))
    }

    // ── rutas protegidas ─────────────────────────────────────────────────────────────────────

    @Test
    fun `protected system paths are denied`() {
        assertTrue(denied("cat /system/build.prop"))
        assertTrue(denied("ls /data/adb/modules"))
        assertTrue(denied("ls -la /vendor/lib64"))
        assertTrue(denied("stat /data/system/packages.xml"))
        assertTrue(denied("cat /dev/block/mmcblk0"))
        assertTrue(denied("cat /proc/kcore"))
        assertTrue(denied("ls /data/data/com.banco.movil"))
        assertTrue(denied("cat /oem/etc/config"))
    }

    @Test
    fun `proc and sys stay readable because telemetry depends on them`() {
        assertTrue(allowed("cat /proc/self/status"))
        assertTrue(allowed("cat /proc/modules"))
        assertTrue(allowed("cat /sys/class/net/wlan0/address"))
        assertTrue(allowed("cat /proc/sys/kernel/randomize_va_space"))
    }

    @Test
    fun `protected path is denied even inside a pipeline`() {
        assertTrue(denied("id | cat /system/build.prop"))
        assertTrue(denied("cat /system/build.prop && id"))
    }

    // ── contrato de ShellRunner ──────────────────────────────────────────────────────────────

    @Test
    fun `shell runner refuses a command the policy denies without starting a process`() {
        val result = kotlinx.coroutines.runBlocking {
            ShellRunner.run("rm -rf /data/local/tmp/x", elevated = true, timeoutMs = 1000)
        }
        assertFalse("un comando denegado nunca debe ejecutarse", result.succeeded)
        assertTrue(result.blockedReason != null)
        assertTrue(result.stdout.isEmpty())
    }

    @Test
    fun `shell runner runs an allowed command in userland`() {
        val result = kotlinx.coroutines.runBlocking {
            ShellRunner.run("echo aura-ok", elevated = false, timeoutMs = 5000)
        }
        assertTrue(result.combined.contains("aura-ok"))
    }

    @Test
    fun `shell runner kills a hung process instead of waiting forever`() {
        // `cat` sin argumentos en un pipe abierto se queda esperando: es el proceso colgado típico.
        val start = System.currentTimeMillis()
        val result = kotlinx.coroutines.runBlocking {
            ShellRunner.run("cat", elevated = false, timeoutMs = 600)
        }
        val elapsed = System.currentTimeMillis() - start
        assertTrue("no debe colgarse: ${elapsed}ms", elapsed < 5000)
        assertTrue("debe cortarse por timeout", result.timedOut)
    }
}
