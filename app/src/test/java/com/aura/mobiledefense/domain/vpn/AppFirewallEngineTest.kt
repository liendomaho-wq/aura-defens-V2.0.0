package com.aura.mobiledefense.domain.vpn

import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Firewall por app: lo que se puede fijar sin un kernel de verdad.
 *
 * El DROP real por uid-owner requiere root y un dispositivo real; aquí se fija el resto del
 * contrato: los comandos firmados exactos, las negativas de seguridad (auto-bloqueo, paquete
 * vacío/inexistente) y la atribución best-effort que degrada a null en vez de fallar.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AppFirewallEngineTest {

    private val context: android.content.Context get() = ApplicationProvider.getApplicationContext()

    @Test
    fun `signed commands are exact, not templated loosely`() {
        assertEquals(
            "iptables -C OUTPUT -m owner --uid-owner 10042 -j DROP 2>/dev/null || iptables -I OUTPUT -m owner --uid-owner 10042 -j DROP",
            AppFirewallEngine.checkOrInsertCommand(10042)
        )
        assertEquals(
            "iptables -D OUTPUT -m owner --uid-owner 10042 -j DROP",
            AppFirewallEngine.deleteCommand(10042)
        )
    }

    @Test
    fun `aura can never block itself`() = runBlocking {
        val result = AppFirewallEngine.setAppBlocked(context, context.packageName, blocked = true)
        assertFalse(result.enforcedAtKernel)
        assertTrue(result.message.contains("sí misma"))
    }

    @Test
    fun `blank package is rejected`() = runBlocking {
        val result = AppFirewallEngine.setAppBlocked(context, "   ", blocked = true)
        assertFalse(result.enforcedAtKernel)
        assertTrue(result.uid == null)
    }

    @Test
    fun `unknown package is rejected honestly instead of fabricating a uid`() = runBlocking {
        val result = AppFirewallEngine.setAppBlocked(context, "com.no.existe.en.este.dispositivo", blocked = true)
        assertFalse(result.enforcedAtKernel)
        assertNull(result.uid)
        assertTrue(result.message.contains("no está instalado"))
    }

    @Test
    fun `owner uid attribution degrades to null when the platform hides it`() {
        val local = java.net.InetSocketAddress("10.8.0.2", 40123)
        val remote = java.net.InetSocketAddress("93.184.216.34", 443)
        // En JVM/Robolectric la API oculta no existe: debe devolver null, nunca lanzar.
        assertNull(AppFirewallEngine.attributeOwnerUidBestEffort(context, 6, local, remote))
    }
}
