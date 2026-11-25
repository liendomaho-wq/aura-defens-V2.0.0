package com.aura.mobiledefense

import android.content.Context
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import com.aura.mobiledefense.data.local.NyxDatabase
import com.aura.mobiledefense.data.model.AuraChatMessage
import com.aura.mobiledefense.data.model.ChatSpeaker
import com.aura.mobiledefense.data.model.ExecutionStepState
import com.aura.mobiledefense.data.model.FirewallPacketEventAction
import com.aura.mobiledefense.data.model.FirewallRuleType
import com.aura.mobiledefense.data.model.GeneratedPatch
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.data.model.SolutionExecutionStep
import com.aura.mobiledefense.data.model.VpnFirewallTelemetry
import com.aura.mobiledefense.domain.ai.NeuralIntentClassifier
import com.aura.mobiledefense.domain.vpn.PacketCodec
import com.aura.mobiledefense.domain.vpn.VpnFirewallManager
import com.aura.mobiledefense.ui.components.BlackConversationalPanel
import com.aura.mobiledefense.ui.theme.NyxCoreTheme
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class VpnFirewallAndBlackPanelTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun `packet codec parses IPv4 UDP DNS query and builds valid NXDOMAIN packet`() {
        // Minimal DNS wire query for "ads.doubleclick.net" (TXID=0x1234, RD=1, QDCOUNT=1)
        val qname = byteArrayOf(
            3, 'a'.code.toByte(), 'd'.code.toByte(), 's'.code.toByte(),
            11, 'd'.code.toByte(), 'o'.code.toByte(), 'u'.code.toByte(), 'b'.code.toByte(),
            'l'.code.toByte(), 'e'.code.toByte(), 'c'.code.toByte(), 'l'.code.toByte(),
            'i'.code.toByte(), 'c'.code.toByte(), 'k'.code.toByte(),
            3, 'n'.code.toByte(), 'e'.code.toByte(), 't'.code.toByte(),
            0
        )
        val dnsHeader = byteArrayOf(
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Standard query, RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00  // ARCOUNT=0
        )
        val qtypeQclass = byteArrayOf(0x00, 0x01, 0x00, 0x01)
        val dnsQuery = dnsHeader + qname + qtypeQclass

        val srcIp = byteArrayOf(10, 8, 0, 2)
        val dstIp = byteArrayOf(10, 8, 0, 1)
        val udpPacket = PacketCodec.buildIpv4UdpPacket(
            srcIp = srcIp,
            dstIp = dstIp,
            srcPort = 51234,
            dstPort = 53,
            payload = dnsQuery
        )

        val parsed = PacketCodec.parseIpv4Packet(udpPacket, udpPacket.size)
        assertNotNull(parsed)
        parsed!!
        assertEquals(4, parsed.version)
        assertEquals(PacketCodec.PROTO_UDP, parsed.protocol)
        assertEquals("10.8.0.2", parsed.srcIpString)
        assertEquals("10.8.0.1", parsed.dstIpString)
        assertEquals(51234, parsed.srcPort)
        assertEquals(53, parsed.dstPort)

        val extractedDomain = PacketCodec.extractDnsQueryDomain(
            udpPacket,
            parsed.payloadOffset,
            parsed.payloadLength
        )
        assertEquals("ads.doubleclick.net", extractedDomain)

        val nxDomain = PacketCodec.buildDnsNxDomainResponse(dnsQuery)
        assertEquals(0x81.toByte(), nxDomain[2])
        assertEquals(0x83.toByte(), nxDomain[3]) // RCODE=3 (NXDOMAIN)

        val responseIpPacket = PacketCodec.buildIpv4UdpPacket(
            srcIp = dstIp,
            dstIp = srcIp,
            srcPort = 53,
            dstPort = 51234,
            payload = nxDomain
        )
        val ipChecksum = ((responseIpPacket[10].toInt() and 0xFF) shl 8) or (responseIpPacket[11].toInt() and 0xFF)
        val udpChecksum = ((responseIpPacket[26].toInt() and 0xFF) shl 8) or (responseIpPacket[27].toInt() and 0xFF)
        assertTrue(ipChecksum != 0)
        assertTrue(udpChecksum != 0)
    }

    @Test
    fun `vpn firewall manager seeds Room rules, blocks domains and ports, and records telemetry`() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        VpnFirewallManager.ensureInitialized(context)

        val trackerDecision = VpnFirewallManager.evaluateDnsDomain("sub.doubleclick.net")
        assertFalse(trackerDecision.allowed)

        val safeDecision = VpnFirewallManager.evaluateDnsDomain("kernel.org")
        assertTrue(safeDecision.allowed)

        val adbPortDecision = VpnFirewallManager.evaluatePacketRoute("192.168.1.10", 5555)
        assertFalse(adbPortDecision.allowed)

        VpnFirewallManager.addBlockRule(
            context = context,
            pattern = "203.0.113.9",
            ruleType = FirewallRuleType.IP,
            reason = "IP sospechosa de prueba"
        )
        assertTrue(VpnFirewallManager.getBlockedIpRoutes().contains("203.0.113.9"))
        assertFalse(VpnFirewallManager.evaluatePacketRoute("203.0.113.9", 443).allowed)

        val beforeInspected = VpnFirewallManager.telemetry.value.packetsInspected
        VpnFirewallManager.recordPacketEvent(
            protocol = "DNS/UDP",
            destination = "sub.doubleclick.net",
            port = 53,
            action = FirewallPacketEventAction.BLOCKED,
            reason = "Tracker",
            bytesInDelta = 64L,
            bytesOutDelta = 64L,
            rttMs = 2L
        )
        val after = VpnFirewallManager.telemetry.value
        assertEquals(beforeInspected + 1, after.packetsInspected)
        assertTrue(after.recentEvents.firstOrNull()?.destination == "sub.doubleclick.net")

        VpnFirewallManager.removeRule(context, "203.0.113.9")
    }

    @Test
    fun `neural intent classifier routes VPN, firewall block, and live solution execution commands`() {
        val classifier = NeuralIntentClassifier()

        val vpnStart = classifier.classify("/vpn on", PrivilegeMode.USERLAND)
        assertEquals("VPN_START", vpnStart.plan.toolId)

        val vpnOff = classifier.classify("apaga la vpn local", PrivilegeMode.USERLAND)
        assertEquals("VPN_STOP", vpnOff.plan.toolId)

        val blockRule = classifier.classify("/block telemetry.example.com", PrivilegeMode.USERLAND)
        assertEquals("FIREWALL_BLOCK", blockRule.plan.toolId)
        assertEquals("telemetry.example.com", blockRule.plan.target)

        val execFix = classifier.classify("ejecuta las soluciones ahora", PrivilegeMode.USERLAND)
        assertEquals("EXECUTE_SOLUTIONS", execFix.plan.toolId)
    }

    @Test
    fun `black conversational panel renders Q&A, live execution steps, and triggers callbacks without UI buttons`() {
        var executedSolutionsCount = 0
        var toggledVpnCount = 0
        var whisperedPrompt: String? = null

        val messages = listOf(
            AuraChatMessage(
                speaker = ChatSpeaker.USER,
                text = "audita mi sistema y aplica soluciones"
            ),
            AuraChatMessage(
                speaker = ChatSpeaker.AURA,
                text = "Detecté puerto ADB 5555 expuesto y rastreadores DNS activos.",
                subtitle = "AUDIT · USERLAND",
                recommendations = listOf("Activa la VPN local con firewall DNS"),
                suggestions = listOf("ver telemetría VPN"),
                patches = listOf(
                    GeneratedPatch(
                        id = "p1",
                        title = "Bloquear ADB TCP 5555",
                        targetArtifact = "firewall_rules/5555",
                        severity = "HIGH",
                        rationale = "Evita acceso ADB remoto",
                        patchContent = "BLOCK PORT 5555"
                    )
                ),
                executionSteps = listOf(
                    SolutionExecutionStep(
                        stepNumber = 1,
                        title = "Aplicando regla firewall",
                        detail = "Puerto 5555 bloqueado en Room y TUN",
                        state = ExecutionStepState.DONE
                    )
                ),
                isExecuting = false,
                hasReport = true
            )
        )

        val pendingPatchMessage = listOf(
            AuraChatMessage(
                speaker = ChatSpeaker.AURA,
                text = "Solución lista para aplicar.",
                patches = listOf(
                    GeneratedPatch(
                        id = "p2",
                        title = "Mitigar tracker",
                        targetArtifact = "firewall_rules/tracker",
                        severity = "MEDIUM",
                        rationale = "Bloqueo DNS",
                        patchContent = "BLOCK DOMAIN tracker.test"
                    )
                ),
                suggestions = listOf("ver telemetría VPN")
            )
        )

        composeTestRule.setContent {
            NyxCoreTheme {
                BlackConversationalPanel(
                    messages = pendingPatchMessage + messages.first(),
                    activeScene = null,
                    vpnTelemetry = VpnFirewallTelemetry(isRunning = true, packetsInspected = 12, packetsBlocked = 3, activeRulesCount = 6),
                    privilegeMode = PrivilegeMode.USERLAND,
                    analyzingPhase = null,
                    errorMessage = null,
                    onExecuteWhisper = { whisperedPrompt = it },
                    onExecuteSolutionsNow = { executedSolutionsCount++ },
                    onToggleVpn = { toggledVpnCount++ },
                    onOpenReportAndPatches = {}
                )
            }
        }
        composeTestRule.waitForIdle()

        composeTestRule.onNodeWithTag("black_conversational_panel").assertIsDisplayed()
        composeTestRule.onNodeWithTag("vpn_quick_whisper").assertIsDisplayed().performClick()
        composeTestRule.onNodeWithTag("execute_solutions_whisper").assertIsDisplayed().performClick()
        composeTestRule.onNodeWithTag("whisper_prompt_0").assertIsDisplayed().performClick()
        composeTestRule.onNodeWithText("VPN TUN ACTIVA · 12 pkt (3 bloq.)").assertIsDisplayed()

        composeTestRule.waitForIdle()
        assertEquals(1, toggledVpnCount)
        assertEquals(1, executedSolutionsCount)
        assertEquals("ver telemetría VPN", whisperedPrompt)
    }
}
