package com.aura.mobiledefense.domain.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import com.aura.mobiledefense.data.local.FirewallRuleEntity
import com.aura.mobiledefense.data.local.ForensicSessionDao
import com.aura.mobiledefense.data.local.NyxDatabase
import com.aura.mobiledefense.data.model.FirewallPacketEvent
import com.aura.mobiledefense.data.model.FirewallPacketEventAction
import com.aura.mobiledefense.data.model.FirewallRuleType
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.data.model.ToolExecutionResult
import com.aura.mobiledefense.data.model.VisualTopologyKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong

data class RuleEvaluationDecision(
    val allowed: Boolean,
    val reason: String
)

/**
 * Centralized real-time state, Room-persisted rules, and packet telemetry hub
 * for Aura Mobile Defense's Local VPN + Firewall.
 */
object VpnFirewallManager {

    private val _telemetry = MutableStateFlow(VpnFirewallTelemetryDefaults.initial())
    val telemetry: StateFlow<com.aura.mobiledefense.data.model.VpnFirewallTelemetry> = _telemetry.asStateFlow()

    private val _rules = MutableStateFlow<List<FirewallRuleEntity>>(emptyList())
    val rules: StateFlow<List<FirewallRuleEntity>> = _rules.asStateFlow()

    private val inspectedCount = AtomicLong(0L)
    private val allowedCount = AtomicLong(0L)
    private val blockedCount = AtomicLong(0L)
    private val bytesInCount = AtomicLong(0L)
    private val bytesOutCount = AtomicLong(0L)
    private val recentBuffer = ArrayDeque<FirewallPacketEvent>(64)

    @Volatile
    private var vpnRunning = false

    @Volatile
    private var startedAt = 0L

    @Volatile
    private var lastDnsRtt = 0L

    suspend fun ensureInitialized(context: Context) = withContext(Dispatchers.IO) {
        val dao = NyxDatabase.getInstance(context).forensicSessionDao()
        if (dao.countFirewallRules() == 0) {
            val now = System.currentTimeMillis()
            val seedRules = listOf(
                FirewallRuleEntity(
                    id = "fw_port_adb",
                    pattern = "5555",
                    ruleType = FirewallRuleType.PORT.name,
                    action = "BLOCK",
                    reason = "Bloqueo de puerto ADB TCP (5555) expuesto",
                    enabled = true,
                    createdAt = now
                ),
                FirewallRuleEntity(
                    id = "fw_port_telnet",
                    pattern = "23",
                    ruleType = FirewallRuleType.PORT.name,
                    action = "BLOCK",
                    reason = "Bloqueo de Telnet en texto claro (23)",
                    enabled = true,
                    createdAt = now
                ),
                FirewallRuleEntity(
                    id = "fw_port_redis",
                    pattern = "6379",
                    ruleType = FirewallRuleType.PORT.name,
                    action = "BLOCK",
                    reason = "Bloqueo de Redis sin cifrado (6379)",
                    enabled = true,
                    createdAt = now
                ),
                FirewallRuleEntity(
                    id = "fw_dom_doubleclick",
                    pattern = "doubleclick.net",
                    ruleType = FirewallRuleType.DOMAIN.name,
                    action = "BLOCK",
                    reason = "Telemetría/rastreador publicitario de terceros",
                    enabled = true,
                    createdAt = now
                ),
                FirewallRuleEntity(
                    id = "fw_dom_appmeasurement",
                    pattern = "app-measurement.com",
                    ruleType = FirewallRuleType.DOMAIN.name,
                    action = "BLOCK",
                    reason = "Telemetría de rastreo en segundo plano",
                    enabled = true,
                    createdAt = now
                ),
                FirewallRuleEntity(
                    id = "fw_dom_graph_fb",
                    pattern = "pixel.facebook.com",
                    ruleType = FirewallRuleType.DOMAIN.name,
                    action = "BLOCK",
                    reason = "Tracker de perfilado entre aplicaciones",
                    enabled = true,
                    createdAt = now
                )
            )
            dao.upsertFirewallRules(seedRules)
        }
        refreshRulesFromDao(dao)
    }

    suspend fun refreshRulesFromDao(dao: ForensicSessionDao) = withContext(Dispatchers.IO) {
        _rules.value = dao.getEnabledFirewallRules()
        publishTelemetry()
    }

    suspend fun addBlockRule(
        context: Context,
        pattern: String,
        ruleType: FirewallRuleType,
        reason: String
    ): FirewallRuleEntity = withContext(Dispatchers.IO) {
        ensureInitialized(context)
        val cleanPattern = pattern.trim().lowercase()
            .removePrefix("https://")
            .removePrefix("http://")
            .substringBefore("/")
        val dao = NyxDatabase.getInstance(context).forensicSessionDao()
        val rule = FirewallRuleEntity(
            id = "fw_${UUID.randomUUID().toString().take(8)}",
            pattern = cleanPattern,
            ruleType = ruleType.name,
            action = "BLOCK",
            reason = reason,
            enabled = true,
            createdAt = System.currentTimeMillis()
        )
        dao.upsertFirewallRule(rule)
        refreshRulesFromDao(dao)
        if (vpnRunning) {
            sendVpnCommand(context, AuraLocalVpnService.ACTION_RELOAD)
        }
        rule
    }

    suspend fun removeRule(context: Context, patternOrId: String) = withContext(Dispatchers.IO) {
        val dao = NyxDatabase.getInstance(context).forensicSessionDao()
        val clean = patternOrId.trim().lowercase()
        dao.deleteFirewallRuleByPatternOrId(clean)
        refreshRulesFromDao(dao)
        if (vpnRunning) {
            sendVpnCommand(context, AuraLocalVpnService.ACTION_RELOAD)
        }
    }

    fun getBlockedIpRoutes(): List<String> {
        val ipv4Regex = Regex("^\\d{1,3}(?:\\.\\d{1,3}){3}$")
        return _rules.value
            .filter { it.enabled && it.action == "BLOCK" && it.ruleType == FirewallRuleType.IP.name }
            .map { it.pattern }
            .filter { ipv4Regex.matches(it) }
    }

    /**
     * Dominios de DNS cifrado (DoH/DoT). Si se permite, una app puede saltarse el firewall de
     * dominios resolviendo por su cuenta. Es una regla de la política, no una ocurrencia del código.
     */
    private val encryptedDnsDomains = setOf(
        "dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "dns.quad9.net",
        "doh.opendns.com", "dns.adguard-dns.com", "dns.nextdns.io", "doh.pub", "dns.alidns.com"
    )

    @Volatile
    private var blockEncryptedDns = false

    fun setEncryptedDnsPolicy(blocked: Boolean) {
        blockEncryptedDns = blocked
    }

    fun isEncryptedDnsPolicyEnabled(): Boolean = blockEncryptedDns

    fun isEncryptedDnsDomain(domain: String): Boolean =
        encryptedDnsDomains.any { domain == it || domain.endsWith(".$it") }

    /**
     * Decide si un dominio se permite. Se usa tanto para el DNS interceptado como para el SNI del
     * TLS, así que cubre a las apps que resuelven por su cuenta y a los túneles que ignoran el DNS
     * del sistema.
     */
    fun evaluateDnsDomain(domain: String): RuleEvaluationDecision {
        val lower = domain.trim().lowercase().trimEnd('.')
        val matched = _rules.value.firstOrNull { rule ->
            rule.enabled && rule.action == "BLOCK" && rule.ruleType == FirewallRuleType.DOMAIN.name &&
                (lower == rule.pattern || lower.endsWith(".${rule.pattern}"))
        }
        if (matched != null) {
            return RuleEvaluationDecision(allowed = false, reason = matched.reason)
        }
        if (blockEncryptedDns && isEncryptedDnsDomain(lower)) {
            return RuleEvaluationDecision(
                allowed = false,
                reason = "DNS cifrado (DoH/DoT) bloqueado: evade el firewall de dominios"
            )
        }
        return RuleEvaluationDecision(allowed = true, reason = "DNS permitido")
    }

    /** Guarda la asociación dominio→IP observada en el DNS, para poder bloquearla en el túnel. */
    fun recordObservedDomain(domain: String, ip: String) {
        DomainSinkhole.rememberResolution(domain, listOf(ip), blocked = !evaluateDnsDomain(domain).allowed)
    }

    fun evaluatePacketRoute(dstIp: String, dstPort: Int): RuleEvaluationDecision {
        val matchedIp = _rules.value.firstOrNull { rule ->
            rule.enabled && rule.action == "BLOCK" && rule.ruleType == FirewallRuleType.IP.name && rule.pattern == dstIp
        }
        if (matchedIp != null) {
            return RuleEvaluationDecision(allowed = false, reason = matchedIp.reason)
        }
        val matchedPort = _rules.value.firstOrNull { rule ->
            rule.enabled && rule.action == "BLOCK" && rule.ruleType == FirewallRuleType.PORT.name &&
                rule.pattern.toIntOrNull() == dstPort
        }
        if (matchedPort != null) {
            return RuleEvaluationDecision(allowed = false, reason = matchedPort.reason)
        }
        val learned = DomainSinkhole.isBlockedIp(dstIp)
        if (learned.blocked) {
            return RuleEvaluationDecision(allowed = false, reason = learned.reason)
        }
        return RuleEvaluationDecision(allowed = true, reason = "Tráfico permitido")
    }

    fun onVpnStateChanged(running: Boolean) {
        vpnRunning = running
        startedAt = if (running) System.currentTimeMillis() else 0L
        publishTelemetry()
    }

    fun recordPacketEvent(
        protocol: String,
        destination: String,
        port: Int,
        action: FirewallPacketEventAction,
        reason: String,
        bytesInDelta: Long,
        bytesOutDelta: Long,
        rttMs: Long = 0L
    ) {
        inspectedCount.incrementAndGet()
        if (action == FirewallPacketEventAction.ALLOWED) {
            allowedCount.incrementAndGet()
        } else {
            blockedCount.incrementAndGet()
        }
        if (bytesInDelta > 0) bytesInCount.addAndGet(bytesInDelta)
        if (bytesOutDelta > 0) bytesOutCount.addAndGet(bytesOutDelta)
        if (rttMs > 0) lastDnsRtt = rttMs

        synchronized(recentBuffer) {
            recentBuffer.addFirst(
                FirewallPacketEvent(
                    protocol = protocol,
                    destination = destination,
                    port = port,
                    action = action,
                    reason = reason,
                    rttMs = rttMs
                )
            )
            while (recentBuffer.size > 40) {
                recentBuffer.removeLast()
            }
        }
        publishTelemetry()
    }

    fun startLocalVpnIfPrepared(context: Context): Boolean {
        val prepareIntent = VpnService.prepare(context)
        if (prepareIntent != null) return false
        sendVpnCommand(context, AuraLocalVpnService.ACTION_START)
        return true
    }

    fun stopLocalVpn(context: Context) {
        sendVpnCommand(context, AuraLocalVpnService.ACTION_STOP)
    }

    fun sendVpnCommand(context: Context, action: String) {
        val intent = Intent(context, AuraLocalVpnService::class.java).apply {
            this.action = action
        }
        if (action == AuraLocalVpnService.ACTION_START && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
    }

    fun buildTelemetryReport(mode: PrivilegeMode): ToolExecutionResult {
        val t = _telemetry.value
        val activeRules = _rules.value
        val sb = StringBuilder()
        sb.appendLine("=== TELEMETRÍA REAL DE VPN LOCAL & FIREWALL AURA ===")
        sb.appendLine("Estado VPN TUN: ${if (t.isRunning) "ACTIVA (En ejecución real)" else "DETENIDA"}")
        sb.appendLine("Interfaz virtual TUN: ${t.tunAddress} | DNS Upstream: ${t.upstreamDns}")
        sb.appendLine("Paquetes inspeccionados: ${t.packetsInspected} (Permitidos: ${t.packetsAllowed} | Bloqueados: ${t.packetsBlocked})")
        sb.appendLine("Tráfico TUN: RX ${t.bytesIn} B / TX ${t.bytesOut} B | Última latencia DNS: ${t.lastDnsRttMs} ms")
        sb.appendLine("Reglas de Firewall activas (${activeRules.size}):")
        activeRules.take(12).forEach { r ->
            sb.appendLine("  • [${r.ruleType}] ${r.pattern} -> ${r.action} (${r.reason})")
        }
        if (t.recentEvents.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("--- Últimos eventos reales de paquetes ---")
            t.recentEvents.take(10).forEach { ev ->
                sb.appendLine("  [${ev.action.name}] ${ev.protocol} ${ev.destination}:${ev.port} (${ev.rttMs}ms) — ${ev.reason}")
            }
        }
        val spectrum = listOf(
            if (t.isRunning) 0.9f else 0.25f,
            (t.packetsBlocked.coerceAtMost(20) / 20f).coerceIn(0.15f, 1f),
            (t.lastDnsRttMs.coerceAtMost(200) / 200f).coerceIn(0.15f, 1f),
            (activeRules.size.coerceAtMost(15) / 15f).coerceIn(0.2f, 1f)
        )
        return ToolExecutionResult(
            toolId = "VPN_TELEMETRY",
            target = "Aura Local VPN (${t.tunAddress})",
            privilegeUsed = mode,
            rawTelemetry = sb.toString(),
            measuredSpectrum = spectrum,
            suggestedVisual = VisualTopologyKind.NEURAL_SYNAPTIC_LATTICE
        )
    }

    private fun publishTelemetry() {
        val snapshotEvents = synchronized(recentBuffer) { recentBuffer.toList() }
        _telemetry.value = com.aura.mobiledefense.data.model.VpnFirewallTelemetry(
            isRunning = vpnRunning,
            tunAddress = "10.8.0.2/32",
            upstreamDns = "1.1.1.1:53",
            startedAtMs = startedAt,
            packetsInspected = inspectedCount.get(),
            packetsAllowed = allowedCount.get(),
            packetsBlocked = blockedCount.get(),
            bytesIn = bytesInCount.get(),
            bytesOut = bytesOutCount.get(),
            lastDnsRttMs = lastDnsRtt,
            activeRulesCount = _rules.value.count { it.enabled },
            recentEvents = snapshotEvents
        )
    }
}

private object VpnFirewallTelemetryDefaults {
    fun initial() = com.aura.mobiledefense.data.model.VpnFirewallTelemetry()
}
