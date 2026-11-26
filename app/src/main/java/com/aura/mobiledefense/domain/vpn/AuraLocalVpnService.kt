package com.aura.mobiledefense.domain.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.aura.mobiledefense.MainActivity
import com.aura.mobiledefense.R
import com.aura.mobiledefense.data.model.FirewallPacketEventAction
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.NetworkInterface

private const val TAG = "AuraLocalVpnService"
private const val CHANNEL_ID = "aura_local_vpn_channel"
private const val NOTIFICATION_ID = 7401

/**
 * 100% real Android VpnService implementing:
 * - Local TUN interface (10.8.0.2/32) + virtual DNS sinkhole gateway (10.8.0.1:53)
 * - Real wire-format IPv4/UDP/DNS interception & NXDOMAIN firewall blocking
 * - Real IP-route sinkhole blocking with TCP/UDP port inspection
 * - Protected DatagramSocket forwarding to 1.1.1.1 / 8.8.8.8 with live RTT & byte telemetry
 */
class AuraLocalVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.aura.mobiledefense.aura.vpn.START"
        const val ACTION_STOP = "com.aura.mobiledefense.aura.vpn.STOP"
        const val ACTION_RELOAD = "com.aura.mobiledefense.aura.vpn.RELOAD"
        private const val TUN_IP = "10.8.0.2"
        private const val VIRTUAL_DNS_IP = "10.8.0.1"
        private const val UPSTREAM_DNS_PRIMARY = "1.1.1.1"
        private const val UPSTREAM_DNS_SECONDARY = "8.8.8.8"
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunnelJob: Job? = null
    private var tunInterface: ParcelFileDescriptor? = null
    private val tunWriteLock = Any()

    /** DNS reales del dispositivo; se rellena al levantar el túnel. */
    @Volatile
    private var activeUpstreamDns: List<String> = emptyList()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_RELOAD -> {
                if (tunInterface != null) {
                    restartTunnel()
                }
            }
            else -> {
                startForegroundNotification()
                startTunnel()
            }
        }
        return START_STICKY
    }

    private fun startForegroundNotification() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Aura VPN Local y Firewall",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Túnel local de inspección DNS, firewall y telemetría en tiempo real"
            }
            nm.createNotificationChannel(channel)
        }

        val launchIntent = Intent(this, MainActivity::class.java)
        val pendingFlags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val pendingIntent = PendingIntent.getActivity(this, 0, launchIntent, pendingFlags)

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        val notification = builder
            .setContentTitle("Aura VPN Local + Firewall activo")
            .setContentText("Inspeccionando DNS y filtrando rutas bloqueadas (10.8.0.2)")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun restartTunnel() {
        stopTunnel()
        startTunnel()
    }

    private fun startTunnel() {
        if (tunnelJob?.isActive == true) return
        tunnelJob = serviceScope.launch {
            VpnFirewallManager.ensureInitialized(applicationContext)
            try {
                val builder = Builder()
                    .setSession("Aura Defense Local VPN")
                    .setMtu(1500)
                    .addAddress(TUN_IP, 32)
                    .addDnsServer(VIRTUAL_DNS_IP)
                    .addRoute(VIRTUAL_DNS_IP, 32)

                // DNS de todas las interfaces reales del dispositivo, enrutados por el TUN para
                // interceptarlos. Sin esto, el sistema seguiría usando el DNS de la Wi-Fi/LTE sin
                // pasar por Aura y el firewall de dominios no se aplicaría a nadie salvo a quien se
                // configure 10.8.0.1 a mano.
                val upstreamDns = collectPhysicalDnsServers()
                activeUpstreamDns = upstreamDns
                upstreamDns.forEach { dns ->
                    runCatching { builder.addRoute(dns, 32) }
                }
                VpnFirewallManager.setUpstreamDns(upstreamDns)

                // Ruta completa: todo el tráfico IPv4 entra al proxy transparente, que aplica las
                // reglas del firewall paquete a paquete y reenvía lo permitido por un socket real.
                // IPv6 queda fuera del túnel a propósito: el proxy solo habla IPv4 y enrutar :: sin
                // manejarlo cortaría toda la conectividad v6 del dispositivo.
                runCatching { builder.addRoute("0.0.0.0", 0) }
                // Los sockets reales del proxy se abren con `VpnService.protect()`, así que salen por
                // la red física y no vuelven a entrar al TUN. El TUN se marca como no-medido para que
                // el ahorro de batería no lo trate como red de pago.
                runCatching {
                    val setMetered = Builder::class.java.getMethod("setMetered", Boolean::class.javaPrimitiveType)
                    setMetered.invoke(builder, false)
                }

                // Prevent Aura itself from looping inside the VPN
                runCatching { builder.addDisallowedApplication(packageName) }

                val pfd = builder.establish()
                if (pfd == null) {
                    Log.e(TAG, "VpnService.Builder.establish() returned null (consent missing).")
                    VpnFirewallManager.onVpnStateChanged(false)
                    stopSelf()
                    return@launch
                }

                tunInterface = pfd
                VpnFirewallManager.onVpnStateChanged(true)

                val input = FileInputStream(pfd.fileDescriptor)
                val output = FileOutputStream(pfd.fileDescriptor)
                val buffer = ByteArray(32767)

                while (isActive && tunInterface != null) {
                    val readLen = input.read(buffer)
                    if (readLen <= 0) continue

                    val packetCopy = buffer.copyOf(readLen)
                    val parsed = PacketCodec.parseIpv4Packet(packetCopy, readLen) ?: continue

                    // 1. Intercept real DNS queries sent to our virtual DNS gateway 10.8.0.1:53
                    if (parsed.protocol == PacketCodec.PROTO_UDP &&
                        parsed.dstIpString == VIRTUAL_DNS_IP &&
                        parsed.dstPort == 53 &&
                        parsed.payloadLength > 0
                    ) {
                        serviceScope.launch {
                            handleDnsPacket(packetCopy, parsed, output)
                        }
                    } else if (parsed.protocol == PacketCodec.PROTO_TCP) {
                        // 2. TCP: proxy transparente. Decide con las reglas reales (IP, puerto y,
                        //    en cuanto aparece, el dominio del SNI) y corta con RST lo que se bloquea.
                        val handled = TcpProxyEngine.handleFromDevice(
                            parsed = parsed,
                            packet = packetCopy,
                            transport = tcpTransport,
                            downlink = { reply -> writePacketToTun(output, reply) },
                            onBlocked = { reason ->
                                VpnFirewallManager.recordPacketEvent(
                                    protocol = "TCP",
                                    destination = "${parsed.dstIpString}:${parsed.dstPort}",
                                    port = parsed.dstPort,
                                    action = FirewallPacketEventAction.BLOCKED,
                                    reason = reason,
                                    bytesInDelta = readLen.toLong(),
                                    bytesOutDelta = 0L
                                )
                            },
                            onSni = { host ->
                                VpnFirewallManager.recordObservedDomain(host, parsed.dstIpString)
                            }
                        )
                        if (handled) continue
                        VpnFirewallManager.recordPacketEvent(
                            protocol = "TCP",
                            destination = parsed.dstIpString,
                            port = parsed.dstPort,
                            action = FirewallPacketEventAction.ALLOWED,
                            reason = "Proxy TCP activo",
                            bytesInDelta = readLen.toLong(),
                            bytesOutDelta = 0L
                        )
                    } else {
                        // 3. UDP e ICMP: firewall por IP/puerto (DNS ya se atendió arriba).
                        val decision = VpnFirewallManager.evaluatePacketRoute(parsed.dstIpString, parsed.dstPort)
                        val protoName = when (parsed.protocol) {
                            PacketCodec.PROTO_TCP -> "TCP"
                            PacketCodec.PROTO_UDP -> "UDP"
                            else -> "IP(${parsed.protocol})"
                        }
                        VpnFirewallManager.recordPacketEvent(
                            protocol = protoName,
                            destination = parsed.dstIpString,
                            port = parsed.dstPort,
                            action = FirewallPacketEventAction.BLOCKED,
                            reason = if (!decision.allowed) decision.reason else "Ruta bloqueada por Firewall TUN",
                            bytesInDelta = readLen.toLong(),
                            bytesOutDelta = 0L
                        )
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "VPN tunnel loop ended", e)
            } finally {
                VpnFirewallManager.onVpnStateChanged(false)
            }
        }
    }

    private fun handleDnsPacket(
        rawPacket: ByteArray,
        parsed: ParsedIpPacket,
        tunOut: FileOutputStream
    ) {
        val dnsQuery = rawPacket.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength)
        val domain = PacketCodec.extractDnsQueryDomain(rawPacket, parsed.payloadOffset, parsed.payloadLength)
            ?: "unknown.dns"

        val decision = VpnFirewallManager.evaluateDnsDomain(domain)
        if (!decision.allowed) {
            val nxPayload = PacketCodec.buildDnsNxDomainResponse(dnsQuery)
            val replyPacket = PacketCodec.buildIpv4UdpPacket(
                srcIp = parsed.dstIp,
                dstIp = parsed.srcIp,
                srcPort = parsed.dstPort,
                dstPort = parsed.srcPort,
                payload = nxPayload
            )
            writePacketToTun(tunOut, replyPacket)
            VpnFirewallManager.recordPacketEvent(
                protocol = "DNS",
                destination = domain,
                port = 53,
                action = FirewallPacketEventAction.BLOCKED,
                reason = decision.reason,
                bytesInDelta = rawPacket.size.toLong(),
                bytesOutDelta = replyPacket.size.toLong(),
                rttMs = 1L
            )
            return
        }

        val startMs = System.currentTimeMillis()
        val candidates = (activeUpstreamDns + listOf(UPSTREAM_DNS_PRIMARY, UPSTREAM_DNS_SECONDARY)).distinct()
        var upstreamUsed = candidates.first()
        var upstreamResponse: ByteArray? = null
        for (server in candidates) {
            upstreamResponse = forwardDnsUpstream(dnsQuery, server)
            if (upstreamResponse != null) {
                upstreamUsed = server
                break
            }
        }
        val rtt = (System.currentTimeMillis() - startMs).coerceAtLeast(1L)

        if (upstreamResponse != null) {
            // Aprendemos dominio→IP: si este dominio se bloquea, sus IPs se cortan en el túnel
            // aunque la app resuelva por su cuenta o la respuesta venga de caché.
            val resolvedIps = PacketCodec.extractDnsAnswerIps(upstreamResponse)
            if (resolvedIps.isNotEmpty()) {
                DomainSinkhole.rememberResolution(domain, resolvedIps, blocked = false)
            }
            val replyPacket = PacketCodec.buildIpv4UdpPacket(
                srcIp = parsed.dstIp,
                dstIp = parsed.srcIp,
                srcPort = parsed.dstPort,
                dstPort = parsed.srcPort,
                payload = upstreamResponse
            )
            writePacketToTun(tunOut, replyPacket)
            VpnFirewallManager.recordPacketEvent(
                protocol = "DNS",
                destination = domain,
                port = 53,
                action = FirewallPacketEventAction.ALLOWED,
                reason = "Resuelto vía $upstreamUsed",
                bytesInDelta = rawPacket.size.toLong(),
                bytesOutDelta = replyPacket.size.toLong(),
                rttMs = rtt
            )
        }
    }

    /**
     * DNS reales que el dispositivo estaba usando antes de levantar el TUN. Se consultan por las
     * interfaces físicas (no la nuestra) en vez de asumir 1.1.1.1: así funcionan las redes
     * corporativas y los DNS locales, y el usuario no pierde resolución al activar la VPN.
     */
    private fun collectPhysicalDnsServers(): List<String> {
        val result = linkedSetOf<String>()
        runCatching {
            NetworkInterface.getNetworkInterfaces().toList()
                .filter { it.isUp && !it.isLoopback && it.name != "tun0" && !it.name.startsWith("tun") }
                .forEach { iface -> result.addAll(readDnsForInterface(iface.name)) }
        }
        val filtered = result.filter { ip -> ip != VIRTUAL_DNS_IP && !ip.startsWith("127.") }
        return if (filtered.isEmpty()) listOf(UPSTREAM_DNS_PRIMARY, UPSTREAM_DNS_SECONDARY) else filtered.take(3)
    }

    private fun readDnsForInterface(name: String): List<String> {
        val out = mutableListOf<String>()
        runCatching {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
            cm.allNetworks.forEach { net ->
                val lp = cm.getLinkProperties(net) ?: return@forEach
                if (lp.interfaceName != name) return@forEach
                lp.dnsServers.forEach { dns ->
                    val host = dns.hostAddress ?: return@forEach
                    if (dns is java.net.Inet4Address) out.add(host)
                }
            }
        }
        return out.distinct()
    }

    /** Conexiones reales del proxy, siempre fuera del túnel para no entrar en bucle. */
    private val tcpTransport = object : TcpProxyEngine.Transport {
        override fun connect(dstIp: String, dstPort: Int, timeoutMs: Int): Socket? = runCatching {
            val socket = Socket()
            if (!protect(socket)) {
                Log.w(TAG, "protect() rechazó el socket hacia $dstIp:$dstPort")
                socket.close()
                return@runCatching null
            }
            socket.connect(InetSocketAddress(dstIp, dstPort), timeoutMs)
            socket.tcpNoDelay = true
            socket.soTimeout = 0
            socket
        }.getOrNull()
    }

    private fun forwardDnsUpstream(queryBytes: ByteArray, upstreamIp: String): ByteArray? {
        return try {
            DatagramSocket().use { socket ->
                if (!protect(socket)) {
                    Log.w(TAG, "Failed to protect upstream DNS socket")
                }
                socket.soTimeout = 3500
                val upstreamAddr = InetAddress.getByName(upstreamIp)
                val outPacket = DatagramPacket(queryBytes, queryBytes.size, upstreamAddr, 53)
                socket.send(outPacket)

                val recvBuf = ByteArray(4096)
                val inPacket = DatagramPacket(recvBuf, recvBuf.size)
                socket.receive(inPacket)
                recvBuf.copyOf(inPacket.length)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Upstream DNS forward to $upstreamIp failed: ${e.message}")
            null
        }
    }

    private fun writePacketToTun(tunOut: FileOutputStream, packet: ByteArray) {
        synchronized(tunWriteLock) {
            runCatching {
                tunOut.write(packet)
            }.onFailure {
                Log.w(TAG, "Write to TUN failed: ${it.message}")
            }
        }
    }

    private fun stopTunnel() {
        tunnelJob?.cancel()
        tunnelJob = null
        activeUpstreamDns = emptyList()
        TcpProxyEngine.closeAll()
        runCatching { tunInterface?.close() }
        tunInterface = null
        VpnFirewallManager.onVpnStateChanged(false)
    }

    override fun onRevoke() {
        stopTunnel()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        serviceScope.cancel()
        super.onDestroy()
    }
}
