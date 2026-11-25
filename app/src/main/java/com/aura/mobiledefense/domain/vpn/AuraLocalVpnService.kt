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
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

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

                // Route firewall-blocked IPv4 targets directly into TUN to drop & log real packets
                VpnFirewallManager.getBlockedIpRoutes().forEach { blockedIp ->
                    runCatching { builder.addRoute(blockedIp, 32) }
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
                    } else {
                        // 2. Any other packet hitting TUN came from a firewall-blocked IP route -> drop & log!
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
        val upstreamResponse = forwardDnsUpstream(dnsQuery, UPSTREAM_DNS_PRIMARY)
            ?: forwardDnsUpstream(dnsQuery, UPSTREAM_DNS_SECONDARY)
        val rtt = (System.currentTimeMillis() - startMs).coerceAtLeast(1L)

        if (upstreamResponse != null) {
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
                reason = "Resuelto vía $UPSTREAM_DNS_PRIMARY",
                bytesInDelta = rawPacket.size.toLong(),
                bytesOutDelta = replyPacket.size.toLong(),
                rttMs = rtt
            )
        }
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
