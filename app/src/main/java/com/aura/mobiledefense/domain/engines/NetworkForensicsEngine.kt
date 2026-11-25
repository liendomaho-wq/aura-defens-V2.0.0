package com.aura.mobiledefense.domain.engines

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.domain.security.ShellRunner
import com.aura.mobiledefense.data.model.ToolExecutionResult
import com.aura.mobiledefense.data.model.VisualTopologyKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class NetworkForensicsEngine(private val context: Context) {

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .followRedirects(false)
        .build()

    private val commonSecurityPorts = listOf(
        21 to "FTP",
        22 to "SSH",
        23 to "Telnet",
        25 to "SMTP",
        53 to "DNS",
        80 to "HTTP",
        110 to "POP3",
        143 to "IMAP",
        443 to "HTTPS",
        445 to "SMB",
        554 to "RTSP",
        993 to "IMAPS",
        995 to "POP3S",
        1433 to "MSSQL",
        1883 to "MQTT",
        3306 to "MySQL",
        3389 to "RDP",
        5037 to "ADB-Server",
        5432 to "PostgreSQL",
        5555 to "ADB-TCP",
        6379 to "Redis",
        8080 to "HTTP-Alt",
        8443 to "HTTPS-Alt",
        9200 to "Elasticsearch",
        27017 to "MongoDB"
    )

    suspend fun inspectLocalNetworkAndSockets(mode: PrivilegeMode): ToolExecutionResult =
        withContext(Dispatchers.IO) {
            val sb = StringBuilder()
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val activeNet = cm.activeNetwork
            val caps = activeNet?.let { cm.getNetworkCapabilities(it) }
            val linkProps = activeNet?.let { cm.getLinkProperties(it) }

            sb.appendLine("=== TOPOLOGÍA DE RED LOCAL ===")
            val transports = buildList {
                if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) add("Wi-Fi")
                if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true) add("Cellular")
                if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) add("VPN")
                if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true) add("Ethernet")
            }.ifEmpty { listOf("Sin transporte activo / Offline") }

            sb.appendLine("Transportes activos: ${transports.joinToString(", ")}")
            sb.appendLine("Interfaz LinkProperties: ${linkProps?.interfaceName ?: "N/D"}")
            sb.appendLine("Servidores DNS: ${linkProps?.dnsServers?.joinToString { it.hostAddress ?: "" } ?: "N/D"}")
            sb.appendLine("Proxy HTTP: ${linkProps?.httpProxy?.let { "${it.host}:${it.port}" } ?: "Ninguno"}")
            sb.appendLine("Rutas activas: ${linkProps?.routes?.take(6)?.joinToString { it.destination.toString() } ?: "N/D"}")
            sb.appendLine()

            sb.appendLine("=== INTERFACES DE RED ===")
            val interfaces = runCatching { NetworkInterface.getNetworkInterfaces().toList() }
                .getOrDefault(emptyList())
                .filter { it.isUp }
            interfaces.forEach { iface ->
                val addrs = iface.inetAddresses.toList()
                    .mapNotNull { it.hostAddress?.substringBefore('%') }
                    .joinToString(", ")
                sb.appendLine("${iface.name} (MTU ${iface.mtu}, virtual=${iface.isVirtual}, loopback=${iface.isLoopback}): $addrs")
            }

            sb.appendLine()
            sb.appendLine("=== SOCKETS & TABLA ARP (/proc/net) ===")
            val tcpEntries = parseProcNetTcp("/proc/net/tcp")
            val tcp6Entries = parseProcNetTcp("/proc/net/tcp6")
            val arpContent = readReadableFile("/proc/net/arp")

            if (tcpEntries.isNotEmpty() || tcp6Entries.isNotEmpty()) {
                sb.appendLine("TCP IPv4 (${tcpEntries.size} entradas):")
                tcpEntries.take(15).forEach { sb.appendLine("  $it") }
                sb.appendLine("TCP IPv6 (${tcp6Entries.size} entradas):")
                tcp6Entries.take(15).forEach { sb.appendLine("  $it") }
            } else {
                sb.appendLine("/proc/net/tcp inaccesible bajo política SELinux actual en Userland.")
            }

            if (!arpContent.isNullOrBlank()) {
                sb.appendLine("ARP Cache:")
                arpContent.lines().take(10).forEach { sb.appendLine("  $it") }
            }

            if (mode == PrivilegeMode.ROOT) {
                sb.appendLine()
                sb.appendLine("=== AUDITORÍA KERNEL DE SOCKETS Y NETFILTER (su) ===")
                val suNet = ShellRunner.run(
                    command = "ss -tulnpa 2>/dev/null || netstat -tulnpa 2>/dev/null; echo '---IP-NEIGH---'; ip neigh show 2>/dev/null; echo '---IPTABLES---'; iptables -L -n 2>/dev/null | head -n 25",
                    elevated = true,
                    timeoutMs = 7000L
                ).combined.ifBlank { "Sin salida de la inspección kernel." }
                sb.appendLine(suNet)
            }

            val spectrum = buildList {
                add((interfaces.size / 6f).coerceIn(0.1f, 1f))
                add(if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) 0.9f else 0.35f)
                add(if (linkProps?.httpProxy == null) 0.85f else 0.45f)
                add(((tcpEntries.size + tcp6Entries.size) / 20f).coerceIn(0.15f, 1f))
                repeat(12) { idx ->
                    val v = ((interfaces.size * 17 + idx * 13 + tcpEntries.size * 7) % 85 + 15) / 100f
                    add(v)
                }
            }

            ToolExecutionResult(
                toolId = "NETWORK_SOCKETS",
                target = linkProps?.interfaceName ?: "Interfaces locales",
                privilegeUsed = mode,
                rawTelemetry = sb.toString(),
                measuredSpectrum = spectrum,
                suggestedVisual = VisualTopologyKind.CONSTELLATION_MESH
            )
        }

    suspend fun probePorts(rawTarget: String, mode: PrivilegeMode): ToolExecutionResult =
        withContext(Dispatchers.IO) {
            val host = sanitizeHost(rawTarget).ifBlank { "127.0.0.1" }
            val resolvedIp = runCatching { InetAddress.getByName(host).hostAddress }.getOrNull()
            val semaphore = Semaphore(10)

            val results = coroutineScope {
                commonSecurityPorts.map { (port, service) ->
                    async {
                        semaphore.withPermit {
                            val start = System.currentTimeMillis()
                            try {
                                Socket().use { socket ->
                                    socket.connect(InetSocketAddress(host, port), 850)
                                    val rtt = System.currentTimeMillis() - start
                                    socket.soTimeout = 700
                                    val banner = runCatching {
                                        if (port in listOf(80, 8080, 8000)) {
                                            socket.getOutputStream().write(
                                                "HEAD / HTTP/1.0\r\nHost: $host\r\n\r\n".toByteArray()
                                            )
                                            socket.getOutputStream().flush()
                                        }
                                        val buf = ByteArray(256)
                                        val n = socket.getInputStream().read(buf)
                                        if (n > 0) String(buf, 0, n)
                                            .replace("\r", " ")
                                            .replace("\n", " | ")
                                            .trim()
                                        else ""
                                    }.getOrDefault("")
                                    PortProbeEntry(port, service, true, rtt, banner)
                                }
                            } catch (_: Exception) {
                                PortProbeEntry(port, service, false, -1L, "")
                            }
                        }
                    }
                }.awaitAll()
            }

            val openPorts = results.filter { it.open }
            val sb = StringBuilder().apply {
                appendLine("=== SONDEO TCP Y BANNER GRABBING ===")
                appendLine("Objetivo: $host (IP resuelta: ${resolvedIp ?: "No resuelta"})")
                appendLine("Puertos sondeados: ${results.size} | Abiertos: ${openPorts.size}")
                appendLine()
                if (openPorts.isEmpty()) {
                    appendLine("No se detectaron puertos TCP abiertos en el perfil analizado (filtrados o cerrados).")
                } else {
                    openPorts.forEach { p ->
                        appendLine("[ABIERTO] ${p.port}/tcp (${p.service}) — RTT ${p.rttMs}ms")
                        if (p.banner.isNotBlank()) {
                            appendLine("   Banner: ${p.banner.take(160)}")
                        }
                    }
                }
            }

            val spectrum = results.map { entry ->
                if (entry.open) 0.92f else 0.14f
            }

            ToolExecutionResult(
                toolId = "PORT_PROBE",
                target = host,
                privilegeUsed = mode,
                rawTelemetry = sb.toString(),
                measuredSpectrum = spectrum,
                suggestedVisual = VisualTopologyKind.ENTROPY_MATRIX
            )
        }

    suspend fun inspectTlsCertificate(rawTarget: String, mode: PrivilegeMode): ToolExecutionResult =
        withContext(Dispatchers.IO) {
            val clean = sanitizeHost(rawTarget).ifBlank { "google.com" }
            val parts = clean.split(":")
            val host = parts[0]
            val port = parts.getOrNull(1)?.toIntOrNull() ?: 443

            val sb = StringBuilder()
            val spectrum = mutableListOf<Float>()

            try {
                val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
                (factory.createSocket() as SSLSocket).use { socket ->
                    socket.connect(InetSocketAddress(host, port), 6000)
                    socket.soTimeout = 6000
                    socket.startHandshake()

                    val session = socket.session
                    val protocol = session.protocol
                    val cipher = session.cipherSuite
                    val certs = session.peerCertificates.filterIsInstance<X509Certificate>()

                    sb.appendLine("=== INSPECCIÓN TLS / X.509 ===")
                    sb.appendLine("Endpoint: $host:$port")
                    sb.appendLine("Protocolo negociado: $protocol")
                    sb.appendLine("Cipher Suite: $cipher")
                    sb.appendLine("Longitud de cadena: ${certs.size} certificado(s)")
                    sb.appendLine()

                    val df = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)
                    val now = Date()

                    certs.forEachIndexed { idx, cert ->
                        val daysLeft = ((cert.notAfter.time - now.time) / (1000L * 60 * 60 * 24))
                        val pubKeyInfo = when (val pk = cert.publicKey) {
                            is RSAPublicKey -> "RSA-${pk.modulus.bitLength()}"
                            is ECPublicKey -> "EC-${pk.params.order.bitLength()}"
                            else -> pk.algorithm
                        }
                        val sha256 = MessageDigest.getInstance("SHA-256")
                            .digest(cert.encoded)
                            .joinToString(":") { "%02X".format(it) }
                        val sans = runCatching {
                            cert.subjectAlternativeNames
                                ?.mapNotNull { it.getOrNull(1)?.toString() }
                                ?.take(8)
                                ?.joinToString(", ")
                        }.getOrNull().orEmpty()

                        sb.appendLine("--- Certificado #$idx ---")
                        sb.appendLine("Subject: ${cert.subjectX500Principal.name}")
                        sb.appendLine("Issuer: ${cert.issuerX500Principal.name}")
                        sb.appendLine("Validez: ${df.format(cert.notBefore)} → ${df.format(cert.notAfter)} ($daysLeft días restantes)")
                        sb.appendLine("Algoritmo firma: ${cert.sigAlgName} | Clave pública: $pubKeyInfo")
                        if (sans.isNotBlank()) sb.appendLine("SANs: $sans")
                        sb.appendLine("SHA-256 Fingerprint: $sha256")
                        sb.appendLine()

                        spectrum.add(if (daysLeft > 30) 0.9f else 0.35f)
                        spectrum.add(if (protocol.contains("1.3")) 0.95f else 0.65f)
                        spectrum.add(if (cipher.contains("GCM") || cipher.contains("CHACHA20")) 0.92f else 0.45f)
                    }
                }
            } catch (e: Exception) {
                sb.appendLine("=== ERROR EN HANDSHAKE TLS ($host:$port) ===")
                sb.appendLine("${e.javaClass.simpleName}: ${e.message}")
                spectrum.addAll(listOf(0.2f, 0.15f, 0.2f, 0.1f))
            }

            while (spectrum.size < 12) {
                spectrum.add((spectrum.lastOrNull() ?: 0.5f))
            }

            ToolExecutionResult(
                toolId = "TLS_INSPECT",
                target = "$host:$port",
                privilegeUsed = mode,
                rawTelemetry = sb.toString(),
                measuredSpectrum = spectrum,
                suggestedVisual = VisualTopologyKind.PROTOCOL_STRATA
            )
        }

    suspend fun inspectDnsRecon(rawTarget: String, mode: PrivilegeMode): ToolExecutionResult =
        withContext(Dispatchers.IO) {
            val host = sanitizeHost(rawTarget).ifBlank { "example.com" }
            val recordTypes = listOf("A", "AAAA", "MX", "TXT", "NS", "CAA")
            val sb = StringBuilder()
            sb.appendLine("=== RECONOCIMIENTO DNS (DoH + Sistema) ===")
            sb.appendLine("Dominio: $host")

            val systemResolved = runCatching {
                InetAddress.getAllByName(host).map {
                    val v = if (it is Inet4Address) "IPv4" else "IPv6"
                    "$v: ${it.hostAddress}"
                }
            }.getOrDefault(emptyList())

            sb.appendLine("Resolución local: ${systemResolved.joinToString(", ").ifBlank { "Sin respuesta local" }}")
            sb.appendLine()

            val spectrum = mutableListOf<Float>()
            recordTypes.forEach { type ->
                val answers = queryDnsOverHttps(host, type)
                sb.appendLine("[$type] (${answers.size} registro(s)):")
                if (answers.isEmpty()) {
                    sb.appendLine("  (sin registros)")
                    spectrum.add(0.2f)
                } else {
                    answers.take(6).forEach { sb.appendLine("  • $it") }
                    spectrum.add((0.45f + answers.size * 0.12f).coerceAtMost(0.95f))
                }
            }

            ToolExecutionResult(
                toolId = "DNS_RECON",
                target = host,
                privilegeUsed = mode,
                rawTelemetry = sb.toString(),
                measuredSpectrum = spectrum + spectrum,
                suggestedVisual = VisualTopologyKind.CONSTELLATION_MESH
            )
        }

    suspend fun inspectHttpSecurityHeaders(rawTarget: String, mode: PrivilegeMode): ToolExecutionResult =
        withContext(Dispatchers.IO) {
            val trimmed = rawTarget.trim()
            val url = when {
                trimmed.startsWith("http://") || trimmed.startsWith("https://") -> trimmed
                trimmed.isBlank() -> "https://example.com"
                else -> "https://$trimmed"
            }

            val sb = StringBuilder()
            val spectrum = mutableListOf<Float>()
            val securityHeaders = listOf(
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Permissions-Policy",
                "Cross-Origin-Opener-Policy"
            )

            try {
                val req = Request.Builder()
                    .url(url)
                    .header("User-Agent", "NyxCore-Security-Inspector/1.0")
                    .get()
                    .build()

                httpClient.newCall(req).execute().use { resp ->
                    sb.appendLine("=== AUDITORÍA DE CABECERAS HTTP ===")
                    sb.appendLine("URL: $url")
                    sb.appendLine("HTTP Status: ${resp.code} ${resp.message} (${resp.protocol})")
                    resp.handshake?.let { hs ->
                        sb.appendLine("TLS: ${hs.tlsVersion} | Cipher: ${hs.cipherSuite}")
                    }
                    sb.appendLine("Server Header: ${resp.header("Server") ?: "(oculto)"}")
                    sb.appendLine("Location (Redirect): ${resp.header("Location") ?: "(ninguno)"}")
                    sb.appendLine()
                    sb.appendLine("--- Controles de Seguridad ---")
                    securityHeaders.forEach { header ->
                        val value = resp.header(header)
                        if (value != null) {
                            sb.appendLine("[PRESENTE] $header: ${value.take(140)}")
                            spectrum.add(0.9f)
                        } else {
                            sb.appendLine("[AUSENTE]  $header")
                            spectrum.add(0.22f)
                        }
                    }

                    val cookies = resp.headers("Set-Cookie")
                    if (cookies.isNotEmpty()) {
                        sb.appendLine()
                        sb.appendLine("--- Cookies (${cookies.size}) ---")
                        cookies.take(5).forEach { sb.appendLine("  • ${it.take(160)}") }
                    }
                }
            } catch (e: Exception) {
                sb.appendLine("=== ERROR HTTP AUDITORÍA ($url) ===")
                sb.appendLine("${e.javaClass.simpleName}: ${e.message}")
                spectrum.addAll(listOf(0.15f, 0.15f, 0.15f, 0.15f))
            }

            ToolExecutionResult(
                toolId = "HTTP_HEADERS",
                target = url,
                privilegeUsed = mode,
                rawTelemetry = sb.toString(),
                measuredSpectrum = spectrum + spectrum,
                suggestedVisual = VisualTopologyKind.SPECTRUM_INTERFERENCE
            )
        }

    private fun queryDnsOverHttps(host: String, type: String): List<String> {
        return try {
            val req = Request.Builder()
                .url("https://dns.google/resolve?name=$host&type=$type")
                .header("Accept", "application/dns-json")
                .build()
            httpClient.newCall(req).execute().use { resp ->
                val body = resp.body?.string() ?: return emptyList()
                val json = JSONObject(body)
                val answers = json.optJSONArray("Answer") ?: return emptyList()
                (0 until answers.length()).mapNotNull { i ->
                    val ans = answers.getJSONObject(i)
                    val data = ans.optString("data")
                    val ttl = ans.optInt("TTL", 0)
                    if (data.isNotBlank()) "$data (TTL ${ttl}s)" else null
                }
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun parseProcNetTcp(path: String): List<String> {
        val raw = readReadableFile(path) ?: return emptyList()
        val lines = raw.lines().drop(1).filter { it.isNotBlank() }
        return lines.mapNotNull { line ->
            val cols = line.trim().split(Regex("\\s+"))
            if (cols.size < 4) return@mapNotNull null
            val local = decodeHexIpPort(cols[1])
            val remote = decodeHexIpPort(cols[2])
            val state = decodeTcpState(cols[3])
            val uid = cols.getOrNull(7) ?: "?"
            "$state $local -> $remote (uid=$uid)"
        }
    }

    private fun decodeHexIpPort(token: String): String {
        val parts = token.split(":")
        if (parts.size != 2) return token
        val ipHex = parts[0]
        val port = parts[1].toIntOrNull(16) ?: 0
        val ip = if (ipHex.length == 8) {
            ipHex.chunked(2).reversed().mapNotNull { it.toIntOrNull(16) }.joinToString(".")
        } else {
            "[ipv6]"
        }
        return "$ip:$port"
    }

    private fun decodeTcpState(hex: String): String = when (hex.uppercase()) {
        "01" -> "ESTABLISHED"
        "02" -> "SYN_SENT"
        "03" -> "SYN_RECV"
        "04" -> "FIN_WAIT1"
        "05" -> "FIN_WAIT2"
        "06" -> "TIME_WAIT"
        "07" -> "CLOSE"
        "08" -> "CLOSE_WAIT"
        "09" -> "LAST_ACK"
        "0A" -> "LISTEN"
        "0B" -> "CLOSING"
        else -> "STATE_$hex"
    }

    private fun sanitizeHost(raw: String): String {
        return raw.trim()
            .removePrefix("https://")
            .removePrefix("http://")
            .substringBefore("/")
            .substringBefore(" ")
            .trim()
    }

    private fun readReadableFile(path: String): String? = try {
        val f = File(path)
        if (f.exists() && f.canRead()) f.readText() else null
    } catch (_: Exception) {
        null
    }

    private data class PortProbeEntry(
        val port: Int,
        val service: String,
        val open: Boolean,
        val rttMs: Long,
        val banner: String
    )
}
