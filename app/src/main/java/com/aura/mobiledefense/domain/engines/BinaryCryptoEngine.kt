package com.aura.mobiledefense.domain.engines

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.util.Base64
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.domain.security.ShellRunner
import com.aura.mobiledefense.data.model.ToolExecutionResult
import com.aura.mobiledefense.data.model.VisualTopologyKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import kotlin.math.ln

class BinaryCryptoEngine(private val context: Context) {

    suspend fun auditInstalledAppSurface(
        filterQuery: String,
        mode: PrivilegeMode
    ): ToolExecutionResult = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val mainIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)

        val resolveList = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.queryIntentActivities(
                mainIntent,
                PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY.toLong())
            )
        } else {
            @Suppress("DEPRECATION")
            pm.queryIntentActivities(mainIntent, 0)
        }

        val packageNames = resolveList
            .map { it.activityInfo.packageName }
            .distinct()
            .filter {
                filterQuery.isBlank() || it.contains(filterQuery, ignoreCase = true)
            }


        val sb = StringBuilder()
        sb.appendLine("=== AUDITORÍA DE SUPERFICIE DE APLICACIONES ===")
        sb.appendLine("Paquetes visibles evaluados: ${packageNames.size} (Filtro: '${filterQuery.ifBlank { "*" }}')")
        sb.appendLine()

        val spectrum = mutableListOf<Float>()

        packageNames.forEach { pkg ->
            val flags = PackageManager.GET_PERMISSIONS or
                PackageManager.GET_ACTIVITIES or
                PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS or
                PackageManager.GET_PROVIDERS or
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    PackageManager.GET_SIGNING_CERTIFICATES
                } else {
                    @Suppress("DEPRECATION")
                    PackageManager.GET_SIGNATURES
                }

            val pkgInfo = runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(flags.toLong()))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(pkg, flags)
                }
            }.getOrNull() ?: return@forEach

            val appInfo = pkgInfo.applicationInfo
            val debuggable = (appInfo?.flags ?: 0) and ApplicationInfo.FLAG_DEBUGGABLE != 0
            val allowBackup = (appInfo?.flags ?: 0) and ApplicationInfo.FLAG_ALLOW_BACKUP != 0
            val cleartext = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                (appInfo?.flags ?: 0) and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC != 0
            } else {
                false
            }
            val exportedCount =
                (pkgInfo.activities?.count { it.exported } ?: 0) +
                    (pkgInfo.services?.count { it.exported } ?: 0) +
                    (pkgInfo.receivers?.count { it.exported } ?: 0) +
                    (pkgInfo.providers?.count { it.exported } ?: 0)

            val permsCount = pkgInfo.requestedPermissions?.size ?: 0
            val certSha256 = extractSignerSha256(pkgInfo)

            val riskFactor = (
                (if (debuggable) 0.4f else 0f) +
                    (if (allowBackup) 0.15f else 0f) +
                    (if (cleartext) 0.25f else 0f) +
                    (exportedCount.coerceAtMost(10) * 0.025f)
                ).coerceIn(0.1f, 0.98f)
            spectrum.add(riskFactor)

            sb.appendLine("• $pkg (targetSdk=${appInfo?.targetSdkVersion ?: "?"})")
            sb.appendLine("  Flags: debuggable=$debuggable, allowBackup=$allowBackup, cleartext=$cleartext")
            sb.appendLine("  Superficie: $exportedCount componentes exportados | $permsCount permisos | Cert: ${certSha256.take(23)}…")
        }

        if (mode == PrivilegeMode.ROOT) {
            sb.appendLine()
            sb.appendLine("=== INVENTARIO DE PAQUETES DE TERCEROS (su) ===")
            // Todo shell pasa por ShellRunner, que evalúa RootCommandPolicy antes de crear el
            // proceso. Antes esta llamada iba directo a `su -c`, saltándose la política.
            val suPkgs = ShellRunner.run(
                command = "pm list packages -3 -f",
                elevated = true,
                timeoutMs = 5000L
            ).combined.ifBlank { "(sin salida de pm list packages)" }
            sb.appendLine(suPkgs.take(3000))
        }

        ToolExecutionResult(
            toolId = "APP_SURFACE_AUDIT",
            target = filterQuery.ifBlank { "Paquetes instalados" },
            privilegeUsed = mode,
            rawTelemetry = sb.toString(),
            measuredSpectrum = spectrum.ifEmpty { listOf(0.2f, 0.3f, 0.2f) },
            suggestedVisual = VisualTopologyKind.ATTACK_VECTOR_FLOW
        )
    }

    suspend fun analyzeBinaryUri(uri: Uri, mode: PrivilegeMode): ToolExecutionResult =
        withContext(Dispatchers.IO) {
            val resolver = context.contentResolver
            val displayName = uri.lastPathSegment ?: "archivo_seleccionado"
            val maxReadBytes = 12 * 1024 * 1024 // Cap memory footprint at 12MB for safe in-memory analysis

            val bytes = resolver.openInputStream(uri)?.use { input ->
                val baos = ByteArrayOutputStream()
                val buffer = ByteArray(16384)
                var total = 0
                while (total < maxReadBytes) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    baos.write(buffer, 0, read)
                    total += read
                }
                baos.toByteArray()
            } ?: return@withContext ToolExecutionResult(
                toolId = "BINARY_ENTROPY",
                target = displayName,
                privilegeUsed = mode,
                rawTelemetry = "No se pudo leer el flujo del archivo seleccionado.",
                suggestedVisual = VisualTopologyKind.BINARY_HELIX
            )

            val sha256 = digestHex("SHA-256", bytes)
            val sha1 = digestHex("SHA-1", bytes)
            val md5 = digestHex("MD5", bytes)
            val magic = detectMagicSignature(bytes)
            val globalEntropy = computeShannonEntropy(bytes)

            // 32-slice entropy profile for real visualization
            val sliceCount = 32
            val sliceSize = (bytes.size / sliceCount).coerceAtLeast(1)
            val entropyProfile = (0 until sliceCount).map { idx ->
                val start = idx * sliceSize
                val end = (start + sliceSize).coerceAtMost(bytes.size)
                if (start < end) {
                    (computeShannonEntropy(bytes.copyOfRange(start, end)) / 8.0).toFloat()
                        .coerceIn(0.05f, 1f)
                } else 0.05f
            }

            val strings = extractAsciiStrings(bytes, minLen = 6, maxCount = 30)
            val urls = strings.filter { it.contains("http://") || it.contains("https://") }
            val ips = strings.filter { Regex("\\b\\d{1,3}(\\.\\d{1,3}){3}\\b").containsMatchIn(it) }

            val sb = StringBuilder().apply {
                appendLine("=== ANÁLISIS BINARIO Y ENTROPÍA DE SHANNON ===")
                appendLine("Archivo: $displayName (${bytes.size} bytes analizados)")
                appendLine("Firma Magic: $magic")
                appendLine("Entropía Global: ${"%.3f".format(globalEntropy)} / 8.000 bits/byte")
                appendLine("SHA-256: $sha256")
                appendLine("SHA-1:   $sha1")
                appendLine("MD5:     $md5")
                appendLine()
                if (urls.isNotEmpty()) {
                    appendLine("--- URLs Embebidas (${urls.size}) ---")
                    urls.take(10).forEach { appendLine("  • $it") }
                }
                if (ips.isNotEmpty()) {
                    appendLine("--- IPs Embebidas (${ips.size}) ---")
                    ips.take(10).forEach { appendLine("  • $it") }
                }
                appendLine("--- Muestra de Strings ASCII ---")
                strings.take(15).forEach { appendLine("  $it") }
            }

            ToolExecutionResult(
                toolId = "BINARY_ENTROPY",
                target = displayName,
                privilegeUsed = mode,
                rawTelemetry = sb.toString(),
                measuredSpectrum = entropyProfile,
                suggestedVisual = VisualTopologyKind.BINARY_HELIX
            )
        }

    suspend fun analyzeCryptoOrJwt(input: String, mode: PrivilegeMode): ToolExecutionResult =
        withContext(Dispatchers.IO) {
            val payload = input.trim()
                .removePrefix("/jwt")
                .removePrefix("/hash")
                .removePrefix("/crypto")
                .trim()

            val sb = StringBuilder()
            val jwtCandidate = Regex("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*")
                .find(payload)?.value

            if (jwtCandidate != null) {
                val parts = jwtCandidate.split(".")
                val headerJson = decodeBase64Url(parts.getOrElse(0) { "" })
                val claimsJson = decodeBase64Url(parts.getOrElse(1) { "" })
                val sigPresent = parts.getOrElse(2) { "" }.isNotBlank()

                sb.appendLine("=== INSPECCIÓN CRIPTOGRÁFICA JWT ===")
                sb.appendLine("Header: $headerJson")
                sb.appendLine("Claims: $claimsJson")
                sb.appendLine("Firma presente: $sigPresent (${parts.getOrElse(2) { "" }.length} chars Base64URL)")

                runCatching {
                    val h = JSONObject(headerJson)
                    val alg = h.optString("alg", "desconocido")
                    sb.appendLine("Algoritmo declarado: $alg")
                    if (alg.equals("none", ignoreCase = true)) {
                        sb.appendLine("[CRÍTICO] Algoritmo 'none' detectado: token sin verificación criptográfica.")
                    }
                }
                runCatching {
                    val c = JSONObject(claimsJson)
                    if (c.has("exp")) {
                        val exp = c.getLong("exp") * 1000L
                        val expired = exp < System.currentTimeMillis()
                        sb.appendLine("Expiración (exp): ${if (expired) "EXPIRADO" else "Vigente"} ($exp ms)")
                    }
                }
            } else {
                val rawBytes = payload.toByteArray(Charsets.UTF_8)
                val entropy = computeShannonEntropy(rawBytes)
                val b64Decoded = runCatching {
                    val decoded = Base64.decode(payload, Base64.DEFAULT)
                    val str = String(decoded, Charsets.UTF_8)
                    if (str.all { !it.isISOControl() || it == '\n' || it == '\t' }) str else null
                }.getOrNull()

                sb.appendLine("=== WORKBENCH CRIPTOGRÁFICO ===")
                sb.appendLine("Longitud: ${rawBytes.size} bytes | Entropía Shannon: ${"%.3f".format(entropy)} bits/byte")
                sb.appendLine("SHA-256: ${digestHex("SHA-256", rawBytes)}")
                sb.appendLine("SHA-512: ${digestHex("SHA-512", rawBytes).take(64)}…")
                sb.appendLine("SHA-1:   ${digestHex("SHA-1", rawBytes)}")
                sb.appendLine("MD5:     ${digestHex("MD5", rawBytes)}")
                sb.appendLine("Base64:  ${Base64.encodeToString(rawBytes, Base64.NO_WRAP)}")
                if (b64Decoded != null && b64Decoded != payload) {
                    sb.appendLine("Decodificación Base64 detectada: $b64Decoded")
                }
            }

            val bytes = payload.toByteArray()
            val spectrum = (0 until 24).map { i ->
                if (bytes.isEmpty()) 0.2f
                else ((bytes[i % bytes.size].toInt() and 0xFF) / 255f).coerceIn(0.1f, 0.96f)
            }

            ToolExecutionResult(
                toolId = "CRYPTO_JWT",
                target = if (jwtCandidate != null) "JWT Token" else "Payload Criptográfico",
                privilegeUsed = mode,
                rawTelemetry = sb.toString(),
                measuredSpectrum = spectrum,
                suggestedVisual = VisualTopologyKind.BINARY_HELIX
            )
        }

    private fun extractSignerSha256(pkgInfo: PackageInfo): String {
        return try {
            val certs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkgInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                pkgInfo.signatures
            }
            val first = certs?.firstOrNull()?.toByteArray() ?: return "N/D"
            digestHex("SHA-256", first)
        } catch (_: Exception) {
            "N/D"
        }
    }

    private fun digestHex(algo: String, data: ByteArray): String {
        return MessageDigest.getInstance(algo)
            .digest(data)
            .joinToString("") { "%02x".format(it) }
    }

    private fun computeShannonEntropy(data: ByteArray): Double {
        if (data.isEmpty()) return 0.0
        val counts = IntArray(256)
        for (b in data) counts[b.toInt() and 0xFF]++
        var entropy = 0.0
        val len = data.size.toDouble()
        for (c in counts) {
            if (c > 0) {
                val p = c / len
                entropy -= p * (ln(p) / ln(2.0))
            }
        }
        return entropy
    }

    private fun detectMagicSignature(bytes: ByteArray): String {
        if (bytes.size < 4) return "Desconocido (<4 bytes)"
        val h = bytes.take(4).joinToString("") { "%02X".format(it) }
        return when {
            h == "7F454C46" -> "ELF Executable / Shared Object (.so)"
            h.startsWith("6465780A") -> "Android Dalvik Executable (.dex)"
            h.startsWith("504B0304") -> "ZIP / APK Archive"
            h == "25504446" -> "PDF Document"
            String(bytes.take(11).toByteArray()).startsWith("-----BEGIN") -> "PEM Cryptographic Material"
            String(bytes.take(15).toByteArray()).startsWith("SQLite format 3") -> "SQLite 3 Database"
            else -> "Binario / Datos ($h)"
        }
    }

    private fun extractAsciiStrings(bytes: ByteArray, minLen: Int, maxCount: Int): List<String> {
        val result = LinkedHashSet<String>()
        val current = StringBuilder()
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            if (c in 32..126) {
                current.append(c.toChar())
            } else {
                if (current.length >= minLen) {
                    result.add(current.toString().take(120))
                    if (result.size >= maxCount) break
                }
                current.clear()
            }
        }
        if (current.length >= minLen && result.size < maxCount) {
            result.add(current.toString().take(120))
        }
        return result.toList()
    }

    private fun decodeBase64Url(segment: String): String {
        return try {
            val bytes = Base64.decode(segment, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            String(bytes, Charsets.UTF_8)
        } catch (_: Exception) {
            "(no decodificable)"
        }
    }
}
