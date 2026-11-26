package com.aura.mobiledefense.domain.vpn

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.aura.mobiledefense.data.local.FirewallRuleEntity
import com.aura.mobiledefense.data.local.NyxDatabase
import com.aura.mobiledefense.data.model.FirewallRuleType
import com.aura.mobiledefense.domain.security.ShellRunner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Firewall por app: bloquea (o desbloquea) todo el tráfico de una aplicación concreta.
 *
 * Realidad de la plataforma, sin adornos:
 *
 *  - **Con root** el bloqueo es real a nivel de kernel: `iptables -m owner --uid-owner <uid> -j DROP`
 *    en la cadena OUTPUT. Se administra por comandos firmados y validados por
 *    [com.aura.mobiledefense.domain.security.RootCommandPolicy] (estructura exacta, cadena, target
 *    y rango de UID), nunca por texto libre.
 *  - **Sin root** Android 10+ no permite a una app corriente atribuir ni cortar el tráfico de OTRA
 *    app: `/proc/net/*` oculta las entradas ajenas y `ConnectivityManager.getConnectionOwnerUid`
 *    es una API oculta que en muchos dispositivos devuelve -1 o lanza. Aquí solo se expone como
 *    atribución *best-effort* para telemetría forense ([attributeOwnerUidBestEffort]); el bloqueo
 *    real declara honestamente que no está disponible y la regla queda persistida para aplicarse
 *    cuando haya root (o en el siguiente arranque con root).
 *
 * Nunca se puede bloquear al propio Aura ni UIDs por debajo de 10000 (root/sistema): un DROP
 * equivocado ahí dejaría el dispositivo sin red de forma no recuperable desde la app.
 */
object AppFirewallEngine {

    const val RULE_PREFIX = "appfw_"
    const val MIN_BLOCKABLE_UID = 10_000

    data class InstalledApp(
        val packageName: String,
        val uid: Int,
        val label: String,
        val isSystemApp: Boolean
    )

    data class AppBlockResult(
        val packageName: String,
        val uid: Int?,
        val blocked: Boolean,
        /** true solo cuando el kernel aceptó la regla iptables (root disponible). */
        val enforcedAtKernel: Boolean,
        val message: String
    )

    /** Apps instaladas visibles (sin el propio Aura). Las de sistema se marcan, no se ocultan. */
    fun listInstalledApps(context: Context, includeSystem: Boolean = false): List<InstalledApp> {
        val pm = context.packageManager
        val apps = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(0)
        }
        return apps
            .filter { it.packageName != context.packageName }
            .filter { includeSystem || (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 }
            .map { info ->
                InstalledApp(
                    packageName = info.packageName,
                    uid = info.uid,
                    label = pm.getApplicationLabel(info).toString(),
                    isSystemApp = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                )
            }
            .sortedBy { it.label.lowercase() }
    }

    /** UID actual del paquete, o null si no está instalado / no es consultable. */
    fun uidForPackage(context: Context, packageName: String): Int? = runCatching {
        @Suppress("DEPRECATION")
        context.packageManager.getPackageInfo(packageName.trim(), 0).applicationInfo?.uid
    }.getOrNull()

    // ── Comandos firmados (la política los valida literalmente; no generan texto libre) ──

    fun checkOrInsertCommand(uid: Int): String =
        "iptables -C OUTPUT -m owner --uid-owner $uid -j DROP 2>/dev/null || iptables -I OUTPUT -m owner --uid-owner $uid -j DROP"

    fun deleteCommand(uid: Int): String =
        "iptables -D OUTPUT -m owner --uid-owner $uid -j DROP"

    // ── Toggle ─────────────────────────────────────────────────────────────────────────

    /**
     * Bloquea o desbloquea la app. Persiste la regla SIEMPRE (es la fuente de verdad) y la aplica
     * al kernel cuando hay root. El resultado dice explícitamente si el kernel quedó protegido.
     */
    suspend fun setAppBlocked(context: Context, packageName: String, blocked: Boolean): AppBlockResult {
        val clean = packageName.trim().lowercase()
        if (clean.isBlank()) {
            return AppBlockResult(clean, null, blocked, enforcedAtKernel = false, message = "Indica el paquete a bloquear.")
        }
        if (clean == context.packageName.lowercase()) {
            return AppBlockResult(clean, null, blocked, enforcedAtKernel = false,
                message = "Aura no puede bloquearse a sí misma: sería un corte de red sin salida.")
        }
        val uid = uidForPackage(context, clean)
        if (uid == null) {
            return AppBlockResult(clean, null, blocked, enforcedAtKernel = false,
                message = "El paquete '$clean' no está instalado o no se puede consultar.")
        }
        if (uid < MIN_BLOCKABLE_UID) {
            return AppBlockResult(clean, uid, blocked, enforcedAtKernel = false,
                message = "UID $uid pertenece al sistema/root (<10000): bloquearlo podría dejar sin red al dispositivo. Rechazado.")
        }

        val dao = NyxDatabase.getOrInMemory(context).forensicSessionDao()
        if (blocked) {
            dao.upsertFirewallRule(
                FirewallRuleEntity(
                    id = "${RULE_PREFIX}${clean.hashCode().toString(16)}_${System.currentTimeMillis() % 100000}",
                    pattern = clean,
                    ruleType = FirewallRuleType.APP_UID.name,
                    action = "BLOCK",
                    reason = "Bloqueo por app (kernel, uid $uid): $clean",
                    enabled = true,
                    createdAt = System.currentTimeMillis()
                )
            )
        } else {
            dao.deleteFirewallRuleByPatternOrId(clean)
        }
        VpnFirewallManager.refreshRulesFromDao(dao)

        val rootProbe = ShellRunner.run("id", elevated = true, timeoutMs = 4000L)
        val rootAvailable = rootProbe.succeeded
        if (!rootAvailable) {
            return AppBlockResult(
                clean, uid, blocked, enforcedAtKernel = false,
                message = if (blocked) {
                    "Regla persistida, pero NO aplicada al kernel: este dispositivo no ofrece root " +
                        "(o Aura no tiene permiso su). Sin root, Android 10+ no permite cortar el tráfico " +
                        "de otra app; el bloqueo quedará activo en el próximo arranque con root disponible."
                } else {
                    "Regla eliminada. No había aplicación de kernel que revertir (sin root)."
                }
            )
        }

        val applied = if (blocked) {
            ShellRunner.run(checkOrInsertCommand(uid), elevated = true, timeoutMs = 6000L).succeeded
        } else {
            // -D borra una sola instancia; repetir 3 veces por si quedó duplicada de sesiones previas.
            // El resultado real lo decide la verificación posterior en el kernel, no aquí.
            repeat(3) { ShellRunner.run(deleteCommand(uid), elevated = true, timeoutMs = 6000L) }
            true
        }
        // Verificación real: comprobar que el kernel tiene (o no) la regla inscrita.
        val verify = ShellRunner.run("iptables -L OUTPUT -n", elevated = true, timeoutMs = 6000L)
        val listed = verify.combined.lineSequence().any { line ->
            line.contains("owner UID match $uid") && (line.trimStart().startsWith("DROP"))
        }
        val kernelState = if (blocked) listed else !listed
        return AppBlockResult(
            clean, uid, blocked, enforcedAtKernel = applied && kernelState,
            message = if (blocked) {
                if (applied && kernelState) "App bloqueada a nivel de kernel (uid $uid): todo su tráfico saliente cae en DROP."
                else "Regla escrita pero no se pudo verificar en el kernel (iptables -L). Revisa permisos su y vuelve a intentarlo."
            } else {
                if (kernelState) "App desbloqueada: la regla DROP ya no está en la cadena OUTPUT."
                else "Regla eliminada de Room, pero el kernel aún muestra DROP para uid $uid. Revisa permisos su."
            }
        )
    }

    /**
     * Reaplica todas las reglas APP_UID persistidas. Se llama al arrancar el túnel VPN: las reglas
     * de kernel no sobreviven a los reinicios del dispositivo. Devuelve cuántas quedaron activas.
     */
    suspend fun applyPersistedRules(context: Context): Int = withContext(Dispatchers.IO) {
        val dao = NyxDatabase.getOrInMemory(context).forensicSessionDao()
        val appRules = dao.getEnabledFirewallRules().filter { it.ruleType == FirewallRuleType.APP_UID.name }
        var applied = 0
        for (rule in appRules) {
            val uid = uidForPackage(context, rule.pattern) ?: continue
            if (uid < MIN_BLOCKABLE_UID) continue
            val out = ShellRunner.run(checkOrInsertCommand(uid), elevated = true, timeoutMs = 6000L)
            if (out.succeeded) applied++
        }
        applied
    }

    /** Reglas APP_UID actualmente persistidas y habilitadas (para telemetría/UI). */
    suspend fun listPersistedRules(context: Context): List<FirewallRuleEntity> {
        val dao = NyxDatabase.getOrInMemory(context).forensicSessionDao()
        return dao.getEnabledFirewallRules().filter { it.ruleType == FirewallRuleType.APP_UID.name }
    }

    /**
     * Atribución best-effort de un socket a su app propietaria, vía la API oculta
     * `ConnectivityManager.getConnectionOwnerUid`. No es pública ni garantizada: en Android 10+
     * suele devolver -1 (o lanzar) para sockets de otras apps. Se usa SOLO para enriquecer la
     * telemetría ("la conexión bloqueada probablemente pertenecía a uid N"), nunca para decidir
     * acciones. Devuelve null cuando la plataforma no lo permite.
     */
    fun attributeOwnerUidBestEffort(
        context: Context,
        protocol: Int,
        localAddress: java.net.InetSocketAddress,
        remoteAddress: java.net.InetSocketAddress
    ): Int? {
        return runCatching {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) ?: return null
            val method = cm.javaClass.getMethod(
                "getConnectionOwnerUid",
                Int::class.javaPrimitiveType,
                java.net.InetSocketAddress::class.java,
                java.net.InetSocketAddress::class.java
            )
            val uid = method.invoke(cm, protocol, localAddress, remoteAddress) as? Int ?: return null
            if (uid < 0) null else uid
        }.getOrNull()
    }
}
