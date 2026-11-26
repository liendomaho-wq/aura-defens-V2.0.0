package com.aura.mobiledefense.data.local

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import android.util.Base64

/**
 * Cifrado en reposo de la base forense (SQLCipher).
 *
 * Lo que guarda Aura no es telemetría anodina: es qué dispositivos se auditaron, qué CVE le afectan
 * al usuario, qué dominios bloquea y el historial completo de la investigación. En claro, cualquiera
 * con `adb backup` o un móvil rooteado se lo lleva entero — justo lo que esta app dice proteger.
 *
 * Diseño:
 * - La clave real de SQLCipher es aleatoria (32 bytes de [SecureRandom]).
 * - Esa clave se cifra con una clave AES-GCM que vive **en el AndroidKeyStore** y nunca sale de él.
 * - El blob cifrado va a SharedPreferences; sin el KeyStore (otro móvil, otro usuario) es basura.
 * - Si el KeyStore no entrega la clave (o el blob no descifra), [factory] lanza y el ViewModel abre
 *   una base **en memoria** avisando en la UI: nunca se abre en claro una base cifrada existente y
 *   nunca se borra. El archivo original queda intacto para cuando la clave vuelva.
 */
object AuraDatabaseCipher {

    private const val TAG = "AuraDatabaseCipher"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "aura_db_master_key"
    private const val PREFS = "aura_db_cipher"
    private const val PREF_BLOB = "db_key_blob"
    private const val GCM_TAG_BITS = 128

    @Volatile
    private var passphrase: CharArray? = null

    /** Motivo por el que la base quedó sin cifrar, o null si está cifrada. */
    @Volatile
    var lastFaultReason: String? = null
        private set

    @Volatile
    private var nativeLoaded = false

    /**
     * SQLCipher trae su propia librería nativa y hay que cargarla antes de abrir la base.
     * [com.aura.mobiledefense.MainActivity] lo hace al arrancar, pero el servicio VPN, el monitor
     * en segundo plano y los tests pueden tocar Room sin pasar por la Activity.
     */
    private fun ensureNativeLibrary() {
        if (nativeLoaded) return
        synchronized(this) {
            if (!nativeLoaded) {
                runCatching { System.loadLibrary("sqlcipher") }
                    .onFailure { Log.w(TAG, "No se pudo cargar libsqlcipher: ${it.message}") }
                nativeLoaded = true
            }
        }
    }

    /** ¿Está la base realmente cifrada? Lo consulta el aviso de seguridad de la UI. */
    fun isEncrypted(): Boolean = passphrase != null

    fun factory(context: Context): SupportSQLiteOpenHelper.Factory {
        ensureNativeLibrary()
        val key = runCatching { loadOrCreatePassphrase(context.applicationContext) }
            .onFailure {
                lastFaultReason = it.message ?: "KeyStore no disponible: ${it.javaClass.simpleName}"
                Log.e(TAG, "No se pudo obtener la clave del KeyStore", it)
            }
            .getOrNull()

        // Nunca devolver un factory en claro: la base en disco puede estar cifrada con SQLCipher y
        // abrirla con el framework SQLite solo lograría "file is not a database" en el primer
        // acceso, o peor, crear una nueva base en claro creyendo que está cifrada. Se lanza y el
        // llamador (NyxDatabase.getInstance -> NyxViewModel) cae a una base en memoria con aviso.
        if (key == null || key.isEmpty()) {
            if (lastFaultReason == null) lastFaultReason = "Sin clave utilizable en el AndroidKeyStore"
            throw IllegalStateException(lastFaultReason)
        }
        lastFaultReason = null
        passphrase = key
        // SQLCipher 4.x pide los bytes UTF-8 de la clave, no un CharArray.
        return SupportOpenHelperFactory(String(key).toByteArray(Charsets.UTF_8))
    }

    /**
     * Borra la clave. La base queda ilegible para siempre — se usa solo en "borrar todos mis datos",
     * nunca en el arranque.
     */
    fun destroyKey(context: Context) {
        passphrase?.fill('\u0000')
        passphrase = null
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
        runCatching {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(KEY_ALIAS)
        }.onFailure { Log.w(TAG, "No se pudo borrar la clave del KeyStore", it) }
    }

    private fun loadOrCreatePassphrase(context: Context): CharArray {
        passphrase?.let { return it.copyOf() }

        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val keystore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val master = (keystore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey

        val existing = prefs.getString(PREF_BLOB, null)
        if (existing != null && master != null) {
            val decrypted = runCatching { decrypt(master, existing) }.getOrNull()
            if (decrypted != null) {
                return String(decrypted, Charsets.UTF_8).toCharArray()
            }
            // La clave existe pero no se puede descifrar (ROM modificada, backup restaurado en otro
            // móvil, KeyStore reseteado…). Sobrescribirla dejaría la base forense ilegible para
            // siempre. Se conserva el blob y se aborta: la app arranca con una base en memoria
            // (NyxDatabase.getInMemory), la UI avisa, y los datos cifrados siguen en disco hasta que
            // la clave vuelva a estar disponible.
            throw IllegalStateException(
                "Clave de la base forense ilegible con este AndroidKeyStore; se conserva el blob original"
            )
        }

        // Si hay un blob guardado pero el KeyStore no tiene la clave maestra (por ejemplo, el
        // usuario borró el llavero del sistema), NO se puede recuperar: mismo caso catastrófico que
        // un descifrado fallido. Se aborta sin tocar el blob.
        if (existing != null && master == null) {
            throw IllegalStateException(
                "La clave maestra del AndroidKeyStore ya no existe; se conserva el blob original"
            )
        }

        val secretKey = master ?: generateMasterKey()
        val dbKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        prefs.edit().putString(PREF_BLOB, encrypt(secretKey, dbKey)).apply()
        // CharArray (UTF-8) y no ByteArray: es lo que acepta SupportOpenHelperFactory.
        return String(dbKey.toHexBytes(), Charsets.UTF_8).toCharArray()
    }

    private fun generateMasterKey(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // No se pide autenticación del usuario: el servicio VPN y el monitor corren sin UI.
                .setUserAuthenticationRequired(false)
                .build()
        )
        return generator.generateKey()
    }

    private fun encrypt(key: SecretKey, plain: ByteArray): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val body = cipher.doFinal(plain)
        return Base64.encodeToString(iv + body, Base64.NO_WRAP)
    }

    private fun decrypt(key: SecretKey, blob: String): ByteArray {
        val raw = Base64.decode(blob, Base64.NO_WRAP)
        require(raw.size > 12) { "blob demasiado corto" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, raw, 0, 12))
        return cipher.doFinal(raw, 12, raw.size - 12)
    }

    private fun ByteArray.toHexBytes(): ByteArray {
        val hex = "0123456789abcdef".toByteArray(Charsets.US_ASCII)
        val out = ByteArray(size * 2)
        forEachIndexed { i, b ->
            val v = b.toInt() and 0xFF
            out[i * 2] = hex[v ushr 4]
            out[i * 2 + 1] = hex[v and 0x0F]
        }
        return out
    }

    /** Para pruebas: permite inyectar una clave sin KeyStore. */
    internal fun setPassphraseForTest(key: CharArray) {
        passphrase = key
    }

    /** Para pruebas: comprueba que una base abierta está realmente cifrada. */
    internal fun isDatabaseEncrypted(db: SupportSQLiteDatabase): Boolean = runCatching {
        db.query("PRAGMA cipher_version").use { it.moveToFirst() && it.getString(0) != null }
    }.getOrDefault(false)
}
