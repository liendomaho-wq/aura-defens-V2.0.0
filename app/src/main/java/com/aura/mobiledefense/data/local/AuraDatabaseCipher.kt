package com.aura.mobiledefense.data.local

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
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
 * - Si algo falla al abrir, se avisa por log y se cae al modo sin cifrar **solo** para no dejar la
 *   app inservible: nunca se borra la base del usuario.
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

    /** ¿Está la base realmente cifrada? Lo consulta el aviso de seguridad de la UI. */
    fun isEncrypted(): Boolean = passphrase != null

    fun factory(context: Context): SupportSQLiteOpenHelper.Factory {
        val key = runCatching { loadOrCreatePassphrase(context.applicationContext) }
            .onFailure { Log.e(TAG, "No se pudo obtener la clave del KeyStore; base sin cifrar", it) }
            .getOrNull()

        if (key == null || key.isEmpty()) {
            return FrameworkSQLiteOpenHelperFactory()
        }
        passphrase = key
        return SupportOpenHelperFactory(key.copyOf())
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
            runCatching { return decrypt(master, existing).toCharArray() }
                .onFailure { Log.e(TAG, "Blob de clave ilegible; se genera uno nuevo", it) }
        }

        val secretKey = master ?: generateMasterKey()
        val dbKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        prefs.edit().putString(PREF_BLOB, encrypt(secretKey, dbKey)).apply()
        return dbKey.toHexChars()
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

    private fun ByteArray.toHexChars(): CharArray {
        val hex = "0123456789abcdef"
        val out = CharArray(size * 2)
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
