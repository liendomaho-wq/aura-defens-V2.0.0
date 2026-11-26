package com.aura.mobiledefense.data.local

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.RandomAccessFile

/**
 * Cifrado en reposo: se comprueba en el archivo, no en la intención.
 *
 * Escribir una sesión y leerla demuestra que la app funciona; lo que importa aquí es que
 * **los bytes del archivo no contengan el texto en claro**. Si el cifrado se cae en silencio
 * (clave no disponible, fallback a SQLite normal), esta prueba lo detecta.
 */
@RunWith(AndroidJUnit4::class)
class DatabaseEncryptionTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val dbName = "encryption-test.db"
    private lateinit var db: NyxDatabase

    @Before
    fun setUp() {
        System.loadLibrary("sqlcipher")
        AuraDatabaseCipher.setPassphraseForTest(
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".toCharArray()
        )
        context.deleteDatabase(dbName)
        db = Room.databaseBuilder(context, NyxDatabase::class.java, dbName)
            .addMigrations(*AuraMigrations.ALL)
            .openHelperFactory(AuraDatabaseCipher.factory(context))
            .build()
    }

    @After
    fun tearDown() {
        db.close()
        context.deleteDatabase(dbName)
    }

    @Test
    fun databaseFileIsEncryptedAndReadable() = runBlocking {
        val secretQuery = "audita midominio.example"
        db.forensicSessionDao().upsertSession(
            ForensicSessionEntity(
                id = "s1",
                timestamp = 1L,
                query = secretQuery,
                title = "Auditoría",
                visualKind = "RADIAL",
                privilegeMode = "LOCAL",
                severityScore = 0.5f,
                toolExecuted = "FULL_AUTONOMOUS_AUDIT",
                sceneJson = "{}"
            )
        )
        // La app lee sus propios datos...
        assertTrue(db.forensicSessionDao().observeSessions().first().any { it.query == secretQuery })

        // ...pero el archivo no los contiene en claro.
        val file = File(context.getDatabasePath(dbName).absolutePath)
        assertTrue("la base no se creó", file.exists())
        val bytes = ByteArray(file.length().toInt().coerceAtMost(2_000_000))
        RandomAccessFile(file, "r").use { it.readFully(bytes) }
        val asText = String(bytes, Charsets.ISO_8859_1)
        assertFalse(
            "el texto de la consulta está en claro dentro del archivo",
            asText.contains(secretQuery)
        )
        // Y la cabecera no es la de SQLite ("SQLite format 3").
        assertFalse(asText.startsWith("SQLite format 3"))
    }

    @Test
    fun sqlcipherIsActuallyCompiledIn() {
        val helper = AuraDatabaseCipher.factory(context).create(
            androidx.sqlite.db.SupportSQLiteOpenHelper.Configuration.builder(context)
                .name("probe.db")
                .callback(object : androidx.sqlite.db.SupportSQLiteOpenHelper.Callback(1) {
                    override fun onCreate(db: androidx.sqlite.db.SupportSQLiteDatabase) = Unit
                    override fun onUpgrade(
                        db: androidx.sqlite.db.SupportSQLiteDatabase, old: Int, new: Int
                    ) = Unit
                })
                .build()
        )
        val writable = helper.writableDatabase
        assertTrue(
            "SQLCipher no está activo: la base quedaría sin cifrar",
            AuraDatabaseCipher.isDatabaseEncrypted(writable)
        )
        helper.close()
        context.deleteDatabase("probe.db")
    }
}
