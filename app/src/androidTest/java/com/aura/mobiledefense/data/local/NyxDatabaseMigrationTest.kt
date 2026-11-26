package com.aura.mobiledefense.data.local

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Migraciones de verdad, ejecutadas contra SQLite real.
 *
 * La base guarda evidencia forense: si una migración está mal, el usuario no pierde una pantalla,
 * pierde su historial — y antes ni siquiera se podía arrancar (`version = 3` sin migraciones).
 *
 * Estrategia del test (sin JSONs de esquema): se crea una base v1/v2 con DDL crudo —los
 * `createSql` de las entidades—, se abre con **Room** y `AuraMigrations.ALL`, y se verifica el
 * resultado usando el DAO de producción (si una tabla no existe, Room falla) y el catálogo
 * `sqlite_master` para los índices. Es el mismo camino que la app usa en producción.
 */
@RunWith(AndroidJUnit4::class)
class NyxDatabaseMigrationTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val dbName = "migration-test.db"

    private val forensicSessionsDdl = """
        CREATE TABLE IF NOT EXISTS `forensic_sessions` (
            `id` TEXT NOT NULL,
            `timestamp` INTEGER NOT NULL,
            `query` TEXT NOT NULL,
            `title` TEXT NOT NULL,
            `visualKind` TEXT NOT NULL,
            `privilegeMode` TEXT NOT NULL,
            `severityScore` REAL NOT NULL,
            `toolExecuted` TEXT NOT NULL,
            `sceneJson` TEXT NOT NULL,
            PRIMARY KEY(`id`)
        )
    """.trimIndent()

    private val monitorTargetsDdl = """
        CREATE TABLE IF NOT EXISTS `monitor_targets` (
            `target` TEXT NOT NULL,
            `baselineRttMs` INTEGER NOT NULL,
            `lastRttMs` INTEGER NOT NULL,
            `baselineStatusCode` INTEGER NOT NULL,
            `lastStatusCode` INTEGER NOT NULL,
            `baselineTlsSha256` TEXT NOT NULL,
            `lastTlsSha256` TEXT NOT NULL,
            `baselineHeaderCount` INTEGER NOT NULL,
            `lastHeaderCount` INTEGER NOT NULL,
            `checkCount` INTEGER NOT NULL,
            `anomalyCount` INTEGER NOT NULL,
            `lastCheckedAt` INTEGER NOT NULL,
            `isActive` INTEGER NOT NULL,
            PRIMARY KEY(`target`)
        )
    """.trimIndent()

    private val anomalyEventsDdl = """
        CREATE TABLE IF NOT EXISTS `anomaly_events` (
            `id` TEXT NOT NULL,
            `target` TEXT NOT NULL,
            `kind` TEXT NOT NULL,
            `severity` TEXT NOT NULL,
            `description` TEXT NOT NULL,
            `timestamp` INTEGER NOT NULL,
            PRIMARY KEY(`id`)
        )
    """.trimIndent()

    // Reproduce exactamente lo que MIGRATION_1_2 deja en una base real (tablas e índices).
    // La entidad AnomalyEventEntity declara esos índices y Room los valida al migrar.
    private val migration12IndexDdl = listOf(
        "CREATE INDEX IF NOT EXISTS `index_anomaly_events_target` ON `anomaly_events` (`target`)",
        "CREATE INDEX IF NOT EXISTS `index_anomaly_events_timestamp` ON `anomaly_events` (`timestamp`)"
    )

    @Before
    fun setUp() {
        context.deleteDatabase(dbName)
    }

    @After
    fun tearDown() {
        context.deleteDatabase(dbName)
    }

    private fun createRawDatabase(version: Int, extraDdl: List<String> = emptyList()): File {
        val file = context.getDatabasePath(dbName)
        file.parentFile?.mkdirs()
        SQLiteDatabase.openOrCreateDatabase(file, null).apply {
            execSQL(forensicSessionsDdl)
            extraDdl.forEach { execSQL(it) }
            setVersion(version)
            close()
        }
        return file
    }

    private fun indexNames(file: File): List<String> =
        SQLiteDatabase.openDatabase(file.absolutePath, null, SQLiteDatabase.OPEN_READONLY).use { db ->
            db.rawQuery("SELECT name FROM sqlite_master WHERE type='index'", null).use { c ->
                val out = mutableListOf<String>()
                while (c.moveToNext()) out.add(c.getString(0))
                out
            }
        }

    private fun openWithRoom(): NyxDatabase =
        Room.databaseBuilder(context, NyxDatabase::class.java, dbName)
            .addMigrations(*AuraMigrations.ALL)
            .build()

    @Test
    fun migrate1To2CreatesMonitorTables() = runBlocking {
        val file = createRawDatabase(version = 1)

        val db = openWithRoom()
        try {
            db.forensicSessionDao().upsertMonitorTarget(
                MonitorTargetEntity(
                    target = "example.com",
                    baselineRttMs = 10, lastRttMs = 10,
                    baselineStatusCode = 200, lastStatusCode = 200,
                    baselineTlsSha256 = "a", lastTlsSha256 = "a",
                    baselineHeaderCount = 5, lastHeaderCount = 5,
                    checkCount = 1, anomalyCount = 0,
                    lastCheckedAt = 1L, isActive = true
                )
            )
            db.forensicSessionDao().insertAnomaly(
                AnomalyEventEntity(
                    id = "e1", target = "example.com", kind = "TLS_CHANGE",
                    severity = "HIGH", description = "huella TLS cambió", timestamp = 1L
                )
            )
            assertTrue(
                "falta el monitor_target",
                db.forensicSessionDao().getMonitorTarget("example.com")?.target == "example.com"
            )
        } finally {
            db.close()
        }

        val indices = indexNames(file)
        assertTrue("falta index_anomaly_events_target", "index_anomaly_events_target" in indices)
        assertTrue("falta index_anomaly_events_timestamp", "index_anomaly_events_timestamp" in indices)
    }

    @Test
    fun migrate2To3CreatesThreatAndFirewallTables() = runBlocking {
        val file = createRawDatabase(
            version = 2,
            extraDdl = listOf(monitorTargetsDdl, anomalyEventsDdl) + migration12IndexDdl
        )

        val db = openWithRoom()
        try {
            val dao = db.forensicSessionDao()
            dao.upsertThreatRules(
                listOf(
                    ThreatRuleEntity(
                        ruleId = "CVE-2026-0001", source = "CISA_KEV",
                        vendorOrCategory = "Vendor", title = "Prueba",
                        keywords = "vendor,producto", severity = 0.9f,
                        remediationHint = "parchea", updatedAt = 1L
                    )
                )
            )
            dao.upsertFirewallRule(
                FirewallRuleEntity(
                    id = "r1", pattern = "criteo.com", ruleType = "DOMAIN",
                    action = "BLOCK", reason = "rastreador", enabled = true, createdAt = 1L
                )
            )
            assertTrue("falta la regla CISA KEV", dao.countThreatRules() == 1)
            assertTrue("falta la regla de firewall", dao.countFirewallRules() == 1)
        } finally {
            db.close()
        }

        val indices = indexNames(file)
        assertTrue("falta index_threat_rules_vendorOrCategory", "index_threat_rules_vendorOrCategory" in indices)
        assertTrue("falta index_firewall_rules_pattern", "index_firewall_rules_pattern" in indices)
    }

    @Test
    fun fullPathPreservesExistingSessions() = runBlocking {
        val file = createRawDatabase(version = 1).also { f ->
            SQLiteDatabase.openOrCreateDatabase(f, null).use { db ->
                db.execSQL(
                    "INSERT INTO forensic_sessions " +
                        "(id, timestamp, query, title, visualKind, privilegeMode, severityScore, toolExecuted, sceneJson) " +
                        "VALUES ('s1', 123, 'audita todo', 'Auditoría', 'RADIAL', 'LOCAL', 0.42, 'FULL_AUTONOMOUS_AUDIT', '{}')"
                )
            }
        }

        val db = openWithRoom()
        try {
            val sessions = db.forensicSessionDao().observeSessions().first()
            assertTrue(
                "la sesión se perdió en la migración",
                sessions.any { it.id == "s1" && it.query == "audita todo" }
            )
            val dao = db.forensicSessionDao()
            dao.upsertFirewallRule(
                FirewallRuleEntity(
                    id = "r1", pattern = "criteo.com", ruleType = "DOMAIN",
                    action = "BLOCK", reason = "rastreador", enabled = true, createdAt = 1L
                )
            )
            assertTrue(dao.countFirewallRules() == 1)
        } finally {
            db.close()
        }
    }
}
