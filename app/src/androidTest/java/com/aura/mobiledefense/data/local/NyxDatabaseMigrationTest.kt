package com.aura.mobiledefense.data.local

import androidx.room.testing.MigrationTestHelper
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Migraciones de verdad, ejecutadas contra SQLite.
 *
 * La base guarda evidencia forense: si una migración está mal, el usuario no pierde una pantalla,
 * pierde su historial — y antes ni siquiera se podía arrancar (`version = 3` sin migraciones).
 */
@RunWith(AndroidJUnit4::class)
class NyxDatabaseMigrationTest {

    @get:Rule
    val helper = MigrationTestHelper(
        InstrumentationRegistry.getInstrumentation(),
        NyxDatabase::class.java
    )

    private val dbName = "migration-test.db"

    @Test
    fun migrate1To2CreatesMonitorTables() {
        helper.createDatabase(dbName, 1).close()
        val db = helper.runMigrationsAndValidate(dbName, 2, true, AuraMigrations.MIGRATION_1_2)

        db.query("SELECT name FROM sqlite_master WHERE type='table' AND name='monitor_targets'").use {
            assertTrue("falta monitor_targets", it.moveToFirst())
        }
        db.query("SELECT name FROM sqlite_master WHERE type='table' AND name='anomaly_events'").use {
            assertTrue("falta anomaly_events", it.moveToFirst())
        }
    }

    @Test
    fun migrate2To3CreatesThreatAndFirewallTables() {
        helper.createDatabase(dbName, 2).close()
        val db = helper.runMigrationsAndValidate(dbName, 3, true, AuraMigrations.MIGRATION_2_3)

        db.query("SELECT name FROM sqlite_master WHERE type='table' AND name='threat_rules'").use {
            assertTrue("falta threat_rules", it.moveToFirst())
        }
        db.query("SELECT name FROM sqlite_master WHERE type='table' AND name='firewall_rules'").use {
            assertTrue("falta firewall_rules", it.moveToFirst())
        }
    }

    @Test
    fun fullPathPreservesExistingSessions() {
        helper.createDatabase(dbName, 1).apply {
            execSQL(
                """
                INSERT INTO forensic_sessions
                (id, timestamp, query, title, visualKind, privilegeMode, severityScore, toolExecuted, sceneJson)
                VALUES ('s1', 123, 'audita todo', 'Auditoría', 'RADIAL', 'LOCAL', 0.42, 'FULL_AUTONOMOUS_AUDIT', '{}')
                """.trimIndent()
            )
            close()
        }

        val db = helper.runMigrationsAndValidate(
            dbName, 3, true, AuraMigrations.MIGRATION_1_2, AuraMigrations.MIGRATION_2_3
        )
        db.query("SELECT query FROM forensic_sessions WHERE id='s1'").use {
            assertTrue("la sesión se perdió en la migración", it.moveToFirst())
            assertTrue(it.getString(0) == "audita todo")
        }
        // Y las tablas nuevas funcionan
        db.execSQL(
            "INSERT INTO firewall_rules (id, pattern, ruleType, action, reason, enabled, createdAt) " +
                "VALUES ('r1', 'criteo.com', 'DOMAIN', 'BLOCK', 'rastreador', 1, 1)"
        )
        db.query("SELECT COUNT(*) FROM firewall_rules").use {
            assertTrue(it.moveToFirst() && it.getInt(0) == 1)
        }
    }
}
