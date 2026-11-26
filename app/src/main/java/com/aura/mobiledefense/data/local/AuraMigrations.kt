package com.aura.mobiledefense.data.local

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * Migraciones reales de la base forense.
 *
 * `version = 3` con `MIGRATIONS` vacío y sin `app/schemas/` significaba que cualquier usuario con la
 * versión anterior instalada recibía un `IllegalStateException` de Room al abrir la base: la app
 * moría en el arranque, sin arreglo salvo desinstalar (y perder la evidencia forense, que es
 * justamente lo que la app promete conservar).
 *
 * Las migraciones son defensivas: comprueban si la tabla existe antes de tocar nada, porque la
 * versión inicial pudo crearse con `fallbackToDestructiveMigration` en alguna instalación previa.
 * Una migración que no hace nada es preferible a una que borra.
 */
object AuraMigrations {

    /** v1 → v2: añadida la tabla de destinos monitorizados. */
    val MIGRATION_1_2 = object : Migration(1, 2) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                """
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
            )
            db.execSQL(
                """
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
            )
            db.execSQL("CREATE INDEX IF NOT EXISTS `index_anomaly_events_target` ON `anomaly_events` (`target`)")
            db.execSQL("CREATE INDEX IF NOT EXISTS `index_anomaly_events_timestamp` ON `anomaly_events` (`timestamp`)")
        }
    }

    /** v2 → v3: añadida la base de conocimiento de amenazas y las reglas de firewall. */
    val MIGRATION_2_3 = object : Migration(2, 3) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                """
                CREATE TABLE IF NOT EXISTS `threat_rules` (
                    `ruleId` TEXT NOT NULL,
                    `source` TEXT NOT NULL,
                    `vendorOrCategory` TEXT NOT NULL,
                    `title` TEXT NOT NULL,
                    `keywords` TEXT NOT NULL,
                    `severity` REAL NOT NULL,
                    `remediationHint` TEXT NOT NULL,
                    `updatedAt` INTEGER NOT NULL,
                    PRIMARY KEY(`ruleId`)
                )
                """.trimIndent()
            )
            db.execSQL(
                """
                CREATE TABLE IF NOT EXISTS `firewall_rules` (
                    `id` TEXT NOT NULL,
                    `pattern` TEXT NOT NULL,
                    `ruleType` TEXT NOT NULL,
                    `action` TEXT NOT NULL,
                    `reason` TEXT NOT NULL,
                    `enabled` INTEGER NOT NULL,
                    `createdAt` INTEGER NOT NULL,
                    PRIMARY KEY(`id`)
                )
                """.trimIndent()
            )
            db.execSQL("CREATE INDEX IF NOT EXISTS `index_threat_rules_vendorOrCategory` ON `threat_rules` (`vendorOrCategory`)")
            db.execSQL("CREATE INDEX IF NOT EXISTS `index_firewall_rules_pattern` ON `firewall_rules` (`pattern`)")
        }
    }

    /** v3 → v4: índice sobre forensic_sessions.timestamp (ORDER BY del historial). */
    val MIGRATION_3_4 = object : Migration(3, 4) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("CREATE INDEX IF NOT EXISTS `index_forensic_sessions_timestamp` ON `forensic_sessions` (`timestamp`)")
        }
    }

    val ALL: Array<Migration> = arrayOf(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4)
}
