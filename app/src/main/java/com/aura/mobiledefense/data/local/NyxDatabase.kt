package com.aura.mobiledefense.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration

@Database(
    entities = [
        ForensicSessionEntity::class,
        MonitorTargetEntity::class,
        AnomalyEventEntity::class,
        ThreatRuleEntity::class,
        FirewallRuleEntity::class
    ],
    version = 3,
    exportSchema = true
)
abstract class NyxDatabase : RoomDatabase() {
    abstract fun forensicSessionDao(): ForensicSessionDao

    companion object {
        @Volatile
        private var INSTANCE: NyxDatabase? = null

        /**
         * Migraciones reales (ver [AuraMigrations]). Cada subida de `version` debe añadir la suya:
         * la base guarda evidencia forense y no hay fallback destructivo.
         */
        private val MIGRATIONS: Array<Migration> = AuraMigrations.ALL

        fun getInstance(context: Context): NyxDatabase {
            val current = INSTANCE
            if (current != null && current.isOpen) return current
            return synchronized(this) {
                val existing = INSTANCE
                if (existing != null && existing.isOpen) {
                    existing
                } else {
                    Room.databaseBuilder(
                        context.applicationContext,
                        NyxDatabase::class.java,
                        "aura_defense_forensics.db"
                    )
                        // No destructive fallback: this database holds forensic evidence, anomaly
                        // history and firewall rules. Every schema change must ship a real Migration
                        // in `migrations` below instead of silently wiping the user's history.
                        .addMigrations(*MIGRATIONS)
                        .build()
                        .also { INSTANCE = it }
                }
            }
        }
    }
}
