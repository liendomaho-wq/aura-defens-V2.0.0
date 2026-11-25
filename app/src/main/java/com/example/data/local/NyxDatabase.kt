package com.example.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [
        ForensicSessionEntity::class,
        MonitorTargetEntity::class,
        AnomalyEventEntity::class,
        ThreatRuleEntity::class,
        FirewallRuleEntity::class
    ],
    version = 3,
    exportSchema = false
)
abstract class NyxDatabase : RoomDatabase() {
    abstract fun forensicSessionDao(): ForensicSessionDao

    companion object {
        @Volatile
        private var INSTANCE: NyxDatabase? = null

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
                        .fallbackToDestructiveMigration(dropAllTables = true)
                        .build()
                        .also { INSTANCE = it }
                }
            }
        }
    }
}
