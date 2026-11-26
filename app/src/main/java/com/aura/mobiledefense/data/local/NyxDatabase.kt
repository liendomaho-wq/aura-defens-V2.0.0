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

        /**
         * Base **en memoria** para cuando el AndroidKeyStore no puede entregar (ni crear) la clave
         * de SQLCipher: la app sigue funcionando y avisa de que la evidencia no se persistirá, en
         * vez de morir en el arranque. Nunca se usa para sobrescribir la base cifrada existente.
         */
        fun getInMemory(context: Context): NyxDatabase =
            Room.inMemoryDatabaseBuilder(context.applicationContext, NyxDatabase::class.java).build()

        /**
         * Variante tolerante a fallos del KeyStore para rutas que no pueden permitirse lanzar:
         * el servicio VPN se inicializa antes de que la UI pueda avisar, así que si cifrar en
         * reposo no es posible (KeyStore roto, ROM restaurada…) se usa una base volátil en
         * memoria en vez de tumbar el firewall. La UI se entera por
         * [AuraDatabaseCipher.lastFaultReason]. getInstance sigue lanzando a propósito.
         */
        fun getOrInMemory(context: Context): NyxDatabase =
            runCatching { getInstance(context) }.getOrElse { getInMemory(context) }

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
                        // Cifrado en reposo: la evidencia forense (hosts auditados, CVE que te
                        // afectan, historial) es de lo más sensible que guarda la app. SQLCipher
                        // cifra el archivo completo con una clave del AndroidKeyStore, así que un
                        // backup de la carpeta o un móvil con root no lo lee en claro.
                        .openHelperFactory(AuraDatabaseCipher.factory(context))
                        .build()
                        .also { INSTANCE = it }
                }
            }
        }
    }
}
