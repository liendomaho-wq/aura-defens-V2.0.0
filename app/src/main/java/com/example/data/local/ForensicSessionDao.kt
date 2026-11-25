package com.example.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ForensicSessionDao {
    @Query("SELECT * FROM forensic_sessions ORDER BY timestamp DESC LIMIT 50")
    fun observeSessions(): Flow<List<ForensicSessionEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertSession(entity: ForensicSessionEntity)

    @Query("DELETE FROM forensic_sessions WHERE id = :id")
    suspend fun deleteSession(id: String)

    @Query("DELETE FROM forensic_sessions")
    suspend fun clearAll()

    // Monitor targets & baselines
    @Query("SELECT * FROM monitor_targets ORDER BY lastCheckedAt DESC")
    fun observeMonitorTargets(): Flow<List<MonitorTargetEntity>>

    @Query("SELECT * FROM monitor_targets WHERE isActive = 1")
    suspend fun getActiveMonitorTargets(): List<MonitorTargetEntity>

    @Query("SELECT * FROM monitor_targets WHERE target = :target LIMIT 1")
    suspend fun getMonitorTarget(target: String): MonitorTargetEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertMonitorTarget(entity: MonitorTargetEntity)

    @Query("DELETE FROM monitor_targets WHERE target = :target")
    suspend fun deleteMonitorTarget(target: String)

    // Anomaly events
    @Query("SELECT * FROM anomaly_events ORDER BY timestamp DESC LIMIT 40")
    fun observeAnomalies(): Flow<List<AnomalyEventEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAnomaly(entity: AnomalyEventEntity)

    // Self-trained threat rules (CISA KEV + local heuristics)
    @Query("SELECT * FROM threat_rules ORDER BY updatedAt DESC LIMIT 300")
    suspend fun getAllThreatRules(): List<ThreatRuleEntity>

    @Query("SELECT COUNT(*) FROM threat_rules")
    suspend fun countThreatRules(): Int

    @Query("SELECT COUNT(*) FROM threat_rules WHERE source = 'CISA_KEV'")
    suspend fun countCisaKevRules(): Int

    @Query("SELECT MAX(updatedAt) FROM threat_rules")
    suspend fun getLastTrainedTimestamp(): Long?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertThreatRules(rules: List<ThreatRuleEntity>)

    // Local VPN Firewall Rules
    @Query("SELECT * FROM firewall_rules ORDER BY createdAt DESC")
    fun observeFirewallRules(): Flow<List<FirewallRuleEntity>>

    @Query("SELECT * FROM firewall_rules WHERE enabled = 1")
    suspend fun getEnabledFirewallRules(): List<FirewallRuleEntity>

    @Query("SELECT COUNT(*) FROM firewall_rules")
    suspend fun countFirewallRules(): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertFirewallRule(rule: FirewallRuleEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertFirewallRules(rules: List<FirewallRuleEntity>)

    @Query("DELETE FROM firewall_rules WHERE pattern = :pattern OR id = :pattern")
    suspend fun deleteFirewallRuleByPatternOrId(pattern: String)
}

