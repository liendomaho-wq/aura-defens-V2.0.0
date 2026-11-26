package com.aura.mobiledefense.data.local

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "forensic_sessions")
data class ForensicSessionEntity(
    @PrimaryKey val id: String,
    val timestamp: Long,
    val query: String,
    val title: String,
    val visualKind: String,
    val privilegeMode: String,
    val severityScore: Float,
    val toolExecuted: String,
    val sceneJson: String
)

@Entity(tableName = "monitor_targets")
data class MonitorTargetEntity(
    @PrimaryKey val target: String,
    val baselineRttMs: Long,
    val lastRttMs: Long,
    val baselineStatusCode: Int,
    val lastStatusCode: Int,
    val baselineTlsSha256: String,
    val lastTlsSha256: String,
    val baselineHeaderCount: Int,
    val lastHeaderCount: Int,
    val checkCount: Int,
    val anomalyCount: Int,
    val lastCheckedAt: Long,
    val isActive: Boolean
)

@Entity(tableName = "anomaly_events")
data class AnomalyEventEntity(
    @PrimaryKey val id: String,
    val target: String,
    val kind: String,
    val severity: String,
    val description: String,
    val timestamp: Long
)

@Entity(tableName = "threat_rules")
data class ThreatRuleEntity(
    @PrimaryKey val ruleId: String,
    val source: String,
    val vendorOrCategory: String,
    val title: String,
    val keywords: String,
    val severity: Float,
    val remediationHint: String,
    val updatedAt: Long
)

@Entity(tableName = "firewall_rules")
data class FirewallRuleEntity(
    @PrimaryKey val id: String,
    val pattern: String,
    val ruleType: String,
    val action: String,
    val reason: String,
    val enabled: Boolean,
    val createdAt: Long
)

