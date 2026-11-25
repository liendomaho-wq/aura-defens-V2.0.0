package com.aura.mobiledefense.data.local

import com.aura.mobiledefense.data.model.AiEngineMode
import com.aura.mobiledefense.data.model.AiStratumLayer
import com.aura.mobiledefense.data.model.AiVisualEdge
import com.aura.mobiledefense.data.model.AiVisualNode
import com.aura.mobiledefense.data.model.AiVisualScene
import com.aura.mobiledefense.data.model.AnomalyAlert
import com.aura.mobiledefense.data.model.CompleteAuditReport
import com.aura.mobiledefense.data.model.GeneratedPatch
import com.aura.mobiledefense.data.model.MonitorTargetSnapshot
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.data.model.VisualTopologyKind
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.json.JSONArray
import org.json.JSONObject

class ForensicSessionRepository(
    private val dao: ForensicSessionDao
) {
    val sessions: Flow<List<AiVisualScene>> = dao.observeSessions().map { entities ->
        entities.mapNotNull { decodeScene(it.sceneJson) }
    }

    val monitorTargets: Flow<List<MonitorTargetSnapshot>> = dao.observeMonitorTargets().map { list ->
        list.map {
            MonitorTargetSnapshot(
                target = it.target,
                lastStatusCode = it.lastStatusCode,
                baselineRttMs = it.baselineRttMs,
                lastRttMs = it.lastRttMs,
                baselineTlsSha256 = it.baselineTlsSha256,
                lastTlsSha256 = it.lastTlsSha256,
                checkCount = it.checkCount,
                anomalyCount = it.anomalyCount,
                lastCheckedAt = it.lastCheckedAt,
                isActive = it.isActive
            )
        }
    }

    val anomalies: Flow<List<AnomalyAlert>> = dao.observeAnomalies().map { list ->
        list.map {
            AnomalyAlert(
                id = it.id,
                target = it.target,
                kind = it.kind,
                severity = it.severity,
                description = it.description,
                timestamp = it.timestamp
            )
        }
    }

    suspend fun saveScene(scene: AiVisualScene) {
        val entity = ForensicSessionEntity(
            id = scene.id,
            timestamp = scene.timestamp,
            query = scene.query,
            title = scene.title,
            visualKind = scene.visualKind.name,
            privilegeMode = scene.privilegeMode.name,
            severityScore = scene.severityScore,
            toolExecuted = scene.toolExecuted,
            sceneJson = encodeScene(scene)
        )
        dao.upsertSession(entity)
    }

    suspend fun deleteSession(id: String) = dao.deleteSession(id)

    suspend fun clearHistory() = dao.clearAll()

    private fun encodeScene(scene: AiVisualScene): String {
        val root = JSONObject().apply {
            put("id", scene.id)
            put("timestamp", scene.timestamp)
            put("query", scene.query)
            put("title", scene.title)
            put("subtitle", scene.subtitle)
            put("visualKind", scene.visualKind.name)
            put("severityScore", scene.severityScore.toDouble())
            put("narrative", scene.narrative)
            put("rawTelemetry", scene.rawTelemetry)
            put("toolExecuted", scene.toolExecuted)
            put("privilegeMode", scene.privilegeMode.name)
            put("engineMode", scene.engineMode.name)
            put("technicalFindings", JSONArray(scene.technicalFindings))
            put("whisperPrompts", JSONArray(scene.whisperPrompts))
            put("spectrumValues", JSONArray(scene.spectrumValues.map { it.toDouble() }))
            put("nodes", JSONArray().apply {
                scene.nodes.forEach { n ->
                    put(JSONObject().apply {
                        put("id", n.id)
                        put("label", n.label)
                        put("sublabel", n.sublabel)
                        put("category", n.category)
                        put("riskScore", n.riskScore.toDouble())
                        put("xNorm", n.xNorm.toDouble())
                        put("yNorm", n.yNorm.toDouble())
                        put("forensicDetail", n.forensicDetail)
                        put("layerIndex", n.layerIndex)
                    })
                }
            })
            put("edges", JSONArray().apply {
                scene.edges.forEach { e ->
                    put(JSONObject().apply {
                        put("fromId", e.fromId)
                        put("toId", e.toId)
                        put("relation", e.relation)
                        put("intensity", e.intensity.toDouble())
                    })
                }
            })
            put("strata", JSONArray().apply {
                scene.strata.forEach { s ->
                    put(JSONObject().apply {
                        put("name", s.name)
                        put("status", s.status)
                        put("healthScore", s.healthScore.toDouble())
                        put("summary", s.summary)
                    })
                }
            })
            scene.report?.let { r ->
                put("report", JSONObject().apply {
                    put("whatWasDone", r.whatWasDone)
                    put("whatWasFound", r.whatWasFound)
                    put("measuresAndPatchesTaken", r.measuresAndPatchesTaken)
                    put("improvementRecommendations", r.improvementRecommendations)
                })
            }
            put("patches", JSONArray().apply {
                scene.patches.forEach { p ->
                    put(JSONObject().apply {
                        put("id", p.id)
                        put("title", p.title)
                        put("targetArtifact", p.targetArtifact)
                        put("severity", p.severity)
                        put("rationale", p.rationale)
                        put("patchContent", p.patchContent)
                    })
                }
            })
        }
        return root.toString()
    }

    private fun decodeScene(json: String): AiVisualScene? {
        return try {
            val obj = JSONObject(json)
            val findingsArr = obj.optJSONArray("technicalFindings") ?: JSONArray()
            val whispersArr = obj.optJSONArray("whisperPrompts") ?: JSONArray()
            val spectrumArr = obj.optJSONArray("spectrumValues") ?: JSONArray()
            val nodesArr = obj.optJSONArray("nodes") ?: JSONArray()
            val edgesArr = obj.optJSONArray("edges") ?: JSONArray()
            val strataArr = obj.optJSONArray("strata") ?: JSONArray()
            val patchesArr = obj.optJSONArray("patches") ?: JSONArray()
            val reportObj = obj.optJSONObject("report")

            AiVisualScene(
                id = obj.getString("id"),
                timestamp = obj.optLong("timestamp", System.currentTimeMillis()),
                query = obj.optString("query", ""),
                title = obj.optString("title", "Sesión Aura"),
                subtitle = obj.optString("subtitle", ""),
                visualKind = VisualTopologyKind.fromWire(
                    obj.optString("visualKind", "NEURAL_SYNAPTIC_LATTICE")
                ),
                severityScore = obj.optDouble("severityScore", 0.3).toFloat().coerceIn(0f, 1f),
                narrative = obj.optString("narrative", ""),
                technicalFindings = (0 until findingsArr.length()).map { findingsArr.getString(it) },
                nodes = (0 until nodesArr.length()).map { i ->
                    val n = nodesArr.getJSONObject(i)
                    AiVisualNode(
                        id = n.optString("id", "n$i"),
                        label = n.optString("label", "Neurona"),
                        sublabel = n.optString("sublabel", ""),
                        category = n.optString("category", "CORE"),
                        riskScore = n.optDouble("riskScore", 0.3).toFloat().coerceIn(0f, 1f),
                        xNorm = n.optDouble("xNorm", 0.5).toFloat().coerceIn(0.08f, 0.92f),
                        yNorm = n.optDouble("yNorm", 0.5).toFloat().coerceIn(0.10f, 0.88f),
                        forensicDetail = n.optString("forensicDetail", ""),
                        layerIndex = n.optInt("layerIndex", 1)
                    )
                },
                edges = (0 until edgesArr.length()).map { i ->
                    val e = edgesArr.getJSONObject(i)
                    AiVisualEdge(
                        fromId = e.optString("fromId", ""),
                        toId = e.optString("toId", ""),
                        relation = e.optString("relation", ""),
                        intensity = e.optDouble("intensity", 0.5).toFloat().coerceIn(0.1f, 1f)
                    )
                },
                strata = (0 until strataArr.length()).map { i ->
                    val s = strataArr.getJSONObject(i)
                    AiStratumLayer(
                        name = s.optString("name", "Capa"),
                        status = s.optString("status", "NOMINAL"),
                        healthScore = s.optDouble("healthScore", 0.8).toFloat().coerceIn(0f, 1f),
                        summary = s.optString("summary", "")
                    )
                },
                spectrumValues = (0 until spectrumArr.length()).map {
                    spectrumArr.optDouble(it, 0.4).toFloat().coerceIn(0.05f, 1f)
                },
                whisperPrompts = (0 until whispersArr.length()).map { whispersArr.getString(it) },
                rawTelemetry = obj.optString("rawTelemetry", ""),
                toolExecuted = obj.optString("toolExecuted", "FULL_AUDIT"),
                privilegeMode = if (obj.optString("privilegeMode") == PrivilegeMode.ROOT.name) {
                    PrivilegeMode.ROOT
                } else {
                    PrivilegeMode.USERLAND
                },
                engineMode = if (obj.optString("engineMode") == AiEngineMode.LOCAL_AUTONOMOUS.name) {
                    AiEngineMode.LOCAL_AUTONOMOUS
                } else {
                    AiEngineMode.ONLINE_CLOUD
                },
                report = reportObj?.let {
                    CompleteAuditReport(
                        whatWasDone = it.optString("whatWasDone", ""),
                        whatWasFound = it.optString("whatWasFound", ""),
                        measuresAndPatchesTaken = it.optString("measuresAndPatchesTaken", ""),
                        improvementRecommendations = it.optString("improvementRecommendations", "")
                    )
                },
                patches = (0 until patchesArr.length()).map { i ->
                    val p = patchesArr.getJSONObject(i)
                    GeneratedPatch(
                        id = p.optString("id", "patch_$i"),
                        title = p.optString("title", "Parche"),
                        targetArtifact = p.optString("targetArtifact", ""),
                        severity = p.optString("severity", "MEDIA"),
                        rationale = p.optString("rationale", ""),
                        patchContent = p.optString("patchContent", "")
                    )
                }
            )
        } catch (_: Exception) {
            null
        }
    }
}
