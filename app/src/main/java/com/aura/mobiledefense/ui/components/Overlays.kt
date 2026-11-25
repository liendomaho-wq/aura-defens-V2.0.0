package com.aura.mobiledefense.ui.components

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.aura.mobiledefense.R
import com.aura.mobiledefense.data.model.AiVisualNode
import com.aura.mobiledefense.data.model.AiVisualScene
import com.aura.mobiledefense.data.model.AnomalyAlert
import com.aura.mobiledefense.data.model.MonitorTargetSnapshot
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.ui.theme.NyxAmber
import com.aura.mobiledefense.ui.theme.NyxCrimson
import com.aura.mobiledefense.ui.theme.NyxCyan
import com.aura.mobiledefense.ui.theme.NyxEmerald
import com.aura.mobiledefense.ui.theme.NyxHairline
import com.aura.mobiledefense.ui.theme.NyxSurface
import com.aura.mobiledefense.ui.theme.NyxTextMuted
import com.aura.mobiledefense.ui.theme.NyxTextPrimary
import com.aura.mobiledefense.ui.theme.NyxTextSecondary
import com.aura.mobiledefense.ui.theme.NyxViolet
import com.aura.mobiledefense.ui.theme.NyxVoid
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun NodeDeepDiveOverlay(
    node: AiVisualNode,
    onDismiss: () -> Unit,
    onPivotNode: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    BackHandler(onBack = onDismiss)
    val cdNode = stringResource(R.string.cd_node_overlay)
    val riskColor = when {
        node.riskScore >= 0.78f -> NyxCrimson
        node.riskScore >= 0.48f -> NyxAmber
        else -> NyxEmerald
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(NyxVoid.copy(alpha = 0.65f))
            .pointerInput(Unit) {
                var dragY = 0f
                detectVerticalDragGestures(
                    onDragStart = { dragY = 0f },
                    onVerticalDrag = { _, delta -> dragY += delta },
                    onDragEnd = { if (dragY > 65f) onDismiss() }
                )
            }
            .clickable(onClick = onDismiss),
        contentAlignment = Alignment.BottomCenter
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 640.dp)
                .fillMaxWidth()
                .background(
                    Brush.verticalGradient(listOf(NyxSurface.copy(alpha = 0.96f), NyxVoid)),
                    RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp)
                )
                .clickable(enabled = false) {}
                .navigationBarsPadding()
                .padding(horizontal = 24.dp, vertical = 18.dp)
                .testTag("node_deep_dive_overlay")
                .semantics { contentDescription = cdNode }
        ) {
            Box(
                modifier = Modifier
                    .align(Alignment.CenterHorizontally)
                    .width(42.dp)
                    .height(3.dp)
                    .clip(RoundedCornerShape(2.dp))
                    .background(NyxHairline)
            )

            Spacer(modifier = Modifier.height(14.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "${node.category.uppercase()} · CAPA ${node.layerIndex + 1}",
                    style = MaterialTheme.typography.labelMedium.copy(color = riskColor)
                )
                Text(
                    text = "RIESGO ${(node.riskScore * 100).toInt()}%",
                    style = MaterialTheme.typography.labelMedium.copy(
                        color = riskColor,
                        fontWeight = FontWeight.Bold
                    )
                )
            }

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = node.label,
                style = MaterialTheme.typography.headlineSmall.copy(color = NyxTextPrimary)
            )
            if (node.sublabel.isNotBlank()) {
                Text(
                    text = node.sublabel,
                    style = MaterialTheme.typography.bodySmall.copy(color = NyxTextSecondary)
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = node.forensicDetail.ifBlank { "Sin telemetría extendida para esta neurona." },
                style = MaterialTheme.typography.bodyMedium.copy(color = NyxTextPrimary)
            )

            Spacer(modifier = Modifier.height(14.dp))

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag("node_pivot_whisper")
                    .clickable {
                        onPivotNode("Profundizar auditoría y parches sobre ${node.label} (${node.sublabel})")
                    },
                contentAlignment = Alignment.CenterStart
            ) {
                Text(
                    text = "↳ profundizar análisis y generar solución sobre ${node.label}",
                    style = MaterialTheme.typography.bodySmall.copy(color = NyxCyan)
                )
            }

            Text(
                text = "Desliza ↓ o toca fuera para volver a la red neuronal",
                style = MaterialTheme.typography.labelSmall.copy(color = NyxTextMuted)
            )
        }
    }
}

@Composable
fun ReportAndPatchOverlay(
    scene: AiVisualScene,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    BackHandler(onBack = onDismiss)
    val context = LocalContext.current
    var copiedPatchTitle by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(copiedPatchTitle) {
        if (copiedPatchTitle != null) {
            delay(2000L)
            copiedPatchTitle = null
        }
    }

    val fullMarkdownExport = remember(scene.id) {
        buildString {
            appendLine("# Reporte Aura Mobile Defense: ${scene.title}")
            appendLine("Modo: ${scene.privilegeMode.name} | Motor: ${scene.engineMode.name}")
            scene.report?.let { r ->
                appendLine("\n## 1. Qué se hizo\n${r.whatWasDone}")
                appendLine("\n## 2. Qué se encontró\n${r.whatWasFound}")
                appendLine("\n## 3. Medidas y parches generados\n${r.measuresAndPatchesTaken}")
                appendLine("\n## 4. Recomendaciones de mejora\n${r.improvementRecommendations}")
            }
            if (scene.patches.isNotEmpty()) {
                appendLine("\n## Parches Generados")
                scene.patches.forEach { p ->
                    appendLine("\n### ${p.title} (${p.targetArtifact}) [${p.severity}]")
                    appendLine(p.rationale)
                    appendLine("```\n${p.patchContent}\n```")
                }
            }
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(NyxVoid.copy(alpha = 0.97f))
            .statusBarsPadding()
            .navigationBarsPadding()
            .pointerInput(Unit) {
                var dragY = 0f
                detectVerticalDragGestures(
                    onDragStart = { dragY = 0f },
                    onVerticalDrag = { _, d -> dragY += d },
                    onDragEnd = { if (dragY > 85f) onDismiss() }
                )
            }
            .padding(horizontal = 20.dp, vertical = 16.dp)
            .testTag("report_patch_overlay")
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "REPORTE INTEGRAL & PARCHES",
                style = MaterialTheme.typography.titleMedium.copy(
                    color = NyxTextPrimary,
                    fontWeight = FontWeight.Bold
                )
            )
            Text(
                text = "doble toque = exportar",
                style = MaterialTheme.typography.labelSmall.copy(color = NyxCyan),
                modifier = Modifier.pointerInput(scene.id) {
                    detectTapGestures(
                        onDoubleTap = {
                            val share = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_SUBJECT, "Aura Reporte: ${scene.title}")
                                putExtra(Intent.EXTRA_TEXT, fullMarkdownExport)
                            }
                            context.startActivity(Intent.createChooser(share, "Exportar reporte y parches"))
                        }
                    )
                }
            )
        }

        Text(
            text = "Desliza ↓ para cerrar · Mantén presionado cualquier parche para copiarlo",
            style = MaterialTheme.typography.labelSmall.copy(color = NyxTextMuted),
            modifier = Modifier.padding(top = 4.dp, bottom = 14.dp)
        )

        if (copiedPatchTitle != null) {
            Text(
                text = "✓ Parche '$copiedPatchTitle' copiado al portapapeles",
                style = MaterialTheme.typography.labelSmall.copy(color = NyxEmerald),
                modifier = Modifier.padding(bottom = 8.dp)
            )
        }

        Column(
            modifier = Modifier
                .widthIn(max = 680.dp)
                .fillMaxWidth()
                .weight(1f)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            scene.report?.let { r ->
                ReportBlock("01 · QUÉ SE HIZO", r.whatWasDone, NyxCyan)
                ReportBlock("02 · QUÉ SE ENCONTRÓ", r.whatWasFound, NyxAmber)
                ReportBlock("03 · MEDIDAS Y PARCHES GENERADOS", r.measuresAndPatchesTaken, NyxEmerald)
                ReportBlock("04 · RECOMENDACIONES DE MEJORA", r.improvementRecommendations, NyxViolet)
            }

            if (scene.patches.isNotEmpty()) {
                Text(
                    text = "SOLUCIONES Y PARCHES (${scene.patches.size})",
                    style = MaterialTheme.typography.labelMedium.copy(
                        color = NyxEmerald,
                        fontWeight = FontWeight.Bold
                    )
                )
                scene.patches.forEach { patch ->
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(NyxSurface, RoundedCornerShape(10.dp))
                            .pointerInput(patch.id) {
                                detectTapGestures(
                                    onLongPress = {
                                        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                        cm.setPrimaryClip(ClipData.newPlainText(patch.title, patch.patchContent))
                                        copiedPatchTitle = patch.title
                                    },
                                    onDoubleTap = {
                                        val share = Intent(Intent.ACTION_SEND).apply {
                                            type = "text/plain"
                                            putExtra(Intent.EXTRA_SUBJECT, "Parche Aura: ${patch.title}")
                                            putExtra(Intent.EXTRA_TEXT, "${patch.title} (${patch.targetArtifact})\n\n${patch.patchContent}")
                                        }
                                        context.startActivity(Intent.createChooser(share, "Compartir parche"))
                                    }
                                )
                            }
                            .padding(14.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = patch.targetArtifact,
                                style = MaterialTheme.typography.labelSmall.copy(color = NyxCyan)
                            )
                            Text(
                                text = patch.severity,
                                style = MaterialTheme.typography.labelSmall.copy(
                                    color = if (patch.severity.contains("CRIT", true)) NyxCrimson else NyxAmber
                                )
                            )
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = patch.title,
                            style = MaterialTheme.typography.titleMedium.copy(color = NyxTextPrimary)
                        )
                        if (patch.rationale.isNotBlank()) {
                            Text(
                                text = patch.rationale,
                                style = MaterialTheme.typography.bodySmall.copy(color = NyxTextSecondary),
                                modifier = Modifier.padding(top = 4.dp, bottom = 8.dp)
                            )
                        }
                        Text(
                            text = patch.patchContent,
                            style = MaterialTheme.typography.bodySmall.copy(color = NyxEmerald)
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ReportBlock(
    heading: String,
    body: String,
    accent: androidx.compose.ui.graphics.Color
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = heading,
            style = MaterialTheme.typography.labelMedium.copy(color = accent)
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = body.ifBlank { "Sin observaciones adicionales." },
            style = MaterialTheme.typography.bodyMedium.copy(color = NyxTextPrimary)
        )
        Spacer(modifier = Modifier.height(8.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(NyxHairline)
        )
    }
}

@Composable
fun MemoryTimelineOverlay(
    sessions: List<AiVisualScene>,
    monitorTargets: List<MonitorTargetSnapshot>,
    anomalies: List<AnomalyAlert>,
    onRestoreSession: (AiVisualScene) -> Unit,
    onDeleteSession: (String) -> Unit,
    onDeleteMonitorTarget: (String) -> Unit,
    onRunMonitorNow: (String) -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    BackHandler(onBack = onDismiss)
    val cdMemory = stringResource(R.string.cd_memory_timeline)
    val formatter = SimpleDateFormat("dd MMM HH:mm", Locale.getDefault())

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(NyxVoid.copy(alpha = 0.96f))
            .statusBarsPadding()
            .navigationBarsPadding()
            .pointerInput(Unit) {
                var dragY = 0f
                detectVerticalDragGestures(
                    onDragStart = { dragY = 0f },
                    onVerticalDrag = { _, delta -> dragY += delta },
                    onDragEnd = { if (dragY < -75f) onDismiss() }
                )
            }
            .padding(horizontal = 20.dp, vertical = 16.dp)
            .testTag("memory_timeline_overlay")
            .semantics { contentDescription = cdMemory }
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "MEMORIA, MONITORES Y ANOMALÍAS",
                style = MaterialTheme.typography.titleMedium.copy(
                    color = NyxTextPrimary,
                    fontWeight = FontWeight.Bold
                )
            )
            Text(
                text = "${sessions.size} trazas · ${monitorTargets.size} vigilados",
                style = MaterialTheme.typography.labelSmall.copy(color = NyxCyan)
            )
        }

        Text(
            text = "Toca una traza/monitor para inspeccionar · Desliza ← para purgar · Desliza ↑ para cerrar",
            style = MaterialTheme.typography.labelSmall.copy(color = NyxTextMuted),
            modifier = Modifier.padding(top = 4.dp, bottom = 14.dp)
        )

        LazyColumn(
            modifier = Modifier
                .widthIn(max = 680.dp)
                .fillMaxWidth()
                .weight(1f),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            if (anomalies.isNotEmpty()) {
                item {
                    Text(
                        text = "ANOMALÍAS RECIENTES (${anomalies.size})",
                        style = MaterialTheme.typography.labelMedium.copy(color = NyxCrimson)
                    )
                }
                items(anomalies.take(6), key = { "anom_${it.id}" }) { alert ->
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(NyxSurface.copy(alpha = 0.7f), RoundedCornerShape(8.dp))
                            .padding(10.dp)
                    ) {
                        Text(
                            text = "[${alert.severity}] ${alert.kind} · ${alert.target}",
                            style = MaterialTheme.typography.labelSmall.copy(color = NyxCrimson)
                        )
                        Text(
                            text = alert.description,
                            style = MaterialTheme.typography.bodySmall.copy(color = NyxTextPrimary)
                        )
                    }
                }
            }

            if (monitorTargets.isNotEmpty()) {
                item {
                    Text(
                        text = "SERVIDORES VIGILADOS (${monitorTargets.size})",
                        style = MaterialTheme.typography.labelMedium.copy(color = NyxEmerald),
                        modifier = Modifier.padding(top = 6.dp)
                    )
                }
                items(monitorTargets, key = { "mon_${it.target}" }) { mon ->
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 48.dp)
                            .pointerInput(mon.target) {
                                var dragX = 0f
                                detectHorizontalDragGestures(
                                    onDragStart = { dragX = 0f },
                                    onHorizontalDrag = { _, d -> dragX += d },
                                    onDragEnd = {
                                        if (dragX < -90f || dragX > 90f) {
                                            onDeleteMonitorTarget(mon.target)
                                        }
                                    }
                                )
                            }
                            .clickable { onRunMonitorNow(mon.target) }
                            .padding(vertical = 8.dp)
                    ) {
                        Text(
                            text = mon.target,
                            style = MaterialTheme.typography.titleMedium.copy(color = NyxTextPrimary),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = "HTTP ${mon.lastStatusCode} · RTT ${mon.lastRttMs}ms (base ${mon.baselineRttMs}ms) · ${mon.checkCount} chequeos · ${mon.anomalyCount} anomalías",
                            style = MaterialTheme.typography.bodySmall.copy(
                                color = if (mon.anomalyCount > 0) NyxAmber else NyxEmerald
                            )
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Box(modifier = Modifier.fillMaxWidth().height(1.dp).background(NyxHairline))
                    }
                }
            }

            item {
                Text(
                    text = "HISTORIAL DE AUDITORÍAS (${sessions.size})",
                    style = MaterialTheme.typography.labelMedium.copy(color = NyxCyan),
                    modifier = Modifier.padding(top = 6.dp)
                )
            }

            if (sessions.isEmpty()) {
                item {
                    Text(
                        text = "Aún no existen auditorías guardadas localmente.",
                        style = MaterialTheme.typography.bodyMedium.copy(color = NyxTextSecondary)
                    )
                }
            } else {
                items(sessions, key = { it.id }) { session ->
                    val modeColor = if (session.privilegeMode == PrivilegeMode.ROOT) NyxAmber else NyxCyan
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 48.dp)
                            .pointerInput(session.id) {
                                var dragX = 0f
                                detectHorizontalDragGestures(
                                    onDragStart = { dragX = 0f },
                                    onHorizontalDrag = { _, d -> dragX += d },
                                    onDragEnd = {
                                        if (dragX < -90f || dragX > 90f) {
                                            onDeleteSession(session.id)
                                        }
                                    }
                                )
                            }
                            .clickable { onRestoreSession(session) }
                            .padding(vertical = 10.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = "${session.privilegeMode.name} · ${session.engineMode.name}",
                                style = MaterialTheme.typography.labelSmall.copy(color = modeColor)
                            )
                            Text(
                                text = formatter.format(Date(session.timestamp)),
                                style = MaterialTheme.typography.labelSmall.copy(color = NyxTextMuted)
                            )
                        }

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = session.title,
                            style = MaterialTheme.typography.titleMedium.copy(color = NyxTextPrimary),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )

                        Text(
                            text = session.query,
                            style = MaterialTheme.typography.bodySmall.copy(color = NyxTextSecondary),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )

                        Spacer(modifier = Modifier.height(6.dp))

                        Canvas(modifier = Modifier.fillMaxWidth().height(10.dp)) {
                            val vals = session.spectrumValues.ifEmpty { listOf(0.4f, 0.7f, 0.5f) }
                            val step = size.width / vals.size.coerceAtLeast(1)
                            vals.forEachIndexed { idx, v ->
                                val x = idx * step + step * 0.5f
                                drawLine(
                                    color = modeColor.copy(alpha = 0.65f),
                                    start = Offset(x, size.height),
                                    end = Offset(x, size.height * (1f - v.coerceIn(0.1f, 1f))),
                                    strokeWidth = 2.5f
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(8.dp))
                        Box(modifier = Modifier.fillMaxWidth().height(1.dp).background(NyxHairline))
                    }
                }
            }
        }
    }
}
