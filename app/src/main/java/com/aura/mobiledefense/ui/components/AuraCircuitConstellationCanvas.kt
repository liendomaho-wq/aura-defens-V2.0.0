package com.aura.mobiledefense.ui.components

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.calculatePan
import androidx.compose.foundation.gestures.calculateZoom
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.positionChanged
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.sp
import com.aura.mobiledefense.R
import com.aura.mobiledefense.data.model.AiVisualEdge
import com.aura.mobiledefense.data.model.AiVisualNode
import com.aura.mobiledefense.data.model.VpnFirewallTelemetry
import com.aura.mobiledefense.ui.theme.JetBrainsMonoFontFamily
import com.aura.mobiledefense.ui.theme.NyxAmber
import com.aura.mobiledefense.ui.theme.NyxCrimson
import com.aura.mobiledefense.ui.theme.NyxCyan
import com.aura.mobiledefense.ui.theme.NyxEmerald
import com.aura.mobiledefense.ui.theme.NyxHairline
import com.aura.mobiledefense.ui.theme.NyxTextMuted
import com.aura.mobiledefense.ui.theme.NyxTextPrimary
import com.aura.mobiledefense.ui.theme.NyxTextSecondary
import com.aura.mobiledefense.ui.theme.NyxViolet
import com.aura.mobiledefense.ui.theme.NyxVoid
import kotlinx.coroutines.launch
import java.util.Locale
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.hypot
import kotlin.math.min
import kotlin.math.sin

/**
 * Aura Mobile Defens holographic Integrated Circuit (PCB traces, solder vias, segmented orbital arcs)
 * + Celestial Constellation visualization rendered directly on Compose Canvas.
 * Zero buttons, zero shields, zero radars, zero brain shapes.
 */
@Composable
fun AuraCircuitConstellationCanvas(
    sceneKey: String,
    nodes: List<AiVisualNode>,
    edges: List<AiVisualEdge>,
    cpuLoad: Float,
    networkLoad: Float,
    networkKbps: Float,
    vpnTelemetry: VpnFirewallTelemetry,
    accentColor: Color,
    selectedNodeId: String?,
    highlightLayer: Int?,
    isSynthesizing: Boolean,
    onNodeTapped: (AiVisualNode?) -> Unit,
    modifier: Modifier = Modifier
) {
    val textMeasurer = rememberTextMeasurer()
    val scope = rememberCoroutineScope()
    val cdCanvas = stringResource(R.string.cd_ai_canvas)

    val vpnBoost = if (vpnTelemetry.isRunning) {
        (vpnTelemetry.packetsInspected.coerceAtMost(50) / 150f).coerceIn(0.05f, 0.35f)
    } else 0f

    val smoothCpu by animateFloatAsState(
        targetValue = cpuLoad.coerceIn(0.05f, 1f),
        animationSpec = spring(stiffness = Spring.StiffnessLow),
        label = "aura_cpu_pulse"
    )
    val smoothNet by animateFloatAsState(
        targetValue = (networkLoad + vpnBoost).coerceIn(0.05f, 1f),
        animationSpec = spring(stiffness = Spring.StiffnessLow),
        label = "aura_net_pulse"
    )

    var zoom by remember { mutableFloatStateOf(1f) }
    var panOffset by remember { mutableStateOf(Offset.Zero) }
    var canvasSize by remember { mutableStateOf(Size.Zero) }
    var pointerField by remember { mutableStateOf<Offset?>(null) }

    val nodeDragOffsets = remember(sceneKey) { mutableStateMapOf<String, Offset>() }

    var shockwaveOrigin by remember { mutableStateOf<Offset?>(null) }
    val shockwaveProgress = remember { Animatable(1f) }

    val infiniteTransition = rememberInfiniteTransition(label = "aura_motion")
    val phase by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = (2f * PI).toFloat(),
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 7200, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "phase"
    )
    val signalProgress by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2400, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "signal"
    )

    LaunchedEffect(sceneKey) {
        zoom = 1f
        panOffset = Offset.Zero
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .testTag("interactive_neural_network_graph")
            .semantics { contentDescription = cdCanvas }
            .pointerInput(Unit) {
                awaitPointerEventScope {
                    while (true) {
                        val event = awaitPointerEvent(PointerEventPass.Initial)
                        val first = event.changes.firstOrNull()
                        pointerField = if (first != null && first.pressed) first.position else null
                    }
                }
            }
            .pointerInput(sceneKey, nodes, zoom, panOffset, canvasSize) {
                awaitEachGesture {
                    val firstDown = awaitFirstDown(requireUnconsumed = false)
                    val hitRadius = 76f
                    val grabbedNode = if (canvasSize.width > 0f) {
                        nodes.minByOrNull { node ->
                            val p = resolveAuraNodePosition(
                                node = node,
                                dragDelta = nodeDragOffsets[node.id] ?: Offset.Zero,
                                size = canvasSize,
                                zoom = zoom,
                                pan = panOffset
                            )
                            hypot(p.x - firstDown.position.x, p.y - firstDown.position.y)
                        }?.takeIf { candidate ->
                            val p = resolveAuraNodePosition(
                                node = candidate,
                                dragDelta = nodeDragOffsets[candidate.id] ?: Offset.Zero,
                                size = canvasSize,
                                zoom = zoom,
                                pan = panOffset
                            )
                            hypot(p.x - firstDown.position.x, p.y - firstDown.position.y) <= hitRadius
                        }
                    } else null

                    var draggingNode = grabbedNode != null
                    do {
                        val event = awaitPointerEvent()
                        val pressedCount = event.changes.count { it.pressed }
                        if (pressedCount > 1) {
                            draggingNode = false
                            val zoomChange = event.calculateZoom()
                            val panChange = event.calculatePan()
                            zoom = (zoom * zoomChange).coerceIn(0.65f, 2.6f)
                            panOffset = Offset(
                                x = (panOffset.x + panChange.x).coerceIn(-380f, 380f),
                                y = (panOffset.y + panChange.y).coerceIn(-380f, 380f)
                            )
                            event.changes.forEach { if (it.positionChanged()) it.consume() }
                        } else if (pressedCount == 1) {
                            val change = event.changes.first()
                            val delta = change.position - change.previousPosition
                            if (hypot(delta.x, delta.y) > 0.5f) {
                                if (draggingNode && grabbedNode != null) {
                                    val current = nodeDragOffsets[grabbedNode.id] ?: Offset.Zero
                                    nodeDragOffsets[grabbedNode.id] = current + (delta / zoom)
                                    change.consume()
                                } else {
                                    panOffset = Offset(
                                        x = (panOffset.x + delta.x).coerceIn(-380f, 380f),
                                        y = (panOffset.y + delta.y).coerceIn(-380f, 380f)
                                    )
                                    change.consume()
                                }
                            }
                        }
                    } while (event.changes.any { it.pressed })
                }
            }
            .pointerInput(sceneKey, nodes, zoom, panOffset, canvasSize) {
                detectTapGestures(
                    onTap = { tapOffset ->
                        if (canvasSize.width <= 0f) return@detectTapGestures
                        val hit = nodes.minByOrNull { node ->
                            val p = resolveAuraNodePosition(
                                node = node,
                                dragDelta = nodeDragOffsets[node.id] ?: Offset.Zero,
                                size = canvasSize,
                                zoom = zoom,
                                pan = panOffset
                            )
                            hypot(p.x - tapOffset.x, p.y - tapOffset.y)
                        }?.takeIf { nearest ->
                            val p = resolveAuraNodePosition(
                                node = nearest,
                                dragDelta = nodeDragOffsets[nearest.id] ?: Offset.Zero,
                                size = canvasSize,
                                zoom = zoom,
                                pan = panOffset
                            )
                            hypot(p.x - tapOffset.x, p.y - tapOffset.y) <= 78f
                        }

                        if (hit != null) {
                            shockwaveOrigin = resolveAuraNodePosition(
                                node = hit,
                                dragDelta = nodeDragOffsets[hit.id] ?: Offset.Zero,
                                size = canvasSize,
                                zoom = zoom,
                                pan = panOffset
                            )
                            scope.launch {
                                shockwaveProgress.snapTo(0f)
                                shockwaveProgress.animateTo(1f, tween(650))
                            }
                        }
                        onNodeTapped(hit)
                    },
                    onDoubleTap = {
                        zoom = 1f
                        panOffset = Offset.Zero
                        nodeDragOffsets.clear()
                    }
                )
            }
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            canvasSize = size
            drawRect(color = NyxVoid)

            // 1. Starfield Constellation + Aura Mobile Defens Holographic Orbital Calibration Rings
            drawAuraStarfieldAndOrbits(
                size = size,
                phase = phase,
                accent = accentColor,
                pointerField = pointerField,
                cpuLoad = smoothCpu,
                pan = panOffset
            )

            if (nodes.isNotEmpty()) {
                val nodePositions = nodes.associate { node ->
                    node.id to resolveAuraNodePosition(
                        node = node,
                        dragDelta = nodeDragOffsets[node.id] ?: Offset.Zero,
                        size = size,
                        zoom = zoom,
                        pan = panOffset
                    )
                }

                // 2. Integrated Circuit (45°-chamfered PCB traces + solder vias) & Constellation vectors
                val netSpeedPhase = (signalProgress * (1f + smoothNet * 1.6f)) % 1f
                edges.forEachIndexed { idx, edge ->
                    val p1 = nodePositions[edge.fromId] ?: return@forEachIndexed
                    val p2 = nodePositions[edge.toId] ?: return@forEachIndexed
                    val fromNode = nodes.firstOrNull { it.id == edge.fromId }
                    val toNode = nodes.firstOrNull { it.id == edge.toId }

                    val edgeRisk = maxOf(fromNode?.riskScore ?: 0.3f, toNode?.riskScore ?: 0.3f)
                    val traceColor = auraRiskColor(edgeRisk, accentColor)
                    val isNearPointer = pointerField?.let {
                        hypot((p1.x + p2.x) / 2f - it.x, (p1.y + p2.y) / 2f - it.y) < 170f
                    } ?: false
                    val layerAlpha = if (
                        highlightLayer != null &&
                        fromNode?.layerIndex != highlightLayer &&
                        toNode?.layerIndex != highlightLayer
                    ) 0.20f else 1f

                    val waypoints = computeCircuitTraceWaypoints(p1, p2, idx)
                    val tracePath = Path().apply {
                        moveTo(waypoints.first().x, waypoints.first().y)
                        for (w in 1 until waypoints.size) {
                            lineTo(waypoints[w].x, waypoints[w].y)
                        }
                    }

                    val baseAlpha = (0.28f + edge.intensity * 0.25f + smoothNet * 0.24f) *
                        (if (isNearPointer) 1.6f else 1f) * layerAlpha

                    // Faint celestial constellation direct filament
                    drawLine(
                        color = NyxViolet.copy(alpha = (0.16f * layerAlpha).coerceIn(0.05f, 0.38f)),
                        start = p1,
                        end = p2,
                        strokeWidth = 0.9f
                    )

                    // Soft luminous glow conduit underneath PCB trace
                    drawPath(
                        path = tracePath,
                        color = traceColor.copy(alpha = (baseAlpha * 0.28f).coerceIn(0.04f, 0.32f)),
                        style = Stroke(
                            width = (5.2f + smoothNet * 3.4f) * (if (isNearPointer) 1.3f else 1f),
                            cap = StrokeCap.Round,
                            join = StrokeJoin.Round
                        )
                    )

                    // Crisp PCB Integrated Circuit trace
                    drawPath(
                        path = tracePath,
                        color = traceColor.copy(alpha = baseAlpha.coerceIn(0.12f, 0.94f)),
                        style = Stroke(
                            width = (1.7f + smoothNet * 1.8f) * (if (isNearPointer) 1.35f else 1f),
                            cap = StrokeCap.Round,
                            join = StrokeJoin.Round
                        )
                    )

                    // Solder-pad vias at trace bends
                    if (waypoints.size >= 4) {
                        listOf(waypoints[1], waypoints[2]).forEach { via ->
                            drawCircle(
                                color = NyxVoid,
                                radius = 3.2f,
                                center = via
                            )
                            drawCircle(
                                color = traceColor.copy(alpha = 0.78f * layerAlpha),
                                radius = 3.2f,
                                center = via,
                                style = Stroke(width = 1.2f)
                            )
                        }
                    }

                    // Traveling IC bus telemetry light packet with glowing tail
                    val t = (netSpeedPhase + idx * 0.17f) % 1f
                    val tailT = (t - 0.045f + 1f) % 1f
                    val packetPt = samplePolyline(waypoints, t)
                    if (t > tailT) {
                        val tailPt = samplePolyline(waypoints, tailT)
                        drawLine(
                            color = traceColor.copy(alpha = 0.55f * layerAlpha),
                            start = tailPt,
                            end = packetPt,
                            strokeWidth = 2.6f + smoothNet * 1.6f,
                            cap = StrokeCap.Round
                        )
                    }
                    drawCircle(
                        color = traceColor.copy(alpha = 0.35f * layerAlpha),
                        radius = 6f + smoothNet * 4f,
                        center = packetPt
                    )
                    drawCircle(
                        color = (if (isNearPointer) NyxTextPrimary else traceColor).copy(alpha = 0.96f * layerAlpha),
                        radius = 2.8f + smoothNet * 2.4f,
                        center = packetPt
                    )
                }

                // Interactive pointer-to-constellation magnetic filaments
                pointerField?.let { touchPt ->
                    nodes.forEach { node ->
                        val np = nodePositions[node.id] ?: return@forEach
                        val dist = hypot(np.x - touchPt.x, np.y - touchPt.y)
                        if (dist < 185f) {
                            val strength = (1f - dist / 185f)
                            val nodeColor = auraRiskColor(node.riskScore, accentColor)
                            drawLine(
                                brush = Brush.linearGradient(
                                    colors = listOf(
                                        NyxTextPrimary.copy(alpha = strength * 0.55f),
                                        nodeColor.copy(alpha = strength * 0.45f)
                                    ),
                                    start = touchPt,
                                    end = np
                                ),
                                start = touchPt,
                                end = np,
                                strokeWidth = 1.1f + strength * 1.4f,
                                cap = StrokeCap.Round
                            )
                        }
                    }
                }

                // 3. Aura Mobile Defens Holographic IC + Star Constellation Nodes
                nodes.forEachIndexed { idx, node ->
                    val basePos = nodePositions[node.id] ?: return@forEachIndexed
                    val microOsc = sin(phase * (1f + smoothCpu * 0.7f) + idx * 1.15f) * (1.8f + smoothCpu * 3.5f)
                    val center = Offset(basePos.x, basePos.y + microOsc)

                    val isNet = node.category.contains("NET", true) || node.category.contains("TLS", true)
                    val nodeActivity = if (isNet) (smoothNet * 0.75f + smoothCpu * 0.25f) else (smoothCpu * 0.75f + smoothNet * 0.25f)
                    val pulseWave = 0.5f + 0.5f * sin(phase * (1.3f + nodeActivity * 2.2f) + idx * 0.85f)
                    val pointerBoost = pointerField?.let {
                        val d = hypot(center.x - it.x, center.y - it.y)
                        if (d < 160f) (1f - d / 160f) * 7f else 0f
                    } ?: 0f

                    val isSelected = node.id == selectedNodeId
                    val layerAlpha = if (highlightLayer == null || node.layerIndex == highlightLayer) 1f else 0.28f
                    val color = auraRiskColor(node.riskScore, accentColor)
                    val coreRadius = (if (isSelected) 16f else 10.5f + node.riskScore * 4f) +
                        (pulseWave * nodeActivity * 5.5f) + pointerBoost

                    // Star constellation radiance
                    drawCircle(
                        brush = Brush.radialGradient(
                            colors = listOf(
                                color.copy(alpha = ((0.22f + nodeActivity * 0.34f * pulseWave) * layerAlpha).coerceIn(0.05f, 0.72f)),
                                Color.Transparent
                            ),
                            center = center,
                            radius = coreRadius * (2.8f + nodeActivity)
                        ),
                        radius = coreRadius * (2.8f + nodeActivity),
                        center = center
                    )

                    // Segmented spinning Aura Mobile Defens orbital arc rings
                    val rotDeg = ((phase * 57.2958f) * (if (idx % 2 == 0) 1f else -1f) + idx * 45f) % 360f
                    val ringRadius = coreRadius + 7f + pulseWave * nodeActivity * 6f
                    val arcSize = Size(ringRadius * 2f, ringRadius * 2f)
                    val arcTopLeft = Offset(center.x - ringRadius, center.y - ringRadius)
                    for (seg in 0..2) {
                        drawArc(
                            color = color.copy(alpha = (0.72f * layerAlpha).coerceIn(0.1f, 0.9f)),
                            startAngle = rotDeg + seg * 120f,
                            sweepAngle = 72f,
                            useCenter = false,
                            topLeft = arcTopLeft,
                            size = arcSize,
                            style = Stroke(width = if (isSelected) 2.2f else 1.4f, cap = StrokeCap.Round)
                        )
                    }

                    // Integrated-Circuit Micro-Chip Frame with 8 external PCB pins
                    drawIcChipNode(
                        center = center,
                        halfSize = coreRadius * 0.85f,
                        color = color.copy(alpha = layerAlpha),
                        selected = isSelected
                    )

                    // 4-point Constellation Star Flare inside IC Core
                    drawStarFlare(
                        center = center,
                        radius = coreRadius * 0.65f,
                        color = NyxTextPrimary.copy(alpha = 0.92f * layerAlpha)
                    )

                    // Node labels
                    val labelLayout = textMeasurer.measure(
                        text = node.label,
                        style = TextStyle(
                            fontFamily = JetBrainsMonoFontFamily,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = NyxTextPrimary.copy(alpha = layerAlpha)
                        )
                    )
                    val lx = (center.x - labelLayout.size.width / 2f).coerceIn(10f, size.width - labelLayout.size.width - 10f)
                    val ly = (center.y + ringRadius + 5f).coerceIn(16f, size.height - 38f)
                    drawText(labelLayout, topLeft = Offset(lx, ly))

                    if (node.sublabel.isNotBlank()) {
                        val subLayout = textMeasurer.measure(
                            text = node.sublabel,
                            style = TextStyle(
                                fontFamily = JetBrainsMonoFontFamily,
                                fontSize = 8.5.sp,
                                color = NyxTextSecondary.copy(alpha = layerAlpha)
                            )
                        )
                        val sx = (center.x - subLayout.size.width / 2f).coerceIn(10f, size.width - subLayout.size.width - 10f)
                        drawText(subLayout, topLeft = Offset(sx, ly + labelLayout.size.height))
                    }
                }
            } else {
                drawDefaultAuraBootCircuit(size, phase, signalProgress, accentColor, smoothCpu, smoothNet)
            }

            // 4. Circuit Tap Shockwave
            shockwaveOrigin?.let { origin ->
                val p = shockwaveProgress.value
                if (p < 0.99f) {
                    val r = 14f + p * 145f
                    drawCircle(
                        color = accentColor.copy(alpha = (1f - p) * 0.72f),
                        radius = r,
                        center = origin,
                        style = Stroke(width = 2f)
                    )
                }
            }

            // 5. Compact Aura Mobile Defens Telemetry Strip directly on Canvas
            val vpnText = if (vpnTelemetry.isRunning) {
                "VPN ON (PKT ${vpnTelemetry.packetsInspected} · BLK ${vpnTelemetry.packetsBlocked})"
            } else {
                "VPN OFF"
            }
            val activityText = "Aura Mobile Defens · CPU ${(smoothCpu * 100).toInt()}% · NET ${String.format(Locale.US, "%.1f", networkKbps)} KB/s · $vpnText"
            val activityLayout = textMeasurer.measure(
                text = activityText,
                style = TextStyle(
                    fontFamily = JetBrainsMonoFontFamily,
                    fontSize = 8.5.sp,
                    color = if (vpnTelemetry.isRunning) NyxEmerald.copy(alpha = 0.9f) else NyxTextMuted.copy(alpha = 0.9f)
                )
            )
            drawText(
                textLayoutResult = activityLayout,
                topLeft = Offset(
                    x = (size.width - activityLayout.size.width) / 2f,
                    y = size.height * 0.495f
                )
            )

            if (isSynthesizing) {
                drawAuraCarrierWave(size, phase, accentColor)
            }
        }
    }
}

private fun resolveAuraNodePosition(
    node: AiVisualNode,
    dragDelta: Offset,
    size: Size,
    zoom: Float,
    pan: Offset
): Offset {
    val usableTop = size.height * 0.12f
    val usableHeight = size.height * 0.34f
    val rawX = node.xNorm * size.width + dragDelta.x
    val rawY = usableTop + node.yNorm * usableHeight + dragDelta.y
    val cx = size.width / 2f
    val cy = usableTop + usableHeight / 2f
    return Offset(
        x = cx + (rawX - cx) * zoom + pan.x,
        y = cy + (rawY - cy) * zoom + pan.y
    )
}

private fun auraRiskColor(risk: Float, fallbackAccent: Color): Color = when {
    risk >= 0.78f -> NyxCrimson
    risk >= 0.52f -> NyxAmber
    risk >= 0.30f -> NyxViolet
    else -> fallbackAccent
}

private fun computeCircuitTraceWaypoints(p1: Offset, p2: Offset, idx: Int): List<Offset> {
    val dx = p2.x - p1.x
    val dy = p2.y - p1.y
    val laneShift = ((idx % 3) - 1) * 14f
    val midX = p1.x + dx * 0.5f + laneShift
    val chamfer = min(kotlin.math.abs(dx) * 0.22f, kotlin.math.abs(dy) * 0.45f)
    return if (kotlin.math.abs(dy) > 10f && kotlin.math.abs(dx) > 28f) {
        val dirX = if (dx >= 0f) 1f else -1f
        listOf(
            p1,
            Offset(midX - dirX * chamfer * 0.6f, p1.y),
            Offset(midX + dirX * chamfer * 0.6f, p2.y),
            p2
        )
    } else {
        listOf(p1, Offset(midX, p1.y), Offset(midX, p2.y), p2)
    }
}

private fun samplePolyline(pts: List<Offset>, tRaw: Float): Offset {
    if (pts.size < 2) return pts.firstOrNull() ?: Offset.Zero
    val t = tRaw.coerceIn(0f, 1f)
    val segLengths = FloatArray(pts.size - 1)
    var total = 0f
    for (i in 0 until pts.size - 1) {
        val d = hypot(pts[i + 1].x - pts[i].x, pts[i + 1].y - pts[i].y)
        segLengths[i] = d
        total += d
    }
    if (total <= 1e-3f) return pts.first()
    var targetDist = t * total
    for (i in 0 until pts.size - 1) {
        val seg = segLengths[i]
        if (targetDist <= seg || i == pts.size - 2) {
            val localT = if (seg > 1e-3f) (targetDist / seg).coerceIn(0f, 1f) else 0f
            return Offset(
                x = pts[i].x + (pts[i + 1].x - pts[i].x) * localT,
                y = pts[i].y + (pts[i + 1].y - pts[i].y) * localT
            )
        }
        targetDist -= seg
    }
    return pts.last()
}

private fun DrawScope.drawAuraStarfieldAndOrbits(
    size: Size,
    phase: Float,
    accent: Color,
    pointerField: Offset?,
    cpuLoad: Float,
    pan: Offset
) {
    val hub = Offset(size.width * 0.5f + pan.x * 0.35f, size.height * 0.29f + pan.y * 0.35f)
    val glowCenter = pointerField ?: hub
    drawRect(
        brush = Brush.radialGradient(
            colors = listOf(
                accent.copy(alpha = (0.09f + cpuLoad * 0.08f) + if (pointerField != null) 0.05f else 0f),
                NyxViolet.copy(alpha = 0.04f),
                Color.Transparent
            ),
            center = glowCenter,
            radius = size.maxDimension * 0.52f
        )
    )

    // Subtle Aura Mobile Defens holographic orbital calibration rings (no radar sweeps, no crosshairs)
    val baseOrbit = min(size.width, size.height) * 0.28f
    for (ringIdx in 1..3) {
        val r = baseOrbit * (0.48f + ringIdx * 0.24f)
        val rot = (phase * 57.2958f) * (if (ringIdx % 2 == 0) 0.4f else -0.55f)
        val topLeft = Offset(hub.x - r, hub.y - r)
        val arcSize = Size(r * 2f, r * 2f)
        drawArc(
            color = NyxHairline.copy(alpha = 0.36f),
            startAngle = rot,
            sweepAngle = 110f,
            useCenter = false,
            topLeft = topLeft,
            size = arcSize,
            style = Stroke(width = 1f)
        )
        drawArc(
            color = accent.copy(alpha = 0.18f),
            startAngle = rot + 180f,
            sweepAngle = 70f,
            useCenter = false,
            topLeft = topLeft,
            size = arcSize,
            style = Stroke(width = 1f)
        )
    }

    // Fluid dark nebula drift + Celestial starfield & constellation links
    val driftNebula = Offset(
        x = size.width * 0.5f + cos(phase * 0.5f) * size.width * 0.14f,
        y = size.height * 0.24f + sin(phase * 0.7f) * size.height * 0.06f
    )
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(NyxViolet.copy(alpha = 0.07f), Color.Transparent),
            center = driftNebula,
            radius = size.maxDimension * 0.42f
        ),
        radius = size.maxDimension * 0.42f,
        center = driftNebula
    )

    val starPoints = List(28) { i ->
        val sx = ((i * 73 + 19) % 94 + 3) / 100f * size.width
        val sy = ((i * 41 + 11) % 52 + 4) / 100f * size.height
        Offset(sx, sy)
    }
    for (i in 0 until starPoints.lastIndex step 2) {
        val s1 = starPoints[i]
        val s2 = starPoints[(i + 3) % starPoints.size]
        if (hypot(s2.x - s1.x, s2.y - s1.y) < size.width * 0.34f) {
            drawLine(
                color = accent.copy(alpha = 0.08f),
                start = s1,
                end = s2,
                strokeWidth = 0.8f
            )
        }
    }
    starPoints.forEachIndexed { i, pt ->
        val twinkle = 0.3f + 0.7f * (0.5f + 0.5f * sin(phase * 1.4f + i * 0.9f))
        drawCircle(
            color = (if (i % 4 == 0) accent else NyxTextPrimary).copy(alpha = twinkle * 0.52f),
            radius = if (i % 5 == 0) 2.1f else 1.15f,
            center = pt
        )
    }
}

private fun DrawScope.drawIcChipNode(
    center: Offset,
    halfSize: Float,
    color: Color,
    selected: Boolean
) {
    // 8 external IC pins (2 per side)
    val pinLen = halfSize * 0.42f
    val pinOffset = halfSize * 0.45f
    listOf(-pinOffset, pinOffset).forEach { off ->
        // Top & Bottom pins
        drawLine(color.copy(alpha = 0.75f), Offset(center.x + off, center.y - halfSize), Offset(center.x + off, center.y - halfSize - pinLen), strokeWidth = 1.4f)
        drawLine(color.copy(alpha = 0.75f), Offset(center.x + off, center.y + halfSize), Offset(center.x + off, center.y + halfSize + pinLen), strokeWidth = 1.4f)
        // Left & Right pins
        drawLine(color.copy(alpha = 0.75f), Offset(center.x - halfSize, center.y + off), Offset(center.x - halfSize - pinLen, center.y + off), strokeWidth = 1.4f)
        drawLine(color.copy(alpha = 0.75f), Offset(center.x + halfSize, center.y + off), Offset(center.x + halfSize + pinLen, center.y + off), strokeWidth = 1.4f)
    }

    // Chamfered octagonal IC die
    val c = halfSize * 0.38f
    val chipPath = Path().apply {
        moveTo(center.x - halfSize + c, center.y - halfSize)
        lineTo(center.x + halfSize - c, center.y - halfSize)
        lineTo(center.x + halfSize, center.y - halfSize + c)
        lineTo(center.x + halfSize, center.y + halfSize - c)
        lineTo(center.x + halfSize - c, center.y + halfSize)
        lineTo(center.x - halfSize + c, center.y + halfSize)
        lineTo(center.x - halfSize, center.y + halfSize - c)
        lineTo(center.x - halfSize, center.y - halfSize + c)
        close()
    }
    drawPath(chipPath, color = NyxVoid)
    drawPath(
        chipPath,
        color = color.copy(alpha = 0.32f)
    )
    drawPath(
        chipPath,
        color = if (selected) NyxTextPrimary else color,
        style = Stroke(width = if (selected) 2.2f else 1.5f)
    )
}

private fun DrawScope.drawStarFlare(center: Offset, radius: Float, color: Color) {
    val inner = radius * 0.25f
    val path = Path().apply {
        moveTo(center.x, center.y - radius)
        lineTo(center.x + inner, center.y - inner)
        lineTo(center.x + radius, center.y)
        lineTo(center.x + inner, center.y + inner)
        lineTo(center.x, center.y + radius)
        lineTo(center.x - inner, center.y + inner)
        lineTo(center.x - radius, center.y)
        lineTo(center.x - inner, center.y - inner)
        close()
    }
    drawPath(path, color = color)
}

private fun DrawScope.drawDefaultAuraBootCircuit(
    size: Size,
    phase: Float,
    signal: Float,
    accent: Color,
    cpuLoad: Float,
    netLoad: Float
) {
    val layers = listOf(listOf(0.25f, 0.50f, 0.75f), listOf(0.25f, 0.75f), listOf(0.35f, 0.65f))
    val layerX = listOf(0.18f, 0.50f, 0.82f)
    val pts = layers.mapIndexed { lIdx, ys ->
        ys.map { y -> Offset(layerX[lIdx] * size.width, size.height * 0.13f + y * size.height * 0.30f) }
    }
    var idx = 0
    for (l in 0 until pts.lastIndex) {
        pts[l].forEach { p1 ->
            pts[l + 1].forEach { p2 ->
                val wp = computeCircuitTraceWaypoints(p1, p2, idx++)
                val path = Path().apply {
                    moveTo(wp.first().x, wp.first().y)
                    for (k in 1 until wp.size) lineTo(wp[k].x, wp[k].y)
                }
                drawPath(path, color = accent.copy(alpha = 0.28f + netLoad * 0.25f), style = Stroke(width = 1.6f))
                val pt = samplePolyline(wp, (signal + idx * 0.15f) % 1f)
                drawCircle(color = NyxTextPrimary.copy(alpha = 0.85f), radius = 2.6f, center = pt)
            }
        }
    }
    pts.flatten().forEachIndexed { i, pt ->
        val r = 9f + (0.5f + 0.5f * sin(phase + i)) * cpuLoad * 5f
        drawIcChipNode(pt, r, accent, false)
        drawStarFlare(pt, r * 0.6f, NyxTextPrimary)
    }
}

private fun DrawScope.drawAuraCarrierWave(size: Size, phase: Float, accent: Color) {
    val path = Path()
    val yCenter = size.height * 0.29f
    val steps = 64
    for (i in 0..steps) {
        val t = i.toFloat() / steps
        val x = t * size.width
        val env = sin(t * PI.toFloat())
        val y = yCenter + sin(t * 20f + phase * 3f) * 26f * env
        if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
    }
    drawPath(
        path = path,
        brush = Brush.horizontalGradient(listOf(Color.Transparent, accent, NyxViolet, Color.Transparent)),
        style = Stroke(width = 3.2f, cap = StrokeCap.Round)
    )
}
