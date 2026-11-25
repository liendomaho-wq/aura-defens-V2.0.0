package com.example.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextMeasurer
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.sp
import com.example.R
import com.example.data.model.AiVisualNode
import com.example.data.model.AiVisualScene
import com.example.data.model.PrivilegeMode
import com.example.data.model.VisualTopologyKind
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.NyxAmber
import com.example.ui.theme.NyxCrimson
import com.example.ui.theme.NyxCyan
import com.example.ui.theme.NyxEmerald
import com.example.ui.theme.NyxTextPrimary
import com.example.ui.theme.NyxTextSecondary
import com.example.ui.theme.NyxViolet
import com.example.ui.theme.NyxVoid
import kotlin.math.PI
import kotlin.math.hypot
import kotlin.math.sin

@Composable
fun GenerativeVisualCanvas(
    scene: AiVisualScene?,
    privilegeMode: PrivilegeMode,
    isAnalyzing: Boolean,
    selectedNodeId: String?,
    highlightLayer: Int? = null,
    cpuLoad: Float = 0.2f,
    networkLoad: Float = 0.15f,
    networkKbps: Float = 0f,
    vpnTelemetry: com.example.data.model.VpnFirewallTelemetry = com.example.data.model.VpnFirewallTelemetry(),
    onNodeTapped: (AiVisualNode?) -> Unit,
    modifier: Modifier = Modifier
) {
    val modeAccent = if (privilegeMode == PrivilegeMode.ROOT) NyxAmber else NyxCyan

    if (scene == null ||
        scene.visualKind == VisualTopologyKind.NEURAL_SYNAPTIC_LATTICE ||
        scene.visualKind == VisualTopologyKind.CONSTELLATION_MESH
    ) {
        InteractiveNeuralNetworkGraph(
            sceneKey = scene?.id ?: "boot",
            nodes = scene?.nodes.orEmpty(),
            edges = scene?.edges.orEmpty(),
            cpuLoad = cpuLoad,
            networkLoad = networkLoad,
            networkKbps = networkKbps,
            vpnTelemetry = vpnTelemetry,
            accentColor = modeAccent,
            selectedNodeId = selectedNodeId,
            highlightLayer = highlightLayer,
            isSynthesizing = isAnalyzing,
            onNodeTapped = onNodeTapped,
            modifier = modifier
        )
        return
    }

    val cdCanvas = stringResource(R.string.cd_ai_canvas)
    val textMeasurer = rememberTextMeasurer()

    var zoom by remember { mutableFloatStateOf(1f) }
    var panOffset by remember { mutableStateOf(Offset.Zero) }
    var canvasSize by remember { mutableStateOf(Size.Zero) }
    var pointerField by remember { mutableStateOf<Offset?>(null) }

    val transition = rememberInfiniteTransition(label = "aura_neural_phase")
    val phase by transition.animateFloat(
        initialValue = 0f,
        targetValue = (2f * PI).toFloat(),
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 6800, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "phase"
    )
    val pulse by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2800, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulse"
    )

    Box(
        modifier = modifier
            .fillMaxSize()
            .testTag("generative_ai_canvas")
            .semantics { contentDescription = cdCanvas }
            .pointerInput(Unit) {
                awaitPointerEventScope {
                    while (true) {
                        val event = awaitPointerEvent(PointerEventPass.Initial)
                        val change = event.changes.firstOrNull()
                        pointerField = if (change != null && change.pressed) change.position else null
                    }
                }
            }
            .pointerInput(scene.id) {
                detectTransformGestures { _, pan, gestureZoom, _ ->
                    zoom = (zoom * gestureZoom).coerceIn(0.7f, 2.4f)
                    panOffset = Offset(
                        x = (panOffset.x + pan.x).coerceIn(-350f, 350f),
                        y = (panOffset.y + pan.y).coerceIn(-350f, 350f)
                    )
                }
            }
            .pointerInput(scene.id, zoom, panOffset, canvasSize) {
                detectTapGestures(
                    onTap = { tapOffset ->
                        val currentNodes = scene.nodes
                        if (currentNodes.isEmpty() || canvasSize.width <= 0f) {
                            onNodeTapped(null)
                            return@detectTapGestures
                        }
                        val hitRadius = 78f
                        val hit = currentNodes.minByOrNull { node ->
                            val p = projectNodePoint(node, canvasSize, zoom, panOffset)
                            hypot(p.x - tapOffset.x, p.y - tapOffset.y)
                        }?.let { nearest ->
                            val p = projectNodePoint(nearest, canvasSize, zoom, panOffset)
                            if (hypot(p.x - tapOffset.x, p.y - tapOffset.y) <= hitRadius) nearest else null
                        }
                        onNodeTapped(hit)
                    },
                    onDoubleTap = {
                        zoom = 1f
                        panOffset = Offset.Zero
                    }
                )
            }
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            canvasSize = size
            drawRect(color = NyxVoid)

            drawAmbientNeuralField(size, phase, modeAccent, pointerField)

            when (scene.visualKind) {
                VisualTopologyKind.SPECTRUM_INTERFERENCE -> {
                    drawSpectrumInterference(scene, size, phase, modeAccent)
                    drawConstellationLightNodes(scene, size, zoom, panOffset, phase, modeAccent, selectedNodeId, highlightLayer, pointerField, textMeasurer)
                }
                VisualTopologyKind.ENTROPY_MATRIX -> {
                    drawEntropyMatrix(scene, size, phase, modeAccent)
                    drawConstellationLightNodes(scene, size, zoom, panOffset, phase, modeAccent, selectedNodeId, highlightLayer, pointerField, textMeasurer)
                }
                VisualTopologyKind.PROTOCOL_STRATA -> {
                    drawProtocolStrata(scene, size, phase, modeAccent, textMeasurer)
                    drawConstellationLightNodes(scene, size, zoom, panOffset, phase, modeAccent, selectedNodeId, highlightLayer, pointerField, textMeasurer)
                }
                VisualTopologyKind.BINARY_HELIX -> {
                    drawBinaryHelix(scene, size, phase, modeAccent)
                    drawConstellationLightNodes(scene, size, zoom, panOffset, phase, modeAccent, selectedNodeId, highlightLayer, pointerField, textMeasurer)
                }
                VisualTopologyKind.ATTACK_VECTOR_FLOW -> {
                    drawAttackVectorFlow(scene, size, zoom, panOffset, phase, pulse, modeAccent, selectedNodeId, highlightLayer, pointerField, textMeasurer)
                }
                else -> Unit
            }

            if (isAnalyzing) {
                drawSynthesisInterferenceOverlay(size, phase, modeAccent)
            }
        }
    }
}

private fun projectNodePoint(
    node: AiVisualNode,
    size: Size,
    zoom: Float,
    pan: Offset
): Offset {
    val usableTop = size.height * 0.14f
    val usableHeight = size.height * 0.44f
    val rawX = node.xNorm * size.width
    val rawY = usableTop + node.yNorm * usableHeight
    val cx = size.width / 2f
    val cy = usableTop + usableHeight / 2f
    return Offset(
        x = cx + (rawX - cx) * zoom + pan.x,
        y = cy + (rawY - cy) * zoom + pan.y
    )
}

private fun riskColor(risk: Float, fallbackAccent: Color): Color = when {
    risk >= 0.78f -> NyxCrimson
    risk >= 0.52f -> NyxAmber
    risk >= 0.30f -> NyxViolet
    else -> fallbackAccent
}

private fun DrawScope.drawAmbientNeuralField(
    size: Size,
    phase: Float,
    accent: Color,
    pointerField: Offset?
) {
    val glowCenter = pointerField ?: Offset(size.width * 0.5f, size.height * 0.30f)
    drawRect(
        brush = Brush.radialGradient(
            colors = listOf(
                accent.copy(alpha = if (pointerField != null) 0.14f else 0.09f),
                NyxViolet.copy(alpha = 0.05f),
                Color.Transparent
            ),
            center = glowCenter,
            radius = size.maxDimension * 0.56f
        )
    )
    // Fluid constellation starfield & connecting filaments
    val stars = List(24) { i ->
        Offset(
            x = ((i * 67 + 17) % 92 + 4) / 100f * size.width,
            y = ((i * 37 + 13) % 52 + 4) / 100f * size.height
        )
    }
    for (i in 0 until stars.lastIndex step 2) {
        val s1 = stars[i]
        val s2 = stars[(i + 3) % stars.size]
        if (hypot(s2.x - s1.x, s2.y - s1.y) < size.width * 0.35f) {
            drawLine(
                color = accent.copy(alpha = 0.09f),
                start = s1,
                end = s2,
                strokeWidth = 0.85f
            )
        }
    }
    stars.forEachIndexed { i, pt ->
        val shimmer = 0.35f + 0.65f * (0.5f + 0.5f * sin(phase * 1.2f + i * 0.7f))
        drawCircle(
            color = (if (i % 4 == 0) accent else NyxTextPrimary).copy(alpha = 0.45f * shimmer),
            radius = if (i % 5 == 0) 2.0f else 1.2f,
            center = pt
        )
    }
}

private fun DrawScope.drawConstellationLightNodes(
    scene: AiVisualScene,
    size: Size,
    zoom: Float,
    pan: Offset,
    phase: Float,
    modeAccent: Color,
    selectedNodeId: String?,
    highlightLayer: Int?,
    pointerField: Offset?,
    textMeasurer: TextMeasurer
) {
    // Interconnected circuit edges between nodes
    val nodePos = scene.nodes.associate { it.id to projectNodePoint(it, size, zoom, pan) }
    scene.edges.forEach { edge ->
        val p1 = nodePos[edge.fromId] ?: return@forEach
        val p2 = nodePos[edge.toId] ?: return@forEach
        val midX = (p1.x + p2.x) * 0.5f
        val circuitPath = Path().apply {
            moveTo(p1.x, p1.y)
            lineTo(midX, p1.y)
            lineTo(midX, p2.y)
            lineTo(p2.x, p2.y)
        }
        drawPath(
            path = circuitPath,
            color = modeAccent.copy(alpha = 0.28f * edge.intensity.coerceIn(0.3f, 1f)),
            style = Stroke(width = 1.4f, cap = StrokeCap.Round)
        )
    }

    scene.nodes.forEachIndexed { idx, node ->
        val basePt = nodePos[node.id] ?: return@forEachIndexed
        val driftY = sin(phase + idx * 1.15f) * 3.2f
        val pt = Offset(basePt.x, basePt.y + driftY)
        val color = riskColor(node.riskScore, modeAccent)
        val isSelected = node.id == selectedNodeId
        val pointerBoost = pointerField?.let {
            val d = hypot(pt.x - it.x, pt.y - it.y)
            if (d < 160f) (1f - d / 160f) * 7f else 0f
        } ?: 0f
        val layerActive = highlightLayer == null || node.layerIndex == highlightLayer
        val alphaMult = if (layerActive) 1f else 0.32f
        val radius = (if (isSelected) 15f else 10f + node.riskScore * 4.5f) + pointerBoost

        // Constellation light aura
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(color.copy(alpha = (if (isSelected) 0.58f else 0.34f) * alphaMult), Color.Transparent),
                center = pt,
                radius = radius * 3.0f
            ),
            radius = radius * 3.0f,
            center = pt
        )

        // Segmented orbital ring
        val rotDeg = ((phase * 57.2958f) + idx * 45f) % 360f
        val ringR = radius + 6f
        for (seg in 0..2) {
            drawArc(
                color = color.copy(alpha = 0.72f * alphaMult),
                startAngle = rotDeg + seg * 120f,
                sweepAngle = 70f,
                useCenter = false,
                topLeft = Offset(pt.x - ringR, pt.y - ringR),
                size = Size(ringR * 2f, ringR * 2f),
                style = Stroke(width = 1.4f, cap = StrokeCap.Round)
            )
        }

        // Chamfered IC light die + 4-point star flare
        drawRect(
            color = NyxVoid,
            topLeft = Offset(pt.x - radius * 0.75f, pt.y - radius * 0.75f),
            size = Size(radius * 1.5f, radius * 1.5f)
        )
        drawRect(
            color = (if (isSelected) NyxTextPrimary else color).copy(alpha = alphaMult),
            topLeft = Offset(pt.x - radius * 0.75f, pt.y - radius * 0.75f),
            size = Size(radius * 1.5f, radius * 1.5f),
            style = Stroke(width = if (isSelected) 2f else 1.4f)
        )
        val starR = radius * 0.7f
        val innerR = starR * 0.25f
        val flare = Path().apply {
            moveTo(pt.x, pt.y - starR)
            lineTo(pt.x + innerR, pt.y - innerR)
            lineTo(pt.x + starR, pt.y)
            lineTo(pt.x + innerR, pt.y + innerR)
            lineTo(pt.x, pt.y + starR)
            lineTo(pt.x - innerR, pt.y + innerR)
            lineTo(pt.x - starR, pt.y)
            lineTo(pt.x - innerR, pt.y - innerR)
            close()
        }
        drawPath(flare, color = NyxTextPrimary.copy(alpha = 0.92f * alphaMult))

        val labelLayout = textMeasurer.measure(
            text = node.label,
            style = TextStyle(
                fontFamily = JetBrainsMonoFontFamily,
                fontSize = 10.sp,
                fontWeight = FontWeight.SemiBold,
                color = NyxTextPrimary.copy(alpha = alphaMult)
            )
        )
        val labelX = (pt.x - labelLayout.size.width / 2f).coerceIn(10f, size.width - labelLayout.size.width - 10f)
        val labelY = (pt.y + ringR + 5f).coerceIn(16f, size.height - 40f)
        drawText(labelLayout, topLeft = Offset(labelX, labelY))

        if (node.sublabel.isNotBlank()) {
            val subLayout = textMeasurer.measure(
                text = node.sublabel,
                style = TextStyle(
                    fontFamily = JetBrainsMonoFontFamily,
                    fontSize = 8.5.sp,
                    color = NyxTextSecondary.copy(alpha = alphaMult)
                )
            )
            val subX = (pt.x - subLayout.size.width / 2f).coerceIn(10f, size.width - subLayout.size.width - 10f)
            drawText(subLayout, topLeft = Offset(subX, labelY + labelLayout.size.height))
        }
    }
}

private fun DrawScope.drawAttackVectorFlow(
    scene: AiVisualScene,
    size: Size,
    zoom: Float,
    pan: Offset,
    phase: Float,
    pulse: Float,
    modeAccent: Color,
    selectedNodeId: String?,
    highlightLayer: Int?,
    pointerField: Offset?,
    textMeasurer: TextMeasurer
) {
    val nodeMap = scene.nodes.associateBy { it.id }
    scene.edges.forEachIndexed { idx, edge ->
        val from = nodeMap[edge.fromId] ?: return@forEachIndexed
        val to = nodeMap[edge.toId] ?: return@forEachIndexed
        val p1 = projectNodePoint(from, size, zoom, pan)
        val p2 = projectNodePoint(to, size, zoom, pan)
        val c1 = Offset(p1.x + (p2.x - p1.x) * 0.45f, p1.y)
        val c2 = Offset(p1.x + (p2.x - p1.x) * 0.55f, p2.y)
        val path = Path().apply {
            moveTo(p1.x, p1.y)
            cubicTo(c1.x, c1.y, c2.x, c2.y, p2.x, p2.y)
        }
        val color = riskColor(to.riskScore, modeAccent)
        drawPath(
            path = path,
            brush = Brush.linearGradient(
                colors = listOf(modeAccent.copy(alpha = 0.35f), color.copy(alpha = 0.7f)),
                start = p1,
                end = p2
            ),
            style = Stroke(width = 3.2f * edge.intensity + 1.4f, cap = StrokeCap.Round)
        )
        val t = (pulse + idx * 0.23f) % 1f
        val inv = 1f - t
        val px = inv * inv * inv * p1.x + 3 * inv * inv * t * c1.x + 3 * inv * t * t * c2.x + t * t * t * p2.x
        val py = inv * inv * inv * p1.y + 3 * inv * inv * t * c1.y + 3 * inv * t * t * c2.y + t * t * t * p2.y
        drawCircle(color = NyxTextPrimary, radius = 4f, center = Offset(px, py))
    }
    drawConstellationLightNodes(scene, size, zoom, pan, phase, modeAccent, selectedNodeId, highlightLayer, pointerField, textMeasurer)
}

private fun DrawScope.drawSpectrumInterference(
    scene: AiVisualScene,
    size: Size,
    phase: Float,
    modeAccent: Color
) {
    val values = scene.spectrumValues.ifEmpty { listOf(0.3f, 0.7f, 0.5f, 0.8f, 0.4f, 0.6f) }
    val bandCenterY = size.height * 0.35f
    val maxAmp = size.height * 0.14f

    for (harmonic in 0..2) {
        val path = Path()
        val steps = 80
        val color = when (harmonic) {
            0 -> modeAccent
            1 -> NyxViolet
            else -> NyxEmerald
        }
        for (i in 0..steps) {
            val t = i.toFloat() / steps
            val x = t * size.width
            val idx = ((t * (values.size - 1)).toInt()).coerceIn(0, values.lastIndex)
            val v = values[idx]
            val wave = sin(t * 14f + phase * (harmonic + 1) * 0.7f + harmonic * 1.4f)
            val y = bandCenterY + wave * v * maxAmp * (1f - harmonic * 0.22f)
            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        drawPath(
            path = path,
            color = color.copy(alpha = 0.62f - harmonic * 0.14f),
            style = Stroke(width = 3.2f - harmonic * 0.6f, cap = StrokeCap.Round)
        )
    }

    val barCount = values.size.coerceAtMost(32)
    val barStep = size.width / (barCount + 2)
    values.take(barCount).forEachIndexed { idx, v ->
        val x = (idx + 1.5f) * barStep
        val h = v * size.height * 0.18f
        drawLine(
            color = riskColor(v, modeAccent).copy(alpha = 0.36f),
            start = Offset(x, bandCenterY - h * 0.5f),
            end = Offset(x, bandCenterY + h * 0.5f),
            strokeWidth = 3f,
            cap = StrokeCap.Round
        )
    }
}

private fun DrawScope.drawEntropyMatrix(
    scene: AiVisualScene,
    size: Size,
    phase: Float,
    modeAccent: Color
) {
    val values = scene.spectrumValues.ifEmpty { List(24) { 0.35f } }
    val cols = 8
    val rows = ((values.size + cols - 1) / cols).coerceIn(3, 6)
    val marginX = size.width * 0.08f
    val topY = size.height * 0.16f
    val gridW = size.width - marginX * 2f
    val gridH = size.height * 0.36f
    val cellW = gridW / cols
    val cellH = gridH / rows

    for (r in 0 until rows) {
        for (c in 0 until cols) {
            val idx = (r * cols + c) % values.size
            val v = values[idx]
            val pulseAlpha = 0.18f + 0.52f * v + 0.08f * sin(phase + r * 0.7f + c * 0.5f)
            val x = marginX + c * cellW + 5f
            val y = topY + r * cellH + 5f
            drawRoundRect(
                color = riskColor(v, modeAccent).copy(alpha = pulseAlpha.coerceIn(0.1f, 0.85f)),
                topLeft = Offset(x, y),
                size = Size(cellW - 10f, cellH - 10f),
                cornerRadius = CornerRadius(10f, 10f)
            )
        }
    }
}

private fun DrawScope.drawProtocolStrata(
    scene: AiVisualScene,
    size: Size,
    phase: Float,
    modeAccent: Color,
    textMeasurer: TextMeasurer
) {
    val strata = scene.strata.ifEmpty { return }
    val topY = size.height * 0.15f
    val totalH = size.height * 0.38f
    val layerH = totalH / strata.size.coerceAtLeast(1)

    strata.forEachIndexed { idx, layer ->
        val y = topY + idx * layerH + layerH * 0.45f
        val color = if (layer.healthScore >= 0.75f) NyxEmerald
        else if (layer.healthScore >= 0.45f) modeAccent
        else NyxCrimson

        val path = Path()
        val steps = 40
        for (s in 0..steps) {
            val t = s.toFloat() / steps
            val x = size.width * 0.06f + t * size.width * 0.88f
            val ripple = sin(t * 8f + phase + idx * 0.9f) * (1f - layer.healthScore + 0.25f) * 8f
            val py = y + ripple
            if (s == 0) path.moveTo(x, py) else path.lineTo(x, py)
        }
        drawPath(path = path, color = color.copy(alpha = 0.55f), style = Stroke(width = 3.5f, cap = StrokeCap.Round))

        val labelLayout = textMeasurer.measure(
            text = "${layer.name.uppercase()} · ${layer.status}",
            style = TextStyle(
                fontFamily = JetBrainsMonoFontFamily,
                fontSize = 10.sp,
                fontWeight = FontWeight.Medium,
                color = color.copy(alpha = 0.92f)
            )
        )
        drawText(labelLayout, topLeft = Offset(size.width * 0.08f, y - labelLayout.size.height - 8f))
    }
}

private fun DrawScope.drawBinaryHelix(
    scene: AiVisualScene,
    size: Size,
    phase: Float,
    modeAccent: Color
) {
    val values = scene.spectrumValues.ifEmpty { List(28) { 0.5f } }
    val startX = size.width * 0.08f
    val endX = size.width * 0.92f
    val centerY = size.height * 0.34f
    val amp = size.height * 0.12f
    val pathA = Path()
    val pathB = Path()

    values.forEachIndexed { idx, v ->
        val t = idx.toFloat() / (values.lastIndex.coerceAtLeast(1))
        val x = startX + t * (endX - startX)
        val angle = t * 4f * PI.toFloat() + phase
        val yA = centerY + sin(angle) * amp * (0.5f + v * 0.6f)
        val yB = centerY + sin(angle + PI.toFloat()) * amp * (0.5f + v * 0.6f)

        if (idx == 0) {
            pathA.moveTo(x, yA)
            pathB.moveTo(x, yB)
        } else {
            pathA.lineTo(x, yA)
            pathB.lineTo(x, yB)
        }

        val rungColor = riskColor(v, modeAccent)
        drawLine(color = rungColor.copy(alpha = 0.35f), start = Offset(x, yA), end = Offset(x, yB), strokeWidth = 2f)
        drawCircle(color = rungColor, radius = 4f, center = Offset(x, yA))
        drawCircle(color = NyxViolet, radius = 3.5f, center = Offset(x, yB))
    }

    drawPath(pathA, color = modeAccent.copy(alpha = 0.75f), style = Stroke(width = 2.8f))
    drawPath(pathB, color = NyxViolet.copy(alpha = 0.75f), style = Stroke(width = 2.8f))
}

private fun DrawScope.drawSynthesisInterferenceOverlay(
    size: Size,
    phase: Float,
    accent: Color
) {
    val path = Path()
    val yCenter = size.height * 0.34f
    val steps = 72
    for (i in 0..steps) {
        val t = i.toFloat() / steps
        val x = t * size.width
        val envelope = sin(t * PI.toFloat())
        val y = yCenter + sin(t * 18f + phase * 3f) * 38f * envelope
        if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
    }
    drawPath(
        path = path,
        brush = Brush.horizontalGradient(listOf(Color.Transparent, accent, NyxViolet, Color.Transparent)),
        style = Stroke(width = 4f, cap = StrokeCap.Round)
    )
}
