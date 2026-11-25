package com.aura.mobiledefense.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.aura.mobiledefense.data.model.AiVisualScene
import com.aura.mobiledefense.data.model.AuraChatMessage
import com.aura.mobiledefense.data.model.ChatSpeaker
import com.aura.mobiledefense.data.model.ExecutionStepState
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.data.model.VpnFirewallTelemetry
import com.aura.mobiledefense.ui.theme.NyxAmber
import com.aura.mobiledefense.ui.theme.NyxCrimson
import com.aura.mobiledefense.ui.theme.NyxCyan
import com.aura.mobiledefense.ui.theme.NyxEmerald
import com.aura.mobiledefense.ui.theme.NyxHairline
import com.aura.mobiledefense.ui.theme.NyxTextMuted
import com.aura.mobiledefense.ui.theme.NyxTextPrimary
import com.aura.mobiledefense.ui.theme.NyxTextSecondary
import com.aura.mobiledefense.ui.theme.NyxViolet

/**
 * Pure-black (#000000) conversational panel for Aura Mobile Defense.
 * Displays multi-turn conversation, recommendations, suggestions, solutions,
 * live step-by-step execution progress, and live VPN/Firewall telemetry with zero UI buttons.
 */
@Composable
fun BlackConversationalPanel(
    messages: List<AuraChatMessage>,
    activeScene: AiVisualScene?,
    vpnTelemetry: VpnFirewallTelemetry,
    privilegeMode: PrivilegeMode,
    analyzingPhase: String?,
    errorMessage: String?,
    onExecuteWhisper: (String) -> Unit,
    onExecuteSolutionsNow: () -> Unit,
    onToggleVpn: () -> Unit,
    onOpenReportAndPatches: () -> Unit,
    modifier: Modifier = Modifier
) {
    // 0 = compact, 1 = standard (default), 2 = expanded
    var panelStage by remember { mutableIntStateOf(1) }
    var showVpnPacketFeed by remember { mutableStateOf(false) }

    val panelHeight by animateDpAsState(
        targetValue = when (panelStage) {
            0 -> 145.dp
            1 -> 295.dp
            else -> 430.dp
        },
        label = "black_panel_height"
    )
    val accent = if (privilegeMode == PrivilegeMode.ROOT) NyxAmber else NyxCyan
    val listState = rememberLazyListState()

    LaunchedEffect(messages.size, messages.lastOrNull()?.executionSteps?.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.lastIndex)
        }
    }

    Column(
        modifier = modifier
            .widthIn(max = 720.dp)
            .fillMaxWidth()
            .background(Color.Black)
            .testTag("black_conversational_panel")
    ) {
        // Subtle luminous hairline separating Aura Mobile Defens circuit hologram from pure black chat panel
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(accent.copy(alpha = 0.45f))
        )

        // Drag handle to expand / collapse pure black panel
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 34.dp)
                .testTag("stream_drag_handle")
                .pointerInput(panelStage) {
                    var dragY = 0f
                    detectVerticalDragGestures(
                        onDragStart = { dragY = 0f },
                        onVerticalDrag = { _, delta -> dragY += delta },
                        onDragEnd = {
                            if (dragY < -40f) panelStage = (panelStage + 1).coerceAtMost(2)
                            else if (dragY > 40f) panelStage = (panelStage - 1).coerceAtLeast(0)
                        }
                    )
                }
                .pointerInput(panelStage) {
                    detectTapGestures(onTap = { panelStage = if (panelStage == 2) 1 else panelStage + 1 })
                },
            contentAlignment = Alignment.Center
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = if (vpnTelemetry.isRunning) {
                        "VPN TUN ACTIVA · ${vpnTelemetry.packetsInspected} pkt (${vpnTelemetry.packetsBlocked} bloq.)"
                    } else {
                        "VPN LOCAL + FIREWALL EN ESPERA (${vpnTelemetry.activeRulesCount} reglas)"
                    },
                    style = MaterialTheme.typography.labelSmall.copy(
                        color = if (vpnTelemetry.isRunning) NyxEmerald else NyxTextMuted
                    ),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier
                        .weight(1f)
                        .clickable { showVpnPacketFeed = !showVpnPacketFeed }
                )

                Box(
                    modifier = Modifier
                        .width(38.dp)
                        .height(3.dp)
                        .clip(RoundedCornerShape(2.dp))
                        .background(NyxHairline)
                )

                Text(
                    text = if (vpnTelemetry.isRunning) "↳ apagar VPN" else "↳ encender VPN",
                    style = MaterialTheme.typography.labelSmall.copy(
                        color = if (vpnTelemetry.isRunning) NyxAmber else NyxCyan
                    ),
                    modifier = Modifier
                        .testTag("vpn_quick_whisper")
                        .clickable { onToggleVpn() }
                        .padding(start = 10.dp, top = 6.dp, bottom = 6.dp)
                )
            }
        }

        // Optional live VPN/Firewall packet telemetry drawer inside black panel
        AnimatedVisibility(visible = showVpnPacketFeed) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF070709))
                    .padding(horizontal = 20.dp, vertical = 8.dp)
            ) {
                Text(
                    text = "TELEMETRÍA VPN (${vpnTelemetry.tunAddress} → ${vpnTelemetry.upstreamDns} · RTT ${vpnTelemetry.lastDnsRttMs}ms · RX ${vpnTelemetry.bytesIn}B / TX ${vpnTelemetry.bytesOut}B)",
                    style = MaterialTheme.typography.labelSmall.copy(color = NyxCyan)
                )
                if (vpnTelemetry.recentEvents.isEmpty()) {
                    Text(
                        text = "Sin paquetes capturados aún. Activa la VPN o navega para inspeccionar DNS y rutas bloqueadas en tiempo real.",
                        style = MaterialTheme.typography.bodySmall.copy(color = NyxTextMuted),
                        modifier = Modifier.padding(top = 4.dp)
                    )
                } else {
                    vpnTelemetry.recentEvents.take(5).forEach { ev ->
                        val evColor = if (ev.action.name == "BLOCKED") NyxCrimson else NyxEmerald
                        Text(
                            text = "[${ev.action.name}] ${ev.protocol} ${ev.destination}:${ev.port} (${ev.rttMs}ms) — ${ev.reason}",
                            style = MaterialTheme.typography.labelSmall.copy(color = evColor),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
        }

        if (analyzingPhase != null) {
            Text(
                text = "◈ $analyzingPhase",
                style = MaterialTheme.typography.labelMedium.copy(color = NyxViolet),
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp)
            )
        }

        if (errorMessage != null) {
            Text(
                text = "⚠ $errorMessage",
                style = MaterialTheme.typography.bodySmall.copy(color = NyxCrimson),
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp)
            )
        }

        // Multi-turn pure black conversational feed
        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxWidth()
                .height(panelHeight)
                .padding(horizontal = 20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(messages, key = { it.id }) { msg ->
                if (msg.speaker == ChatSpeaker.USER) {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalAlignment = Alignment.End
                    ) {
                        Text(
                            text = "> ${msg.text}",
                            style = MaterialTheme.typography.bodyMedium.copy(
                                color = accent,
                                fontWeight = FontWeight.Medium
                            ),
                            modifier = Modifier
                                .background(Color(0xFF0D1117), RoundedCornerShape(10.dp))
                                .padding(horizontal = 12.dp, vertical = 8.dp)
                        )
                    }
                } else {
                    AuraBlackReplyBlock(
                        message = msg,
                        accent = accent,
                        onExecuteWhisper = onExecuteWhisper,
                        onExecuteSolutionsNow = onExecuteSolutionsNow,
                        onOpenReportAndPatches = onOpenReportAndPatches
                    )
                }
            }

            if (activeScene != null && messages.isEmpty()) {
                item {
                    Text(
                        text = activeScene.narrative,
                        style = MaterialTheme.typography.bodyMedium.copy(color = NyxTextPrimary),
                        modifier = Modifier.testTag("ai_narrative_text")
                    )
                }
            }
        }
    }
}

@Composable
private fun AuraBlackReplyBlock(
    message: AuraChatMessage,
    accent: Color,
    onExecuteWhisper: (String) -> Unit,
    onExecuteSolutionsNow: () -> Unit,
    onOpenReportAndPatches: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 4.dp)
    ) {
        if (message.subtitle.isNotBlank()) {
            Text(
                text = message.subtitle,
                style = MaterialTheme.typography.labelSmall.copy(color = NyxTextMuted),
                modifier = Modifier.padding(bottom = 3.dp)
            )
        }

        Text(
            text = message.text,
            style = MaterialTheme.typography.bodyMedium.copy(color = NyxTextPrimary),
            modifier = Modifier.testTag("ai_narrative_text")
        )

        // Live Step-by-Step Execution Log inside the black panel
        if (message.executionSteps.isNotEmpty()) {
            Spacer(modifier = Modifier.height(8.dp))
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF080C10), RoundedCornerShape(8.dp))
                    .padding(10.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text(
                    text = if (message.isExecuting) {
                        "EJECUTANDO SOLUCIONES EN VIVO…"
                    } else {
                        "EJECUCIÓN DE SOLUCIONES COMPLETADA"
                    },
                    style = MaterialTheme.typography.labelSmall.copy(
                        color = if (message.isExecuting) NyxCyan else NyxEmerald,
                        fontWeight = FontWeight.Bold
                    )
                )
                message.executionSteps.forEach { step ->
                    val (glyph, stepColor) = when (step.state) {
                        ExecutionStepState.RUNNING -> "◈" to NyxCyan
                        ExecutionStepState.DONE -> "✓" to NyxEmerald
                        ExecutionStepState.NEEDS_CONSENT -> "!" to NyxAmber
                        ExecutionStepState.FAILED -> "✕" to NyxCrimson
                    }
                    Column {
                        Text(
                            text = "[$glyph] Paso ${step.stepNumber}: ${step.title}",
                            style = MaterialTheme.typography.labelMedium.copy(color = stepColor)
                        )
                        Text(
                            text = step.detail,
                            style = MaterialTheme.typography.bodySmall.copy(color = NyxTextSecondary)
                        )
                    }
                }
            }
        }

        // Recommendations
        if (message.recommendations.isNotEmpty()) {
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = "Recomendaciones:",
                style = MaterialTheme.typography.labelSmall.copy(color = NyxViolet)
            )
            message.recommendations.forEach { rec ->
                Text(
                    text = "· $rec",
                    style = MaterialTheme.typography.bodySmall.copy(color = NyxTextSecondary),
                    modifier = Modifier.padding(vertical = 1.dp)
                )
            }
        }

        // Solutions ready + live execution trigger (zero buttons)
        if (message.patches.isNotEmpty() && message.executionSteps.isEmpty()) {
            Spacer(modifier = Modifier.height(4.dp))
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag("execute_solutions_whisper")
                    .clickable { onExecuteSolutionsNow() },
                contentAlignment = Alignment.CenterStart
            ) {
                Text(
                    text = "↳ ejecutar ${message.patches.size} solución(es) ahora en vivo (Firewall / Parches / Hardening)",
                    style = MaterialTheme.typography.bodySmall.copy(
                        color = NyxEmerald,
                        fontWeight = FontWeight.SemiBold
                    )
                )
            }
        }

        if (message.hasReport) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag("open_report_patches_whisper")
                    .clickable { onOpenReportAndPatches() },
                contentAlignment = Alignment.CenterStart
            ) {
                Text(
                    text = "↳ ver reporte integral y código de soluciones",
                    style = MaterialTheme.typography.labelMedium.copy(color = NyxAmber)
                )
            }
        }

        // Interactive suggestions
        if (message.suggestions.isNotEmpty()) {
            message.suggestions.forEachIndexed { idx, suggestion ->
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag("whisper_prompt_$idx")
                        .clickable { onExecuteWhisper(suggestion) },
                    contentAlignment = Alignment.CenterStart
                ) {
                    Text(
                        text = "↳ $suggestion",
                        style = MaterialTheme.typography.bodySmall.copy(color = accent),
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(6.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(NyxHairline.copy(alpha = 0.55f))
        )
    }
}
