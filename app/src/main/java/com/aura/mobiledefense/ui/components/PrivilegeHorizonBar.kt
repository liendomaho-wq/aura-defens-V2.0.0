package com.aura.mobiledefense.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import com.aura.mobiledefense.R
import com.aura.mobiledefense.data.model.AiEngineMode
import com.aura.mobiledefense.data.model.PrivilegeMode
import com.aura.mobiledefense.data.model.RootCapabilityState
import com.aura.mobiledefense.data.model.ThreatKnowledgeStats
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
import kotlin.math.roundToInt

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun PrivilegeHorizonBar(
    privilegeMode: PrivilegeMode,
    engineMode: AiEngineMode,
    rootState: RootCapabilityState,
    knowledgeStats: ThreatKnowledgeStats,
    monitorBanner: String?,
    onSwitchPrivilegeMode: (PrivilegeMode) -> Unit,
    onToggleEngineMode: (AiEngineMode) -> Unit,
    onOpenLlmSettings: () -> Unit,
    onPullDownMemory: () -> Unit,
    modifier: Modifier = Modifier
) {
    val cdHorizon = stringResource(R.string.cd_privilege_horizon)
    val accent by animateColorAsState(
        targetValue = if (privilegeMode == PrivilegeMode.ROOT) NyxAmber else NyxCyan,
        label = "horizon_accent"
    )
    val targetFraction = if (privilegeMode == PrivilegeMode.ROOT) 1f else 0f
    var dragDeltaPx by remember { mutableFloatStateOf(0f) }

    val sliderFraction by animateFloatAsState(
        targetValue = targetFraction,
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
        label = "slider_fraction"
    )

    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(
                Brush.verticalGradient(
                    colors = listOf(NyxVoid.copy(alpha = 0.94f), NyxVoid.copy(alpha = 0.62f), Color.Transparent)
                )
            )
            .statusBarsPadding()
            .padding(horizontal = 20.dp, vertical = 8.dp)
            .pointerInput(Unit) {
                var verticalDrag = 0f
                detectVerticalDragGestures(
                    onDragStart = { verticalDrag = 0f },
                    onVerticalDrag = { _, dragAmount ->
                        verticalDrag += dragAmount
                        if (verticalDrag > 72f) {
                            verticalDrag = 0f
                            onPullDownMemory()
                        }
                    }
                )
            }
            .semantics { contentDescription = cdHorizon }
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "AURA DEFENSE",
                style = MaterialTheme.typography.titleMedium.copy(
                    fontWeight = FontWeight.Bold,
                    color = NyxTextPrimary
                )
            )

            // Tappable text telemetry line to switch Online <-> Local Autonomous without buttons
            val engineText = if (engineMode == AiEngineMode.ONLINE_CLOUD) {
                "AURA IA · LLM ON (${knowledgeStats.totalRules} firmas)"
            } else {
                "AURA IA · LOCAL (${knowledgeStats.totalRules} firmas)"
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = engineText,
                    style = MaterialTheme.typography.labelSmall.copy(
                        color = if (engineMode == AiEngineMode.ONLINE_CLOUD) NyxViolet else NyxEmerald
                    ),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier
                        .heightIn(min = 32.dp)
                        .testTag("engine_mode_toggle")
                        .combinedClickable(
                            onClick = {
                                val next = if (engineMode == AiEngineMode.ONLINE_CLOUD) {
                                    AiEngineMode.LOCAL_AUTONOMOUS
                                } else {
                                    AiEngineMode.ONLINE_CLOUD
                                }
                                onToggleEngineMode(next)
                            },
                            onLongClick = onOpenLlmSettings
                        )
                        .padding(vertical = 6.dp)
                )
                // Explicit affordance for the BYOK sheet: long-press is discoverable only by accident.
                Text(
                    text = "⚙",
                    style = MaterialTheme.typography.labelMedium.copy(
                        color = if (engineMode == AiEngineMode.ONLINE_CLOUD) NyxViolet else NyxTextMuted
                    ),
                    modifier = Modifier
                        .heightIn(min = 40.dp)
                        .width(40.dp)
                        .testTag("open_llm_settings")
                        .clickable { onOpenLlmSettings() }
                        .padding(start = 8.dp, top = 6.dp, bottom = 6.dp)
                )
            }
        }

        // Gesture-based Magnetic Privilege Horizon (minimum 48dp touch area, zero buttons)
        BoxWithConstraints(
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp)
                .testTag("privilege_horizon_slider")
                .pointerInput(privilegeMode) {
                    detectHorizontalDragGestures(
                        onDragStart = { dragDeltaPx = 0f },
                        onHorizontalDrag = { _, dragAmount -> dragDeltaPx += dragAmount },
                        onDragEnd = {
                            if (dragDeltaPx > 48f && privilegeMode != PrivilegeMode.ROOT) {
                                onSwitchPrivilegeMode(PrivilegeMode.ROOT)
                            } else if (dragDeltaPx < -48f && privilegeMode != PrivilegeMode.USERLAND) {
                                onSwitchPrivilegeMode(PrivilegeMode.USERLAND)
                            }
                            dragDeltaPx = 0f
                        }
                    )
                }
                .pointerInput(privilegeMode) {
                    detectTapGestures { offset ->
                        val next = if (offset.x > size.width / 2f) PrivilegeMode.ROOT else PrivilegeMode.USERLAND
                        if (next != privilegeMode) onSwitchPrivilegeMode(next)
                    }
                },
            contentAlignment = Alignment.Center
        ) {
            val density = LocalDensity.current
            val trackWidthPx = with(density) { maxWidth.toPx() }
            val thumbWidthDp = 128.dp
            val thumbWidthPx = with(density) { thumbWidthDp.toPx() }
            val maxTravelPx = (trackWidthPx - thumbWidthPx).coerceAtLeast(0f)

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(2.dp)
                    .background(NyxHairline)
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.mode_userland_label),
                    style = MaterialTheme.typography.labelSmall.copy(
                        color = if (privilegeMode == PrivilegeMode.USERLAND) NyxCyan else NyxTextMuted
                    )
                )
                Text(
                    text = stringResource(R.string.mode_root_label),
                    style = MaterialTheme.typography.labelSmall.copy(
                        color = if (privilegeMode == PrivilegeMode.ROOT) NyxAmber else NyxTextMuted
                    )
                )
            }

            Box(
                modifier = Modifier
                    .align(Alignment.CenterStart)
                    .offset { IntOffset((maxTravelPx * sliderFraction).roundToInt(), 0) }
                    .width(thumbWidthDp)
                    .height(4.dp)
                    .clip(RoundedCornerShape(2.dp))
                    .background(
                        Brush.horizontalGradient(
                            colors = listOf(Color.Transparent, accent, Color.Transparent)
                        )
                    )
            )
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "${rootState.uidOutput} · SELinux ${rootState.selinuxMode}",
                style = MaterialTheme.typography.labelSmall.copy(color = NyxTextSecondary),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )
            Text(
                text = stringResource(R.string.horizon_gesture_hint),
                style = MaterialTheme.typography.labelSmall.copy(color = NyxTextMuted),
                maxLines = 1
            )
        }

        if (!monitorBanner.isNullOrBlank()) {
            Text(
                text = "⚠ $monitorBanner",
                style = MaterialTheme.typography.labelSmall.copy(color = NyxCrimson),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier
                    .padding(top = 4.dp)
                    .clickable(onClick = onPullDownMemory)
            )
        }
    }
}
