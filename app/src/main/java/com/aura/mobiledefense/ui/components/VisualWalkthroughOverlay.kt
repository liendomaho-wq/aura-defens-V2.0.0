package com.aura.mobiledefense.ui.components

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.aura.mobiledefense.ui.theme.NyxAmber
import com.aura.mobiledefense.ui.theme.NyxCyan
import com.aura.mobiledefense.ui.theme.NyxEmerald
import com.aura.mobiledefense.ui.theme.NyxHairline
import com.aura.mobiledefense.ui.theme.NyxTextMuted
import com.aura.mobiledefense.ui.theme.NyxTextPrimary
import com.aura.mobiledefense.ui.theme.NyxTextSecondary
import com.aura.mobiledefense.ui.theme.NyxViolet
import com.aura.mobiledefense.ui.theme.NyxVoid

@Composable
fun VisualWalkthroughOverlay(
    step: Int,
    onStepChange: (Int) -> Unit,
    onComplete: () -> Unit,
    modifier: Modifier = Modifier
) {
    BackHandler(onBack = onComplete)

    val acts = listOf(
        WalkthroughAct(
            phaseTag = "01 / 03 · QUÉ HACE AURA MOBILE DEFENSE",
            headline = "Matriz Aura Mobile Defens de circuitos, constelaciones y VPN real",
            body = "Aura reemplaza dashboards, botones, escudos y radares por una matriz holográfica de circuitos integrados y constelaciones junto a un panel conversacional en negro. Audita tu teléfono (Con y Sin Root), enciende una VPN local con firewall real y ejecuta soluciones en vivo.",
            accent = NyxCyan
        ),
        WalkthroughAct(
            phaseTag = "02 / 03 · POR QUÉ LO HACE",
            headline = "Visibilidad instantánea frente a brechas silenciosas",
            body = "Las amenazas modernas ocurren en capas ocultas: tráfico en texto claro, certificados que cambian por MITM, puertos administrativos abiertos o componentes Android expuestos. Aura vigila continuamente red y servidores contra líneas base aprendidas y verifica su propia integridad anti-manipulación.",
            accent = NyxViolet
        ),
        WalkthroughAct(
            phaseTag = "03 / 03 · CÓMO TE AYUDA (ONLINE Y LOCAL)",
            headline = "IA conversacional propia, parches y autoentrenamiento",
            body = "Conversa en lenguaje natural o toca cualquier neurona para automatizar auditorías, recibir contención defensiva y copiar parches listos para aplicar. Su IA fue creada desde cero sin claves ni pagos: usa internet para autoentrenamiento CISA KEV y vigilancia de red, o trabaja 100% offline en modo local.",
            accent = NyxEmerald
        )
    )

    val current = acts[step.coerceIn(0, acts.lastIndex)]

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        NyxVoid.copy(alpha = 0.35f),
                        NyxVoid.copy(alpha = 0.72f),
                        NyxVoid.copy(alpha = 0.96f)
                    )
                )
            )
            .pointerInput(step) {
                var dragX = 0f
                detectHorizontalDragGestures(
                    onDragStart = { dragX = 0f },
                    onHorizontalDrag = { _, d -> dragX += d },
                    onDragEnd = {
                        if (dragX < -60f) onStepChange(1)
                        else if (dragX > 60f) onStepChange(-1)
                    }
                )
            }
            .pointerInput(Unit) {
                var dragY = 0f
                detectVerticalDragGestures(
                    onDragStart = { dragY = 0f },
                    onVerticalDrag = { _, d -> dragY += d },
                    onDragEnd = {
                        if (dragY > 80f) onComplete()
                    }
                )
            }
            .testTag("visual_walkthrough_overlay")
    ) {
        // Top minimal guide indicator
        Row(
            modifier = Modifier
                .align(Alignment.TopCenter)
                .fillMaxWidth()
                .statusBarsPadding()
                .padding(horizontal = 24.dp, vertical = 18.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "AURA MOBILE DEFENSE",
                style = MaterialTheme.typography.titleMedium.copy(
                    color = NyxTextPrimary,
                    fontWeight = FontWeight.Bold
                )
            )
            Text(
                text = "RECORRIDO VISUAL",
                style = MaterialTheme.typography.labelSmall.copy(color = current.accent)
            )
        }

        // Lower typographic explanation floating seamlessly below the live neural network
        Column(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .widthIn(max = 640.dp)
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = 24.dp, vertical = 22.dp)
        ) {
            // Luminous step progress filament (no buttons)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                acts.forEachIndexed { idx, act ->
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .height(2.5.dp)
                            .background(if (idx <= step) act.accent else NyxHairline)
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            Text(
                text = current.phaseTag,
                style = MaterialTheme.typography.labelMedium.copy(color = current.accent)
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = current.headline,
                style = MaterialTheme.typography.headlineSmall.copy(
                    color = NyxTextPrimary,
                    fontWeight = FontWeight.Bold
                )
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = current.body,
                style = MaterialTheme.typography.bodyMedium.copy(color = NyxTextSecondary)
            )

            Spacer(modifier = Modifier.height(14.dp))

            // Gesture whisper lines (minimum 48dp touch height, zero buttons)
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag("walkthrough_advance_whisper")
                    .clickable { onStepChange(1) },
                contentAlignment = Alignment.CenterStart
            ) {
                Text(
                    text = if (step < 2) {
                        "↳ desliza ← o toca aquí para continuar (${step + 1}/3)"
                    } else {
                        "↳ entrar a la estación neuronal Aura Mobile Defense"
                    },
                    style = MaterialTheme.typography.bodySmall.copy(
                        color = if (step < 2) current.accent else NyxAmber,
                        fontWeight = FontWeight.Medium
                    )
                )
            }

            if (step < 2) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag("walkthrough_skip_whisper")
                        .clickable { onComplete() },
                    contentAlignment = Alignment.CenterStart
                ) {
                    Text(
                        text = "↳ omitir recorrido e iniciar directamente",
                        style = MaterialTheme.typography.labelSmall.copy(color = NyxTextMuted)
                    )
                }
            }
        }
    }
}

private data class WalkthroughAct(
    val phaseTag: String,
    val headline: String,
    val body: String,
    val accent: Color
)
