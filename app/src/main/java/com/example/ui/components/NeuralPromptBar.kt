package com.example.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.data.model.PrivilegeMode
import com.example.ui.theme.NyxAmber
import com.example.ui.theme.NyxCyan
import com.example.ui.theme.NyxTextMuted
import com.example.ui.theme.NyxTextPrimary
import com.example.ui.theme.NyxTextSecondary
import com.example.ui.theme.NyxVoid

@Composable
fun NeuralPromptBar(
    privilegeMode: PrivilegeMode,
    isBusy: Boolean,
    onSubmitQuery: (String) -> Unit,
    onTriggerFileInspection: () -> Unit,
    modifier: Modifier = Modifier
) {
    var text by remember { mutableStateOf("") }
    val accent = if (privilegeMode == PrivilegeMode.ROOT) NyxAmber else NyxCyan
    val cdInput = stringResource(R.string.cd_neural_input)
    val cdGlyph = stringResource(R.string.cd_file_drop_zone)

    val quickTemplates = remember {
        listOf(
            "/audit",
            "/vpn on",
            "/fix",
            "/monitor cloudflare.com",
            "/train",
            "/integrity",
            "/tls cloudflare.com",
            "/sockets",
            "/apps",
            "/intro"
        )
    }
    var templateIdx by remember { mutableIntStateOf(0) }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(
                Brush.verticalGradient(
                    colors = listOf(Color.Transparent, NyxVoid.copy(alpha = 0.88f), NyxVoid)
                )
            )
            .navigationBarsPadding()
            .imePadding()
            .pointerInput(text, isBusy) {
                var verticalDrag = 0f
                detectVerticalDragGestures(
                    onDragStart = { verticalDrag = 0f },
                    onVerticalDrag = { _, dragAmount ->
                        verticalDrag += dragAmount
                        if (verticalDrag < -55f && text.isNotBlank() && !isBusy) {
                            val toSend = text
                            text = ""
                            verticalDrag = 0f
                            onSubmitQuery(toSend)
                        }
                    }
                )
            }
            .padding(horizontal = 20.dp, vertical = 10.dp)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.5.dp)
                .background(
                    Brush.horizontalGradient(
                        colors = listOf(Color.Transparent, accent.copy(alpha = 0.85f), Color.Transparent)
                    )
                )
        )

        Spacer(modifier = Modifier.height(6.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .sizeIn(minWidth = 48.dp, minHeight = 48.dp)
                    .testTag("neural_glyph_gesture")
                    .semantics { contentDescription = cdGlyph }
                    .pointerInput(Unit) {
                        detectTapGestures(
                            onTap = {
                                text = quickTemplates[templateIdx % quickTemplates.size]
                                templateIdx++
                            },
                            onLongPress = {
                                onTriggerFileInspection()
                            }
                        )
                    },
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = if (privilegeMode == PrivilegeMode.ROOT) "#" else "⌘",
                    style = MaterialTheme.typography.headlineSmall.copy(color = accent)
                )
            }

            Spacer(modifier = Modifier.width(6.dp))

            Box(
                modifier = Modifier
                    .weight(1f)
                    .sizeIn(minHeight = 48.dp),
                contentAlignment = Alignment.CenterStart
            ) {
                if (text.isEmpty()) {
                    Text(
                        text = if (isBusy) "Aura ejecutando análisis neuronal…" else stringResource(R.string.neural_prompt_hint),
                        style = MaterialTheme.typography.bodySmall.copy(color = NyxTextMuted)
                    )
                }
                BasicTextField(
                    value = text,
                    onValueChange = { text = it },
                    enabled = !isBusy,
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodySmall.copy(color = NyxTextPrimary),
                    cursorBrush = SolidColor(accent),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                    keyboardActions = KeyboardActions(
                        onSend = {
                            if (text.isNotBlank() && !isBusy) {
                                val cmd = text
                                text = ""
                                onSubmitQuery(cmd)
                            }
                        }
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("neural_command_input")
                        .semantics { contentDescription = cdInput }
                )
            }
        }

        Text(
            text = "Enter o desliza ↑ para conversar/ejecutar · Toca ⌘ atajos · Mantén ⌘ APK/binario",
            style = MaterialTheme.typography.labelSmall.copy(color = NyxTextSecondary.copy(alpha = 0.7f)),
            modifier = Modifier.padding(start = 54.dp)
        )
    }
}
