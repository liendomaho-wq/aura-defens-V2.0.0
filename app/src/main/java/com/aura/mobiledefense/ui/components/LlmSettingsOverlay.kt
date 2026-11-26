package com.aura.mobiledefense.ui.components

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.aura.mobiledefense.domain.ai.llm.LlmBackendKind
import com.aura.mobiledefense.domain.ai.llm.LlmProviderId
import com.aura.mobiledefense.domain.ai.llm.LlmSettings
import com.aura.mobiledefense.domain.ai.llm.LlmSettingsStore
import com.aura.mobiledefense.ui.theme.NyxAmber
import com.aura.mobiledefense.ui.theme.NyxCyan
import com.aura.mobiledefense.ui.theme.NyxEmerald
import com.aura.mobiledefense.ui.theme.NyxHairline
import com.aura.mobiledefense.ui.theme.NyxSurface
import com.aura.mobiledefense.ui.theme.NyxSurfaceElevated
import com.aura.mobiledefense.ui.theme.NyxTextMuted
import com.aura.mobiledefense.ui.theme.NyxTextPrimary
import com.aura.mobiledefense.ui.theme.NyxTextSecondary
import com.aura.mobiledefense.ui.theme.NyxViolet
import com.aura.mobiledefense.ui.theme.NyxVoid

/**
 * BYOK configuration sheet for the LLM backend.
 *
 * Design rules it follows:
 *  - The privacy notice is not optional: nothing is enabled until the user accepts that redacted
 *    telemetry leaves the device.
 *  - The key is a password field, never echoed, stored in EncryptedSharedPreferences by the store.
 *  - Every control has a test tag so the Compose tests can drive it.
 */
@Composable
fun LlmSettingsOverlay(
    settings: LlmSettings,
    status: String,
    onUpdate: ((LlmSettings) -> LlmSettings) -> Unit,
    onTestConnection: () -> Unit,
    onClearKey: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    BackHandler(onBack = onDismiss)
    val scroll = rememberScrollState()
    var presetIndex by remember { mutableStateOf(0) }

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
                    onVerticalDrag = { _, delta -> dragY += delta },
                    onDragEnd = { if (dragY < -75f) onDismiss() }
                )
            }
            .padding(horizontal = 20.dp, vertical = 16.dp)
            .testTag("llm_settings_overlay")
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "MOTOR IA · LLM",
                style = MaterialTheme.typography.titleMedium.copy(
                    color = NyxTextPrimary,
                    fontWeight = FontWeight.Bold
                )
            )
            Text(
                text = "Cerrar ✕",
                style = MaterialTheme.typography.labelSmall.copy(color = NyxCyan),
                modifier = Modifier
                    .clickable { onDismiss() }
                    .padding(8.dp)
                    .testTag("llm_close")
            )
        }

        Text(
            text = "Aura usa tu propia clave (BYOK). Nada se guarda en el APK ni en un servidor nuestro.",
            style = MaterialTheme.typography.labelSmall.copy(color = NyxTextMuted),
            modifier = Modifier.padding(top = 4.dp, bottom = 12.dp)
        )

        Column(
            modifier = Modifier
                .widthIn(max = 680.dp)
                .fillMaxWidth()
                .verticalScroll(scroll)
                .testTag("llm_settings_scroll")
        ) {
            // ── Master switch ────────────────────────────────────────────────────────────────
            SettingRow(
                title = "Activar el motor LLM",
                subtitle = if (settings.enabled) "Encendido" else "Apagado: Aura usa el motor heurístico local"
            ) {
                Switch(
                    checked = settings.enabled,
                    onCheckedChange = { on -> onUpdate { it.copy(enabled = on) } },
                    colors = SwitchDefaults.colors(checkedTrackColor = NyxEmerald),
                    modifier = Modifier.testTag("llm_toggle")
                )
            }

            // ── Privacy consent ──────────────────────────────────────────────────────────────
            if (settings.backend == LlmBackendKind.CLOUD && !settings.cloudConsentGiven) {
                Section(
                    title = "AVISO DE PRIVACIDAD",
                    accent = NyxAmber
                ) {
                    Text(
                        text = "En modo nube, la telemetría del dispositivo —IPs, puertos, certificados, " +
                            "paquetes— se envía REDACTADA al proveedor que elijas. Las IPs privadas, " +
                            "MACs, correos, tokens y JWT se sustituyen por marcadores antes de salir del " +
                            "teléfono. Aun así, el proveedor puede retener lo que recibe.",
                        style = MaterialTheme.typography.bodySmall.copy(color = NyxTextSecondary)
                    )
                    Spacer(Modifier.height(8.dp))
                    ActionChip(
                        label = "Entiendo y acepto",
                        accent = NyxAmber,
                        testTag = "llm_consent",
                        onClick = { onUpdate { it.copy(cloudConsentGiven = true) } }
                    )
                }
            }

            // ── Backend + provider ───────────────────────────────────────────────────────────
            Section(title = "PROVEEDOR", accent = NyxCyan) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    LlmBackendKind.entries.forEach { kind ->
                        SelectChip(
                            label = when (kind) {
                                LlmBackendKind.ON_DEVICE -> "En el dispositivo"
                                LlmBackendKind.CLOUD -> "Nube"
                                LlmBackendKind.SELF_HOSTED -> "Servidor propio"
                            },
                            selected = settings.backend == kind,
                            testTag = "llm_backend_${kind.name}",
                            onClick = { onUpdate { it.copy(backend = kind) } }
                        )
                    }
                }

                Spacer(Modifier.height(10.dp))

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    LlmProviderId.entries.forEach { id ->
                        SelectChip(
                            label = id.label,
                            selected = settings.provider == id,
                            testTag = "llm_provider_${id.name}",
                            onClick = { onUpdate { it.copy(provider = id) } }
                        )
                    }
                }
            }

            // ── Credentials ──────────────────────────────────────────────────────────────────
            if (settings.provider == LlmProviderId.GEMINI) {
                Section(title = "CLAVE GEMINI", accent = NyxViolet) {
                    SecretField(
                        value = settings.apiKey,
                        label = "API key (AI Studio)",
                        testTag = "llm_key",
                        onValueChange = { v -> onUpdate { it.copy(apiKey = v) } }
                    )
                    Spacer(Modifier.height(10.dp))
                    Text(
                        text = "MODELO",
                        style = MaterialTheme.typography.labelSmall.copy(color = NyxTextMuted)
                    )
                    Spacer(Modifier.height(6.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        LlmSettingsStore.geminiModels.forEach { model ->
                            SelectChip(
                                label = model.removePrefix("gemini-"),
                                selected = settings.model.ifBlank { LlmSettingsStore.geminiModels.first() } == model,
                                testTag = "llm_model_$model",
                                onClick = { onUpdate { it.copy(model = model) } }
                            )
                        }
                    }
                }
            }

            if (settings.provider == LlmProviderId.OPENAI_COMPATIBLE) {
                Section(title = "ENDPOINT COMPATIBLE CON OPENAI", accent = NyxViolet) {
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        LlmSettingsStore.openAiCompatiblePresets.forEachIndexed { index, preset ->
                            SelectChip(
                                label = preset.first,
                                selected = presetIndex == index && settings.baseUrl == preset.second,
                                testTag = "llm_preset_${preset.first.replace(' ', '_')}",
                                onClick = {
                                    presetIndex = index
                                    onUpdate {
                                        it.copy(
                                            baseUrl = preset.second,
                                            model = preset.third,
                                            backend = if (preset.first.contains("local")) {
                                                LlmBackendKind.SELF_HOSTED
                                            } else LlmBackendKind.CLOUD
                                        )
                                    }
                                }
                            )
                        }
                    }
                    Spacer(Modifier.height(10.dp))
                    PlainField(
                        value = settings.baseUrl,
                        label = "Base URL",
                        testTag = "llm_base_url",
                        onValueChange = { v -> onUpdate { it.copy(baseUrl = v) } }
                    )
                    Spacer(Modifier.height(8.dp))
                    PlainField(
                        value = settings.model,
                        label = "Modelo",
                        testTag = "llm_model_name",
                        onValueChange = { v -> onUpdate { it.copy(model = v) } }
                    )
                    Spacer(Modifier.height(8.dp))
                    SecretField(
                        value = settings.apiKey,
                        label = "API key (vacía en Ollama/LM Studio)",
                        testTag = "llm_key_compat",
                        onValueChange = { v -> onUpdate { it.copy(apiKey = v) } }
                    )
                }
            }

            if (settings.provider == LlmProviderId.ON_DEVICE) {
                Section(title = "MODELO LOCAL", accent = NyxEmerald) {
                    Text(
                        text = "El motor heurístico de Aura ya funciona sin conexión. Esta ranura queda " +
                            "lista para Gemini Nano / MediaPipe: mientras no haya un modelo local " +
                            "instalado, Aura usa el heurístico y no envía nada a la red.",
                        style = MaterialTheme.typography.bodySmall.copy(color = NyxTextSecondary)
                    )
                }
            }

            // ── Capabilities ────────────────────────────────────────────────────────────────
            Section(title = "QUÉ HACE LA IA", accent = NyxEmerald) {
                SettingRow(
                    title = "Elegir la herramienta",
                    subtitle = "El LLM propone; Aura valida contra el catálogo cerrado de 25 funciones"
                ) {
                    Switch(
                        checked = settings.useForIntent,
                        onCheckedChange = { on -> onUpdate { it.copy(useForIntent = on) } },
                        colors = SwitchDefaults.colors(checkedTrackColor = NyxEmerald),
                        modifier = Modifier.testTag("llm_use_intent")
                    )
                }
                SettingRow(
                    title = "Redactar el informe",
                    subtitle = "El LLM explica la telemetría real medida, sin inventar datos"
                ) {
                    Switch(
                        checked = settings.useForNarrative,
                        onCheckedChange = { on -> onUpdate { it.copy(useForNarrative = on) } },
                        colors = SwitchDefaults.colors(checkedTrackColor = NyxEmerald),
                        modifier = Modifier.testTag("llm_use_narrative")
                    )
                }
            }

            // ── Actions ─────────────────────────────────────────────────────────────────────
            Section(title = "PRUEBA Y MANTENIMIENTO", accent = NyxAmber) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ActionChip(
                        label = "Probar conexión",
                        accent = NyxCyan,
                        testTag = "llm_test",
                        onClick = onTestConnection
                    )
                    ActionChip(
                        label = "Borrar clave",
                        accent = NyxAmber,
                        testTag = "llm_clear",
                        onClick = onClearKey
                    )
                }
                if (status.isNotBlank()) {
                    Spacer(Modifier.height(10.dp))
                    Text(
                        text = status,
                        style = MaterialTheme.typography.labelSmall.copy(color = NyxCyan),
                        modifier = Modifier.testTag("llm_status")
                    )
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun Section(
    title: String,
    accent: androidx.compose.ui.graphics.Color,
    content: @Composable () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 14.dp)
            .background(NyxSurface.copy(alpha = 0.6f), RoundedCornerShape(10.dp))
            .border(1.dp, NyxHairline, RoundedCornerShape(10.dp))
            .padding(12.dp)
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.labelSmall.copy(color = accent, fontWeight = FontWeight.Bold)
        )
        Spacer(Modifier.height(8.dp))
        content()
    }
}

@Composable
private fun SettingRow(
    title: String,
    subtitle: String,
    control: @Composable () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyMedium.copy(color = NyxTextPrimary)
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.labelSmall.copy(color = NyxTextMuted)
            )
        }
        control()
    }
}

@Composable
private fun SelectChip(
    label: String,
    selected: Boolean,
    testTag: String,
    onClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .heightIn(min = 40.dp)
            .background(
                if (selected) NyxCyan.copy(alpha = 0.16f) else NyxSurfaceElevated,
                RoundedCornerShape(8.dp)
            )
            .border(
                1.dp,
                if (selected) NyxCyan else NyxHairline,
                RoundedCornerShape(8.dp)
            )
            .clickable { onClick() }
            .padding(horizontal = 10.dp, vertical = 8.dp)
            .testTag(testTag)
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall.copy(
                color = if (selected) NyxCyan else NyxTextSecondary
            )
        )
    }
}

@Composable
private fun ActionChip(
    label: String,
    accent: androidx.compose.ui.graphics.Color,
    testTag: String,
    onClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .heightIn(min = 42.dp)
            .background(accent.copy(alpha = 0.14f), RoundedCornerShape(8.dp))
            .border(1.dp, accent, RoundedCornerShape(8.dp))
            .clickable { onClick() }
            .padding(horizontal = 14.dp, vertical = 10.dp)
            .testTag(testTag)
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium.copy(color = accent, fontWeight = FontWeight.SemiBold)
        )
    }
}

@Composable
private fun SecretField(
    value: String,
    label: String,
    testTag: String,
    onValueChange: (String) -> Unit
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label, style = MaterialTheme.typography.labelSmall) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        textStyle = MaterialTheme.typography.bodySmall.copy(color = NyxTextPrimary),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = NyxCyan,
            unfocusedBorderColor = NyxHairline,
            focusedLabelColor = NyxCyan,
            unfocusedLabelColor = NyxTextMuted,
            cursorColor = NyxCyan
        ),
        modifier = Modifier
            .fillMaxWidth()
            .testTag(testTag)
    )
}

@Composable
private fun PlainField(
    value: String,
    label: String,
    testTag: String,
    onValueChange: (String) -> Unit
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label, style = MaterialTheme.typography.labelSmall) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
        textStyle = MaterialTheme.typography.bodySmall.copy(color = NyxTextPrimary),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = NyxCyan,
            unfocusedBorderColor = NyxHairline,
            focusedLabelColor = NyxCyan,
            unfocusedLabelColor = NyxTextMuted,
            cursorColor = NyxCyan
        ),
        modifier = Modifier
            .fillMaxWidth()
            .testTag(testTag)
    )
}
