package com.example.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val NyxDarkColorScheme = darkColorScheme(
    primary = NyxCyan,
    onPrimary = NyxVoid,
    primaryContainer = NyxCyanDim,
    onPrimaryContainer = NyxTextPrimary,
    secondary = NyxViolet,
    onSecondary = NyxVoid,
    tertiary = NyxAmber,
    onTertiary = NyxVoid,
    background = NyxVoid,
    onBackground = NyxTextPrimary,
    surface = NyxSurface,
    onSurface = NyxTextPrimary,
    surfaceVariant = NyxSurfaceElevated,
    onSurfaceVariant = NyxTextSecondary,
    outline = NyxHairline,
    error = NyxCrimson,
    onError = NyxVoid
)

@Composable
fun NyxCoreTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = NyxDarkColorScheme,
        typography = NyxTypography,
        content = content
    )
}
