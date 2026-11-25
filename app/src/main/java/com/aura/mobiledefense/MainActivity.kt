package com.aura.mobiledefense

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aura.mobiledefense.ui.screens.NyxWorkspaceScreen
import com.aura.mobiledefense.ui.theme.NyxCoreTheme
import com.aura.mobiledefense.ui.theme.NyxVoid
import com.aura.mobiledefense.ui.viewmodel.NyxViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // SQLCipher trae su propia librería nativa: hay que cargarla antes de que Room abra la
        // base cifrada, o la primera consulta falla en dispositivos con ABI inesperada.
        System.loadLibrary("sqlcipher")

        // STEP 1: Full-bleed dark edge-to-edge system bars
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)
        )

        // STEP 3: Render NyxCore AI workspace
        setContent {
            NyxCoreTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = NyxVoid
                ) {
                    val nyxViewModel: NyxViewModel = viewModel()
                    NyxWorkspaceScreen(viewModel = nyxViewModel)
                }
            }
        }
    }
}
