# Aura Mobile Defense

Plataforma Android de ciberdefensa local: auditoría forense del dispositivo y de endpoints remotos,
VPN local con firewall a nivel de paquete, monitorización de anomalías y un asistente conversacional
que **ejecuta acciones reales** (nunca simuladas) y devuelve informes con parches.

> **Estado: pre-alpha (`versionCode 1`).** No hay release publicado ni APK firmado distribuido.
> El motor conversacional es heurístico y local; ver [Límites reales](#límites-reales-lo-que-no-es).

---

## Qué hace de verdad

| Capacidad | Implementación real |
|---|---|
| Auditoría de integridad propia | SHA-256 de la firma del APK, flag `debuggable`, `TracerPid`, artefactos de instrumentación en `/proc/self/maps` |
| Postura del dispositivo | `/proc` + `getprop`, SELinux, verificación de arranque, depuración ADB, estado de cifrado, TEE/StrongBox vía AndroidKeyStore |
| Red local | Enumeración de interfaces, tabla TCP desde `/proc/net`, sockets, ARP, capacidades de red |
| Endpoints remotos | X.509/TLS, cabeceras HTTP defensivas (HSTS, CSP…), sondeo TCP de puertos con banner |
| Superficie de apps | Componentes exportados, `debuggable`, `allowBackup`, cleartext, firma SHA-256 por paquete |
| **VPN local + firewall** | `VpnService` real: TUN `10.8.0.2/32`, DNS virtual en `10.8.0.1`, respuestas NXDOMAIN construidas a nivel de wire, rutas `/32` para IPs bloqueadas |
| Base de amenazas | Reglas locales + feed **CISA KEV** (JSON oficial) con correlación sobre la telemetría |
| Motor conversacional | **LLM real (BYOK)**: Gemini, OpenAI/Groq/DeepSeek/Mistral o un servidor propio (Ollama/LM Studio), conectado a las 20 funciones de la app. Sin clave, cae al clasificador heurístico local |

## Motor IA (LLM)

Aura tiene dos cerebros intercambiables y elige el mejor disponible en cada momento:

| | Motor heurístico (siempre presente) | Motor LLM (opcional, BYOK) |
|---|---|---|
| Decide la herramienta | `NeuralIntentClassifier` (reglas + pesos, softmax) | LLM con salida JSON validada contra el catálogo |
| Redacta el informe | Plantillas por `toolId` | LLM anclado a la telemetría medida |
| Offline | Sí | Sí, si el endpoint es local (Ollama/LM Studio) |
| Coste | 0 | El de tu proveedor (céntimos por consulta) |

### Cómo conectarlo

1. Escribe `/ia` en el panel (o toca el ⚙ junto a "AURA IA").
2. Elige proveedor y modelo:
   - **Gemini** — clave de [AI Studio](https://aistudio.google.com/apikey), `gemini-2.5-flash` por defecto.
   - **OpenAI / compatible** — OpenAI, Groq, DeepSeek, Mistral, o un endpoint propio.
   - **Ollama / LM Studio** — `http://<ip-de-tu-pc>:11434/v1`, sin clave, 100 % en tu red.
3. Pulsa **Probar conexión**. Si responde, el indicador superior pasa a `AURA IA · LLM ON`.

La clave se guarda en `EncryptedSharedPreferences` (AndroidKeyStore, AES256-GCM). **Nunca** va en el
APK ni en el repositorio, y no se registra en logs.

### Las 20 funciones conectadas

El LLM no ejecuta nada por sí mismo: elige un `toolId` de un catálogo cerrado
(`domain/ai/llm/AuraToolCatalog.kt`) y Aura valida el id y el objetivo antes de despachar:

`FULL_AUTONOMOUS_AUDIT` · `SERVER_MONITOR` · `SELF_TRAIN_KEV` · `SELF_INTEGRITY` · `DEVICE_INTEGRITY` ·
`NETWORK_SOCKETS` · `PORT_PROBE` · `TLS_INSPECT` · `DNS_RECON` · `HTTP_HEADERS` · `APP_SURFACE_AUDIT` ·
`CRYPTO_JWT` · `ROOT_SHELL` · `VPN_START` · `VPN_STOP` · `VPN_TELEMETRY` · `FIREWALL_BLOCK` ·
`FIREWALL_ALLOW` · `EXECUTE_SOLUTIONS` · `AI_THEORETICAL`

Los comandos con `/` **nunca** pasan por el modelo: son deterministas por diseño.

### Cómo se evita que la IA sea un riesgo

| Riesgo | Mitigación |
|---|---|
| El modelo propone una herramienta inexistente | `AuraToolCatalog.allowedIds`; si no está, fallback heurístico |
| El modelo devuelve un objetivo con `;` o `$( )` | `TargetValidator` antes de tocar cualquier engine |
| El modelo intenta subir privilegios | `prefersRoot` solo se honra si el usuario ya está en ROOT; `RootCommandPolicy` sigue siendo la puerta final |
| Prompt injection en el texto del usuario | escaneo de marcadores; si hay sospecha, no se llama al modelo |
| El proveedor cae o tarda | timeout + `null` → plantillas heurísticas; la app nunca queda vacía |
| Telemetría identificable saliendo del teléfono | `TelemetryRedactor`: IPs privadas, MACs, correos, JWT y tokens sustituidos por marcadores estables antes de enviar |

### Qué NO es

- **No entrena un modelo.** El LLM es un modelo ya entrenado que se usa en inferencia; lo que Aura
  aporta es el *prompt de ciberdefensa* (`AuraSystemPrompt`), el catálogo cerrado de herramientas y
  el anclaje a telemetría real. No hay fine-tuning ni pesos propios.
- **No hay IA generativa sin clave.** Sin proveedor configurado, el "cerebro" es el clasificador
  heurístico: reglas con pesos ajustados a mano. El nombre "red neuronal" describe la
  visualización, no el modelo.
- **No es un antivirus.** No hay motor de firmas de malware ni escaneo de contenido de APKs.
- **No hace "hacking" remoto.** Solo inspección pasiva y sondeos TCP/TLS autorizados por el usuario.
- **No sustituye a un EDR.** Sin root, las capacidades de contención se limitan al túnel VPN propio.

## Requisitos

- JDK 17+ (el proyecto compila con toolchain de Gradle 9.3.1)
- Android SDK con `compileSdk 36` (AGP lo descarga si falta)
- Un dispositivo o emulador con **API 24+** (target 36)

## Compilar

```bash
git clone https://github.com/liendomaho-wq/aura-defens-V2.0.0.git
cd aura-defens-V2.0.0

./gradlew :app:assembleDebug          # APK de depuración
./gradlew :app:testDebugUnitTest      # tests JVM + Robolectric
./gradlew :app:assembleRelease        # R8 + shrinkResources (requiere keystore)
```

`gradlew` y `gradle/wrapper/gradle-wrapper.jar` están versionados a propósito: el repo debe compilar
con un `clone` limpio, sin depender de Android Studio ni de AI Studio.

Si necesitas regenerar el wrapper: `gradle wrapper --gradle-version 9.3.1`.

### Firma de release

`app/build.gradle.kts` lee el keystore de variables de entorno (no hay secretos en el repo):

```bash
export KEYSTORE_PATH=/ruta/my-upload-key.jks
export STORE_PASSWORD=...
export KEY_PASSWORD=...
./gradlew :app:assembleRelease
```

## Uso

La app es una sola pantalla: un horizonte de privilegios (desliza ↔ para `SIN ROOT` / `CON ROOT`,
desliza ↓ para el historial forense) y un panel conversacional negro.

```
/audit [host]        Auditoría integral autónoma
/monitor <host>      Monitorización de anomalías (RTT, TLS, estado HTTP)
/tls <host>          Certificado X.509
/dns <host>          Resolución DNS
/http <host>         Cabeceras defensivas
/ports <host>        Sondeo TCP
/sockets             Topología de red y sockets
/apps [filtro]       Superficie de apps instaladas
/jwt <token>         Análisis criptográfico / JWT
/vpn on | off        Activar o detener la VPN local
/block <patrón>      Regla de bloqueo (dominio, IP o puerto)
/allow <patrón>      Retirar regla
/fix                 Ejecutar mitigaciones y parches
/train               Sincronizar feed CISA KEV
/integrity           Autoverificación anti-manipulación
/env                 Postura de kernel y dispositivo
/su <comando>        Inspección shell (sujeta a política, ver abajo)
/ia                  Configurar el motor LLM (BYOK)
```

También acepta lenguaje natural en español ("audita todo", "bloquea doubleclick.net",
"¿qué encontraste?").

## Política de privilegios (importante)

Todo comando que llega a `su -c` / `sh -c` pasa por `RootCommandPolicy` (deny por defecto):

- Solo se permiten binarios de **lectura** (`id`, `getenforce`, `ps`, `ss`, `iptables -L`, `dumpsys`,
  `getprop`…) y un conjunto cerrado de **mitigaciones firmadas** (`setenforce 1`, DROP de los puertos
  23/5555/6379/27017).
- Se bloquean redirecciones, `$()`, backticks, `eval`, `sh -c`, `xargs`, `-exec`, `pm uninstall`,
  `am`, `settings put`, `chmod`, `rm`, `dd`, `reboot`…
- Cualquier denegación se muestra en el panel con el motivo; nunca se ejecuta en silencio.

Esto existe porque el clasificador puede enrutar texto libre del chat hacia la herramienta de shell:
sin esta puerta, una frase se convertía en ejecución de código con privilegios de kernel.

## VPN local: cómo funciona y qué limita

1. `VpnService.Builder` crea un TUN con `10.8.0.2/32` y un DNS virtual `10.8.0.1`.
2. Las consultas DNS al DNS virtual se parsean (IPv4/UDP) y se responden con **NXDOMAIN real** si el
   dominio está bloqueado; si no, se reenvían por un socket protegido con `protect()`.
3. Las IPs bloqueadas se añaden como rutas `/32` al TUN: el paquete entra, se registra y se descarta.
4. Aura queda excluida del túnel con `addDisallowedApplication` para no auto-interceptarse.

Limitaciones honestas: es un filtro DNS + rutas `/32`, no un IDS/IPS con inspección profunda. Sin
root no se puede tocar `iptables` del sistema; con root, la app solo aplica las plantillas firmadas.

## Privacidad y datos

- Todo se guarda en **Room/SQLite privado** (`aura_defense_forensics.db`). Sin cuentas, sin analytics,
  sin telemetría propia.
- `android:allowBackup="false"` y reglas de extracción que excluyen todo: la evidencia no sale del
  dispositivo, ni por backup en la nube ni por transferencia entre dispositivos.
- Únicas salidas de red: el feed `cisa.gov` (KEV), `dns.google` (DoH opcional), los hosts que tú
  ordenes auditar y —solo si activas el motor LLM— el proveedor que elijas, con la telemetría ya
  redactada. La base de datos **no está cifrada** en reposo (ver roadmap).

## Estructura

```
app/src/main/java/com/aura/mobiledefense/
├── MainActivity.kt
├── data/
│   ├── local/        Room: entidades, DAO, repositorio, base de datos
│   └── model/        Modelos de dominio y de la escena visual
├── domain/
│   ├── ai/           Clasificador de intenciones, motor local, síntesis de escena
│   ├── engines/      Integridad, red, cripto, dispositivo, monitor, parches, ejecución
│   ├── security/     Política de privilegios (deny por defecto)
│   └── vpn/          VpnService, códec de paquetes IPv4/UDP, gestor de reglas
└── ui/
    ├── components/   Canvas neuronales, panel conversacional, overlays
    ├── screens/      Workspace
    ├── theme/        Nyx (obsidiana/violeta/esmeralda)
    └── viewmodel/    NyxViewModel (StateFlow)
```

## Roadmap

- [ ] Cifrado en reposo de la evidencia (SQLCipher o cifrado por campo con AndroidKeyStore)
- [ ] Partir `NyxViewModel` (722 líneas) y los canvas de UI en módulos más pequeños
- [ ] Cobertura de tests para los engines que tocan el sistema (ya hay 21 pruebas nuevas de
      firewall y de la política de privilegios)
- [x] `applicationId` propio (`com.aura.mobiledefense`, alineado con el `namespace`)
- [x] Modo "IA Online" implementado como LLM real (BYOK) con catálogo cerrado de herramientas
- [ ] Modelo on-device real: el adaptador `FunctionGemmaToolProvider` y el kit de entrenamiento
      (`aura-train/`) están listos; falta el motor de inferencia (MediaPipe LLM / llama.cpp) y los
      pesos en `assets/`
- [x] Firewall real: ruta 0.0.0.0/0, proxy TCP, bloqueo por SNI y política DoH/DoT
- [x] Migraciones de Room 1→2→3 con pruebas instrumentadas
- [x] `RootCommandPolicy` con la regla 3 implementada y un único `ShellRunner`

## Aviso legal

Herramienta defensiva para auditar **dispositivos y servicios propios o con autorización explícita por
escrito**. El sondeo de puertos y la inspección de terceros sin permiso puede ser ilegal en tu
jurisdicción. El autor no se responsabiliza del mal uso.

## Licencia

MIT — ver [LICENSE](LICENSE). Las fuentes y el feed de amenazas tienen sus propias licencias:
ver [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
