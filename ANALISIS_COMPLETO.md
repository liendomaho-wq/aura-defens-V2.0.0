# Aura Mobile Defense — Análisis técnico completo

> Auditoría de código del repositorio `liendomaho-wq/aura-defens-V2.0.0`
> Fecha del análisis: 2026-11-26 · Commit analizado: `8fc6f80` (`main`) · Rama de trabajo: `arena/e7d0a8fa-aura-defens-v2-0-0`
> Alcance: arquitectura, funcionamiento real de cada módulo, historia del proyecto, riesgos y hoja de ruta.

---

## 0. Resumen ejecutivo

**Qué es.** Aura Mobile Defense es una aplicación **Android nativa en Kotlin + Jetpack Compose** de
ciberdefensa *local* (defensiva, sobre tu propio dispositivo y hosts autorizados). No tiene backend, no
tiene cuentas, no tiene analítica propia: todo ocurre en el teléfono y todo se guarda en una base SQLite
privada.

**Qué hace de verdad, en una frase por bloque:**

| Bloque | Realidad en el código |
|---|---|
| Auditoría forense | Lee `/proc`, `getprop`, `dumpsys`, tabla TCP, ARP, firma del APK, SELinux, verified boot, TEE. **Datos reales del sistema.** |
| Auditoría remota | TLS X.509 real por socket, huella SHA-256 del certificado, cabeceras HTTP por OkHttp, DNS por DoH (`dns.google`), sondeo TCP de 25 puertos con banner. |
| VPN + firewall | `VpnService` real con TUN `10.8.0.2/32`, DNS virtual `10.8.0.1`, respuestas **NXDOMAIN construidas a nivel de wire**, y un proxy TCP con lector de **SNI** de TLS. |
| Motor conversacional | Dos cerebros: (1) clasificador heurístico propio (reglas + softmax) y (2) **LLM real BYOK** (Gemini / OpenAI-compatible / Ollama) con catálogo cerrado de 20 herramientas. |
| Parches | Genera artefactos de mitigación (XML de network security config, bloque de nginx, reglas iptables) y los escribe en disco; aplica reglas de firewall reales. |

**Veredicto técnico en una línea.** Es un proyecto **ambicioso y bien estructurado**, con una capa de
seguridad (`RootCommandPolicy` + `ShellRunner` + `TargetValidator` + `ToolCatalog`) notablemente
cuidada para ser un proyecto individual, pero está en **pre-alpha real**: el build de `main` **no
compila en CI ahora mismo**, hay un fallo funcional grave en el camino de datos de la VPN, y el README
sobreestima algunos puntos (y se quedó corto en otros).

**Nota global: 6,5 / 10.** Muy por encima de la media en diseño de seguridad y documentación; por
debajo de lo que promete en la parte de red y en estado de compilación.

---

## 1. Ficha del proyecto

| Campo | Valor |
|---|---|
| Repositorio | `liendomaho-wq/aura-defens-V2.0.0` (público) |
| Creado | 2026-11-25 16:59 UTC |
| Lenguaje principal | Kotlin (100 % del código de la app) |
| Licencia | MIT (© 2026 liendomaho-wq) |
| Versión | `versionCode 1`, `versionName 1.0` — **pre-alpha** |
| Tamaño | 118 archivos, ~1,7 MB (sin `.git`) |
| Código Kotlin | **12.865 líneas** en `app/src/main` + **1.631** en tests |
| Tests | 11 archivos, **77 métodos `@Test`** |
| Estrellas / PRs | 0 estrellas · 1 PR mergeado (#1) · 10 PRs de Dependabot abiertos |
| Commits | 18 (17 en `main` + el inicial) |
| CI | GitHub Actions (`Android CI`) + Dependabot semanal |
| Distribución | **No hay APK firmado publicado ni release** |

### Stack exacto

```
Kotlin 2.4.21            AGP 9.1.1             Gradle 9.3.1 (wrapper versionado)
compileSdk 36 (minorApi 1)   targetSdk 36      minSdk 24
Compose BOM 2024.09.00   Material 3           Compose Compiler plugin
Room 2.7.0 + KSP 2.3.14  SQLCipher 4.9.0      AndroidX Security Crypto 1.1.0-alpha06
OkHttp 4.10.0            kotlinx-coroutines 1.10.2   Robolectric 4.16.1
```

Arquitectura por capas *de facto* (no es Clean Architecture estricta, pero se le parece):

```
MainActivity
  └─ NyxWorkspaceScreen (Compose)
       └─ NyxViewModel (813 líneas, AndroidViewModel, StateFlow)
            ├─ AuraLlmOrchestrator ── LlmIntentResolver ── Gemini / OpenAI-compatible / OnDevice
            │        └─ AuraNeuralAiEngine (heurístico + NLG por plantillas + grafo)
            ├─ Engines: Integrity · Device · Network · Binary/Crypto · Monitor · Patch · Execution · Threats
            ├─ Security: RootCommandPolicy → ShellRunner (único punto de exec)
            └─ Vpn: AuraLocalVpnService · PacketCodec · TcpProxyEngine · TlsSniExtractor · DomainSinkhole
       └─ Data: Room (SQLCipher) — 5 entidades, DAO, repositorio, migraciones 1→2→3
```

---

## 2. Cómo se hizo: historia reconstruida

El repo nació **por completo el 2026-11-25** y se construyó en varias oleadas en un solo día. Lo que
revelan los commits es un proceso de "generación asistida por IA → primera compilación real → cadena de
correcciones" muy típico de hoy:

| Fecha/hora (UTC) | Commit | Qué pasó |
|---|---|---|
| 25 Nov 17:00 | `1759f79` | Initial commit |
| 25 Nov 17:01 | `1592d28` | `feat(core): initialize Aura Mobile Defense project` — **entra todo el proyecto de golpe** |
| 25 Nov 19:13 | `02e57d0` | `deny-by-default root shell, no backups, real migrations + repo hygiene` (PR #1) |
| 25 Nov 19:23 | `7874b9e` | KSP 2.3.5 → 2.3.14 (compatibilidad AGP 9 + Kotlin 2.4.21) |
| 25 Nov 19:27 | `c616958` | Merge del PR #1 |
| 25 Nov 19:46 | `b193a04` | **LLM real conectado a las 20 funciones** |
| 25 Nov 20:00 | `671bf1e` | Adaptador FunctionGemma 270M |
| 25 Nov 20:09 | `5ba10db` | **Firewall real**: ruta `0.0.0.0/0`, proxy TCP, bloqueo por SNI |
| 25 Nov 20:16 | `9936b95` | Regla 3 de `RootCommandPolicy` + un solo `ShellRunner` |
| 25 Nov 20:17 | `7487f3c` | Migraciones Room 1→2 y 2→3 + tests de migración |
| 25 Nov 20:17 | `01a2f81` | `applicationId` propio, IPv6 fuera del túnel |
| 25 Nov 20:34 | `5100f1c` | **SQLCipher** para la base forense |
| 25 Nov 20:34–20:42 | `678ca38`, `dd9d064` | Errores de compilación reales (imports de tipos anidados, clave UTF-8) |
| 25 Nov 21:00 | `21dd44b` | `fix(test): las 31 pruebas ya compilan` |
| 26 Nov 00:52 | `8fc6f80` | `feat: add GEMINI_API_KEY to environment examples` ← **rompe CI y el arranque** |

**Señales claras de generación asistida y de iteración sin compilar:**
- El cuerpo del PR #1 lo dice literalmente: *"El sandbox donde se preparó no tiene JDK ni Android SDK,
  así que no se compiló en local"*.
- Quedan restos del andamiaje de AI Studio: `app/applet/.env.example`, `app/applet/app/.env.example`,
  `res/values/firebase_applet_config.xml` (una `recaptcha_site_key` de Firebase sin usar), los
  comentarios "Do not remove… they are necessary for Android Studio / AI Studio", `metadata.json`,
  y el `namespace` original `com.aistudio.nyxcore.xkpqvr` documentado en `app/build.gradle.kts`.
- El histórico de CI muestra 4 compilaciones fallidas por errores que solo aparecen al compilar
  (imports, tipos anidados, clave de SQLCipher, tests), seguidas de arreglos en cadena.

**Conclusión sobre "cómo se hizo":** el andamiaje y buena parte del primer borrador son generados
(Android Studio AI Studio + asistente), y el humano (o el agente) hizo después un endurecimiento
consciente y bastante serio: PR de seguridad dedicado, política de comandos, migraciones reales,
SQLCipher, y 77 tests. No es un proyecto "generado y abandonado": hay trabajo de ingeniería real encima.

---

## 3. Para qué sirve (casos de uso reales)

1. **Auditar tu propio móvil**: si está rooteado, si SELinux está *permissive*, si el bootloader está
   desbloqueado, si hay un depurador o Frida enganchado, si la TEE/StrongBox respalda las claves.
2. **Auditar tus servidores y webs**: certificado TLS (caducidad, emisor, huella SHA-256 anti-MITM),
   cabeceras defensivas (HSTS/CSP/XFO), DNS (A/AAAA/MX/TXT/NS por DoH), puertos TCP abiertos con banner.
3. **Auditar la superficie de las apps instaladas**: componentes exportados, `debuggable`,
   `allowBackup`, `cleartext`, firma SHA-256 por paquete.
4. **Vigilar un endpoint en el tiempo**: aprende una línea base (RTT, código HTTP, huella TLS, número
   de cabeceras) y **detecta anomalías** (pico de latencia, cambio de certificado, degradación de
   cabeceras, caída).
5. **Firewall/DNS local sin root**: bloqueo de dominios publicitarios/telemetría a nivel de wire
   (NXDOMAIN) y por SNI, más bloqueo de puertos/IPs.
6. **Análisis de binarios/APKs**: hashes SHA-256/SHA-1/MD5, entropía de Shannon por bloques de 32,
   firma mágica, strings, URLs y IPs embebidas.
7. **Aprendizaje**: es un excelente catálogo de patrones de Android "de sistema" escritos en Kotlin
   (VpnService, codec IPv4/TCP/UDP/DNS, SNI, AndroidKeyStore, SQLCipher, Room con migraciones).

**Para qué NO sirve** (el propio README lo admite, y es de agradecer): no es un antivirus, no hay motor
de firmas de malware ni análisis de contenido de APK más allá de superficie/hashes, no sustituye a un
EDR, no hace "hacking" remoto, y sin root no puede tocar `iptables` del sistema.

---

## 4. Cómo funciona: recorrido extremo a extremo

### 4.1 Arranque de la app

```
MainActivity.onCreate
 ├─ System.loadLibrary("sqlcipher")          // librería nativa antes de abrir Room
 ├─ enableEdgeToEdge(dark)                   // UI full-bleed
 └─ setContent { NyxCoreTheme { NyxWorkspaceScreen(NyxViewModel) } }
```

`NyxViewModel` se construye y en su `init` dispara dos cosas:

1. **`bootstrapEnvironment()`** — cancela cualquier job previo, inicializa el firewall desde Room
   (siembra 8 reglas por defecto), siembra la base de conocimiento (6 reglas locales), sondea root,
   elige el plano (ROOT si `su` verificado, si no USERLAND), ejecuta `runFullAutonomousAudit`, correlaciona
   contra las reglas, y sintetiza la **primera escena visual** que se guarda en Room y se vuelca al chat.
2. **`startBackgroundMonitorLoop()`** — cada 25 s, si hay conectividad, re-sondea hasta 4 endpoints
   monitorizados y emite un banner si aparecen anomalías.

### 4.2 El bucle conversacional (el corazón)

```
usuario escribe en el panel negro
        │
        ▼
NyxViewModel.submitQuery(texto)
        │
        ├─ ¿es comando de UI? (/intro /root /user /local /online /ia /history /report /file /clear)
        │        → cambia estado y sale sin tocar IA
        ▼
AuraLlmOrchestrator.plan(query, mode)
        │
        ├─ 1. empieza por "/"  ──────────────► HeuristicIntentResolver  (SLASH_COMMAND, determinista)
        ├─ 2. LLM configurado y sano ────────► LlmIntentResolver → JSON {toolId,target,reason}
        │        · escaneo de prompt-injection
        │        · toolId debe estar en AuraToolCatalog.allowedIds (20)
        │        · target validado con TargetValidator (HOST / PATTERN / FREETEXT)
        │        · prefersRoot solo se honra si ya estás en ROOT
        │        · si falla → fallback heurístico (nunca error en UI)
        └─ 3. sin modelo ────────────────────► HeuristicIntentResolver  (HEURISTIC)
        ▼
NyxViewModel  when (plan.toolId)  →  despacha al motor real (20 ramas)
        ▼
ToolExecutionResult  { toolId, target, privilegeUsed, rawTelemetry, measuredSpectrum, patches, report }
        ▼
ThreatKnowledgeEngine.matchTelemetryAgainstRules(rawTelemetry)   // correlación de firmas
        ▼
AuraLlmOrchestrator.synthesize(...)
        ├─ AuraNeuralAiEngine.synthesizeScene: grafo de 3 capas (7 nodos, ~12 aristas),
        │   estratos, severidad calibrada, topología visual, 4-partes de informe, parches
        └─ ¿useForNarrative? → LlmNarrativeWriter escribe la narrativa
                 · TelemetryRedactor (IPs, MACs, emails, JWT, tokens, paquetes)
                 · timeout 20 s; si falla, se queda la plantilla determinista
        ▼
Room (saveScene) + chat (appendAuraSceneMessage) + UI Ready(scene)
```

### 4.3 El clasificador heurístico (`NeuralIntentClassifier`, 432 líneas)

**Cómo funciona realmente** — conviene ser honesto porque el nombre engaña:

- Hay 20 "neuronas" (`IntentRuleSet`), una por herramienta, cada una con un `Map<String, Float>` de
  pesos por palabra (unigramas: `"audita"→3.4`, `"frida"→3.6`, `"jwt"→4.5`…).
- El texto se normaliza (NFD + eliminación de diacríticos), se tokeniza con
  `[^a-z0-9._/]+`, y se puntúa cada neurona sumando los pesos de los tokens presentes; hay *bias*
  contextual (si ya citaste un host, se suma a `AUDIT`/`NET`/`VPN`), y memoria del último objetivo.
- Se aplica **softmax real** para obtener la confianza (`exp((z-maxZ))/Σexp`), con suelo de 0.15 y
  techo 0.99. Si la mejor puntuación es `< 1.5` y hay host → fuerza `FULL_AUTONOMOUS_AUDIT`.
- Extracción de entidades por regex: host/IP (`extractHostOrIp`), puerto, nombre de paquete.
- `fastPath()` mapea los comandos `/audit`, `/ports`, `/tls`… de forma determinista **antes** de puntuar.

> **No es una red neuronal.** No hay pesos aprendidos, no hay entrenamiento, no hay backpropagation. Es
> un **clasificador por reglas con puntuación ponderada y softmax**. El README lo dice en su sección
> "Qué NO es", pero los nombres de clases (`NeuralIntentClassifier`, `AuraNeuralAiEngine`,
> `red neuronal`) siguen siendo engañosos. En el mejor de los casos es una heurística bien hecha.

### 4.4 El motor LLM (BYOK)

**Contrato:** `LlmProvider.complete(system, user, jsonMode, maxTokens): String?` — **todo devuelve
`null` en caso de fallo**, nunca lanza. Eso garantiza que la app jamás se quede en blanco.

**Proveedores implementados:**
- `GeminiProvider` — `POST {baseUrl}/models/{model}:generateContent`, cabecera `x-goog-api-key`,
  `responseMimeType: application/json` cuando hace falta JSON. Modelo por defecto
  `gemini-2.5-flash`.
- `OpenAiCompatibleProvider` — `/chat/completions`, sirve para OpenAI (`gpt-4.1-mini`), Groq,
  DeepSeek, Mistral, Ollama, LM Studio, vLLM. Presets con URL y modelo preconfigurados.
- `OnDeviceProvider` — **slot vacío** (delegate null, `isConfigured() == false`).
- `FunctionGemmaToolProvider` — adaptador para un *fine-tune* de FunctionGemma 270M que emite
  `call:PORT_PROBE{target:<escape>…}`. **No hay motor de inferencia**: `inference` es null por defecto.
  Su valor real hoy es que está **probado** (10 tests con fixtures congeladas) y listo para conectar
  MediaPipe/llama.cpp.

**Claves:** van a `EncryptedSharedPreferences` respaldado por AndroidKeyStore (AES256-SIV para claves,
AES256-GCM para valores). **No** hay ninguna clave en el APK ni en el repo. El `.env.example` con
`GEMINI_API_KEY` es inerte en runtime (ver hallazgo H-3).

**Las 20 herramientas del catálogo cerrado** (`AuraToolCatalog`, que es la frontera de seguridad):
`FULL_AUTONOMOUS_AUDIT, SERVER_MONITOR, SELF_TRAIN_KEV, SELF_INTEGRITY, DEVICE_INTEGRITY,
NETWORK_SOCKETS, PORT_PROBE, TLS_INSPECT, DNS_RECON, HTTP_HEADERS, APP_SURFACE_AUDIT, CRYPTO_JWT,
ROOT_SHELL, VPN_START, VPN_STOP, VPN_TELEMETRY, FIREWALL_BLOCK, FIREWALL_ALLOW, EXECUTE_SOLUTIONS,
AI_THEORETICAL`. Cada `LlmToolSpec` declara si requiere objetivo, de qué tipo (`NONE/HOST/PATTERN/FREETEXT`)
y si prefiere root. Hay un test que verifica que **todo `toolId` despachado en el ViewModel está en el
catálogo** (`every tool dispatched by the ViewModel is in the catalogue`).

### 4.5 Los engines forenses (lo que realmente miden)

| Engine | Fuente real de datos | Salida |
|---|---|---|
| `AppSelfIntegrityEngine` | `PackageManager` (firma SHA-256), `FLAG_DEBUGGABLE`, `Debug.isDebuggerConnected()`, `TracerPid` de `/proc/self/status`, `/proc/self/maps` buscando `frida/xposed/lsposed/substrate/gadget` | Puntaje de integridad 0.1–1.0 + telemetría |
| `PrivilegeAndDeviceEngine` | 10 rutas candidatas de `su`, `/sys/fs/selinux/enforce`, `getenforce`, `id`, `/proc/version`, `/proc/meminfo`, `Settings.Global.ADB_ENABLED`, `getprop` de 9 claves, `AndroidKeyStore` (¿TEE/StrongBox?) | `RootCapabilityState` + postura del dispositivo |
| `NetworkForensicsEngine` | `ConnectivityManager`, `NetworkInterface`, `/proc/net/tcp{,6}`, `/proc/net/arp`, `SSLSocket` para X.509, OkHttp para cabeceras, `https://dns.google/resolve` para DoH, 25 puertos con `Socket.connect(850 ms)` y banner | 6 herramientas distintas |
| `BinaryCryptoEngine` | `PackageManager` (superficie de apps) y `ContentResolver` (archivo elegido) | Superficie de apps, hashes, entropía de Shannon en 32 bloques, magic, strings, URLs/IPs, JWT |
| `ThreatKnowledgeEngine` | 6 reglas locales sembradas + feed **CISA KEV** (hasta 140 CVEs priorizando Android/Linux/OpenSSL/nginx/apache/openssh/qualcomm/mediatek/arm/curl) | Base de firmas + correlación por palabras clave |
| `ServerAndNetworkMonitorEngine` | OkHttp GET con línea base (RTT, status, huella TLS, nº de cabeceras) y EMA adaptativa | 4 tipos de anomalía: `LATENCY_SPIKE`, `TLS_CERT_DRIFT`, `HTTP_STATUS_ANOMALY`, `HEADER_REGRESSION`, `ENDPOINT_UNREACHABLE` |
| `PatchAndReportEngine` | Combina 4 engines (y opcionalmente 3 remotos) en una auditoría integral | `CompleteAuditReport` de 4 partes + parches |
| `SolutionExecutionEngine` | Escribe parches en `filesDir/aura_remediations/` con SHA-256, crea reglas de firewall, y con root ejecuta `setenforce 1` / DROP de 5555 | Flujo de pasos en vivo (`RUNNING/DONE/NEEDS_CONSENT/FAILED`) |

### 4.6 El firewall real: tres capas

1. **DNS interceptado.** El TUN anuncia DNS virtual `10.8.0.1`. Todo paquete UDP:53 a esa IP se parsea a
   mano (`PacketCodec.extractDnsQueryDomain`) y, si el dominio está bloqueado, se responde un
   **NXDOMAIN construido byte a byte** (`buildDnsNxDomainResponse`). Si no, se reenvía a 1.1.1.1
   (fallback 8.8.8.8) con `protect()` y se devuelve la respuesta al TUN.
2. **Bloqueo por SNI.** Con ruta `0.0.0.0/0`, todo TCP entra al proxy. `TlsSniExtractor` lee el
   ClientHello (offsets RFC 6066) y extrae el dominio **en claro**; si está bloqueado, se cierra el flujo.
   Y `DomainSinkhole` **aprende dominio→IP** (TTL 30 min, máx. 2048 IPs) para cortar también a las apps
   que resuelven por su cuenta.
3. **Firewall por IP/puerto.** Reglas persistidas en Room (`DOMAIN/IP/PORT`), con 8 reglas sembradas
   (5555 ADB, 23 Telnet, 6379 Redis, `doubleclick.net`, `app-measurement.com`, `pixel.facebook.com`…)
   y política opcional de bloquear **DoH/DoT** para que ninguna app evada el firewall de dominios.

Todo se telemetriza: contadores atómicos de paquetes permitidos/bloqueados, bytes, RTT de DNS y un
buffer circular de 40 eventos que alimenta la UI en tiempo real.

### 4.7 Seguridad de ejecución de comandos (la joya del proyecto)

Toda ejecución de shell pasa por `ShellRunner.run()` → `RootCommandPolicy.evaluate()`, que es
**deny por defecto**:

- **Lista blanca de binarios de lectura**: `id, getenforce, uname, getprop, ls, cat, ps, ss, netstat,
  dmesg, logcat, dumpsys, sha256sum, top…` (~40).
- **Guardas por subcomando**: `pm` solo `list|path|dump|version`; `settings` solo `get`;
  `ip` solo `addr|route|neigh|link` y sin verbos mutantes; `iptables` sin `-A/-I/-D/-F`;
  `nft` solo `list`; `command` solo `-v`; `find` sin `-fprint/-exec/-delete`.
- **Plantillas de mitigación literales** (no reutilizables por el usuario): `setenforce 1`,
  `setenforce 1 && getenforce`, y DROP de puertos administrativos (23/5555/6379/27017).
- **Lista negra dura**: `rm, dd, chmod, reboot, magisk, eval, exec, xargs, sh -c, pm uninstall, am,
  settings put, base64 -d…` (~60 tokens).
- **Rutas protegidas**: `/system, /vendor, /data/data, /dev/block, /proc/kcore…` (con `/proc` y
  `/sys` fuera a propósito porque son la fuente de la telemetría).
- Longitud máx. 400 chars, sin saltos de línea ni bytes nulos, y timeout + `destroyForcibly()` en
  `ShellRunner` para no colgar la app.

Además hay un **guardrail en CI** que falla la compilación si aparece un `ProcessBuilder(` **fuera de**
`domain/security/`, para que ningún módulo futuro se salte la política.

---

## 5. Mapa de archivos (con propósito)

```
app/src/main/java/com/aura/mobiledefense/
├── MainActivity.kt (44)                 entrada, edge-to-edge, carga sqlcipher
├── data/
│   ├── local/
│   │   ├── NyxDatabase.kt (61)          @Database v3, singleton, sin fallback destructivo
│   │   ├── ForensicSessionEntity.kt(68) 5 entidades: sesiones, targets, anomalías, firmas, reglas FW
│   │   ├── ForensicSessionDao.kt (81)   27 consultas/updates
│   │   ├── ForensicSessionRepository.kt (247)  serializa la escena completa a JSON en la BD
│   │   ├── AuraMigrations.kt (99)       migraciones reales 1→2 y 2→3
│   │   └── AuraDatabaseCipher.kt (147)  SQLCipher + clave envuelta con AES-GCM del KeyStore
│   └── model/ForensicModels.kt (241)    todos los modelos + WorkspaceUiState (sealed)
├── domain/
│   ├── ai/
│   │   ├── NeuralIntentClassifier.kt (432)  20 "neuronas" + softmax + fastPath
│   │   ├── AuraNeuralAiEngine.kt (618)      escena visual, grafo, informe, parches, NLG plantillas
│   │   ├── LocalAutonomousEngine.kt (41)    fachada offline (solo usada en tests)
│   │   └── llm/
│   │       ├── AuraLlmOrchestrator.kt (166) decide LLM vs heurístico
│   │       ├── LlmIntentResolver.kt (111)   6 defensas + parseo JSON estricto
│   │       ├── AuraToolCatalog.kt (266)     catálogo cerrado de 20 herramientas
│   │       ├── AuraSystemPrompt.kt (97)     3 prompts + detección de injection
│   │       ├── TargetValidator.kt (92)      normaliza/valida el target del modelo
│   │       ├── TelemetryRedactor.kt (97)    anonimiza telemetría antes de salir
│   │       ├── LlmNarrativeWriter.kt (98)   narrativa anclada a telemetría, timeout 20 s
│   │       ├── GeminiProvider.kt (121) · OpenAiCompatibleProvider.kt (109)
│   │       ├── OnDeviceProvider.kt (36)     slot vacío
│   │       ├── FunctionGemmaToolProvider.kt (114)  adaptador del fine-tune
│   │       ├── HeuristicIntentResolver.kt (29)     fallback determinista
│   │       ├── LlmProvider.kt (76)          contrato + LlmSettings + enums
│   │       └── LlmSettingsStore.kt (156)    EncryptedSharedPreferences + presets
│   ├── engines/  (2.340 líneas)
│   │   ├── NetworkForensicsEngine.kt (517)  la más grande: 6 herramientas de red
│   │   ├── BinaryCryptoEngine.kt (364)      superficie de apps + análisis de archivos
│   │   ├── PrivilegeAndDeviceEngine.kt(330) root, SELinux, props, TEE
│   │   ├── ServerAndNetworkMonitorEngine.kt (261) línea base + anomalías
│   │   ├── PatchAndReportEngine.kt (234)    auditoría integral + parches
│   │   ├── ThreatKnowledgeEngine.kt (231)   CISA KEV + reglas locales
│   │   ├── SolutionExecutionEngine.kt (154) ejecución en vivo de mitigaciones
│   │   ├── SystemActivityMonitor.kt (119)   CPU (/proc/stat), red (TrafficStats), RAM
│   │   └── AppSelfIntegrityEngine.kt (130)  anti-tamper
│   ├── security/ (401)
│   │   ├── RootCommandPolicy.kt (268)       política deny-by-default
│   │   └── ShellRunner.kt (133)             único punto de ProcessBuilder del proyecto
│   └── vpn/ (1.474)
│       ├── AuraLocalVpnService.kt (376)     VpnService + notificación + bucle TUN
│       ├── VpnFirewallManager.kt (367)      estado, reglas Room, telemetría, DoH/DoT
│       ├── TcpProxyEngine.kt (280)          proxy TCP, flujos, RST/ICMP, checksums
│       ├── PacketCodec.kt (288)             IPv4/UDP/TCP/DNS wire format
│       ├── TlsSniExtractor.kt (82)          SNI del ClientHello
│       └── DomainSinkhole.kt (81)           memoria dominio→IP
└── ui/
    ├── screens/NyxWorkspaceScreen.kt (268)   composición de todo
    ├── viewmodel/NyxViewModel.kt (813)       orquestador (el archivo más grande de la app)
    ├── components/
    │   ├── AuraCircuitConstellationCanvas.kt (838)  canvas principal IC + constelación
    │   ├── GenerativeVisualCanvas.kt (635)          6 topologías visuales alternativas
    │   ├── Overlays.kt (633)                        nodo, informe+parches, memoria
    │   ├── LlmSettingsOverlay.kt (504)              hoja BYOK
    │   ├── BlackConversationalPanel.kt (428)        el panel negro
    │   ├── PrivilegeHorizonBar.kt (283)             horizonte de privilegios
    │   ├── VisualWalkthroughOverlay.kt (228)        tutorial de 3 pasos
    │   ├── NeuralPromptBar.kt (191)                 barra de entrada
    │   └── InteractiveNeuralNetworkGraph.kt (45)    delegador
    └── theme/ (Color, Theme, Type)                  obsidiana/violeta/cian/esmeralda
```

---

## 6. Estado real de compilación y CI

**El CI está roto en `main` ahora mismo.** Reconstrucción:

| Run | Commit | Resultado | Paso que falla |
|---|---|---|---|
| `45684809114` | `c616958` (merge PR #1) | ✅ **success** | build + tests + APK OK |
| `45685384608` | `8fc6f80`? (merge) | ✅ **success** | build + tests + APK OK |
| `45696360205` | `c3b581d` | ❌ failure | **Assemble debug APK** (tras añadir SQLCipher) |
| `45696758537` | `678ca38` | ❌ failure | Assemble debug APK |
| `45697531533` | `dd9d064` | ❌ failure | **Unit tests** |
| `45700326757` | `21dd44b` | ⏹ **cancelled** (40 min) | timeout |
| `45731881465` | `8fc6f80` | ❌ failure | **Verify Gradle wrapper** |

**Causa del último fallo (y es trivial):** el commit `8fc6f80` cambió el modo de `gradlew` de
`100755` a `100644`. Comprobado por API en los árboles de git:

```
02e57d0  gradlew -> 100755
c3b581d  gradlew -> 100755
21dd44b  gradlew -> 100755
8fc6f80  gradlew -> 100644   ← aquí se rompió
```

El workflow hace `test -x ./gradlew` y falla. **Un solo `chmod +x gradlew && git update-index
--chmod=+x gradlew` lo arregla.** Es un fallo de 1 minuto con impacto desproporcionado: es lo primero
que ve cualquiera que clone el repo.

**Antes de eso hubo errores reales** (los arregló en commits posteriores): imports de tipos anidados,
la clave de SQLCipher en UTF-8, y `ByteArrayOutputStream.write(ByteArray)` dentro de un `apply {}` en
los tests.

**Lo que sí funciona:** el pipeline en sí está muy bien: verifica el wrapper, tiene el guardrail de
`ProcessBuilder` fuera de `domain/security`, genera un `debug.keystore` cuando falta, publica los
errores de Gradle como anotaciones del check (para leerlos desde la API), sube informes de test y el
APK de debug como artefactos, con `concurrency` para cancelar builds viejos.

**Recomendaciones de CI:**
1. Arreglar el bit de ejecución de `gradlew` (P0, ahora).
2. Añadir `git config core.fileMode true` y un `.gitattributes` que no toque el modo no basta: el modo
   vive en el índice. Mejor un check explícito y un `chmod` en el step.
3. Añadir un job de `androidTest` con emulador (KVM) para que los 5 tests instrumentados
   (`DatabaseEncryptionTest`, `NyxDatabaseMigrationTest`) corran de verdad: hoy **ninguno se ejecuta en CI**,
   y son precisamente los que validan SQLCipher y las migraciones.
4. Fijar `timeout-minutes` por step y cachear `~/.gradle` (ya lo hace `gradle/actions/setup-gradle`).
5. Considerar cerrar/merjear los 10 PRs de Dependabot: varios ya están en estado "success" y llevan
   versiones atrasadas (AGP 9.5.3, Robolectric 4.18.1, actions/checkout 7…).

---

## 7. Hallazgos: bugs y riesgos (ordenados por gravedad)

> Cada hallazgo tiene `archivo:línea`, qué pasa y cómo se arregla. Los **H-x** son bugs de
> comportamiento; los **R-x** son riesgos de seguridad; los **M-x** son mantenibilidad/documentación.

### 🔴 H-1 — El firewall VPN rompe la conectividad TCP del dispositivo (crítico)

`AuraLocalVpnService.kt:147` añade `builder.addRoute("0.0.0.0", 0)` y
`TcpProxyEngine.handleFromDevice()` abre un socket real por cada SYN… **pero nunca hay camino de
vuelta**: no hay `SYN-ACK` sintético hacia el TUN, ni un hilo que lea del socket y escriba los bytes de
respuesta en el TUN. `buildRst()` y `buildIcmpPortUnreachable()` **están implementados y testeados,
pero nunca se invocan** (grep: solo aparecen en `VpnFirewallRealTest`).

**Consecuencia real:** al activar la VPN, las apps dejan de recibir respuesta de ningún servidor. El
dispositivo queda sin datos. El comentario del propio código dice *"se reescribe la cabecera del paquete
y se reenvía"* — eso no está implementado.

**Arreglo:** construir `SYN-ACK` (`TcpProxyEngine` ya tiene los helpers de checksum), lanzar un hilo por
flujo que lea del socket y emita paquetes TCP con seq/ack correctos hacia el TUN, y llamar a `buildRst`
en el camino de bloqueo. Alternativa más simple y honesta: volver a rutas `/32` (sinkhole) y quitar la
`0.0.0.0/0` hasta que el relay completo exista — así el bloqueo por IP funciona y la red sigue viva.

### 🔴 H-2 — Riesgo de pérdida total de la base cifrada ante un fallo del KeyStore

`AuraDatabaseCipher.kt:82-89`: si el blob de clave existe pero `decrypt()` falla (ROM modificada, backup
restaurado en otro móvil, KeyStore reseteado, cambio de bloqueo de pantalla…), el código **genera una
clave nueva y la sobreescribe**. La base SQLCipher anterior queda **ilegible para siempre** — y el
propio archivo del proyecto dice que la base guarda *"evidencia forense"* y que *"una migración que no
hace nada es preferible a una que borra"*. Aquí se borra la clave, que es peor.

**Arreglo:** distinguir "no hay clave" de "hay clave y no se puede descifrar". En el segundo caso, no
sobreescribir: renombrar la BD (`aura_defense_forensics.encrypted.bak`), avisar en la UI y ofrecer
"empezar de cero" explícito. Además, `AuraDatabaseCipher.isEncrypted()` existe pero **la UI nunca lo
usa** para decir al usuario si la base está cifrada de verdad (si cae al fallback sin cifrar, nadie se
entera salvo en logcat). Este es el punto que el `SECURITY.md` considera fuera de alcance ("falta de
cifrado en reposo")… cuando ya está implementado. Desalineación peligrosa.

### 🔴 R-1 — Fuga de la API key al disco en claro en el fallback

`LlmSettingsStore.kt:66-71`: si `EncryptedSharedPreferences` falla al inicializarse, el comentario
promete *"memory-only… never silently writes a key in cleartext"*, pero el código hace
`context.getSharedPreferences("aura_llm_volatile", MODE_PRIVATE)`, que **sí escribe en
`/data/data/.../shared_prefs/aura_llm_volatile.xml` en claro**. La intención y la implementación no
coinciden. **Arreglo:** guardar la clave solo en un `var` en memoria cuando el fallback está activo.

### 🟠 H-3 — El commit "GEMINI_API_KEY" es a la vez inútil y rompe el repo

`8fc6f80` añadió `GEMINI_API_KEY=your_api_key_here` a `.env.example` **y** a `app/applet/.env.example`.
Pero:
1. **Ningún código lee `GEMINI_API_KEY`.** Grep de `BuildConfig.` y `GEMINI_API_KEY` en
   `app/src/main` → 0 resultados. La app es BYOK: se configura desde `/ia` y se guarda cifrada. El
   `.env` no pinta nada (el plugin `secrets` lo procesa, pero nadie lo consume). **Sugiere lo
   contrario de la filosofía del proyecto** (parece que hay una clave compartida en el APK) y confunde.
2. Ese mismo commit puso `gradlew` en `100644` y **rompió el CI**.

**Arreglo:** revertir el `.env.example` (o dejarlo vacío con un comentario que diga "no se usa: la
clave se configura en la app"), borrar `app/applet/` completa, y restaurar el bit `+x` de `gradlew`.

### 🟠 H-4 — El cifrado de la BD y las migraciones se solapan mal en el arranque

`NyxViewModel.kt:66` hace `NyxDatabase.getInstance(application)` **como propiedad de clase**, es decir
en la construcción del ViewModel. Si `AuraDatabaseCipher.factory()` lanza (KeyStore corrupto), la
excepción ocurre **fuera** de cualquier `try/catch` del ViewModel → la app **crashea al abrir** sin
mensaje útil. **Arreglo:** diferir la apertura a `bootstrapEnvironment()`, dentro del `try`, y mostrar
`WorkspaceUiState.Error` con un mensaje accionable.

### 🟠 R-2 — `setenforce 0` está en las plantillas de mitigación

`RootCommandPolicy.kt:50` incluye `"setenforce 0"` (pasar SELinux a *Permissive*) entre las
"mitigaciones firmadas". Aura es una app **defensiva** y su propio motor de integridad **penaliza**
SELinux en Permissive. Que exista un camino que lo desactive —aunque hoy no lo llame nadie— es una
contradicción de diseño que un test de regresión debería impedir. **Arreglo:** eliminar esa entrada y
añadir un test que verifique que ninguna plantilla reduce la postura de seguridad.

### 🟠 H-5 — El CVE «aprendido» no es un CVE: es correlación de palabras

`ThreatKnowledgeEngine.trainFromInternet()` guarda CVEs de CISA KEV con `keywords = vendor, product,
cveID` y `matchTelemetryAgainstRules()` hace `telemetry.lowercase().contains(keyword)`. Palabras como
`linux`, `arm`, `curl` o `apache` aparecen en cualquier telemetría de un Android → **falsos positivos
sistemáticos** y severidades infladas. No hay correlación por versión, producto ni CPECPE. El README
dice "feed CISA KEV con correlación sobre la telemetría", que es técnicamente cierto pero
comercialmente generoso. **Arreglo:** exigir coincidencia de vendor **y** producto, excluir tokens
genéricos (< 4 chars o en lista de stopwords del sistema), y bajar la severidad por defecto a "informativa"
salvo coincidencia fuerte.

### 🟠 H-6 — El escaneo de CISA KEV descarga todo el catálogo por HTTP en el hilo de trabajo

`trainFromInternet()` hace la descarga completa de `cisa.gov` con OkHttp sin paginación ni ETag y la
procesa en `Dispatchers.IO` con `for (i in (vulns.length()-1) downTo 0)` en un hilo único. Con el
catálogo actual (~1.500 entradas) son unos pocos MB, tolerable, pero **no hay límite de tamaño de
respuesta** (`response.body?.string()` carga todo en memoria). **Arreglo:** `body.byteStream()` +
lectura con tope, y `If-None-Match`/`Last-Modified` para no re-descargar.

### 🟡 H-7 — `visualKind` es siempre el mismo y `suggestedVisual` se ignora

`AuraNeuralAiEngine.kt:551`: `chooseVisualTopology()` devuelve `NEURAL_SYNAPTIC_LATTICE` en los 3
caminos (el segundo compara con `"PROTOCOL_STRATA"`, que jamás puede ser un `toolId`, y el primero
también acaba en lattice). Y `ToolExecutionResult.suggestedVisual` **nunca se lee** para decidir la
escena (solo existe en el modelo). Resultado: los 6 renderers visuales de `GenerativeVisualCanvas`
(`CONSTELLATION_MESH`, `SPECTRUM_INTERFERENCE`, `ENTROPY_MATRIX`, `PROTOCOL_STRATA`, `BINARY_HELIX`,
`ATTACK_VECTOR_FLOW`) son **código muerto en la práctica** salvo el `CONSTELLATION_MESH` que también
acaba delegado. **Arreglo:** hacer `visualKind = toolResult.suggestedVisual` y limpiar la función.

### 🟡 H-8 — El `NetworkSecurityConfig` no permite Ollama en el rango privado real

`res/xml/network_security_config.xml:21-22` incluye `<domain>` `192.168.0.0` y `10.0.0.0`. En
`domain-config` de Android, **no se aceptan rangos CIDR**: se interpreta como nombre literal, así que
`http://192.168.1.10:11434` (el preset de Ollama del propio proyecto) **no está exento** de
`cleartextTrafficPermitted="false"` y fallará. Los presets `192.168.1.10` y `172.16-31.x` no están
cubiertos. **Arreglo:** `<base-config cleartextTrafficPermitted="false">` con `domain-config` para
`localhost`/`127.0.0.1` (esos sí funcionan) y un toggle explícito "permitir HTTP en mi LAN" que, si se
activa, use un `network_security_config` alternativo… o simplemente documentar que Ollama debe servirse
en HTTPS o en `localhost` con reenvío `adb reverse`.

### 🟡 H-9 — El target de las mitigaciones se extrae con un `substringBefore("·")` frágil

`NyxViewModel.runLiveSolutionExecution()` hace
`lastScene?.subtitle?.substringBefore("·")?.trim()` para reconstruir el host. El subtitle lo construye
`AuraNeuralAiEngine` como `"${target} · $modeTag · ${conf}%"`, así que funciona… **siempre que el target
no contenga "·"**. Si el usuario pone un dominio con ese carácter (raro) o cambia el formato, las
mitigaciones apuntan a un host equivocado. **Arreglo:** guardar el `target` estructurado en la escena
(ya existe en `ToolExecutionResult`, pero no se propaga a `AiVisualScene`).

### 🟡 H-10 — El paso "NEEDS_CONSENT" de la VPN depende de un evento sin estado

`onVpnConsentGranted(true)` recorre los mensajes buscando pasos `NEEDS_CONSENT` y los marca `DONE`,
pero si el usuario concede el permiso **antes** de que el motor termine de emitir el paso (o el diálogo
del sistema se abre dos veces), el estado queda desincronizado. **Arreglo:** mover el estado del paso a
un `StateFlow` del propio ViewModel y renderizarlo derivado, no mutando la lista de mensajes.

### 🟢 H-11 — Restos muertos y desalineaciones menores

- `LocalAutonomousEngine` solo se usa en `WorkspaceIntegrationTest`; `AuraLlmOrchestrator.resetContext()`
  nunca se llama; `ShellRunner.execArgs()` no se usa en ningún sitio.
- `AuraNeuralAiEngine.computeCalibratedSeverity` y otras funciones de scoring son deterministas y
  aceptables, pero la "confianza" del clasificador (softmax) se muestra en UI como si fuera una
  probabilidad calibrada; no lo es.
- El progreso de `SolutionExecutionEngine` usa `delay(220)` arbitrarios para que los pasos "se sientan
  reales". No es un bug, pero es un adorno: la ejecución real es la de `emitStep`.
- `metadata.json` describe la app **sin LLM** ("motor conversacional heurístico on-device (sin LLM en
  la nube)"), lo que ya no es cierto (hay LLM BYOK). El README sí está al día.
- El README sigue diciendo en dos sitios que la base **no está cifrada** (líneas 178 y 202) cuando
  SQLCipher ya está implementado. Y habla de `aura-train/`, que **no existe** en el repo.

### 🟢 M-1 — El `NyxViewModel` de 813 líneas y el `AuraCircuitConstellationCanvas` de 838

El README promete partirlos ("Partir `NyxViewModel` (722 líneas)"), pero ya van por 813. `submitQuery()`
tiene un `when` de 20 ramas con lógica de negocio (crear reglas de firewall, lanzar VPN) directamente
en el ViewModel. **Arreglo:** extraer un `ToolDispatcher` en `domain` que reciba el `ForensicToolPlan` y
devuelva `ToolExecutionResult`. Eso además hace testeable el despacho sin Android.

### 🟢 M-2 — Sin índices en Room, y las migraciones crean índices que el esquema no declara

Las 5 entidades no tienen `@Index`, pero `AuraMigrations` crea índices en `MIGRATION_1_2`
(`anomaly_events.target`, `.timestamp`) y `MIGRATION_2_3` (`threat_rules.vendorOrCategory`,
`firewall_rules.pattern`). Los índices existen en dispositivos migrados y **no** en instalaciones nuevas,
y como el esquema exportado (`3.json`) no los declara, `runMigrationsAndValidate` podría quejarse de
divergencia. **Arreglo:** declarar `@Entity(indices = [...])` en las entidades, regenerar el esquema y
unificar.

### 🟢 M-3 — Tests: buenos en lo puro, inexistentes en lo que más importa

Los 77 tests son de calidad y cubren bien lo determinista (política de comandos, codec de paquetes,
SNI, redactor, catálogo, prompts). Pero:
- **0 tests** para `NetworkForensicsEngine`, `PrivilegeAndDeviceEngine`, `BinaryCryptoEngine`,
  `PatchAndReportEngine`, `SolutionExecutionEngine` y `ThreatKnowledgeEngine`.
- Los **5 tests instrumentados** (SQLCipher + migraciones) **no corren en CI**.
- No hay tests del flujo completo `submitQuery` → dispatch → escena.
- `WorkspaceIntegrationTest` **sí** abre `NyxDatabase.getInstance()` en Robolectric: como referencia
  `System.loadLibrary("sqlcipher")` no está en el test, esto es exactamente el tipo de test que podría
  hacer fallar la suite en un entorno limpio. Merece revisión cuando el CI vuelva a verde.

---

## 8. Seguridad: lo bueno, con nombre y apellido

No todo es crítica. Hay cosas que están **mejor que en muchos proyectos comerciales**:

| Práctica | Dónde |
|---|---|
| Deny-by-default con lista blanca + guardas por subcomando | `RootCommandPolicy` |
| **Un único punto de `ProcessBuilder`** en toda la app, con timeout y `destroyForcibly` | `ShellRunner` |
| Guardrail de CI que impide `ProcessBuilder` fuera de `domain/security` | `.github/workflows/android-ci.yml` |
| Catálogo cerrado de herramientas para el LLM (el modelo propone, no ejecuta) | `AuraToolCatalog` |
| Validación del target del modelo antes de tocar ningún engine | `TargetValidator` |
| `prefersRoot` del modelo se ignora si no eres ROOT | `AuraToolCatalog.buildPlan` |
| Detección de prompt injection antes de llamar al modelo | `AuraSystemPrompt.isInjectionAttempt` |
| Redacción de telemetría con **tokens estables** (para preservar relaciones) | `TelemetryRedactor` |
| `allowBackup="false"` + reglas que excluyen todo (nube y transferencia) | `AndroidManifest` + `xml/backup_rules.xml`, `data_extraction_rules.xml` |
| Sin `fallbackToDestructiveMigration`, con migraciones reales y esquema exportado | `NyxDatabase`, `AuraMigrations`, `app/schemas/` |
| SQLCipher con clave envuelta en KeyStore (no derivada de password) | `AuraDatabaseCipher` |
| Test que verifica **en bytes** que la BD no contiene el texto en claro | `DatabaseEncryptionTest` |
| Secretos jamás en el APK (BYOK total) | `LlmSettingsStore` |
| `SECURITY.md` con alcance explícito y compromiso de 72 h | `SECURITY.md` |

---

## 9. Documentación: qué está bien y qué hay que corregir

**Bien:** el `README.md` es sorprendentemente honesto (tiene una sección "Qué NO es" y "Límites
reales"), con tabla de capacidades, comandos, política de privilegios y estructura. `SECURITY.md` y
`THIRD_PARTY_NOTICES.md` existen y son correctos.

**Correcciones necesarias (por orden):**

| Línea / sección | Dice | Realidad |
|---|---|---|
| README 178 | "La base de datos **no está cifrada** en reposo" | SQLCipher ya está implementado (`AuraDatabaseCipher`). Actualizar. |
| README 202 | `- [ ] Cifrado en reposo…` | Ya está hecho: marcar `[x]` (con la salvedad de H-2). |
| README 209 | kit de entrenamiento en `aura-train/` "listo" | La carpeta **no existe**. Quitar o añadirla. |
| README (roadmap) | "Partir `NyxViewModel` (722 líneas)" | Ya son 813. Actualizar el número o quitarlo. |
| README tabla VPN | "proxy TCP, bloqueo por SNI" | El proxy TCP no tiene camino de vuelta (H-1). Matizar. |
| `metadata.json` | "motor conversacional heurístico… sin LLM en la nube" | Hay LLM BYOK. Actualizar. |
| `Motor conversacional` | "LLM real (BYOK)… conectado a las 20 funciones" | Correcto. |
| README requisitos | "JDK 17+" | El CI usa **JDK 21**; Gradle 9.3.1 recomienda 21. Unificar. |

---

## 10. Hoja de ruta priorizada

### P0 — antes de tocar nada más (hoy)
1. **Restaurar el bit +x de `gradlew`** (`git update-index --chmod=+x gradlew`) y verificar el CI en verde.
2. **Decidir qué hacer con el camino TCP de la VPN** (H-1): o se implementa el relay completo
   (SYN-ACK + hilo de retorno + RST), o se vuelve a rutas `/32` y se documenta como sinkhole. **Tal
   como está, activar la VPN corta los datos del teléfono.**
3. **Quitar la sobrescritura de clave** en `AuraDatabaseCipher` (H-2) y exponer `isEncrypted()` en UI.
4. **Revertir `.env.example` y borrar `app/applet/`** (H-3).

### P1 — próxima iteración
5. Fallback de la clave LLM realmente en memoria (R-1).
6. Sacar `setenforce 0` de las plantillas (R-2) + test de regresión.
7. Diferir `NyxDatabase.getInstance` al `try` de bootstrap (H-4).
8. Corregir `network_security_config` (H-8).
9. Añadir job de `androidTest` con emulador en CI (SQLCipher + migraciones).
10. Correlación CISA KEV con vendor **y** producto, y severidad por defecto baja (H-5).

### P2 — calidad y producto
11. `visualKind = toolResult.suggestedVisual` y limpiar `chooseVisualTopology` (H-7).
12. `@Index` en entidades + regenerar esquema + unificar migraciones (M-2).
13. Extraer `ToolDispatcher` fuera del ViewModel (M-1) y partirlo.
14. Tests de los engines de red/dispositivo (M-3).
15. Conectar `FunctionGemmaToolProvider` a un motor real (MediaPipe LLM o llama.cpp) y meter el modelo
    en `assets/`; entonces sí se puede hablar de "on-device generativo".
16. Actualizar README/metadata (sección 9).
17. Cerrar los 10 PRs de Dependabot y poner un `gradle wrapper --gradle-version` periódico.

---

## 11. Qué aprender de este proyecto (si eres tú quien lo mantiene)

1. **La documentación honesta es un activo.** La sección "Qué NO es" del README vale más que diez
   features. Mantenla sincronizada: cada vez que diga algo que el código no hace, pierde credibilidad.
2. **Compilar en cada commit no es opcional.** La mitad de los commits del día 1 son arreglos de
   compilación. Un `./gradlew :app:testDebugUnitTest` antes de cada push habría ahorrado 6 builds de CI.
3. **El nombre "neuronal" te está costando.** `NeuralIntentClassifier` es una tabla de pesos escrita a
   mano. No pasa nada por decirlo: un clasificador heurístico bien hecho es respetable, y llamarlo
   "red neuronal" invita a que te pregunten por los pesos, el dataset y el entrenamiento — que no existen.
4. **Los 20 `toolId` y el catálogo cerrado son la mejor idea del proyecto.** Esa frontera
   (el modelo propone, la app valida y ejecuta) es exactamente cómo se debe integrar un LLM en una app
   con privilegios. Sigue invirtiendo ahí: tests de contrato, y un test que asegure que
   `dispatch` del catálogo y el `when` del ViewModel no se desincronizan (hoy el test solo cubre la
   dirección "todo lo despachado está en el catálogo", no la inversa).
5. **El firewall es el punto más difícil y el más vendido.** Un `VpnService` con `0.0.0.0/0` es un
   proxy transparente completo: hay que hacer TCP de verdad (handshake, seq/ack, ventana, retransmisión).
   Si no se quiere ese coste, un sinkhole de rutas `/32` + DNS + SNI es un producto defendible y honesto.
   Lo que no se puede es anunciar proxy y no tener camino de vuelta.

---

## 12. Cómo verificarlo tú mismo

```bash
# 1. Arreglar el modo del wrapper y compilar
chmod +x gradlew && git update-index --chmod=+x gradlew
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest          # 77 tests JVM + Robolectric

# 2. Tests instrumentados (necesitan dispositivo/emulador)
./gradlew :app:connectedDebugAndroidTest  # SQLCipher + migraciones 1→2→3

# 3. Reproducir H-1: activa la VPN en el móvil y comprueba que el navegador deja de cargar
#    (esperado: sin datos, por el hueco del relay TCP).

# 4. Ver el estado del CI
gh run list --repo liendomaho-wq/aura-defens-V2.0.0 --limit 5
```

---

*Análisis generado leyendo los 118 archivos del repositorio, el árbol de git y el historial de
GitHub Actions. Todas las referencias `archivo:línea` corresponden al commit `8fc6f80`.*

---

## Anexo — remediación ejecutada el 2026-11-26 (rama `arena/e7d0a8fa-aura-defens-v2-0-0`)

Este anexo documenta lo arreglado tras la auditoría. **Verificado en este entorno** = compilado con
`kotlinc` (Kotlin 2.4.21) y ejecutado; **solo estático** = revisado a mano, lo ejecuta el CI.

### Críticos / altos (verificado en arnés JVM con el código real del módulo VPN)

- **VPN sin camino de retorno**: proxy TCP completo en `TcpProxyEngine` — SYN → conexión real
  protegida + SYN-ACK sintético (ISN, secuencias y checksums correctos), relay bidireccional con
  ACK de datos, FIN/RST de cierre y corte por RST cuando el firewall bloquea. `AuraLocalVpnService`
  enruta `0.0.0.0/0` y DNS físicos al TUN; `VpnFirewallManager` aprende las IPs de dominios
  bloqueados y expone `upstreamDns` real. **Verificado**: 21 comprobaciones de ida y vuelta
  (SYN-ACK válido, payload íntegro, RST con checksum correcto, 0 bytes reenviados al servidor
  cuando el dominio está bloqueado, FIN cierra el flujo).
- **El DNS nunca se interceptaba**: rutas `/32` para los DNS físicos reales (Wi-Fi/LTE), respuestas
  construidas en el wire (NXDOMAIN real) y reenvío al DNS original del dispositivo. UDP e ICMP se
  filtran por IP/puerto.
- **`TcpSegment.parse` descartaba todo SYN** (validaba la longitud de payload como si fuera la
  cabecera TCP). Corregido con `ihlBytes`/`totalLength`. **Verificado.**
- **SNI fragmentado**: `FlowState.sniProbe` acumula hasta 6144 bytes y reintenta la extracción en
  cada segmento mientras `sni == null`. **Verificado.**
- **Tests VPN rotos**: el fixture de ClientHello estaba mal formado (byte de handshake ausente,
  longitud de nombre de 3 bytes); el test `sni is extracted from a client hello` ya fallaba.
  Reescrito el fixture en `VpnFirewallRealTest` y añadido `TcpDataPathTest` (handshake, datos en
  ambos sentidos, bloqueo, FIN). **Verificado en arnés; JVM de Gradle en CI.**

### Altos (datos del usuario y postura de seguridad)

- **Clave SQLCipher sobrescrita al fallar el descifrado** (blob ilegible o KeyStore sin la clave
  maestra): antes se regeneraba una clave nueva dejando la base — y las evidencias — ilegibles para
  siempre. Ahora `AuraDatabaseCipher` **aborta** conservando el blob; `factory()` lanza y
  `NyxDatabase.getInstance` propaga, el ViewModel abre una **base en memoria**, avisa en el panel
  ("ALMACENAMIENTO DEGRADADO") y muestra el aviso "EVIDENCIA SIN CIFRAR" en la barra superior.
  El archivo original no se toca en ningún camino.
- **`db` fuera del try en el bootstrap**: la base se abre de forma protegida y el fallo llega a la UI
  como estado de error legible, no como crash anterior a la primera pantalla.
- **`setenforce 0` en RootCommandPolicy**: eliminado (Aura no puede tener un camino firmado que reduzca
  la postura SELinux). Añadidos `RootCommandPolicySecurityInvariantsTest` (5 tests) y un test extra.
- **API key del LLM en SharedPreferences en claro** cuando EncryptedSharedPreferences fallaba:
  ahora solo se guarda cifrada o en RAM; `/ia` avisa cuando el KeyStore no está disponible; los
  presets de LAN usan `localhost` (adb reverse) y hay aviso explícito si configuras HTTP en claro
  contra una IP de la LAN (CIDR no válidos eliminados de `network_security_config.xml`).
- **`gradlew` sin bit de ejecución** (`8fc6f80`, 100644): `chmod +x` + `git update-index --chmod=+x`.
  CI roto → arreglado y verificado el workflow en YAML. Detonante del análisis de historia completa.
- **Tests instrumentados SQLCipher + migraciones nunca ejecutados**: añadido job
  `instrumented-tests` con emulador KVM en CI; `androidTest` ya incluye `schemas/` como assets
  (si no, `runMigrationsAndValidate` falla); migración Room **3→4** real (índice
  `forensic_sessions.timestamp`) con `4.json` y test ampliado.

### Medios

- **Correlación CISA KEV por substring** (vendor/producto genéricos ⇒ falsos positivos masivos):
  `matchTelemetryAgainstRules` ahora exige 2+ keywords fuertes (o el CVE explícito) para KEV y
  ordena por puntuación. Tope de lectura del feed (4 MB) con aviso de truncamiento.
- **@Index vs migraciones/export Room**: las migraciones ya creaban índices pero las entidades no los
  declaraban y el schema exportado no los conocía — `MigrationTestHelper` validaba contra un JSON
  que no encajaba. Unificado: entidades declaran los índices (`timestamp`, `target`,
  `vendorOrCategory`, `pattern` + el nuevo de sesiones), migraciones los crean, `3.json`/`4.json`
  los exportan. *Nota: `identityHash` de los JSON será regenerado por KSP en el próximo build local
  (Room re-exporta `app/schemas/`); los índices y tablas ya coinciden.*
- **TLS SNI / Core VPN**: `cleartextWarning`, topologías visuales muertas reparadas
  (`resolveVisualTopology` respeta `suggestedVisual`; el canvas solo usa nodos para
  NEURAL_SYNAPTIC_LATTICE), target estructurado en `AiVisualScene` (antes
  `substringBefore("·")` del subtítulo), avisos de fallback del LLM (`LlmFailure` → mensaje legible
  en el panel), `databaseEncrypted`/`databaseEncryptionFault` visibles en la barra superior.
- **Documentación**: README actualizado a la realidad (proxy TCP completo, base cifrada, JDK 21,
  `connectedDebugAndroidTest`, puertos/adb reverse, límite de almacén degradado), `metadata.json`
  describe el motor con LLM BYOK opcional, `.env.example` reescrito, `app/applet` (restos del
  template de AI Studio) eliminado.

### Sin verificar en este entorno (lo ejecuta el CI)

- `./gradlew :app:assembleDebug`, `:app:testDebugUnitTest` — no hay Android SDK aquí. El módulo VPN
  (el área con más riesgo) sí está verificado end-to-end en JVM con los archivos reales del repo.
- `:app:connectedDebugAndroidTest` — corre en el nuevo job `instrumented-tests` del CI (emulador).
