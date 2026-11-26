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
| **VPN local + firewall** | `VpnService` real: TUN `10.8.0.2/32`, DNS virtual en `10.8.0.1` con NXDOMAIN a nivel de wire, **proxy TCP transparente completo** (SYN-ACK, relay bidireccional, RST), **proxy UDP real** (sockets protegidos, tabla acotada, checksums válidos) e IPv6 en **blackhole auditado** (`::/0` al TUN) |
| Base de amenazas | Reglas locales + feed **CISA KEV** (JSON oficial) con correlación sobre la telemetría + **OSV** (vulnerabilidades por versión de paquete) y **URLhaus** (hosts maliciosos conocidos) **bajo demanda** |
| Motor conversacional | **LLM real (BYOK)**: Gemini, OpenAI/Groq/DeepSeek/Mistral o un servidor propio (Ollama/LM Studio), conectado a las 25 funciones de la app. Sin clave, cae al clasificador heurístico local |

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

> Para Ollama/LM Studio en tu LAN usa `adb reverse tcp:11434 tcp:11434` y apunta a
> `http://localhost:11434/v1`. Los rangos `192.168.x.x` **no** se pueden eximir por CIDR en
> `network_security_config.xml` (solo acepta nombres literales), así que Aura te avisa en `/ia` si
> configuras HTTP en claro contra una IP de la LAN.

La clave se guarda en `EncryptedSharedPreferences` (AndroidKeyStore, AES256-GCM). **Nunca** va en el
APK ni en el repositorio, y no se registra en logs.

### Las 25 funciones conectadas

El LLM no ejecuta nada por sí mismo: elige un `toolId` de un catálogo cerrado
(`domain/ai/llm/AuraToolCatalog.kt`) y Aura valida el id y el objetivo antes de despachar:

`FULL_AUTONOMOUS_AUDIT` · `SERVER_MONITOR` · `SELF_TRAIN_KEV` · `SELF_INTEGRITY` · `DEVICE_INTEGRITY` ·
`NETWORK_SOCKETS` · `PORT_PROBE` · `TLS_INSPECT` · `DNS_RECON` · `HTTP_HEADERS` · `APP_SURFACE_AUDIT` ·
`CRYPTO_JWT` · `ROOT_SHELL` · `VPN_START` · `VPN_STOP` · `VPN_TELEMETRY` · `FIREWALL_BLOCK` ·
`FIREWALL_ALLOW` · `APP_FIREWALL_BLOCK` · `APP_FIREWALL_ALLOW` · `APP_FIREWALL_LIST` ·
`INTEL_OSV_QUERY` · `INTEL_URLHAUS_CHECK` · `EXECUTE_SOLUTIONS` · `AI_THEORETICAL`

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

- JDK 21 (es el que usa el CI; Gradle 9.3.1 lo recomienda)
- Android SDK con `compileSdk 36` (AGP lo descarga si falta)
- Un dispositivo o emulador con **API 24+** (target 36)

## Compilar

```bash
git clone https://github.com/liendomaho-wq/aura-defens-V2.0.0.git
cd aura-defens-V2.0.0

./gradlew :app:assembleDebug              # APK de depuración
./gradlew :app:testDebugUnitTest          # tests JVM + Robolectric
./gradlew :app:connectedDebugAndroidTest  # SQLCipher + migraciones (requiere emulador)
./gradlew :app:assembleRelease            # R8 + shrinkResources (requiere keystore)
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
/jwt <token>         Análisis criptográfico / JWT
/vpn on | off        Activar o detener la VPN local
/block <patrón>      Regla de bloqueo (dominio, IP o puerto)
/allow <patrón>      Retirar regla
/apps [filtro]       Superficie de apps COMPLETA (sin tope de líneas ni de paquetes)
/block-app <paquete> Bloqueo por app a nivel de kernel (root; sin root queda persistida)
/allow-app <paquete> Retirar bloqueo por app
/apps-blocked        Listar reglas de bloqueo por app
/osv <eco:pkg:ver>   Vulnerabilidades conocidas en OSV (ej. PyPI:django:3.2.1)
/urlhaus <host|url>  ¿Host malicioso conocido según URLhaus?
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
  `getprop`…) y un conjunto cerrado de **mitigaciones firmadas**: `setenforce 1`, el DROP de los
  puertos administrativos 23/5555/6379/27017 (forma `-I` y forma combinada `-C || -I`, en un set
  literal, sin matching por prefijo) y las **reglas firmadas de firewall por app**
  (`iptables OUTPUT -m owner --uid-owner N -j DROP`, estructura exacta, UID ≥ 10000).
- Todos los conjuntos de plantillas se **normalizan al cargar** (minúsculas + colapso de espacios),
  igual que la entrada: un flag con mayúsculas no puede romper el reconocimiento.
- Se bloquean redirecciones, `$()`, backticks, `eval`, `sh -c`, `xargs`, `-exec`, `pm uninstall`,
  `am`, `settings put`, `chmod`, `rm`, `dd`, `reboot`…
- Cualquier denegación se muestra en el panel con el motivo; nunca se ejecuta en silencio.

Esto existe porque el clasificador puede enrutar texto libre del chat hacia la herramienta de shell:
sin esta puerta, una frase se convertía en ejecución de código con privilegios de kernel.

## VPN local: cómo funciona y qué limita

1. `VpnService.Builder` crea un TUN con `10.8.0.2/32` y un DNS virtual `10.8.0.1`.
2. Se enrutan al TUN los **DNS reales de las interfaces físicas** (Wi-Fi/LTE) y se interceptan: si el
   dominio está bloqueado se responde **NXDOMAIN real**; si no, se reenvía al DNS original del
   dispositivo con `protect()` (con 1.1.1.1/8.8.8.8 como último recurso).
3. Todo el TCP IPv4 va por `0.0.0.0/0` al **proxy transparente**: SYN → conexión real protegida +
   SYN-ACK sintético, datos en ambos sentidos con secuencias y checksums correctos, y **RST** cuando
   una regla corta el flujo.
4. Todo el UDP IPv4 no-DNS va por un **proxy UDP real** (socket protegido por flujo, respuestas
   reescritas con checksums válidos, tabla de flujos acotada a 256 con expulsión del más antiguo,
   expiración por inactividad de 30 s). Lo bloqueado queda en telemetría; nunca se descarta en
   silencio. ICMP y otros protocolos no se reenvían y se registran explícitamente.
5. IPv6 se enruta al TUN (`::/0`) como **blackhole auditado**: el tráfico v6 no puede salir sin
   inspección. Coste honesto: en redes IPv6-only puras el dispositivo no tendrá conectividad
   mientras Aura esté activo.
6. Los dominios bloqueados se traducen a IPs aprendidas (TTL 30 min) para cortar también a las
   apps que resuelven por su cuenta.
7. Aura queda excluida del túnel con `addDisallowedApplication` para no auto-interceptarse.

Limitaciones honestas: no descifra TLS (solo lee el SNI del ClientHello, que viaja en claro) y no es
un IDS/IPS con inspección profunda. QUIC/UDP no se filtra por dominio (solo IP/puerto): el SNI viaja
cifrado dentro del handshake QUIC. Sin root no se puede tocar `iptables` del sistema; con root, la
app solo aplica las plantillas firmadas de `RootCommandPolicy`.

## Privacidad y datos

- Todo se guarda en **Room/SQLite privado** (`aura_defense_forensics.db`). Sin cuentas, sin analytics,
  sin telemetría propia.
- `android:allowBackup="false"` y reglas de extracción que excluyen todo: la evidencia no sale del
  dispositivo, ni por backup en la nube ni por transferencia entre dispositivos.
- Únicas salidas de red: el feed `cisa.gov` (KEV) **solo cuando lo pides**, `api.osv.dev` y
  `urlhaus.abuse.ch` **solo cuando pides una consulta concreta** (nunca en segundo plano),
  `dns.google` (DoH opcional), los hosts que tú ordenes auditar y —solo si activas el motor LLM—
  el proveedor que elijas, con la telemetría ya redactada.
- La base forense **está cifrada en reposo** con SQLCipher; la clave SQLCipher se envuelve con una
  clave AES-GCM que vive en el AndroidKeyStore. Si el KeyStore del dispositivo no puede entregarla,
  la app arranca con una base **en memoria**, avisa en el panel y **no borra** la base cifrada: los
  datos siguen en disco para cuando la clave vuelva a estar disponible.

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

- [x] Cifrado en reposo de la evidencia (SQLCipher + clave envuelta por AndroidKeyStore)
- [ ] Partir `NyxViewModel` (813 líneas) y los canvas de UI en módulos más pequeños
- [ ] Cobertura de tests para los engines que tocan el sistema (ya hay 21 pruebas nuevas de
      firewall y de la política de privilegios)
- [x] `applicationId` propio (`com.aura.mobiledefense`, alineado con el `namespace`)
- [x] Modo "IA Online" implementado como LLM real (BYOK) con catálogo cerrado de herramientas
- [ ] Modelo on-device real: el adaptador `FunctionGemmaToolProvider` está listo y probado; falta
      el kit de entrenamiento (`aura-train/render_dataset.py`, aún no versionado), el motor de
      inferencia (MediaPipe LLM / llama.cpp) y los pesos en `assets/`
- [x] Firewall real: ruta 0.0.0.0/0, proxy TCP, bloqueo por SNI y política DoH/DoT
- [x] Migraciones de Room 1→2→3 con pruebas instrumentadas
- [x] `RootCommandPolicy` con la regla 3 implementada y un único `ShellRunner`
- [x] P0: set cerrado de mitigaciones (sin matching por prefijo), auditoría sin topes artificiales,
      proxy UDP real con sockets protegidos, IPv6 en blackhole auditado, release verificada en CI (R8)
- [x] P1: firewall por app a nivel de kernel (iptables uid-owner DROP, requiere root) + atribución
      forense best-effort sin root; intel OSV/URLhaus bajo demanda
- [x] P2: respuesta verificable — SELinux y las mitigaciones de kernel se verifican en el dispositivo
      ("VERIFICADO/NO verificado"), nunca se reportan como aplicadas a fe
- [ ] UI dedicada para el firewall por app (hoy se gestiona por conversación: `/block-app`)
- [ ] IPv6 de extremo a extremo (hoy: blackhole; un proxy v6 es trabajo de meses)
- [ ] Modelo on-device real (MediaPipe/llama.cpp) y sincronización periódica de intel (hoy: bajo demanda)

## Preparación para entorno empresa

Estado honesto de lo que una organización debe saber antes de desplegar Aura:

- **Distribución**: no hay release firmado publicado todavía (`versionCode 1`). El CI compila
  `assembleRelease` en cada push a `main` (R8 + keep de SQLCipher) pero el APK es de verificación,
  firmado con una clave desechable. Para un piloto: firma propia con `KEYSTORE_PATH`/`STORE_PASSWORD`/
  `KEY_PASSWORD`.
- **Enrolment**: no hay MDM/EMM ni app de consola. El despliegue es instalar y aceptar el diálogo VPN.
  No hay políticas centralizadas, ni inventario, ni borrado remoto: cada dispositivo es autónomo.
- **Datos**: la evidencia forense queda en el dispositivo (Room + SQLCipher, clave envuelta por
  AndroidKeyStore, `allowBackup=false`, reglas de extracción deny-all). Nada sale sin acción del
  usuario.
- **Permisos**: VPN (obligatorio), notificaciones (opcional). Root **nunca** es obligatorio;
  desbloquea el firewall por app y las mitigaciones de kernel.
- **Operación**: el DNS del dispositivo pasa por el túnel con el firewall de dominios; los servidores
  DoH/DoT conocidos se bloquean si el usuario activa la política. El puerto ADB 5555, Telnet 23,
  Redis 6379 y Mongo 27017 tienen plantillas de DROP firmadas.
- **Verificación**: `./gradlew :app:testDebugUnitTest` (JVM + Robolectric, incl. política root,
  proxy TCP/UDP, parsers de intel), `:app:connectedDebugAndroidTest` (SQLCipher + migraciones),
  `:app:assembleRelease` (R8). El CI corre los tres en cada push a `main`.
- **Sin promesas inflatadas**: Aura no es un EDR con respuesta remota; la "remediación" es local y
  delimitada (VPN/firewall/kernel firmado). La arquitectura empresa real (consola, MDM, atestación)
  es trabajo futuro del roadmap.

## Aviso legal

Herramienta defensiva para auditar **dispositivos y servicios propios o con autorización explícita por
escrito**. El sondeo de puertos y la inspección de terceros sin permiso puede ser ilegal en tu
jurisdicción. El autor no se responsabiliza del mal uso.

## Licencia

MIT — ver [LICENSE](LICENSE). Las fuentes y el feed de amenazas tienen sus propias licencias:
ver [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
