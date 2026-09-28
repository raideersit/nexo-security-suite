---
titulo: Arquitectura general de Nexo Security Suite
tipo: arquitectura
version: 1.0
fecha: 2026-09-28
estado: definitivo
tags: [nexo/arquitectura, nexo/fase-0]
---

# Arquitectura general — Nexo Security Suite

> Salida del [[Prompt 0 Arquitectura general del sistema]].
> Este documento es el contrato que deben respetar [[Prompt 1 Módulo de protección contra amenazas]], [[Prompt 2 Módulo de privacidad y navegación]], [[Prompt 3 Módulo de identidad y cuentas]], [[Prompt 4 Módulo de limpieza y optimización]], [[Prompt 5 Módulo de reportes y visualización (integración con Obsidian)]] y [[Prompt 6  Análisis completo de viabilidad del proyecto]].

---

## 0. Decisiones de base (y por qué)

Antes del diagrama, cuatro decisiones que condicionan todo lo demás. Las pongo primero porque son las que más tiempo ahorran o pierden.

### 0.1 C# .NET 8 es el lenguaje principal; C++ solo donde es inevitable

El perfil de quien desarrolla (Python, Linux, Node.js; nuevo en Windows nativo) hace que escribir todo en C++ sea la forma más rápida de abandonar el proyecto. La realidad técnica es que **el 85% de los requisitos se resuelven en modo usuario**, y ahí C# es estrictamente superior para este caso: GC, `async/await` familiar si vienes de Node, P/Invoke para llegar a cualquier API Win32, WMI de primera clase, y un ciclo de compilación de segundos en vez de minutos.

C++ queda reservado para dos cosas, ambas de fase tardía:

- El **minifiltro de sistema de archivos** (`NexoFsMini`), único camino para *bloquear* una operación de archivo antes de que ocurra.
- Un eventual **callout de WFP** para inspección profunda de paquetes.

Ninguna de las dos es parte del MVP. Ver §4.

### 0.2 Modo usuario detecta y reacciona; modo kernel previene

Esta es la limitación más importante de Windows y conviene interiorizarla ahora:

| Quiero… | Modo usuario puede | Necesita kernel |
|---|---|---|
| Saber que un archivo se creó/modificó | Sí (USN Journal, `ReadDirectoryChangesW`, ETW) | No |
| Impedir que ese archivo se escriba | **No** | Sí (minifiltro, `IRP_MJ_CREATE`/`WRITE` pre-op) |
| Saber que un proceso arrancó | Sí (WMI `Win32_ProcessStartTrace`, ETW Kernel-Process) | No |
| Impedir que ese proceso arranque | **No** (solo matarlo a los ~50–300 ms) | Sí (`PsSetCreateProcessNotifyRoutineEx`) |
| Bloquear/permitir conexiones por app | Sí (Windows Firewall COM, WFP usermode en capas ALE) | No |
| Inspeccionar el contenido de los paquetes | No | Sí (callout WFP) |
| Detectar rootkits que se esconden del SO | **No, por definición** | Sí |

**Consecuencia honesta:** un antivirus 100% en modo usuario es un *detector con retraso*, no un *preventor*. Para uso personal eso es aceptable si se combina con las defensas que Windows ya trae (Defender, Controlled Folder Access, SmartScreen), y ese es explícitamente el enfoque de este diseño: **Nexo complementa a Defender, no lo reemplaza**.

### 0.3 No se desactiva Windows Defender

Dos motores de tiempo real peleando por el mismo archivo causan cuelgues, falsos positivos cruzados y pérdida de datos. Además, Defender tiene lo que Nexo nunca tendrá: base de firmas actualizada cada hora, ELAM, y protección contra manipulación (Tamper Protection) que impide desactivarlo programáticamente sin intervención manual.

Nexo se registra como **herramienta complementaria**, no como AV primario (no se registra en el Security Center vía `WSC_SECURITY_PROVIDER_ANTIVIRUS`, lo que además exige firma y el programa MVI de Microsoft, inaccesible para un individuo). En su lugar:
- Se usa **AMSI** (`AmsiScanBuffer`) como consumidor, no como proveedor.
- Se aprovecha **Controlled Folder Access** de Defender como capa anti-ransomware real, y Nexo la configura y monitorea en vez de reimplementarla.
- Se excluye mutuamente: las carpetas de cuarentena de Nexo se añaden a las exclusiones de Defender, y viceversa.

### 0.4 Obsidian es la capa de visualización del MVP

No se construye dashboard propio. El módulo de Reportes escribe `.md` con front matter YAML en una carpeta que es un vault. Obsidian aporta grafo, backlinks, búsqueda y filtros sin escribir una línea de UI. La bandeja del sistema (tray) cubre lo urgente (toasts, confirmaciones); Obsidian cubre lo histórico y analítico.

---

## 1. Diagrama de módulos

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  SESIÓN DEL USUARIO  (integridad media, sin privilegios)                     ║
║                                                                              ║
║   ┌────────────────────┐   ┌──────────────────────┐   ┌───────────────────┐  ║
║   │  Nexo.Ui.Tray      │   │ Navegador seguro     │   │  Obsidian         │  ║
║   │  (WPF, bandeja)    │   │ (WebView2 / Sandbox) │   │  (app externa)    │  ║
║   │  · toasts          │   │ · perfil efímero     │   │  abre el vault    │  ║
║   │  · confirmaciones  │   │ · filtro de trackers │   │  en modo lectura  │  ║
║   │  · asistentes      │   │ · autocompletado     │   └─────────▲─────────┘  ║
║   └─────────┬──────────┘   └──────────┬───────────┘             │            ║
║             │                         │                         │ lee .md    ║
╚═════════════│═════════════════════════│═════════════════════════│════════════╝
              │  IPC: named pipe          │ IPC: named pipe        │
              │  \\.\pipe\NexoIpc         │ (mismo canal)          │
              │  JSON-RPC, ACL:           │                        │
              │  SYSTEM + usuario interactivo                      │
              ▼                         ▼                          │
╔══════════════════════════════════════════════════════════════════│════════════╗
║  Nexo.Service   —  Windows Service, LocalSystem, .NET 8 Worker   │            ║
║  ┌────────────────────────────────────────────────────────────┐  │            ║
║  │  Núcleo: EventBus (in-proc) + Scheduler + PolicyStore       │ │            ║
║  └───┬──────────┬──────────┬──────────┬──────────────┬─────────┘ │            ║
║      │          │          │          │              │            │            ║
║  ┌───▼────┐ ┌───▼────┐ ┌───▼────┐ ┌───▼─────┐   ┌────▼────────┐  │            ║
║  │Threats │ │Privacy │ │Identity│ │ Cleanup │   │ Nexo.Reports│──┘            ║
║  │  M1    │ │   M2   │ │   M3   │ │   M4    │   │     M5      │  escribe .md  ║
║  └───┬────┘ └───┬────┘ └───┬────┘ └───┬─────┘   └─────────────┘               ║
║      │          │          │          │                                        ║
╚══════│══════════│══════════│══════════│════════════════════════════════════════╝
       │          │          │          │
       │          │          │          └──► Win32 archivos, Registro, WMI/CIM,
       │          │          │               powercfg, SetupAPI, IFileOperation
       │          │          └──► DPAPI, Argon2id+AES-GCM, HIBP API, EventLog
       │          │
       │          └──► WireGuard (wg.exe/wireguard-nt), WebView2, WLAN API,
       │               CapabilityAccessManager (registro), Safe Browsing API
       │
       └──► clamd (TCP 3310), YARA, Windows Firewall COM (INetFwPolicy2),
            WFP usermode (FwpmFilterAdd0), USN Journal, ETW, AMSI, winget

            ┌───────────────────────── FASE 4, OPCIONAL ─────────────────────┐
            │  NexoFsMini.sys  (minifiltro C++/WDK, altitude asignada)       │
            │  ⚠ requiere firma EV + attestation, o modo test signing        │
            │  ↕ comunicación por FltSendMessage / puerto de comunicación    │
            └────────────────────────────────────────────────────────────────┘

            ┌───────────────────────── ARTEFACTO SEPARADO ───────────────────┐
            │  Nexo Rescue  —  imagen WinPE booteable (USB)                  │
            │  Nexo.Cli + clamscan portable, escaneo offline de volúmenes    │
            └────────────────────────────────────────────────────────────────┘
```

### 1.1 Cómo se comunican

**UI ↔ Servicio — Named pipe (`\\.\pipe\NexoIpc`)**
Mensajes JSON delimitados por longitud, estilo JSON-RPC 2.0 (`{"id", "method", "params"}`). Se elige named pipe sobre gRPC/HTTP porque: no abre puertos TCP (nada que escanee un atacante en la red), el SO aplica ACLs nativas, y `NamedPipeServerStream` con `PipeSecurity` es trivial en .NET. La ACL permite `SYSTEM` (FullControl) y el usuario interactivo (Read/Write); se deniega a todo lo demás.

**Regla de oro de seguridad:** el servicio corre como LocalSystem y **nunca confía en la UI**. Toda petición que borre archivos, cambie reglas de firewall o desbloquee la bóveda se valida en el servicio: rutas canonicalizadas (`Path.GetFullPath` + verificación contra lista blanca), sin path traversal, y las operaciones destructivas exigen un *token de confirmación* de un solo uso que el servicio emite y la UI devuelve tras mostrar la vista previa al usuario. Si no se hace esto, cualquier malware en la sesión del usuario convierte a Nexo en su escalada de privilegios.

**Módulos ↔ Núcleo — EventBus in-process**
Todos los módulos viven en el mismo proceso del servicio como clases que implementan `INexoModule` (`StartAsync`, `StopAsync`, `HandleCommandAsync`). Se comunican publicando `NexoEvent` en un bus interno (`System.Threading.Channels`). No hay IPC entre módulos: complejidad innecesaria para un proyecto de una persona. Si un módulo se cae, un supervisor lo reinicia sin tumbar el servicio.

**Cualquier módulo → Reportes**
`Nexo.Reports` es una librería referenciada, no un servicio. Se suscribe al EventBus y persiste cada evento como nota. **Ningún módulo escribe logs propios** (regla explícita de [[Prompt 1 Módulo de protección contra amenazas]] y [[Prompt 4 Módulo de limpieza y optimización]]).

**Servicio ↔ Driver (fase 4)**
Puerto de comunicación de minifiltro: el driver envía notificaciones con `FltSendMessage` y el servicio responde ALLOW/DENY por `FilterReplyMessage`. Se define un timeout duro (p.ej. 200 ms): si el modo usuario no responde, **el driver permite la operación**. Un driver que bloquea esperando respuesta del modo usuario es un bugcheck esperando a ocurrir.

---

## 2. Tabla maestra: las 20 funciones

Leyenda de la columna **Driver**: `NO` = 100% modo usuario · `PARCIAL` = funciona sin driver con capacidad reducida · `SÍ` = sin driver firmado no existe.

### M1 — Protección contra amenazas (`Nexo.Modules.Threats`)

| # | Función | Tecnología / API | Driver | Permisos | Servicio externo |
|---|---|---|---|---|---|
| 1 | Antivirus tiempo real (virus, malware, spyware) | `clamd` vía TCP 3310 (protocolo INSTREAM) + **YARA** para heurística; disparo por **USN Journal** (`FSCTL_READ_USN_JOURNAL`) y `ReadDirectoryChangesW`; `AmsiScanBuffer` para scripts | PARCIAL — sin minifiltro detecta *después* de la escritura, no antes | Admin (leer USN Journal, cuarentena en `ProgramData`) | Base de firmas ClamAV (`freshclam`, gratuita) |
| 1b | Detección de **rootkits** | Comparación cruzada: enumerar procesos/archivos/claves por varias rutas (`NtQuerySystemInformation` vs `ToolHelp32` vs WMI) y reportar discrepancias | **SÍ** para detección real | Admin | — |
| 1c | Análisis de comportamiento | ETW (`Microsoft-Windows-Kernel-Process`, `Kernel-File`, `DNS-Client`) vía `TraceEvent`; scoring propio: proceso sin firma + escribe en `Startup` + crea servicio + tráfico saliente inusual | PARCIAL — solo mata el proceso post-hoc | Admin (sesión ETW) | — |
| 2 | Anti-ransomware (respaldo + bloqueo de cifrado) | **Controlled Folder Access de Defender** (configurado vía WMI `MSFT_MpPreference`) + **archivos canario** vigilados por USN + respaldo versionado con `robocopy`/VSS a carpeta protegida | PARCIAL — CFA bloquea de verdad (es de Microsoft); el bloqueo *propio* necesita minifiltro | Admin | — |
| 3 | Firewall por aplicación | **`INetFwPolicy2`** (COM, `NetFwTypeLib`) para reglas por ejecutable; **WFP en modo usuario** (`FwpmEngineOpen0` + filtros en capas ALE) para bloqueo dinámico por proceso | NO | Admin | — |
| 3b | Modo sigiloso (stealth) | Reglas que **bloqueen** (no rechacen) ICMPv4/v6 Echo Request entrante + denegar inbound por defecto. Windows Firewall ya hace *drop* silencioso, no envía RST ni ICMP unreachable | **NO** — no requiere driver (aclaración explícita para [[Prompt 1 Módulo de protección contra amenazas]]) | Admin | — |
| 4 | Anti-criptojacking | Heurística combinada: CPU/GPU sostenida >X% por proceso no-foreground (PDH / `Win32_PerfFormattedData`) + conexiones a pools de minería (lista *CoinBlockerLists*, gratuita) + reglas YARA sobre memoria del proceso | NO | Admin | Listas de bloqueo públicas (gratis) |
| 5a | Apps desactualizadas | Inventario por `HKLM\...\Uninstall` + **`winget list --upgrade-available`** (incluido en Win10/11, sin costo). Opcional: mapear a CVE con la API de **OSV.dev** o NVD | NO | Usuario (inventario) / Admin (actualizar) | winget (local), OSV.dev (gratis) |
| 5b | Contraseñas débiles del sistema | **No se dumpea la SAM.** Se auditan señales legítimas: `NetUserGetInfo` (flags `UF_PASSWD_NOTREQD`, `DONT_EXPIRE_PASSWD`), política vía `secedit /export`, autologon en texto plano en `Winlogon`, BitLocker apagado. Además `zxcvbn` sobre la bóveda de M3 | NO | Admin | — |
| 5c | Wi-Fi inseguro | **Native Wifi API** (`WlanGetProfile`, `WlanQueryInterface`): detecta Open/WEP/WPA/WPA2-TKIP, y `INetworkListManager` para categoría de red (Pública/Privada) | NO | Usuario | — |
| 6 | Entorno de rescate | **WinPE** construido con Windows ADK + WinPE add-on (gratis): `copype`, `Dism /Add-Package` (WinPE-NetFx, WinPE-PowerShell), `MakeWinPEMedia`. Arranca `Nexo.Cli` + `clamscan` portable contra los volúmenes montados offline | NO (es un SO aparte) | Admin para crear el USB; Secure Boot puede requerir desactivarse para arrancar medio no firmado | Windows ADK (gratis) |

### M2 — Privacidad y navegación (`Nexo.Modules.Privacy`)

| # | Función | Tecnología / API | Driver | Permisos | Servicio externo |
|---|---|---|---|---|---|
| 7 | VPN | **Cliente WireGuard**: `wireguard-nt` + `wireguard.dll` (embeddable service, binarios ya firmados por WireGuard LLC) o, más simple, gestionar el servicio oficial de WireGuard para Windows y sus archivos `.conf` | NO (se usa el driver *ya firmado* de WireGuard, no uno propio) | Admin (crear adaptador de red, alterar rutas) | **SÍ — servidor VPN.** Ver §5 |
| 8 | Navegador seguro para pagos | **WebView2** (runtime preinstalado en Win11, gratis) con perfil de usuario efímero, sin extensiones, sin descargas, HTTPS-only. Fase 2: lanzarlo **dentro de Windows Sandbox** (`.wsb`) para aislamiento real | NO | Usuario (WebView2) / Admin + Win Pro/Enterprise + virtualización (Sandbox) | — |
| 9a | Anti-phishing | **Google Safe Browsing API v4 (Update API)**: descarga prefijos de hash localmente, la URL nunca sale del equipo; 10.000 req/día gratis. Complemento local: *URLhaus*, *OpenPhish*, *PhishTank* | NO | Usuario | Safe Browsing (capa gratuita) |
| 9b | Estafas por SMS | Windows **no expone una API para leer SMS** (Phone Link no tiene SDK público). Alcance realista: un verificador donde el usuario **pega** el texto y Nexo analiza URLs, dominios lookalike (distancia de Levenshtein contra marcas conocidas) y patrones de urgencia | NO | Usuario | — |
| 9c | Deepfakes | **Fuera de alcance como detección de video.** Un modelo propio es infactible para una persona y los detectores públicos tienen falsos positivos masivos. Sustituto: reglas de verificación de remitente/dominio y una checklist guiada de verificación fuera de banda | NO | — | — |
| 10 | Bloqueo de rastreadores | En el navegador seguro: evento `WebResourceRequested` de WebView2 filtrando con **EasyList/EasyPrivacy**. A nivel sistema: sinkhole DNS local o `hosts` con *StevenBlack/hosts*. **No se hace MITM de TLS** | NO | Usuario (WebView2) / Admin (`hosts`) | Listas públicas (gratis) |
| 11 | Cámara y micrófono | Lectura y escritura de `HKCU\...\CapabilityAccessManager\ConsentStore\{webcam,microphone}` (incluye subclave `NonPackaged` y `LastUsedTimeStart/Stop` → detecta *quién* y *cuándo*). Kill switch duro: `CM_Disable_DevNode` (SetupAPI) | PARCIAL — denegar por app funciona bien en apps empaquetadas; para Win32 arbitrarias el bloqueo duro es a nivel de dispositivo (global) | Usuario (leer/ConsentStore) / Admin (deshabilitar dispositivo) | — |

### M3 — Identidad y cuentas (`Nexo.Modules.Identity`)

| # | Función | Tecnología / API | Driver | Permisos | Servicio externo |
|---|---|---|---|---|---|
| 12 | Gestor de contraseñas | **AES-256-GCM**, clave derivada con **Argon2id** (`Konscious.Security.Cryptography`, MIT). Desbloqueo alternativo con **Windows Hello** (`KeyCredentialManager`). Clave en memoria el mínimo tiempo y borrada con `CryptographicOperations.ZeroMemory` | NO | Usuario | — |
| 12b | Autocompletado | Script inyectado por WebView2 en el navegador seguro de M2 (canal interno, no extensión publicada). Fuera de él: portapapeles con auto-borrado a los 30 s. **Autofill global en apps Win32 no se promete** (exigiría UIAutomation y es frágil) | NO | Usuario | — |
| 13 | Monitoreo de dark web | **HIBP API v3** para brechas por email (requiere clave, ~USD 3,95/mes) + **Pwned Passwords Range API** (gratuita, sin clave, k-anonimato: solo salen 5 caracteres del hash SHA-1) | NO | Usuario | HIBP (freemium) |
| 14 | Alertas de robo de identidad | Derivadas de datos reales, no genéricas: (a) hallazgos de #13; (b) **Registro de eventos de Seguridad** vía `EventLogWatcher` — 4720 (cuenta creada), 4728/4732 (añadida a admins), 4624 tipo 10 (RDP), 4698 (tarea programada); (c) nuevos autoruns; (d) cambio de servidores DNS | NO | Admin (log de Seguridad) | — |

### M4 — Limpieza y optimización (`Nexo.Modules.Cleanup`)

| # | Función | Tecnología / API | Driver | Permisos | Servicio externo |
|---|---|---|---|---|---|
| 15 | Limpieza en un clic | Catálogo de rutas declarativo (JSON) + `IFileOperation` (COM, respeta papelera y permisos) + `SHEmptyRecycleBin`. **Vista previa obligatoria** antes de cualquier borrado | NO | Usuario (perfil) / Admin (`C:\Windows\Temp`, `SoftwareDistribution`, WER) | — |
| 16a | Duplicados | Tres etapas para no matar el disco: agrupar por **tamaño** → hash de los **primeros 8 KB** → hash completo **BLAKE3** (o SHA-256). Nunca por nombre | NO | Usuario | — |
| 16b | Desinstalar apps sin uso | Inventario por `Uninstall` + `Get-AppxPackage`; "sin uso" se estima con `LastAccessTime` del ejecutable (advertir: NTFS suele tenerlo deshabilitado) y contadores de `UserAssist`. Desinstala con el `UninstallString` o `winget uninstall` | NO | Admin | — |
| 17 | Optimización de inicio | `HKCU/HKLM\...\Run`, `RunOnce`, carpeta `Startup`, `StartupApproved` (el mismo mecanismo que usa el Administrador de tareas) y Task Scheduler con trigger de logon. Medir impacto con el registro `Microsoft-Windows-Diagnostics-Performance/Operational` (evento 100/101) | NO | Admin (rama HKLM) | — |
| 18 | Perfiles de rendimiento automáticos | Señales reales: `GetSystemPowerStatus` (batería/AC), `SHQueryUserNotificationState` (pantalla completa → juego/video), `INetworkListManager` (Wi-Fi pública), proceso en primer plano. Aplica con `PowerSetActiveScheme` / `powercfg` + `SetPriorityClass` | NO | Admin (cambiar plan de energía) | — |
| 19 | Salud del disco (S.M.A.R.T.) | `root\wmi`: `MSStorageDriver_FailurePredictStatus` y `MSStorageDriver_ATAPISmartData`. Para NVMe, `MSFT_PhysicalDisk` + `MSFT_StorageReliabilityCounter` (Wear, Temperature, ReadErrorsTotal). Sin inventar métricas | NO | Admin | — |
| 20 | Triturador de archivos | Sobrescritura + `SetFileValidData`/rename aleatorio + borrado. **1 pasada de ceros es suficiente en discos modernos (NIST SP 800-88)**; Gutmann 35 pasadas es folclore de los 90. En **SSD no garantiza nada** por wear leveling → la respuesta correcta es BitLocker + TRIM, o `Format /P` con cripto-borrado. Advertir además sobre `$MFT` (archivos residentes <~700 B) y copias de sombra VSS | NO | Usuario (archivos propios) / Admin (otros perfiles) | — |

### M5 — Reportes y visualización (`Nexo.Reports`)

| # | Función | Tecnología / API | Driver | Permisos | Servicio externo |
|---|---|---|---|---|---|
| R1 | Nota markdown por evento relevante | Librería .NET propia; escritura atómica (temp + `File.Move`), front matter YAML, nombres con timestamp para evitar colisiones | NO | Usuario (dueño del vault) | — |
| R2 | Vault de Obsidian como capa de visualización | Solo archivos `.md` en carpeta. **Obsidian no tiene API pública para apps externas**; la integración es el sistema de archivos. Nota-resumen diaria + wikilinks para grafo y backlinks | NO | — | Obsidian (gratis, uso personal) |

**Verificación de cobertura:** las 20 funciones de `<requisitos>` están asignadas (6 de amenazas en filas 1–6, con 1b/1c/3b/5a/5b/5c como desgloses; 5 de privacidad en 7–11; 3 de identidad en 12–14; 6 de limpieza en 15–20). Ninguna queda sin dueño.

**Funciones que requieren driver de kernel o firma digital — lista explícita:**
1. Bloqueo *preventivo* de archivos (anti-ransomware propio, AV en tiempo real real) → minifiltro `NexoFsMini.sys`, **firma obligatoria**.
2. Detección fiable de **rootkits** → driver.
3. Inspección profunda de paquetes → callout WFP, **firma obligatoria**.
4. Bloqueo por aplicación de cámara/micrófono para procesos Win32 arbitrarios → driver (el sustituto sin driver es deshabilitar el dispositivo, que es global).
5. VPN: usa el driver `wireguard-nt`, **ya firmado por terceros** — no hay que firmar nada propio.

Sobre la firma, sin adornos: desde Windows 10 1607, un driver nuevo debe estar firmado por el **Portal de Hardware de Microsoft** (attestation signing), lo que exige un **certificado EV de firma de código** (~USD 250–600/año, con verificación de identidad y token físico) y una cuenta de Partner Center. La alternativa para desarrollo es `bcdedit /set testsigning on`, que **exige desactivar Secure Boot**, pone una marca de agua en el escritorio, puede impedir que funcionen apps con anti-cheat o DRM, e interactúa mal con HVCI/Integridad de memoria.

---

## 3. Estructura de carpetas (solución de Visual Studio)

```
NexoAntivirus\
│  NexoAntivirus.sln
│  Directory.Build.props          ← LangVersion, Nullable, TreatWarningsAsErrors
│  Directory.Packages.props       ← versiones centralizadas de NuGet
│  .editorconfig
│  .gitignore                     ← ignora vault\, artifacts\, *.user
│  README.md
│
├─ src\
│   ├─ Nexo.Core\                 (net8.0)  contratos y modelos, sin dependencias
│   │    INexoModule.cs, NexoEvent.cs, Severity.cs, EventBus.cs,
│   │    PolicyStore.cs, Abstractions\
│   │
│   ├─ Nexo.Reports\              (netstandard2.0 — consumible también desde C++/CLI)
│   │    ReportWriter.cs, NoteTemplate.cs, VaultLayout.cs, DailyNote.cs,
│   │    Redaction.cs, Templates\*.scriban
│   │
│   ├─ Nexo.Ipc\                  (net8.0)  protocolo compartido UI↔servicio
│   │    PipeServer.cs, PipeClient.cs, Contracts\*.cs, ConfirmationToken.cs
│   │
│   ├─ Nexo.Native\               (net8.0)  TODO el P/Invoke vive aquí
│   │    Win32\  Wfp\  Wlan\  Wmi\  SetupApi\  Usn\  Amsi\  SafeHandles\
│   │
│   ├─ Nexo.Service\              (net8.0-windows)  Worker Service, LocalSystem
│   │    Program.cs, NexoWorker.cs, ModuleHost.cs, Scheduler.cs,
│   │    appsettings.json, Install\nexo-service.ps1
│   │
│   ├─ Nexo.Modules.Threats\      (net8.0-windows)
│   │    Scanner\  (ClamdClient, YaraEngine, Quarantine)
│   │    Behavior\ (EtwSession, ProcessScorer)
│   │    Ransomware\(CanaryWatcher, CfaConfigurator, BackupJob)
│   │    Firewall\ (FirewallPolicy, StealthMode, WfpUserFilters)
│   │    CryptoJacking\  Vulnerabilities\
│   │
│   ├─ Nexo.Modules.Privacy\      Vpn\  SecureBrowser\  Phishing\
│   │                             TrackerBlocker\  DeviceGuard\
│   │
│   ├─ Nexo.Modules.Identity\     Vault\  Crypto\  BreachMonitor\  IdentityAlerts\
│   │
│   ├─ Nexo.Modules.Cleanup\      Junk\  Duplicates\  Startup\
│   │                             PerfProfiles\  DiskHealth\  Shredder\
│   │                             Data\cleanup-paths.json
│   │
│   ├─ Nexo.Ui.Tray\              (net8.0-windows, WPF)
│   │    App.xaml, TrayIcon.cs, Views\, ViewModels\, Toasts\
│   │
│   └─ Nexo.Cli\                  (net8.0, publish AOT/self-contained)
│        herramienta de diagnóstico; se reutiliza dentro de WinPE
│
├─ drivers\                       ← FASE 4, no tocar antes
│   └─ NexoFsMini\                (C++, WDK)
│        NexoFsMini.vcxproj, Driver.c, PreOperation.c, CommPort.c, NexoFsMini.inf
│
├─ rescue\
│   └─ winpe\                     build-winpe.ps1, mount\, scripts\, startnet.cmd
│
├─ tests\
│   ├─ Nexo.Core.Tests\           Nexo.Reports.Tests\
│   ├─ Nexo.Modules.Cleanup.Tests\   ← crítico: se prueba borrado en sandbox
│   └─ Nexo.Modules.Identity.Tests\  ← vectores de prueba de cripto
│
├─ tools\                         clamav\ (binarios), yara-rules\, listas\
├─ docs\                          adr\ (decisiones), este documento, prompts
├─ vault\                         ← vault de Obsidian, generado, fuera de git
└─ artifacts\                     ← salida de build
```

**Convenciones** (las deben respetar los prompts 1–5):
- Namespaces = ruta de carpeta: `Nexo.Modules.Cleanup.Duplicates`.
- Nada de P/Invoke fuera de `Nexo.Native`. Si un módulo necesita una API Win32 nueva, se añade el wrapper ahí.
- Un archivo por tipo público. `PascalCase` en C#, `snake_case` en C del driver (estilo WDK).
- Todo I/O es `async` con `CancellationToken`; el servicio debe parar en <5 s o el SCM lo mata.
- Ningún módulo escribe a consola ni a archivos de log propios: publica un `NexoEvent` y `Nexo.Reports` decide.

---

## 4. Plan de desarrollo por fases

Supuesto de tiempo: **8–10 horas semanales** (estudiante con negocio propio). Las estimaciones asumen que gran parte se va en aprender APIs de Windows, no en escribir código.

### Fase 0 — Cimientos (2–3 semanas)
Objetivo: que exista algo que corra y escriba una nota.
- Visual Studio 2022 + workload .NET desktop; VM de pruebas con snapshots (**no desarrollar sobre el equipo principal**).
- Solución, `Nexo.Core` (EventBus, `NexoEvent`), `Nexo.Reports` mínimo.
- `Nexo.Service` instalable como servicio + `Nexo.Ui.Tray` con named pipe y un `ping`.
- **Entregable:** el servicio arranca, la bandeja dice "conectado", y se genera una nota `.md` visible en Obsidian.

### Fase 1 — MVP real (2,5–3,5 meses)
Criterio de selección: máximo valor percibido, cero drivers, cero dependencias de pago.
1. **[[Prompt 5 Módulo de reportes y visualización (integración con Obsidian)]] completo** — es infraestructura de todo lo demás y además es tu herramienta de depuración.
2. **[[Prompt 4 Módulo de limpieza y optimización]]** — funciones 15, 16a, 17, 19, 20. Es el módulo más fácil, el que da resultados visibles la primera semana, y el que enseña Win32/WMI/Registro sin riesgo de bugcheck.
3. **Firewall por app + modo sigiloso** (3, 3b) — `INetFwPolicy2` es COM sencillo y da una victoria de seguridad real.
4. **Escaneo bajo demanda** (parte de 1) — `clamd` + YARA, sin tiempo real todavía. Cuarentena con archivo cifrado (XOR/AES sobre el original) para que Defender no lo re-detecte.

**Al final de Fase 1 tienes una herramienta que usarías de verdad.** Ese es el hito que decide si el proyecto sobrevive.

### Fase 2 — Valor personal alto, dificultad media (2–3 meses)
- **[[Prompt 3 Módulo de identidad y cuentas]]**: bóveda Argon2id + AES-GCM (12), Pwned Passwords gratuito (13), alertas por EventLog (14).
- Cámara/micrófono (11) y bloqueo de rastreadores (10).
- Escaneo de vulnerabilidades (5a, 5b, 5c) — casi todo es leer registro y WMI.
- Perfiles de rendimiento (18) y desinstalador (16b).
- Cliente VPN WireGuard (7) si ya hay servidor.

### Fase 3 — Lo difícil sin driver (2–3 meses)
- Tiempo real en modo usuario: USN Journal + canarios + AMSI (1, 2 parcial).
- Análisis de comportamiento con ETW (1c) — `TraceEvent` tiene curva de aprendizaje real.
- Anti-criptojacking (4).
- Navegador seguro (8) con WebView2, luego Windows Sandbox. Anti-phishing con Safe Browsing (9a) y verificador de SMS pegado (9b).

### Fase 4 — Opcional, solo si el proyecto sigue vivo (4+ meses)
- `NexoFsMini.sys`: minifiltro. Empezar por el *sample* `swapBuffers`/`minispy` del WDK, VM con depurador de kernel (WinDbg + red), y asumir muchas BSOD. **No empezar aquí.**
- Callout WFP, detección de rootkits (1b).
- Imagen WinPE de rescate (6).
- Plugin de Obsidian en TypeScript para vista embebida (stack aparte; ver regla de [[Prompt 5 Módulo de reportes y visualización (integración con Obsidian)]]).
- Deepfakes (9c): permanece fuera de alcance.

### Orden de los prompts, en consecuencia
`Prompt 5` (reportes) → `Prompt 4` (limpieza) → `Prompt 1` (amenazas) → `Prompt 3` (identidad) → `Prompt 2` (privacidad). **`Prompt 6` (viabilidad) conviene ejecutarlo ahora, inmediatamente después de este documento y antes de escribir código**, porque su función es decidir qué recortar.

---

## 5. Dependencias externas, con alternativa gratuita o barata

| Necesidad | Opción recomendada | Costo | Alternativa | Licencia / nota |
|---|---|---|---|---|
| Motor de firmas | **libclamav / clamd** (build oficial Windows) | Gratis | **YARA** solo (`dnYara`, `libyara`) | GPLv2 — ojo: **enlazar libclamav obliga a GPL**; usar `clamd` por TCP evita el enlace estático. YARA es BSD-3 |
| Firmas de malware actualizadas | `freshclam` (oficial ClamAV) | Gratis | Reglas de *YARA-Rules*, *Neo23x0/signature-base* | — |
| Reglas heurísticas | **YARA 4.x** | Gratis | Sigma → traducido a consultas propias | BSD-3 |
| Consumo de ETW | **Microsoft.Diagnostics.Tracing.TraceEvent** | Gratis | `System.Diagnostics.Eventing` crudo | MIT |
| Argon2id | **Konscious.Security.Cryptography.Argon2** | Gratis | PBKDF2-SHA256 (`Rfc2898DeriveBytes`, en .NET, ≥600k iter.) | MIT |
| Hash rápido | **Blake3.NET** | Gratis | `SHA256` de .NET (más lento, suficiente) | — |
| Brechas de datos | **HIBP Pwned Passwords Range** (k-anonimato) | **Gratis, sin clave** | HIBP API v3 para email: **USD 3,95/mes**; Enzoic (freemium) | Requiere `User-Agent` propio |
| Reputación de URL | **Google Safe Browsing v4 — Update API** | Gratis (10k/día) | URLhaus + OpenPhish + PhishTank (feeds locales) | Update API mantiene la URL local |
| Listas de rastreadores | **EasyList + EasyPrivacy** | Gratis | StevenBlack/hosts; CoinBlockerLists para minería | GPL/CC-BY-SA |
| VPN — **infraestructura** | **VPS propio con wg-easy**: Oracle Cloud *Always Free* (2 VM ARM) | **USD 0** | Hetzner CX22 ≈ 4 €/mes; Mullvad 5 €/mes (da `.conf` WireGuard directo) | El módulo es **solo el cliente** |
| VPN — cliente | **wireguard-nt + wireguard.dll** (embeddable) | Gratis | Controlar el servicio oficial de WireGuard | Driver **ya firmado** por WireGuard LLC |
| Navegador embebido | **WebView2** (`Microsoft.Web.WebView2`) | Gratis | CefSharp (~200 MB, builds pesados) | WebView2 viene preinstalado en Win11 |
| Aislamiento real | **Windows Sandbox** | Gratis | Hyper-V con VM dedicada | **Requiere Windows Pro/Enterprise** |
| Medio de rescate | **Windows ADK + WinPE add-on** | Gratis | Rufus + Defender Offline (ya existe y funciona) | — |
| Visualización | **Obsidian** | Gratis (uso personal) | Cualquier editor Markdown | Comercial requiere licencia |
| Tablas sobre reportes | **Dataview** (plugin comunitario) | Gratis | Nada — las notas se leen igual sin él | Opcional por diseño |
| Firma de código (app) | **Certificado OV** | ~USD 100–200/año | Sin firma: SmartScreen advertirá en cada ejecución (tolerable para uso propio) | — |
| Firma de código (driver) | **Certificado EV + attestation signing** | **USD 250–600/año + Partner Center** | `bcdedit /set testsigning on` (exige **Secure Boot apagado**, marca de agua, rompe anti-cheat) | Solo relevante en Fase 4 |
| Depuración de kernel | **WinDbg + VM Hyper-V** | Gratis | — | Imprescindible antes de tocar `drivers\` |

**Costo mínimo para llegar hasta la Fase 3: USD 0.** El primer gasto real (VPS de VPN, ~4 €/mes, o HIBP a 3,95 USD/mes) es opcional y llega en Fase 2.

---

## 6. Verificación final

- **(a) Cobertura** — las 20 funciones de `<requisitos>` aparecen en la tabla de §2, cada una con módulo dueño, tecnología, permisos y dependencia externa. Las dos funciones de reportes y visualización están en M5.
- **(b) Driver / firma** — marcadas explícitamente en la columna *Driver* y repetidas en prosa al cierre de §2: bloqueo preventivo de archivos, anti-ransomware propio, detección de rootkits, inspección profunda de paquetes y bloqueo per-app de cámara para Win32. Se indica el costo y la alternativa (test signing con sus consecuencias).
- **(c) Realismo del plan** — Fases 0 a 3 no requieren una sola línea de C++ ni de código en modo kernel, y avanzan de lo más fácil (registro, archivos, WMI) a lo más difícil (ETW, WFP). El driver queda en Fase 4 justamente porque es donde un desarrollador sin experiencia en Windows nativo se detiene. El módulo escogido para empezar (Limpieza) da retroalimentación visible en días, que es lo que sostiene un proyecto personal.

### Tres advertencias honestas antes de seguir

1. **El alcance completo es de 18–24 meses a 8–10 h/semana.** Este documento describe el destino; [[Prompt 6  Análisis completo de viabilidad del proyecto]] existe para decidir cuánto de ese destino vale la pena.
2. **Llamarlo "antivirus" crea expectativas que este software no cumplirá.** Sin firmas actualizadas cada hora, sin telemetría en la nube y sin driver, es una *suite de higiene y monitoreo de seguridad*. Nombrarlo así es más honesto y evita problemas si alguna vez lo comparte.
3. **Nunca desarrollar sobre el equipo principal.** VM con snapshots desde el día uno, especialmente para el módulo de limpieza y el triturador.
