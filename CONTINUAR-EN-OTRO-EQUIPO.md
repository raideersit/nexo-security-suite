# Continuar en otro equipo

> Documento de traspaso **vigente** (2026-10-04; última actualización 2026-11-02, ver §2j:
> la VM ya no existe). Si abres una sesión nueva de
> Claude Code en este repositorio, léelo primero. Reemplaza a
> [[CONTINUAR-EN-WINDOWS]], que queda como historia del paso Linux → Windows.

---

## 1. Por qué hay un segundo equipo

El equipo principal (HP Pavilion Gaming 15-cx0xxx, Windows 10 Home) **no puede
ejecutar una VM**: la virtualización (VT-x) está desactivada en la BIOS y no se
puede llegar a ella, porque la pantalla del portátil está rota y la salida de
vídeo externa pasa por la GTX 1050, que no muestra la BIOS. La BIOS de ese
modelo (F.20, 2019) tampoco expone el ajuste por WMI: se comprobó leyendo sus 54
ajustes.

El trabajo que **necesita una VM** se hace en un segundo equipo. Todo lo demás
sigue en el principal. VirtualBox 7.2.20 quedó instalado en el principal pero no
se puede usar allí.

---

## 2. Estado exacto

**Repositorio:** `raideersit/nexo-security-suite`, rama `main`. Compila con 0
errores y 0 advertencias (los proyectos de librería tratan las advertencias como
errores).

**678 comprobaciones automatizadas, todas en verde, en Windows 10** (751 con las portables hechas desde Linux el 2026-11-02 —11 de la traducción de rutas, 33 del impacto de arranque, 26 de las tareas programadas y 3 del texto en una línea—, probadas solo en Linux; +6 en Windows sin ejecutar todavía) (127 al
traspaso; +7 del historial de S.M.A.R.T., 2026-10-17; +4 de carpeta inaccesible y
+84 del firewall y +67 del escáner, 2026-10-21; +9 de la purga y +5 de reglas ajenas, +6 del escaneo en paralelo y +5 de la lista de protegidos, +33 del IPC, +100 del servicio y +57 del tiempo real, +10 de identidad en el escáner, +10 en el IPC y +9 en el servicio, +34 de la limpieza, +15 de la aprobación y +40 de la bandeja y +12 de la aprobacion por otro administrador, 2026-10-22):

| Arnés | Comprobaciones | Qué cubre |
|---|---|---|
| `tools/Nexo.Reports.Demo` | 15 | Notas, vault, redacción, nombres NTFS |
| `tools/Nexo.Cleanup.Demo` | 155 | Guardia, limpieza, duplicados, triturador, inicio, impacto de arranque, tareas programadas, S.M.A.R.T. e historial (portable) |
| `tools/Nexo.Cleanup.Windows.Demo` | 29 (+5 sin ejecutar) | Tipo de disco, registro de inicio, impacto de arranque y tareas reales, Papelera, archivos bloqueados, discos reales |
| `tools/Nexo.Firewall.Demo` | 115 | Guardia de reglas, plan/token, reglas ajenas, modo sigiloso (portable) |
| `tools/Nexo.Firewall.Windows.Demo` | 31 | Firewall de Windows real: lectura, reglas por app, sigiloso (como administrador) |
| `tools/Nexo.Scan.Demo` | 93 | Cliente clamd (contra un clamd falso), escáner, cuarentena (portable) |
| `tools/Nexo.Ipc.Demo` | 43 | Protocolo del pipe: tramas, entradas malas, límites, ACL (solo Windows) |
| `tools/Nexo.Service.Demo` | 173 | El servicio en el mismo proceso: ciclo de vida, firewall, escaneo y cuarentena por el pipe con token de un solo uso, planes pendientes (solo Windows), tiempo real y diario USN (la parte elevada se omite sin administrador) |
| `tools/Nexo.RealTime.Demo` | 57 | Vigilante en tiempo real (filtro, estabilización, bloqueados, motor caído, desborde), parser USN con buffers malformados y un FileSystemWatcher real (portable) |
| `tools/Nexo.Tray.Demo` | 40 | Bandeja: modelo de estados sin pantalla, consulta y acciones contra el servicio real, y el ejecutable arrancando de verdad (solo Windows) |

**Implementado esta sesión** (además de lo que ya estaba):

- **Triturador** (`Nexo.Modules.Cleanup/Trituracion`): vista previa + token, una
  pasada aleatoria, `FileShare.None`, renombres aleatorios, truncado y borrado.
  Distingue «no se modificó» de «sobrescrito pero no borrado».
- **Inicio** (`Inicio/`): deshabilita/habilita por `StartupApproved`, nunca
  borra la entrada `Run`. Lista de protección (`SecurityHealth*`,
  `Windows Defender*`, `Nexo*`).
- **S.M.A.R.T.** (`Disco/`): parser de los 512 bytes, evaluador con los 5
  atributos de Backblaze, monitor y fuente WMI.
- **Detección de SSD** (`Nexo.Native/Storage`): `IOCTL_STORAGE_QUERY_PROPERTY`.
  Contrastada con `Get-PhysicalDisk`: NVMe = SSD, SATA y USB = HDD.
- **`nexo-cleanup`** (`tools/Nexo.Cleanup.Run`): el limpiador contra el equipo
  real. Modos `simulado` (defecto), `papelera` y `real`.

### Hallazgos reales de esta sesión (todos corregidos)

1. **Uniones NTFS.** El guardia aceptaba un archivo dentro de una unión que
   apunta fuera de la raíz, y el limpiador entraba en las uniones. Habría
   borrado archivos ajenos. Corregido en `GuardiaDeRutas.CaminoAtraviesaEnlace`
   y con `AttributesToSkip = ReparsePoint`.
2. **Papelera con un archivo bloqueado.** Si un lote fallaba por un archivo en
   uso, el shell ya había movido los demás, pero el reintento los daba por
   omitidos (0 eliminados). Corregido en `BorradorPapelera`.
3. **«Correcta» sin datos.** Un disco que no se pudo leer se habría reportado
   como «correcta». Ahora es «sin datos suficientes».
4. **Regla dura hecha código.** «Nunca `BorradorReal` fuera de una VM» ya no es
   un aviso: `nexo-cleanup --modo real` se niega si `DetectorDeVm` no reconoce
   una VM, y exige `NEXO_PERMITIR_BORRADO_REAL=1`.

### Cosas que conviene saber del catálogo real

La vista previa contra el perfil del equipo principal encontró 22 585 archivos
y 8,9 GB. Dos decisiones que son **tuyas**, no del código:

- `cache-gpu` (4,4 GB, `NVIDIA\DXCache`): es caché de shaders. Borrarla es seguro,
  pero cada juego recompila los shaders y se nota como tirones la primera vez.
- Hay paquetes del instalador de Visual Studio dentro de `Temp`. Si se borran,
  Visual Studio puede tener que volver a descargarlos para reparar o actualizar.

---

## 2b. Resultados en el segundo equipo (2026-10-17)

El segundo equipo resultó ser un **Lenovo 81F4** (i3-7020U, 2 núcleos, **4 GB de
RAM**, NVMe de 128 GB, Windows 10 Home). VT-x está habilitada, pero **no cumple
los requisitos de la VM** de §3.2 (4 GB en total y unos 17 GB libres). Se usó sin
VM para todo lo que no borra; `papelera` y `real` siguen pendientes (§3.3).

Se instaló .NET SDK 8.0.426. Compila con 0 errores y 0 advertencias.

| Arnés | Sin administrador | Como administrador |
|---|---|---|
| `Nexo.Reports.Demo` | 13/13 | — |
| `Nexo.Cleanup.Demo` | 86/86 (aviso: no pudo crear el enlace simbólico) | **87/87** (el enlace simbólico se crea y se rechaza) |
| `Nexo.Cleanup.Windows.Demo` | 28/28 | **28/28**, escribe en `HKLM` y borra la subclave |

- **Tipo de disco:** C:\ = SSD, coincide con `Get-PhysicalDisk` (NVMe).
- **S.M.A.R.T. en NVMe:** como administrador lee temperatura (37 °C) y desgaste
  (0 %). Horas de uso: «-» también como administrador; este disco no expone el
  contador. Predicción de fallo: «no disponible», con el motivo (NVMe no expone
  atributos ATA). Correcto según «no pude leer ≠ está bien».
- **`Nexo.Cleanup.Demo` como administrador** sigue listando «No evaluado por
  falta de permisos»: es a propósito, el arnés usa `esAdministrador: false`
  contra su corpus sintético (`Program.cs`, `new LimpiadorDeBasura`).
- La prueba de Papelera deja **3 archivos sintéticos `nexo-demo-*`** en la
  Papelera del equipo. Esperado.

**`nexo-cleanup` simulado, tres corridas seguidas:** las tres listas son
idénticas línea por línea. 909 archivos, 127,1 MB (`cache-navegadores` 850,
`miniaturas` 13, `temporales` 30, `cache-gpu` 16). Sin administrador quedan sin
evaluar las 3 reglas de sistema, como debe ser.

El guardia omitió 5 rutas: `INetCache\IE\container.dat` (`EsArchivoDeSistema`)
y 4 archivos del corpus que el arnés dejó en `%TEMP%\nexo-cleanup-demo\corpus\`
(`Documents\importante.docx`, `System32\x.dll`, …) por `EnListaNegra`. Buena
prueba real: un documento o una DLL «de sistema» dentro de `Temp` no se tocan.

### Anotado y arreglado

1. **El arnés no limpiaba su corpus.** `Nexo.Cleanup.Demo` dejaba
   `%TEMP%\nexo-cleanup-demo\corpus` al terminar. No era un riesgo (el guardia
   lo protege), pero ensuciaba la vista previa del limpiador real. Ahora lo
   borra al final (quitando antes las uniones NTFS) si todo pasó; si algo
   falló lo conserva para inspeccionarlo. El vault del arnés se conserva.
2. **Codificación.** Las cuatro herramientas fijan `Console.OutputEncoding` a
   UTF-8, así la salida no depende de la página de códigos (con 850 un «—»
   salía como «?»). La lista del vault se escribe con BOM: Windows PowerShell
   5.1 y el Bloc de notas la leen bien sin `-Encoding utf8`.

   Lo que **no** se arregla desde el programa: Windows PowerShell 5.1 decodifica
   la salida redirigida (`*> archivo`) con su propia página de códigos. Antes de
   redirigir, ejecuta `[Console]::OutputEncoding = [Text.Encoding]::UTF8`.

---

## 2c. Las pruebas destructivas por fin corrieron (2026-10-21)

El trabajo que necesitaba una VM se hizo en un **tercer equipo**: un **Acer Nitro
AN515-57** (Windows 11 Home, 15.8 GB de RAM, NVMe). Es el primero de los tres que
cumple §3.2: los otros no podían (HP Pavilion con la BIOS inaccesible, Lenovo 81F4
con solo 4 GB). Con esto se cierra el milestone de §3.3.

**Montaje** (todo bajo `C:\VMs`): VirtualBox 7.2.22; VM **`NexoVM`** con Windows 10
22H2 Home, 4 GB, 2 núcleos, disco de 40 GB, NAT; usuario **`nexo`** / **`nexo`**;
snapshot **`limpia`** tomado tras instalar. El ISO de Windows y el SDK de .NET se
descargaron **en el equipo anfitrión** y se pasaron a la VM por carpeta compartida:
la red NAT del invitado se degradaba y colgaba las descargas largas. .NET quedó en
`C:\Users\nexo\dotnet` (sin administrador, con `dotnet-install`).

> **Si corres el ejecutable `nexo-cleanup.exe` directamente** (no `dotnet run`) con
> un .NET instalado fuera de `Program Files`, define
> `DOTNET_ROOT=C:\Users\nexo\dotnet`. Si no, el *apphost* no encuentra `hostfxr.dll`
> y aborta con «You must install .NET».

**Resultados dentro de la VM** (como usuario normal):

| Prueba | Resultado |
|---|---|
| `dotnet build` | 0 errores, 0 advertencias |
| Los tres arneses | `TODAS LAS VERIFICACIONES PASARON` |
| `simulado` | 60 archivos de miniaturas sintéticas detectados; no se tocó nada |
| `papelera` | 60 archivos a la Papelera (su contador pasó de 1 a 61); reversible |
| **`real`** | 60 borrados de forma **permanente**; la Papelera siguió en 61, confirmando que **no** fueron a ella |

El `DetectorDeVm` informó `innotek GmbH / VirtualBox`, así que el modo `real` se
aceptó (en un equipo físico se niega, como está probado). El corpus de prueba
fueron 60 archivos `thumbcache_9*.db` fechados tres días atrás en
`%LOCALAPPDATA%\Microsoft\Windows\Explorer` (la regla `thumbcache` pide antigüedad
≥ 1 día; un perfil recién instalado no tiene casi nada que limpiar).

### Hallazgo real de esta sesión (corregido 2026-10-21)

**El recorrido de `%TEMP%` se aborta entero ante un archivo sin permisos.** Con la
regla `temp-usuario`, un único archivo que lanza `UnauthorizedAccessException`
detiene la caminata de **toda** la carpeta (la vista previa lo registra como
`%LOCALAPPDATA%\Temp — recorrido interrumpido: UnauthorizedAccessException`) y esa
regla acaba con 0 archivos. Debería **omitir ese archivo y seguir**, como ya hace
con los bloqueados. Anotado antes de tocar, según la convención de §5.

**Causa y arreglo:** `EnumerationOptions` con `RecurseSubdirectories` lanza al llegar a
una subcarpeta sin permisos y el enumerador no puede reanudarse. `RecorrerCarpeta`
(`Junk/LimpiadorDeBasura.cs`) ahora recorre carpeta a carpeta, cada una con su propio
`try`: la inaccesible queda en `RutasOmitidas` («carpeta omitida») y el resto sigue.
Prueba de regresión `2b` en `Nexo.Cleanup.Demo` (carpeta con ACL de denegación vía
`icacls`; se limpia en `finally`; solo Windows). Pendiente: repetirlo en la VM.

### Notas de automatización (por si hay que repetirlo headless)

- El servicio de *guestcontrol* de VirtualBox **se traba a menudo** bajo presión de
  memoria del anfitrión (`Error starting guest session (current status is:
  starting)` / `VERR_TIMEOUT`), sobre todo con salida larga por streaming. Se
  destraba con `VBoxManage controlvm NexoVM reset`; lo ya extraído a disco (SDK,
  logs) sobrevive al reinicio.
- Los procesos lanzados por *guestcontrol* corren en una **sesión aislada, no en el
  escritorio visible**. Para una consola interactiva de verdad (necesaria porque el
  limpiador **rechaza la entrada redirigida** a propósito, `Console.IsInputRedirected`)
  se usó una **tarea programada interactiva** (`schtasks /it`) y la confirmación
  `BORRAR` se escribió por **inyección de teclado** desde el anfitrión
  (`VBoxManage controlvm NexoVM keyboardputstring` + `keyboardputscancode 1c 9c`).

---

## 2d. Firewall por aplicación y modo sigiloso (2026-10-21)

Primer entregable del módulo de amenazas (funciones 3 y 3b de la Salida 0), todo
en **modo usuario y sin driver**: `INetFwPolicy2` por COM.

- `Nexo.Modules.Threats` (portable): `GuardiaDeReglas`, `AdministradorDeFirewall`,
  `VistaPreviaFirewall` + `TokenDeCambio`. Mismo patrón que el limpiador: planear
  no cambia nada; aplicar solo ejecuta ese plan exacto y reverifica cada cambio
  contra el estado real (TOCTOU).
- `Nexo.Modules.Threats.Windows`: `AlmacenDeFirewallWindows` (COM de enlace tardío).
- `tools/Nexo.Firewall.Demo` (66), `tools/Nexo.Firewall.Windows.Demo` (28 como
  administrador) y `tools/Nexo.Firewall.Run` (`nexo-firewall`).
- Eventos nuevos en `Nexo.Reports`: `regla-firewall` y `modo-sigiloso`.

**Decisiones:**

- **Frontera = el grupo «Nexo Security Suite».** Solo se modifican las reglas con
  ese grupo *y* el prefijo `Nexo: `. Una regla de Windows, o una impostora con el
  prefijo pero otro grupo, no se edita ni se borra.
- **No se bloquea** `svchost`, `lsass`, `services`, `winlogon`, Windows Defender
  (`MsMpEng`, `NisSrv`, `SecurityHealthService`…) ni `Nexo*`. Permitir sí se
  acepta. Es la regla «Nexo complementa a Defender» hecha código. (Lo confirmó el
  propio arnés: mi `.exe` de prueba se llamaba `nexo-fw-demo.exe` y el guardia lo
  rechazó.)
- **Modo sigiloso = bloquear el ping entrante** (ICMPv4 tipo 8, ICMPv6 tipo 128).
  El resto ya lo descarta Windows en silencio. **No** cambia las políticas por
  defecto ni enciende un firewall apagado: lo **avisa**.
- Nombres de regla deterministas con sufijo de hash de la ruta: pedir lo mismo
  dos veces es «ya existe», y dos `chrome.exe` de carpetas distintas no chocan.

**Probado en el equipo principal (HP, administrador):** las reglas se crean, se
leen de vuelta con un almacén nuevo (ruta exacta, bloquear, 3 perfiles, grupo),
se quitan y el firewall vuelve exactamente a su número inicial de reglas (744).
Se niega a quitar una regla real de Windows y a bloquear el `svchost.exe` real.

**No probado:** el ping real. El tráfico hacia la propia máquina va por loopback
y no pasa por el filtro; hace falta otro equipo de la red.

**Huecos conocidos del firewall (sin hacer):**

- ~~No lee los bloqueos efectivos~~ Hecho (2026-11-02), ver el recuadro de abajo. Siguen sin
  hacer: exponerlo por el pipe (`firewall.bloqueos`), traducir `FilterRTID` al nombre de la regla,
  y leerlo sin pedir administrador. ~~Convertir la ruta `\device\harddiskvolume3\...` a `C:\...`~~ Hecho
  (2026-11-02, desde Linux): ver «Rutas de dispositivo» abajo.

**Bloqueos del firewall (evento 5157), 2026-11-02:** `nexo-firewall bloqueos [--horas N] [--max N] [--registrar]`.
Solo lee. Windows **no escribe** el 5157 si no está activa la auditoría de fallos de «Filtering Platform
Connection»; Nexo **no la activa** (cambia la política del equipo y llena el registro de Seguridad):
`auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable`.

- Portable (`Nexo.Modules.Threats/Firewall`): `ParserDeEvento5157` (XML defensivo: sin DTD, tamaño acotado, IP y
  puerto validados, rutas con caracteres de control rechazadas), `LectorDeBloqueos` (agrupa por app + dirección +
  destino + puerto + protocolo; `RegistrarAsync` anota como máximo 50 notas, los más repetidos primero).
- Windows: `FuenteDeBloqueosWindows` (`EventLogReader` sobre el registro `Security`; añade el paquete
  `System.Diagnostics.EventLog` 8.0.1) y `Nexo.Native/Audit/PoliticaDeAuditoria` (`AuditQuerySystemPolicy`, solo lee).
- **«No pude leer» ≠ «sin bloqueos»:** `PuedeAfirmarQueNoHuboBloqueos` exige registro leído, auditoría **activa**,
  nada truncado y nada sin interpretar. Sin permisos, registro no disponible, auditoría apagada o desconocida, o
  lectura truncada, el resultado es *no concluyente* (código de salida 2). Probado rompiendo a propósito la regla de
  la auditoría y la de los caracteres de control: las pruebas fallan.
- **Probado:** 38 comprobaciones portables (`Nexo.Firewall.Demo`), incluidas entidades externas y bombas de entidades,
  3000 XML mutados al azar, y los casos «no sé». En el HP **sin administrador** (`Nexo.Firewall.Windows.Demo`, +3): la
  fuente dice `SinPermisos` y no inventa el estado de la auditoría.
- **SIN PROBAR — hace falta administrador y la auditoría activa:** leer eventos 5157 **reales** y que el analizador
  los entienda todos (la prueba de administrador exige `Descartados == 0`); y `AuditQuerySystemPolicy` con permisos
  (sin ellos solo se ha probado el camino «no se sabe»). Hasta entonces el formato real del evento es el que
  documenta Microsoft, no uno observado: los campos `Direction` (`%%14592` entrante / `%%14593` saliente — CORREGIDO 2026-11-03 con un evento real: antes estaban al revés),
  `SourceAddress`/`DestAddress`, `Protocol`, `FilterRTID`.
**Rutas de dispositivo (2026-11-02, hecho desde Linux):** el 5157 escribe la aplicación como
`\device\harddiskvolume3\apps\x.exe`. `TraductorDeRutasNt` (portable) la convierte en `C:\apps\x.exe` con la
tabla letra → dispositivo, que en Windows sale de `Nexo.Native/Storage/DispositivosDeUnidad` (`QueryDosDevice`, sin
administrador). `\device\mup\servidor\recurso\...` pasa a `\\servidor\recurso\...`. Un volumen que no está en la
tabla (USB desconectado) queda **tal cual**: no se adivina la letra. Unidades de red mapeadas y `subst` no entran en
la tabla. `LectorDeBloqueos` traduce antes de agrupar, así que la misma app en las dos formas es un solo grupo;
`nexo-firewall bloqueos` ya lo usa. +11 portables (`Nexo.Firewall.Demo`; dos de ellas comprobadas quitando el arreglo).
**SIN PROBAR en Windows:** la comprobación nueva de `Nexo.Firewall.Windows.Demo` (la unidad del sistema se traduce con
`QueryDosDevice` real) solo se compiló desde Linux.

- Reglas por puerto/IP/protocolo y listas de bloqueo: solo por aplicación.
- ~~Lista de protegidos fija~~ Hecho (2026-10-22): `%LOCALAPPDATA%\Nexo\firewall-protegidos.txt` (o `--protegidos`) añade nombres; solo suma, nunca quita svchost ni Defender.
- Sin integración en `Nexo.Service` (existe, pero solo expone `ping` y `estado`; ver §2f) ni confirmación desde la UI.
- ~~`bloquear` no detecta reglas ajenas~~ Hecho (2026-10-22): ahora las **avisa** (misma app y dirección, habilitadas) sin tocarlas ni impedir la creación. No distingue puertos: la regla ajena podría aplicar solo a algunos.

---

## 2e. Escaneo bajo demanda y cuarentena (2026-10-21)

Segundo entregable del módulo de amenazas (función 1 de la Salida 0, sin tiempo
real). Todo en modo usuario; el motor es **ClamAV vía `clamd` por TCP** (no
`libclamav` enlazada: es GPLv2 y obligaría a publicar Nexo bajo GPL).

- `Nexo.Modules.Threats/Escaner`: `ClamdClient` (protocolo `zINSTREAM`),
  `EscanerBajoDemanda`. `Cuarentena/AlmacenDeCuarentena`.
- `tools/Nexo.Scan.Demo` (82) con un **clamd falso** que implementa el protocolo
  real; `tools/Nexo.Scan.Run` (`nexo-scan`).
- Eventos: `Escaneo(...)` ahora informa `archivos_omitidos` e `incompleto`;
  nuevo `Restaurado(...)`.
- `TokenDeCambio` se generalizó a líneas de texto para reutilizarlo.

**Decisiones:**

- **«No pude leer» != «está bien».** Archivo en uso, sin permisos, mayor que el
  límite (25 MB, el de `clamd`), carpeta cerrada, ruta inexistente o error del
  motor → **omitido y anotado**; `CompletamenteLimpio` solo es cierto si no hubo
  detecciones *ni* omitidos. Si el motor no está al empezar, **no se escanea**
  (lanza, no escribe «0 detecciones»). Si se cae a mitad (5 errores seguidos), el
  escaneo se marca **INCOMPLETO** en vez de seguir.
- **Privacidad:** el cliente solo acepta `localhost`/loopback; otro host exige
  `permitirRemoto: true` explícito. Los archivos no salen del equipo.
- **Escanear no modifica nada.** La cuarentena es otra acción, con vista previa y
  token, y se puede **restaurar** (nunca pisa un archivo existente).
- **Cuarentena:** AES-GCM, `NXQ1 | nonce | etiqueta | datos`. El cifrado **no
  oculta el contenido** (la clave va en el `.json` contiguo): existe para que
  ningún antivirus, incluido Defender, re-detecte el archivo y se pelee con Nexo.
  La integridad sí importa: antes de borrar el original se descifra la copia y se
  compara el SHA-256; si el original no se puede retirar (en uso), se deshace la
  copia. Se reverifica tamaño, fecha **y SHA-256** al aplicar (TOCTOU).
- **No mueve archivos del directorio de Windows:** una detección ahí es un
  incidente a revisar a mano. Los ids de restauración se validan (32 hex) antes de
  formar ninguna ruta.
- El arnés usa una **cadena marcadora propia**, no el EICAR, para no dejar en el
  disco archivos que Defender quiera poner en cuarentena.

Se comprobó que las pruebas tienen dientes: rompiendo a propósito la regla
«error del motor ≠ limpio», fallan 3 comprobaciones.

**NO probado — requiere una VM con ClamAV real:**

- Contra un `clamd` de verdad: versión del protocolo, `StreamMaxLength` real,
  comportamiento con la base de firmas completa y rendimiento en miles de archivos.
- Que Defender no re-detecte el archivo cuarentenado (esperado por el cifrado).
- Dónde queda la cuarentena: hoy `%LOCALAPPDATA%\Nexo\Quarantine`, sin ACL propia.
  La definitiva sería `%ProgramData%\Nexo\Quarantine` con ACL (cuando exista el servicio).

**Huecos conocidos (sin hacer):**

- **YARA** (heurística) no está; el escaneo es solo por firmas de ClamAV.
- ~~Sin tiempo real~~ Hecho (2026-10-22, ver §2g). Siguen sin AMSI ni escaneo programado.
- ~~La cuarentena no purga~~ Hecho (2026-10-22): `nexo-scan cuarentena purgar` elimina lo que superó los 30 días, con vista previa, token y confirmación `PURGAR`. Es manual: nada la ejecuta sola hasta que exista el servicio.
- Sin exclusión mutua con Defender (añadir la carpeta de cuarentena a sus exclusiones).
- ~~Escaneo secuencial~~ Hecho (2026-10-22): `--paralelo N` (1-8) analiza N archivos a la vez, una conexión por archivo. No usa `IDSESSION`. Medido con clamd real (2026-11-02, §2j): compensa; **por omisión 4 desde entonces** (`OpcionesDeEscaneo.ParalelismoPorDefecto`, también en el servicio).
- Archivos > 25 MB no se analizan (quedan como omitidos): ISOs, VMs, instaladores grandes.
- Los archivos comprimidos los abre `clamd`; no hay control de límites de recursión.

---

## 2f. Servicio y canal IPC (2026-10-22)

Base de todo lo que falta (tiempo real, escaneo programado, cuarentena con ACL en
`%ProgramData%`): la Fase 0 de la Salida 0 sin la bandeja.

- `Nexo.Ipc` (`net8.0-windows`): tramas con longitud (4 bytes LE, máx. 1 MiB), JSON
  estilo JSON-RPC, `ServidorDePipe` y `ClienteDePipe`.
- `Nexo.Service`: `Worker` que levanta el vault y el pipe `NexoIpc`, deja notas
  `servicio-iniciado` y `servicio-detenido`, y para en < 4 s. El mismo `.exe` corre como
  servicio o en consola (`AddWindowsService`).
- `src\Nexo.Service\Install\nexo-service.ps1` (instalar / desinstalar / estado). **No se ha
  ejecutado nunca**: solo se comprobó su sintaxis.

**Decisiones de seguridad:**

- **ACL del pipe:** SYSTEM, Administradores y la cuenta del propio servicio con control
  total; el usuario interactivo solo lectura y escritura —**sin** crear instancias del
  pipe ni cambiar permisos, para que nadie suplante al servicio—; red denegada; ni
  Everyone ni Usuarios autenticados.
- **El servidor no confía en lo que llega:** tamaño acotado (un tamaño enorme, cero o
  negativo cierra la conexión sin reservar memoria), JSON y UTF-8 validados, 16
  conexiones como máximo, cierre por inactividad (30 s), tiempo máximo por petición, y
  una excepción del manejador se devuelve como «error interno» **sin** su mensaje.
- **Métodos expuestos (22):** `limpieza.reglas|previsualizar|aplicar` (ver §2h); `ping`, `estado`; `tiempo-real.estado|detecciones` (solo lectura); `firewall.estado|previsualizar|aplicar`;
  `escaneo.estado|iniciar|progreso|resultado|cancelar`; y `cuarentena.listar`,
  `previsualizar`/`aplicar`, `previsualizar-restauracion`/`restaurar`,
  `previsualizar-purga`/`purgar`. Ninguna otra acción que borre o cambie el sistema existe
  (una prueba lo comprueba); cada una nueva debe llegar con su vista previa y su token.
- **Escaneo = trabajo en segundo plano** (dura más que el límite por petición): `iniciar`
  devuelve un id; un solo escaneo a la vez; hasta 8 rutas con letra de unidad (nada de red,
  `\\...`, comodines ni `..`); se avisa YA si no hay motor.
- **La cuarentena solo mueve lo que detectó un escaneo del propio servicio**, nombrado por
  su id. El cliente **no puede pasar una ruta suya** (si pudiera, tendría a SYSTEM
  retirando cualquier archivo del equipo); una prueba lo comprueba y, al desactivar la
  guardia, falla. Restaurar es solo a la ruta original, sin parámetro `destino` (sería
  escribir como SYSTEM donde diga el cliente) y nunca pisa un archivo. La carpeta
  `%ProgramData%\Nexo\Quarantine` guarda la clave junto al archivo: debe ser escribible solo
  por SYSTEM y Administradores (la ACL que fija el script sobre `%ProgramData%\Nexo`); si un
  usuario normal pudiera escribir ahí, fabricaría una entrada y haría que «restaurar»
  escribiera donde quisiera.
- **El servicio actúa con la identidad del llamador, no como SYSTEM (2026-10-22):** antes el
  escaneo leía con la cuenta del servicio, así que quien llamaba podía saber si una ruta que
  no podía leer tenía una detección; y la cuarentena habría borrado como SYSTEM lo que al
  usuario no le dejan borrar. Ahora `ContextoDeLlamada` (`Nexo.Ipc`) captura quién llamó
  (SID y nivel de suplantación que concedió) tras el primer mensaje de cada conexión
  (Windows no deja suplantar antes), y cada operación de archivos —recorrer, consultar,
  abrir, retirar el original, restaurar— pasa por `IAccesoAArchivos` y se ejecuta con
  `WindowsIdentity.RunImpersonated`. El acceso se comprueba al **abrir**; leer después no lo
  repite. Un escaneo largo usa una **copia** del contexto que sobrevive a la conexión.
  **Falla cerrado:** si el cliente conectó con nivel `Identification` (el servicio sabe quién
  es pero no puede usar sus permisos) o no se pudo identificar, el escaneo, la cuarentena
  y la restauración se **rechazan** con un error claro; nunca se recurre a SYSTEM «por si
  acaso». Esa comprobación va **antes** de gastar el token, así que se puede reintentar.
  `ClienteDePipe` conecta por omisión con `Impersonation`: es seguro porque solo SYSTEM y
  Administradores pueden crear el pipe (un servidor falso no puede suplantar al servicio).
  Resultado: solo se puede escanear lo que ese usuario podría leer, poner en cuarentena lo
  que podría leer **y borrar**, y restaurar donde podría escribir.
  **Matiz:** `firewall.previsualizar` comprueba con `File.Exists` (como SYSTEM) que la ruta
  del `.exe` existe, lo que revela si un archivo existe; es el único resto y es mínimo.
  **Sin probar con un usuario distinto del servicio:** los arneses corren servicio y cliente
  como el mismo usuario, así que no pueden *mostrar* la diferencia entre actuar como SYSTEM
  y como el llamador. Lo que sí prueban es que **todas** las operaciones pasan por el acceso
  del llamador (accesos falsos que cuentan, deniegan o fallan), el fallo cerrado, y que la
  suplantación real funciona y sobrevive a la conexión. La prueba definitiva es en la VM:
  servicio como SYSTEM, cliente como usuario normal, un archivo que solo SYSTEM pueda leer.
- **Token de confirmación (`PlanesPendientes`):** el plan vive en el servicio; el cliente
  solo recibe un token aleatorio de 256 bits y pide aplicar **ese** plan, así que no
  puede cambiar lo que se aplica entre la vista previa y la confirmación (los parámetros
  extra de `firewall.aplicar` se ignoran). Es de **un solo uso** (se consume aunque la
  aplicación falle), caduca a los 10 min y hay un máximo de 32 pendientes. Las guardias
  de siempre (procesos protegidos, rutas, grupo de Nexo) siguen mandando. Un token falso,
  ya usado o caducado da el mismo error, sin pistas.
- **Límite que hay que tener presente:** el token prueba que quien aplica tiene el plan
  previsualizado, **no que una persona lo aprobó**. Un proceso malicioso que corra como
  el mismo usuario puede pedir la vista previa y aplicarla. Lo acota lo que un plan puede
  llegar a hacer (no bloquea procesos del sistema ni Defender, solo toca reglas del grupo
  «Nexo Security Suite», todo es reversible y queda en una nota), no el token. Impedirlo
  de verdad exigiría una aprobación fuera de banda (p. ej. un aviso UAC o una ventana del
  servicio): ya existe, ver §2i (aplicar exige UAC por omision).
- El script de instalación se niega si la carpeta del `.exe` admite escritura a usuarios
  normales (sería una escalada a SYSTEM) y restringe el vault a SYSTEM y Administradores.

**NO probado:** instalarlo como servicio y arrancarlo con el SCM (LocalSystem), el
reinicio automático tras una caída, y la ACL contra un cliente de **otro** usuario. Todo
eso es para la VM `NexoVM` (snapshot `limpia`): `dotnet publish src\Nexo.Service -c
Release -o "C:\Program Files\Nexo\service"` y `nexo-service.ps1 -Accion instalar`.

**Huecos conocidos:** la limpieza aún no está cargada en el servicio; el escaneo se probó
con un motor falso por DI (no con `clamd` real); `IModuloDelServicio` es una versión mínima de `INexoModule` (sin
`StartAsync`/`StopAsync` ni `EventBus`); el camino de
aplicar **como administrador** solo está probado contra un almacén en memoria (el arnés
corre sin elevar); y el vault por defecto del servicio es `%ProgramData%\Nexo\Vault` mientras que las
herramientas de consola usan `%LOCALAPPDATA%\Nexo\Vault`.

---

## 2g. Análisis en tiempo real (2026-10-22)

`Nexo.Modules.Threats/TiempoReal` (portable) + `Nexo.Service/ModuloTiempoReal`.

**Qué es y qué NO es:** detecta y **avisa después** de que el archivo se escribió. **No
puede impedir** que se cree ni que se ejecute: eso exigiría el driver de minifiltro (fuera
de alcance). Complementa a Defender, que sí bloquea. El estado del servicio lo repite en
cada respuesta (`nota`).

- **`VigilanteEnTiempoReal`:** recibe cambios de una `IFuenteDeCambios`, filtra por extensión
  (ejecutables, scripts, instaladores, macros) y carpetas excluidas, **espera a que el archivo
  deje de cambiar** (1,5 s) antes de analizarlo, no reanaliza lo que no cambió, reintenta los
  bloqueados (con espera creciente) y solo detecta: **no toca los archivos**. Deja una nota por
  detección y ninguna por archivo analizado (no llena el vault).
- **Cobertura honesta:** lo que no se pudo analizar (bloqueado tras los reintentos, sobre el
  límite, sin permiso, el motor no decidió) cuenta como **no analizado**; lo que se descarta
  por desborde o lo que la fuente dice haber perdido, como **perdido**; tras 5 fallos seguidos
  se declara **motor caído**. `tiempo-real.estado` solo da `cobertura_completa: true` si no hay
  nada de eso ni fuentes no vigiladas. Una prueba lo comprueba con cada causa.
- **Fuentes:** `FuenteFileSystemWatcher` (sin administrador; buffer finito, puede perder
  eventos y lo avisa) y `FuenteUsn` (diario NTFS; administrador o SYSTEM; entrega el evento al
  **cerrar** el archivo, no tiene buffer que se desborde y detecta si el diario sobrescribió lo
  pendiente). Se elige con `Nexo:TiempoReal:Fuente` (`watcher` por omisión, o `usn`).
- **Se excluye a sí mismo:** la carpeta de cuarentena y el vault nunca se analizan (evita el
  bucle de Nexo escaneando lo que Nexo escribe).
- **Apagado por omisión** (`Nexo:TiempoReal:Activo`, en `appsettings.json`). **No hay métodos
  para encenderlo, apagarlo ni cambiar sus carpetas por el pipe**: un proceso malicioso los
  usaría para quitar la protección. Solo se leen `tiempo-real.estado` y `tiempo-real.detecciones`.
  Apagado, el servicio lo dice (`activo: false`), no calla.
- **A cuarentena** con el flujo de siempre (vista previa + token) usando el id de escaneo
  `tiempo-real`; sigue sin poder pedirse un archivo que el vigilante no detectó.
- **Parser del diario USN** (`ParserDeUsn`, portable): defensivo porque el buffer viene del
  sistema y el nombre de un archivo lo controla cualquiera. Longitud 0 o desalineada,
  desplazamientos fuera del registro, nombres enormes o de longitud impar detienen la lectura
  como «corrupto» en vez de seguir a ciegas; 2000 buffers aleatorios no lo hacen lanzar.

**Probado como administrador (2026-10-22, equipo principal HP, Windows 10):** la lectura real del
diario USN (`Nexo.Native/Usn/VolumenUsn` + `FuenteUsn`). `Nexo.Service.Demo` (sección 8), ejecutado
elevado, abre el volumen con el diario activo, recibe por el diario un archivo recién creado con su
ruta completa (`OpenFileById`) y no emite lo que cambia fuera de las carpetas pedidas. Sin
administrador la fuente se **niega con claridad** y no emite nada.

**Todavía SIN PROBAR — hacerlo en la VM `NexoVM`:**

- **El camino de error del diario:** el reintento tras el error 1181 (el diario sobrescribió lo
  pendiente) y el comportamiento con mucha actividad. La prueba de hoy cubre el caso normal, no
  la sobrecarga.
- **Rendimiento y ruido con `clamd` real** en carpetas con mucha actividad (Descargas, Temp), y
  **que Defender y Nexo no se estorben** al leer el mismo archivo recién escrito.
- Los valores por defecto (1,5 s de estabilización, 2 trabajadores, 5000 pendientes) son
  estimaciones, no medidas.

**Huecos conocidos:** sin acción automática (solo avisa; poner en cuarentena exige confirmar),
sin notificación en la bandeja (el evento `Detectado` existe, nadie lo escucha aún), sin
análisis de comportamiento (ETW), y el diario USN es por volumen: solo NTFS.

**Bajo carga con `clamd` real (Linux, 2026-11-02).** `VigilanteEnTiempoReal` + `FuenteFileSystemWatcher` (inotify)
+ ClamAV 1.5.4 en Docker, valores por defecto, con un arnés de un solo uso fuera del repo. **No cubre el diario USN
ni Windows.**

| Ráfaga | Resultado |
|---|---|
| 511 `.exe` (11 EICAR) + 170 `.txt` | 11/11 detectados, 0 falsos positivos, 0 perdidos, 12 s. Un EICAR escrito en dos mitades separadas por 1 s se detecta: la estabilización espera. Cuadra: 511 de 511. |
| 6021 `.exe` (21 EICAR) | Pasa de 5000 pendientes: aviso «demasiados archivos pendientes», **3 EICAR sin ver**, 0 falsos positivos, 53 s. |
| 2011 `.exe`, clamd parado a 0,5 s | `MotorCaido`, 1882 «no analizados», nada dado por limpio. Cuadra: 2011 de 2011. |

**Hallazgos (corregidos el 2026-11-02, desde Linux):**
- ~~`Perdidos` cuenta eventos, no archivos~~. Ahora son **archivos distintos** descartados y no analizados después
  (con tope de 100 000; `PerdidosEsMinimo` si se pasa). Un desborde de la fuente va en `DesbordesDeFuente`, sin
  número de archivos. Repetido con clamd real: 6021 archivos → 5004 analizados + **1017 perdidos = 6021** (antes
  2577). La bandeja ya no muestra «N sin vigilar»: dice «N carpetas por revisar» o solo «cobertura incompleta».
- ~~Lo perdido no se vuelve a mirar~~. La carpeta de todo lo perdido o no analizado queda **por revisar**
  (`VigilanteEnTiempoReal.CarpetasPorRevisar`; tras un desborde de la fuente, todas las raíces). El servicio la
  expone en `tiempo-real.estado` (`por_revisar`) y `cobertura_completa` pasa a depender de ella (los contadores
  quedan como histórico). La bandeja **ofrece** «Revisar lo que no se vio (N carpetas)…»: lanza `escaneo.iniciar`
  (solo lee; hasta 8 rutas, sin subcarpetas repetidas) y avisa del resultado sin decir «limpio» si algo no se
  analizó. Cuando un escaneo **completo** termina, `ModuloEscaneo.EscaneoCompleto` → `ModuloTiempoReal` da por
  revisado lo que cubrió, **salvo** las carpetas que no pudo leer (`ResultadoDeEscaneo.CarpetasNoLeidas`, nuevo) y
  lo que se perdió después de empezar. Un archivo > 25 MB no queda por revisar (el escaneo tiene el mismo límite).
  Con clamd real: la revisión encontró **los 3 EICAR** que el tiempo real no vio, y luego no quedó nada por revisar.
- Pruebas: +11 en `Nexo.RealTime.Demo` (dos comprobadas quitando el arreglo), +1 en `Nexo.Scan.Demo`. La lógica
  nueva de la bandeja (texto, `RutasParaRevisar`, `ResumirRevision`) se ejecutó en Linux compilando esos archivos
  aparte. **SIN EJECUTAR (solo Windows):** +3 en `Nexo.Tray.Demo`, la prueba cambiada y +1 en `Nexo.Service.Demo`
  (desborde → escaneo → cobertura completa), y el menú de la bandeja de verdad.
- **Recuperación tras `MotorCaido` (probado con clamd real, 2026-11-02):** clamd parado → `MotorCaido` y los 8
  archivos escritos mientras tanto, incluido un EICAR, quedan «no analizados» y su carpeta por revisar. Al volver
  clamd, el siguiente archivo (otro EICAR) se detecta y `MotorCaido` vuelve a false; la revisión de la carpeta
  pendiente encuentra el EICAR que no se vio y la deja limpia. ~~Hallazgo menor: `MotorCaido` no se
  borraba hasta que llegaba un archivo nuevo~~. Corregido (2026-11-02): con el motor caído, el vigilante le pregunta
  (`VersionAsync`) cada `ComprobarMotorCada` (30 s por omisión) y deja de estar caído en cuanto responde; lo no
  analizado mientras tanto **sigue por revisar**. Con clamd real se recuperó solo, sin archivos nuevos. +4 en
  `Nexo.RealTime.Demo` (comprobada quitando el arreglo).

---

## 2h. Limpieza en el servicio (2026-10-22)

`Nexo.Service/ModuloLimpieza`: `limpieza.reglas`, `limpieza.previsualizar`, `limpieza.aplicar`.
Es la limpieza de archivos basura (la de siempre: vista previa + token). **No** expone todavía
el triturador, los duplicados, el inicio ni S.M.A.R.T.

- **Con la identidad y el perfil del llamador.** El servicio corre como SYSTEM; si limpiara con su
  cuenta, `%LOCALAPPDATA%` sería el de SYSTEM y borraría otra cosa (o lo que al usuario no le dejan).
  La vista previa y el borrado corren suplantando al llamador con `RunImpersonatedAsync`
  (`ContextoDeLlamada.EjecutarAsync`), que **mantiene la suplantación a través de los `await`**
  (probado: tras un `await` y un cambio de hilo se sigue suplantando). Las carpetas base se sacan
  del **perfil del SID del llamador** (`PerfilDeUsuario`, lista de perfiles del registro), no del
  entorno del servicio. Limite: se usan las subcarpetas estándar; no se siguen carpetas redirigidas.
  Sin identidad utilizable o sin perfil, se rechaza (nunca como SYSTEM).
- **Las notas se escriben con la identidad del servicio** (`ReportesFueraDeSuplantacion`), no con la
  del usuario, que no tiene permiso sobre el vault. Está probado que dentro de la suplantación la
  escritura se hace *sin* suplantar y que luego se vuelve a suplantar.
- **El cliente elige reglas del catálogo por id, nunca rutas.** Un id desconocido, una ruta, `..`,
  una lista vacía o de más de 64, o uno enorme se rechazan. Por omisión solo entran las de riesgo
  bajo; las de riesgo medio/alto solo si se piden por su id. Las que exigen administrador se saltan
  si el **token del llamador** no lo es (un administrador con UAC y token filtrado cuenta como no
  administrador) y se informa.
- **Se borra exactamente lo previsualizado:** el plan vive en el servicio y el cliente solo devuelve
  un token de un solo uso. Probado: un archivo que aparece después de la vista previa **no** se borra
  y uno que cambia de tamaño se omite. **Un plan solo lo puede aplicar quien lo previsualizó** (mismo
  SID); otro usuario recibe el mismo error que con un token falso.
- **Modo de borrado por configuración** (`Nexo:Limpieza:Modo`), no por el cliente: `papelera` (por
  omisión, reversible), `simulado`, o `real` **solo** en una VM y con `NEXO_PERMITIR_BORRADO_REAL=1`
  (la regla de la herramienta de consola); si se pide `real` y no se cumple, usa la Papelera y lo
  anota en la nota de arranque.

**SIN PROBAR:**

- **La Papelera desde el servicio.** `BorradorPapelera` usa `SHFileOperation` (API del shell); se ha
  probado en una sesión de usuario, **no** desde un servicio suplantando a un usuario. Si no
  funcionara, hay que verlo antes de confiar en que el borrado sea reversible (el servicio dice
  `reversible` en cada respuesta).
- **Que actuar «como el llamador» difiera de actuar como el servicio** (los arneses corren los dos
  con el mismo usuario), y el perfil por SID en un equipo con varios usuarios o con perfil en red.

---

## 2i. Bandeja y aprobación fuera de banda (2026-10-22)

**Aprobación con UAC (`PoliticaDeAprobacion`, `Nexo:Aprobacion:Modo`).** Cierra el límite del token
(que no prueba que una *persona* aprobó): con el modo `elevada` —**el de por omisión**; una errata
en la configuración también cuenta como `elevada`— *aplicar* (firewall, cuarentena, restauración,
purga, limpieza) exige que el llamador tenga un **token elevado**, es decir, que alguien aceptó un
aviso de UAC, que sale en el escritorio seguro y un proceso normal del usuario no puede pulsar ni
simular. Previsualizar y leer no lo piden. Se comprueba **antes** de gastar el token, así que el plan
sigue vigente. `ninguna` es una decisión explícita y deja un aviso en la nota de arranque.
Límites: no protege frente a un proceso que ya esté elevado; y con un usuario *estándar* UAC pide las
credenciales de **otro** usuario, cuyo SID no es el del dueño del plan, así que el plan se rechaza
(para esos usuarios hace falta otro diseño).

**Bandeja (`Nexo.Ui.Tray`, `nexo-tray.exe`, WinForms `NotifyIcon`).**

- **Núcleo sin pantalla** (`Nucleo/`): `ConsultorDelServicio` (solo lectura: ping, estado y
  detecciones del tiempo real), `ModeloDeBandeja` (máquina de estados), `AccionesDelServicio`
  (previsualizar y aplicar). El icono y los diálogos son una capa fina encima.
- **Estados:** gris *desconectado*; verde *normal*; ámbar *atención* (tiempo real apagado, motor caído,
  cobertura incompleta, o detecciones revisadas pero sin resolver); rojo *alerta* (detecciones sin
  revisar). **Nunca dice «todo en orden» si no lo sabe.** Una detección manda sobre cualquier otra
  cosa; cada detección se notifica **una sola vez** (la misma ruta con otro contenido es otra).
- **Menú:** estado; revisar detecciones (lista, y si el usuario acepta prepara el plan de cuarentena);
  limpiar archivos basura; salir. Un aviso de globo por cada detección nueva.
- **Muestra el plan que preparó el servicio**, no uno propio: el plan y su token viven en el servicio.
  Al aplicar, prueba por el camino normal; si el servicio contesta «hace falta aprobación», abre
  **este mismo ejecutable elevado** (`--aplicar <tipo> <token>`, aviso de UAC) con el **mismo token**.
  El token se valida (64 hexadecimales) antes de ir a la línea de comandos. El token es visible en la
  línea de comandos para otros procesos del usuario; no les sirve sin elevación.
- **Solo eleva desde una ubicación que el usuario no pueda modificar** (`UbicacionSegura`): la bandeja se
  relanza elevada a sí misma, y si un proceso normal pudiera sustituir ese `.exe`, el aviso de UAC diría
  «Nexo» y ejecutaría con permisos de administrador lo que otro hubiera puesto. Se niega si el archivo o su
  carpeta permiten escribir, borrar o cambiar permisos al usuario o a sus grupos (salvo Administradores,
  SYSTEM y TrustedInstaller), y si no puede comprobarlo asume que **no** es seguro. Consecuencia: ejecutada
  desde la carpeta de compilación (del usuario) **no puede aprobar**; hay que instalarla en Program Files. El
  instalador aplica la misma regla. Probado: un `.exe` del usuario no es seguro, uno de System32 o de
  Program Files sí, y el lanzador se niega sin abrir ningún UAC.
- **Una sola bandeja** (mutex); `--una-vez --salida f.json` hace una consulta y escribe el estado (lo
  usa el arnés para comprobar el cableado real).

**Probado** (`Nexo.Tray.Demo`, 33): el modelo, la consulta contra el servicio real en cada estado
(sin servicio, tiempo real apagado, encendido, con una amenaza), el plan viniendo del servicio, que sin
elevar el servicio pide aprobación y la bandeja lo distingue de un fallo, que abre el proceso elevado con
el mismo token y que si se cancela el UAC no cambia nada, y el ejecutable arrancando, quedándose vivo y
sin duplicarse. Se rompió a propósito la comprobación de aprobación y falló la prueba.

**SIN PROBAR:**

- **La parte visual:** el icono, el menú, los diálogos y los avisos de globo **nunca los ha visto una
  persona** (los arneses no tienen pantalla). Revisar a mano que se ven y se entienden.
- **El camino elevado de verdad:** aceptar el UAC, que el proceso elevado se conecte (su token sigue
  siendo del mismo usuario) y aplique, y que muestre el resultado. Los arneses usan un lanzador falso.
  Si se ejecutan **como administrador** cubren la rama «elevado aplica directamente».
- **El instalador con `-Bandeja`:** `nexo-service.ps1 -Bandeja <nexo-tray.exe>` registra la bandeja en
  `HKLM\...\Run` (arranca con cada usuario) y quita la entrada al desinstalar. Solo se ha comprobado su
  **sintaxis**; nunca se ha ejecutado. También crea y restringe `%ProgramData%\Nexo` (vault y cuarentena).

---

## 2j. Prueba del servicio en la VM, y la VM ya no existe (2026-11-01)

El guion `GUION-PRUEBA-VM.md` se ejecutó en `NexoVM` (Acer, Windows 10 22H2). **La VM, su snapshot
`limpia` y el ISO se borraron al terminar** (el equipo principal es el HP; el Acer ya no se usa). El
código y los scripts del montaje están en git (`tools/vm`, con su `README.md`); la VM, no. Si hay que
repetir algo, hay que montarla de nuevo (resumen y trampas en `tools/vm/README.md`).

**Anotado como hecho** (tabla de resultados del guion, commit `61f06f9`):

| Pasos | Resultado | Detalle |
|---|---|---|
| 1.3 | Hallazgo corregido | `nexo-service.ps1` comparaba por **nombre** de grupo y en Windows en español no reconocía «Usuarios autentificados», así que no se negaba a instalar desde una carpeta modificable. Ahora compara por **SID**. |
| 4.1–4.4 | OK | La bandeja se ve: icono ámbar «tiempo real apagado» al conectar, gris «sin conexión» con el servicio parado, y vuelve a conectado sin reiniciarla. Sin problemas visuales. |
| 5.1–5.8 | OK (5.7 NOTA) | Tiempo real detecta (icono rojo y aviso); el plan no mueve nada; el UAC sale con credenciales del administrador («editor desconocido»: el `.exe` no está firmado); aceptar pone el archivo en cuarentena; cancelar no cambia nada; restaurar funciona; desde una ubicación no segura se niega sin UAC. |

- **5.7:** con un usuario estándar el plan **sí se aplicó** aunque el UAC corre con el SID del
  administrador. Coincide con el cambio `6aab183` (otro administrador puede aprobar el plan de otro
  usuario y se ejecuta como el dueño), pero la tabla lo dejó como «pendiente de entender por qué»: no
  está comprobado que sea exactamente por eso.
- **La bandeja no escanea ni restaura.** Su menú «detecciones» solo muestra lo del tiempo real, que está
  apagado por omisión. Restaurar se hace con `nexo-rpc` desde una consola elevada.
- Con esto quedan **probados** (antes figuraban «SIN PROBAR» en §2i): la parte visual de la bandeja y el
  camino elevado real con UAC.

**Sin resultado anotado** (el guion y los scripts existen, pero la tabla quedó vacía; **no se sabe si se
ejecutaron, así que se tratan como sin probar**): 1.1, 1.2, 2.1–2.3, 3.1–3.2, **6.1–6.3** (limpieza y
Papelera desde el servicio), **7.1–7.2** (diario USN bajo carga), además de 9 (desinstalar).

**Vault aceptado en Obsidian (Linux, 2026-11-02):** el usuario revisó 10 puntos (propiedades, callouts, wikilinks,
vínculos entrantes, nota diaria, búsquedas, títulos con salto de línea) y todo está bien. Ver Salida 5 §6.

**8.1–8.3 (ClamAV real), hecho en Linux el 2026-11-02** con `nexo-scan` contra ClamAV 1.5.4 en Docker
(`docker run -d --name nexo-clamd -p 127.0.0.1:3310:3310 clamav/clamav:1.5.4`; listo en ~20 s). Detalle en la
tabla del guion. Lo importante:
- El protocolo INSTREAM real funciona: EICAR detectado, también dentro de 5 zips anidados; el límite de 25 MB se
  respeta y se anota. Parar clamd a mitad da «ESCANEO INCOMPLETO», nunca «limpio»; sin motor, código 2.
- **Hallazgo (corregido):** un nombre de archivo con salto de línea (Linux siempre; NTFS por la API nativa)
  metía un encabezado falso en la nota (`# Titulo falso`), partía la consola y podía **añadir líneas falsas al
  plan de cuarentena que el usuario confirma**. Ahora `Nexo.Reports.Model.TextoVisible.UnaLinea` escapa los
  caracteres de control (se ven como `\n`): en el título de toda nota (`NexoEvent`), en los `Describir()` de
  cuarentena, purga, limpieza, triturador y firewall, y en la consola de `nexo-scan`. +2 en
  `Nexo.Reports.Demo` y +1 en `Nexo.Scan.Demo`, comprobadas quitando el arreglo.
- **Nota (corregida):** con el escaneo cortado, el resumen decía «NO analizados: 5» sin aclarar que lo que
  faltaba ni se intentó. Ahora lo dice; el código de salida sigue siendo 10 si hubo detecciones.
- **Rendimiento (4 núcleos, 1017 binarios, en frío):** `--paralelo 1` 38,9 s, `4` 8,5 s (4,6× más rápido),
  `8` 8,2 s. El valor por omisión era el peor: **ahora es 4** (en `nexo-scan` y en `escaneo.iniciar` del servicio). Ojo al medir:
  clamd cachea los limpios (la segunda pasada tardó 4,6 s), hay que cambiar los archivos para medir en frío.
- **Sin probar:** convivencia con Defender y el escaneo por el servicio (pipe) en Windows.

**Hallazgo en el HP (2026-11-02, corregido):** con `Nexo:Limpieza:Modo = simulado`, `limpieza.reglas` informaba
`"modo":"papelera"`, porque el modo se deducía solo de `EsReversible` y el simulador también es reversible (no borra
nada). Ahora informa `"simulado"`. Prueba de regresión en `Nexo.Service.Demo` (+3); falla si se quita el arreglo.

**Pendiente:**

- `tools/Nexo.Ipc.Cli` (`nexo-rpc`) reescribe el cliente del pipe cuyo código se perdió. Compila con 0/0
  pero **en el Acer no se pudo ejecutar** (bloqueaba el `.dll` recién compilado). En el HP
  (2026-11-02) compila y arranca, y sin servicio dice «El servicio no esta escuchando en el pipe
  'NexoIpc'». **Falta probarlo contra un servicio de verdad** (llamada y flujo previsualizar/aplicar).
- Todo lo de «Sin resultado anotado» necesita volver a montar una VM. Hasta entonces, §2e–§2h siguen con
  sus avisos de «NO probado».

---

## 3. Lo que necesita el otro equipo

### 3.1 Comprobar si hace falta la BIOS

Administrador de tareas (`Ctrl+Shift+Esc`) → *Rendimiento* → *CPU* → campo
**Virtualización**.

- *Habilitada*: no hace falta entrar a la BIOS.
- *Deshabilitada*: entra a la BIOS **una sola vez**, activa «Intel Virtualization
  Technology» (o «SVM Mode» en AMD), guarda y reinicia.

### 3.2 Montar la VM

Requisitos mínimos: 8 GB de RAM (4 GB para la VM), unos 40 GB libres.

| Edición de Windows del anfitrión | Hipervisor |
|---|---|
| Pro / Enterprise | Hyper-V: `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All` |
| Home | VirtualBox: `winget install Oracle.VirtualBox` |

1. Descarga el ISO de **Windows 10** desde microsoft.com/software-download/windows10
   (Windows 10 y no 11: no exige TPM ni Secure Boot, y para estas pruebas es
   equivalente).
2. Crea la VM: 4 GB de RAM, 2 núcleos, disco dinámico de 40 GB, red NAT.
3. Instala Windows. **Haz un snapshot llamado `limpia`** antes de instalar nada más.
4. Dentro de la VM: `winget install Git.Git Microsoft.DotNet.SDK.8 GitHub.cli`,
   luego `gh auth login`, y clona este repositorio.

### 3.3 Qué ejecutar dentro de la VM

Abre PowerShell **como administrador** (así se ejercitan las rutas que piden
permisos que el equipo principal no pudo probar).

```powershell
dotnet build NexoAntivirus.sln
dotnet run --project tools\Nexo.Cleanup.Demo
dotnet run --project tools\Nexo.Cleanup.Windows.Demo
```

Los dos deben terminar con `TODAS LAS VERIFICACIONES PASARON`. Fíjate en que, siendo
administrador, el arnés de Windows debe escribir en `HKLM` (en una subclave
temporal que borra al final).

Después, el limpiador contra el perfil de la VM:

```powershell
# 1. Simulado, tres veces seguidas. Compara las listas: deben ser casi iguales.
dotnet run --project tools\Nexo.Cleanup.Run
dotnet run --project tools\Nexo.Cleanup.Run
dotnet run --project tools\Nexo.Cleanup.Run

# 2. Cuando la lista sea la esperada: Papelera (reversible, pide escribir BORRAR)
dotnet run --project tools\Nexo.Cleanup.Run -- --modo papelera

# 3. Solo en la VM: borrado permanente
$env:NEXO_PERMITIR_BORRADO_REAL = "1"
dotnet run --project tools\Nexo.Cleanup.Run -- --modo real
```

La lista completa de cada corrida queda en `%LOCALAPPDATA%\Nexo\Vault\lista-*.txt`.
**Contiene rutas completas del equipo: no la subas a git.** Si algo sale mal, vuelve
al snapshot `limpia`.

**No hace falta poblar `C:\TestCorpus`** (el plan original lo pedía): los arneses
generan su propio corpus sintético en `%TEMP%`. Un perfil recién instalado tiene
poco que limpiar, así que si quieres una lista más interesante, abre Edge y
navega un rato antes de la prueba.

### 3.4 Qué NO se puede probar en la VM

- **S.M.A.R.T. con datos reales.** Los discos virtuales no exponen S.M.A.R.T.; el
  arnés debe mostrar «sin datos suficientes» (y eso también es una prueba valiosa).
  La prueba real se hace en el equipo físico, con administrador.

---

## 4. Lo que queda pendiente en el equipo principal

No necesita VM, solo permisos:

- Correr `dotnet run --project tools\Nexo.Cleanup.Windows.Demo` **como
  administrador**, para ver S.M.A.R.T. con datos reales (el NVMe, el SATA y el USB)
  y la escritura en `HKLM`. El intento de esta sesión se canceló en el aviso de UAC.
- Enlaces simbólicos de archivo: requieren activar el modo desarrollador de Windows.

> Ambos puntos se cubrieron en el segundo equipo (§2b), pero solo con un NVMe.
>
> **Hecho en el principal (2026-10-21, como administrador):** 29/29. Escribe en
> `HKLM`. Tipo de disco: C: = SSD, D: y E: = HDD. S.M.A.R.T.:
> - NVMe GIGABYTE: 40 °C, desgaste 0 %; sin atributos ATA, con el motivo (Info).
> - **SATA ST1000LM035 (18 269 h): 23 atributos ATA reales. Evaluación «Alta»:
>   atributo 187 (errores incorregibles reportados) = 90.** Primera lectura ATA
>   real del proyecto; el evaluador y el historial funcionan con ella. El
>   disco está dando señales de fallo: conviene respaldar lo importante.
> - Puente USB: sin comandos S.M.A.R.T. (limitación declarada, Info).
> - El historial guardó 1 de 3 discos (el único con atributos), como debe ser.

---

## 5. Cómo se mueve el trabajo entre equipos

El código viaja por git; las máquinas no comparten nada más.

1. Se desarrolla en el equipo principal (o en Linux) y se hace `git push`.
2. En la VM se hace `git pull`, se corren las pruebas y, si algo falla, se anota.
3. Un hallazgo nuevo se **anota antes de arreglarlo**, se arregla en el principal y
   se vuelve a empujar.

---

## 6. Huecos conocidos (no son bugs, están sin hacer)

- **Triturador y enlaces duros:** si el archivo tiene otros nombres (hard links), el
  truncado destruye el contenido para todos. .NET no expone el número de enlaces.
- ~~**Impacto de arranque** (§1.4): los eventos 100/101 no se leen aún.~~ Hecho (2026-11-02, desde Linux):
  `nexo-cleanup arranque [--dias N]`, solo lee `Microsoft-Windows-Diagnostics-Performance/Operational`.
  - Portable (`Inicio/`): `ParserDeEventoDeArranque` (100 = arranque con `BootTime`, `MainPathBootTime`,
    `BootPostBootTime`, `BootNumStartupApps`, `BootIsDegradation`; 101/102/103 = aplicación/controlador/servicio
    con `Name`, `FriendlyName`, `TotalTime`, `DegradationTime`; mismas defensas que el 5157, tiempos de 0 a 24 h)
    y `AnalizadorDeArranque` (mediana, agrupa por tipo + nombre, `ImpactoDe(entrada)` cruza una entrada de
    inicio con su `.exe`). Windows: `FuenteDeArranqueWindows` (`EventLogReader`; paquete
    `System.Diagnostics.EventLog` 8.0.1 en `Nexo.Modules.Cleanup.Windows`).
  - **Honestidad:** «nada lo retrasó» solo si se leyó, hay al menos un arranque medido (sin el servicio DPS
    Windows no escribe nada), nada truncado ni descartado. Una entrada de inicio sin evento 101 es «sin datos»,
    no «no pesa»: el 101 se escribe cuando algo tarda **más de lo habitual**, no por pesar mucho. Un `.lnk` o un
    script no se cruzan (no se adivina el ejecutable).
  - +33 portables (`Nexo.Cleanup.Demo` §5b; dos comprobadas quitando el arreglo).
  - **SIN PROBAR en Windows:** el formato real de los eventos (es el documentado, no uno observado), si el
    registro exige administrador (la Salida 4 dice que sí; no comprobado), y las +2 de
    `Nexo.Cleanup.Windows.Demo` (§2b), que solo se compilaron. Tampoco está comprobado que coincida con la
    columna «Impacto de inicio» del Administrador de tareas (que parece medir CPU y disco, no estos eventos).
- ~~**S.M.A.R.T.:** la lectura anterior no se guardaba entre ejecuciones.~~
  Hecho (2026-10-17): `Disco/HistorialDeSalud` la guarda en JSON (escritura
  atómica, serie ya redactada) y `MonitorDeSalud` la usa si se le pasa. Una
  lectura sin atributos no pisa a una anterior que sí los tenía; un archivo
  dañado se aparta como `.corrupto` y el evento dice que no se evaluó el
  crecimiento. Es **estado, no un log**: no rompe la regla de §8. Falta decidir
  la ruta definitiva cuando exista el servicio (p. ej. `%ProgramData%\Nexo`).
- **Servicios** como fuente de inicio (§1.4): no se leen (hace falta WMI, `Win32_Service`).
- ~~**Tareas programadas** como fuente de inicio~~ Hecho (2026-11-02, desde Linux), **solo lectura**:
  `nexo-cleanup tareas [--carpeta ruta]`. `LectorDeTareas` recorre `C:\Windows\System32\Tasks` (UTF-16) sin
  seguir enlaces; una carpeta o archivo sin permisos se anota como ilegible y el recorrido sigue.
  `ParserDeTareaProgramada` se queda con las de `LogonTrigger`/`BootTrigger` habilitados (sin `<Enabled>` =
  habilitado, como dice el esquema; un valor desconocido rechaza la tarea), sus comandos `Exec`, si tienen
  acciones COM, si están ocultas, el usuario, `HighestAvailable` y el retraso. La ruta sale del archivo, no del
  `<URI>` del XML. «Bajo \Microsoft\» es una categoría, no una garantía. El comando de cada tarea se cruza con el
  impacto de arranque (`ImpactoDeComando`).
  - **«Lista completa»** solo si no quedó nada ilegible, sin interpretar ni truncado (código de salida 2 si no).
  - +26 portables (`Nexo.Cleanup.Demo` §5c, con archivos UTF-16 reales, un enlace simbólico y `chmod 000`;
    tres comprobadas quitando el arreglo).
  - **SIN PROBAR en Windows:** que las tareas reales se entiendan todas y que como administrador no quede nada
    ilegible (+3 en `Nexo.Cleanup.Windows.Demo`, solo compiladas).
  - **Huecos:** deshabilitar tareas (haría falta la API COM del Programador de tareas) y las tareas que están en
    el registro (`TaskCache`) pero cuyo XML se borró, una técnica conocida para esconderlas.
- **§1.5 Perfiles de rendimiento** sigue en diseño. **§1.3 Desinstalar aplicaciones**
  no se construye, por recomendación de [[Salida 6 - Analisis de viabilidad del proyecto]].

---

## 7. Después de la VM

Según el plan recortado:

- ~~Pasar al firewall por aplicación de `Prompt 1`~~ Hecho: ver §2d. (No hizo
  falta pegar la salida del Prompt 0 en el prompt: el contrato de la
  [[Salida 0 - Arquitectura general del sistema]] se aplicó directamente.)
- ~~Escaneo bajo demanda (`clamd`)~~ Hecho: ver §2e (falta probarlo con ClamAV
  real en una VM). Pendiente de ese paso: YARA.
- Siguiente en el orden de la Salida 0 §4: **probar con ClamAV real en la VM**
  y la integración de los módulos en `Nexo.Service` + `Nexo.Ui.Tray` (Fase 0).
- **Punto de decisión del mes 3** (§4 de la Salida 6): si para entonces no hay
  reportes y limpieza funcionando y usándose cada semana, la conclusión es recortar
  a esos dos módulos y publicarlos como una utilidad honesta y terminada.

---

## 8. Convenciones que no hay que romper

- **Ningún módulo escribe logs propios.** Publican un `NexoEvent` y `Nexo.Reports`
  decide cómo se persiste.
- **Ningún P/Invoke fuera de `Nexo.Native`.** (WMI y el registro son código
  administrado y viven en `Nexo.Modules.Cleanup.Windows`.)
- **Nada que borre sin vista previa y token.** Deshabilitar un programa de inicio
  no borra, por eso no lo necesita; triturar sí.
- **No se desactiva Windows Defender.** Nexo lo complementa.
- **«No pude leer» nunca se presenta como «está bien».**
- **Tres líneas rojas** (riesgo L9, ley 21.459): no dumpear la SAM, no hacer MITM de
  TLS, no capturar pulsaciones de teclado. Ni siquiera «para proteger».
