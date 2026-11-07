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

- **YARA** (heurística): hay un motor (`MotorYara`, §2m), pero no corre junto a ClamAV y no trae reglas propias.
- ~~Sin tiempo real~~ Hecho (2026-10-22, ver §2g). Siguen sin AMSI (el escaneo programado se hizo después, ver §2k).
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

## 2k. Escaneo programado (2026-11-04)

`ModuloEscaneoProgramado` (`src/Nexo.Service`): el servicio escanea solo unas carpetas fijas cada cierto tiempo.

- **Se activa solo en `appsettings.json`** (`Nexo:EscaneoProgramado:Activo`, `IntervaloHoras` = 24 por omisión, `Raices`; sin
  raíces usa las del tiempo real). Apagado por omisión. El pipe solo ofrece **leer**: `escaneo-programado.estado` y
  `escaneo-programado.detecciones` (con el módulo apagado también existen y dicen «no activo»). Ningún método cambia la configuración.
- **Solo detecta**: no mueve ni borra. Las detecciones llegan a cuarentena por el flujo de siempre con el id `programado`.
- **Lee con la cuenta del servicio** (no hay llamador al que suplantar). Por eso las carpetas las fija el administrador y pasan las
  mismas reglas que el pipe (`ModuloEscaneo.MotivoDeRechazo`: nada de UNC, relativas, comodines ni `..`); las rechazadas se anotan en
  la nota de arranque y, si no queda ninguna válida, se dice que NO está activo.
- **Honestidad del estado**: «limpio» solo si terminó completo y sin omitidos. Un escaneo **incompleto o fallido no cuenta como hecho**
  (no se guarda, se reintenta a la hora). `vencido` es verdadero si nunca hubo uno completo o ya pasó un intervalo. El registro está en
  `ProgramData\Nexo\escaneo-programado.json` (solo se guarda cuando terminó un escaneo completo); si no se puede leer se avisa, no se oculta.
  Si el equipo estuvo apagado y la fecha pasó, al arrancar escanea tras 2 min (no espera otro intervalo). Un registro «del futuro»
  (reloj atrasado) no pospone más de un intervalo.
- Un escaneo programado **completo** da por revisadas las carpetas donde el tiempo real perdió eventos (mismo evento que el del pipe).
- Pruebas: sección 13 de `Nexo.Service.Demo` (reloj y espera inyectados). Rotas a propósito: contar el incompleto como hecho
  (3 fallos) y reportar detecciones como limpio (3 fallos). Los métodos expuestos pasan de 22 a 24.
- **Probado con clamd real en Windows (HP, 2026-11-04, ClamAV 1.5.4 portable, 3,29 M de firmas)**, con `nexo-service` en consola y la
  configuración por variables de entorno (`Nexo__EscaneoProgramado__*`; `Registro` fija la ruta del registro, por omisión
  `ProgramData\Nexo\escaneo-programado.json`). Carpeta con 3 archivos limpios y 1 con una firma local (`.ndb` con la cadena de prueba;
  no se usó EICAR para que Defender no lo borrara): estado inicial «nunca»/«vencido», escaneó solo a los 2 min, **4 analizados, 1 detección
  con su firma y sha256, el archivo intacto**, registro guardado. Con clamd parado a mitad: el siguiente escaneo salió «**fallido**»
  («no se pudo conectar con clamd»), `ultimo_completo` sin avanzar, «vencido» y reintento a 1 h.
- **SIN PROBAR**: como servicio instalado de Windows (SCM, cuenta SYSTEM); la recuperación tras el reintento con clamd de nuevo en marcha
  (el reintento de 1 h no es configurable, solo se probó por inyección en la sección 13); el paso de una detección a cuarentena con el id
  `programado`; y cuánto tarda sobre carpetas grandes con `Paralelismo = 2`.

---

## 2l. Ventana principal con Avalonia y tema Classic (2026-11-05, desde Linux)

`src/Nexo.Ui.Desktop` (`nexo-desktop`). Objetivo: Windows 10, Windows 11 **y Linux** con la misma ventana, en estilo Windows
clásico y liviano. La maqueta aprobada (estado, escaneo, tiempo real, firewall, limpieza, disco, cuarentena) está en
https://claude.ai/artifact/NXNyp5WZA2jY3p9kdVGLnT.

- **Avalonia 11.3.0 + `Classic.Avalonia.Theme` 11.3.0.3** (MIT). Se quedó en 11.3 porque el tema para Avalonia 12 aún es beta.
  `ToolBarButton` solo acepta `Bitmap`: los iconos están dibujados en vectores en `App.axaml` y `Iconos.cs` los pasa a mapa de bits
  al abrir (no hay archivos de imagen). No se usa `UseMessageBoxSounds` (no está en este paquete).
- **Dos destinos:** `net8.0-windows` referencia `Nexo.Ipc` y consulta el servicio por el pipe; `net8.0` (Linux) usa
  `FuenteNoDisponible`, que siempre dice «sin conexión» con el motivo («el servicio de Nexo todavía no existe para Linux»).
- **Reutiliza el núcleo de la bandeja sin copiarlo:** `InstantaneaDelServicio` y `DeteccionVista` se separaron de
  `Nucleo/Instantanea.cs` a `Nucleo/InstantaneaDelServicio.cs` (sin cambios de comportamiento), y el proyecto compila por enlace
  ese archivo y `ModeloDeBandeja.cs`; `Instantanea.cs` (el consultor del pipe) solo en Windows. Misma máquina de estados que la
  bandeja: nunca «todo en orden» si no se sabe.
- **Hecho:** la pestaña «Estado» (cabecera con color y texto, tabla de 7 módulos y barra de estado), consulta cada 5 s y con F5.
  **Solo lectura:** ningún botón cambia nada. Las otras 6 pestañas dicen que no están hechas y qué herramienta usar mientras tanto.
  - Además del tiempo real (el consultor de la bandeja), pide en una segunda conexión `escaneo.estado`, `escaneo-programado.estado`,
    `firewall.estado` y `cuarentena.listar`, todos de solo lectura. Cada uno por separado: si uno falla, su fila dice «Sin datos» con
    el motivo y los demás se siguen viendo. `LectorDeModulos` (portable) lee las respuestas; una respuesta con error, vacía o con
    otra forma **no se interpreta a medias**, y un `vencido` ausente no se toma como «al día».
  - **La cabecera muestra lo más grave:** si el tiempo real está bien pero, por ejemplo, el firewall está apagado en un perfil, manda
    el firewall. En empate gana el tiempo real. Con todo bien dice «Sin problemas en lo que se pudo consultar», nunca «todo en orden».
    El escaneo programado apagado sale en gris y no cambia la cabecera (es una elección, no un fallo).
  - Salud del disco: «Sin consultar» (el servicio aún no la expone). Limpieza: «A pedido» (no tiene estado).
- **Pruebas:** `tools/Nexo.Desktop.Demo`, 65, corre en Linux: el lector con JSON de la forma que da cada método y con respuestas
  rotas, las reglas de cada fila y de la cabecera, el modelo con fuentes falsas, y la ventana de verdad cargada sin pantalla
  (`Avalonia.Headless` con Skia; `--captura f.png` guarda una imagen y suma una comprobación). Con la regla de «manda lo más grave»
  rota a propósito, fallan 5. El arnés también encontró que los iconos vectoriales no sirven en `ToolBarButton`
  (`InvalidCastException` al cargar el XAML), y está corregido. En el escritorio Linux real (Avalonia usa X11, aquí por XWayland) la
  ventana arrancó y siguió abierta hasta que se cerró, sin errores.
- **SIN PROBAR:** en Windows (ni compilada ahí ni corrida), y en particular `FuentePorPipe` contra el servicio real: el JSON de las
  pruebas está escrito a partir del código de los módulos, no capturado de un servicio en marcha. Tampoco en Windows 11 (bordes
  redondeados: por eso hereda de `ClassicWindow`), ni el consumo de memoria real.
- **Pestaña «Escaneo» (hecha):** qué analizar (carpeta del usuario, Descargas, unidad del sistema u otra carpeta con «Examinar»),
  archivos a la vez (1/2/4/8), iniciar, avance cada 1 s, cancelar, y el resultado con detecciones y la lista de «sin analizar».
  - Usa `escaneo.iniciar|progreso|resultado|cancelar`. Las rutas las valida el servicio (la ventana solo evita mandar una vacía) y
    escanea con la identidad del usuario. Un fallo suelto al pedir el avance no corta el seguimiento; 5 seguidos sí, y dice que
    el escaneo puede seguir en el servicio. «Terminado» sin resultado se muestra como fallido, nunca como limpio.
  - `ResumirEscaneo`: verde solo si el servicio dice `completamente_limpio`; con archivos sin analizar, incompleto, cancelado o
    fallido nunca es «limpio». Si el servicio recorta la lista de omitidos (200), se dice cuántos se muestran del total.
  - **Poner en cuarentena:** `cuarentena.previsualizar` con el id de ESE escaneo → se muestra el plan (descripción y avisos) →
    solo si se acepta, `AccionesDelServicio.AplicarConAprobacionAsync` con el token. Si el servicio exige UAC, lo pide
    **`nexo-tray.exe --aplicar`** (el mismo camino que la bandeja, con su control de `UbicacionSegura`): la ventana nunca se eleva
    a sí misma. `nexo-tray.exe` tiene que estar en la misma carpeta que `nexo-desktop.exe`; si no está, se dice y no se cambia nada.
    Con `dotnet run` están en carpetas `bin` distintas, así que la aprobación no funcionará así: hay que publicarlas juntas.
  - Para eso `LanzadorElevado` pasó de `Auxiliar.cs` a `Nucleo/LanzadorElevado.cs` (mismo código y espacio de nombres), y la ventana
    compila por enlace ese archivo, `AccionesDelServicio.cs` y `UbicacionSegura.cs` (solo en Windows).
  - Pruebas: +43 (lector de `escaneo.*` y del plan, el resumen del resultado, el modelo con un servicio falso y la pestaña cargada).
    Rotas a propósito «omitidos nunca es limpio» y «terminado sin resultado no es limpio»: falla 1 cada una.
  - **SIN PROBAR:** todo contra el servicio real (escanear, cancelar, la cuarentena y el aviso de UAC por la bandeja) y el
    selector de carpetas de Windows.
- **Pestaña «Cuarentena» (hecha):** lista (`cuarentena.listar`, la más reciente primero, con cuánto falta para que venza),
  «Restaurar...» de la fila elegida (`cuarentena.previsualizar-restauracion` → confirmar → `cuarentena.restaurar` con el token) y
  «Eliminar vencidos...» (`previsualizar-purga` → confirmar → `purgar`). Las dos acciones van por `AccionesDelServicio` con
  `TipoDeAccion.Restauracion|Purga` y, si hace falta UAC, por `nexo-tray.exe`, igual que la cuarentena del escaneo. Se lee al abrir
  la ventana, al entrar en la pestaña, con «Actualizar»/F5 y tras cada acción.
  - **Hallazgo: el servicio NO purga solo.** Lo vencido se queda hasta que alguien pide eliminarlo. La maqueta decía «se eliminan
    solos a los 30 días» y la fila de Cuarentena de «Estado» decía «el próximo se elimina el...»: las dos cosas eran falsas. La fila
    ahora dice «el más antiguo vence el ... (después se puede eliminar)», y la pestaña lo explica. Si se quiere purga automática, es
    trabajo del servicio (no está hecho).
  - No hay «eliminar uno ahora»: el servicio no tiene ese método, y la ventana no lo inventa.
  - Si la lista no se puede leer, se vacía y se dice «No se pudo leer la cuarentena: ...»; nunca se muestra la lista anterior
    como si fuera la actual, ni «vacía» cuando no se sabe. Una entrada rota invalida la lista entera.
  - La confirmación de los planes (escaneo, restaurar, purgar) es una sola función, `ConfirmarPlanAsync`, en `MainWindow.axaml.cs`.
  - Pruebas: +25 (lector, modelo con un servicio falso y la pestaña cargada). Rota a propósito «no mostrar la lista vieja»: falla 1.
  - **SIN PROBAR:** contra el servicio real, incluidos restaurar y purgar con el aviso de UAC por la bandeja.
- **Pestaña «Firewall» (hecha):** los perfiles de Windows (activado o no, y si dejan pasar lo entrante por defecto), el modo
  sigiloso, las reglas del grupo de Nexo y tres acciones: «Bloquear programa...» (elegir un `.exe` y la dirección: las dos, solo
  saliente o solo entrante), «Quitar regla...» de la fila elegida y «Activar/Desactivar modo sigiloso...». Las tres van con
  `firewall.previsualizar` (tipo `regla`, `quitar` o `sigiloso`) → confirmar → `firewall.aplicar` con el token, por
  `AccionesDelServicio` (`TipoDeAccion.Firewall`) y, si hace falta UAC, por `nexo-tray.exe`. Las reglas y negativas (no bloquear
  procesos del sistema ni Defender, solo tocar el grupo de Nexo, no encender un firewall apagado) las aplica el servicio; la
  ventana solo muestra su plan, que ya trae los cambios, los RECHAZADOS y los AVISOS.
  - Si no se sabe cómo está el sigiloso (no se pudo leer), no se ofrece ni activar ni desactivar. Si no se pudo leer el firewall,
    no se muestra nada viejo ni se ofrece ninguna acción.
  - «Conexiones bloqueadas» (eventos 5157): solo un texto que remite a `nexo-firewall bloqueos`; el servicio no los expone.
  - `PlanDeCuarentena` se renombró a `PlanDelServicio` (lo usan también el firewall y la restauración).
  - Pruebas: +27. Rota a propósito «sin datos no se ofrece cambiar el sigiloso»: falla 1.
  - **SIN PROBAR:** contra el servicio real (y el Firewall de Windows real), incluido el aviso de UAC y el selector de archivos.
- **Pestaña «Limpieza» (hecha):** tres recuadros, como el asistente de la maqueta.
  1. **Qué limpiar:** las reglas de `limpieza.reglas` con casillas (marcadas solo las de riesgo bajo, como el servicio), su categoría,
     riesgo y si piden administrador, y el **modo del servicio** (Papelera, simulado o permanente; lo decide su configuración, no la
     ventana). En modo permanente lo avisa en rojo y el botón dice «Borrar para siempre».
  2. **Qué se encontró:** `limpieza.previsualizar` con los ids marcados (nunca rutas): cuánto se liberaría, por categoría, los 20
     más grandes, los que se omitirán (y si el servicio recortó la lista) y las reglas sin permisos. No borra nada.
  3. **Confirmar:** hay que escribir **BORRAR** (exacto) y el botón solo se habilita con una vista previa vigente. Se aplica con
     `AccionesDelServicio` (`TipoDeAccion.Limpieza`) y, si hace falta UAC, por `nexo-tray.exe`.
  - **Si se cambia una casilla después de la vista previa, esa vista previa deja de valer** (y se borra lo escrito): nunca se limpia
    algo distinto de lo que se ve. Una vista previa caducada (`expira`) no se manda. Después de limpiar, el token ya se gastó: para
    volver a limpiar hay que previsualizar otra vez.
  - El catálogo se lee al entrar en la pestaña (una vez; si falla, se reintenta al volver a entrar). La vista previa, solo cuando se
    pide: recorre el perfil del usuario.
  - Pruebas: +31. Rota a propósito «cambiar la selección invalida la vista previa»: fallan 4, entre ellas «sin vista previa vigente
    no se limpia nada».
  - **SIN PROBAR:** contra el servicio real (incluido cuánto tarda la vista previa en un perfil grande, que hoy no muestra avance) y
    el aviso de UAC.
- **Pestaña «Tiempo real» (hecha):** cabecera con lo más grave (detección > apagado > motor caído > cobertura incompleta >
  «Vigilando N carpetas»), motor, contadores (históricos), último aviso y la nota del servicio («detecta DESPUÉS de escribir»),
  carpetas vigiladas (las que la fuente no pudo vigilar, en amarillo), detecciones y carpetas por revisar. Lee
  `tiempo-real.estado` + `tiempo-real.detecciones` al entrar en la pestaña, con F5 y cada 5 s **solo mientras se mira**.
  - **No ofrece encender, apagar ni cambiar carpetas:** el pipe no tiene esos métodos a propósito; la pestaña explica que lo hace un
    administrador en `appsettings.json`.
  - **Poner en cuarentena...:** `cuarentena.previsualizar` con el id `tiempo-real` → confirmar → token, por `IServicioDeEscaneo`
    (mismo camino y misma aprobación por `nexo-tray.exe` que el escaneo).
  - **Revisar lo que no se vio...:** confirma y lanza `escaneo.iniciar` con esas carpetas (sin subcarpetas repetidas, máximo 8; si hay
    más lo dice) y salta a la pestaña «Escaneo», donde se sigue como cualquier escaneo. No cambia lo elegido allí. Si ya hay un escaneo
    en curso, no lanza otro. `RutasParaRevisar` pasó de `AccionesDelServicio` (solo Windows) a `Nucleo/RevisionDeLoNoVisto.cs`
    (portable, enlazado en la ventana); `AccionesDelServicio` delega en él, así la bandeja no cambia.
  - **La ventana no se fía de `cobertura_completa` sola:** si el servicio dice `true` pero manda carpetas por revisar, carpetas no
    vigiladas o el motor caído, se muestra como incompleta. Encendido sin los campos de cobertura, o con las detecciones fallidas,
    no se interpreta a medias. Si la lectura falla, se vacía todo y no se ofrece ninguna acción.
  - Pruebas: +31. Rota a propósito «cobertura completa solo si nada la contradice»: fallan 2.
  - **SIN PROBAR:** contra el servicio real (JSON escrito a partir de `ModuloTiempoReal.cs`, no capturado), la cuarentena con UAC y
    `Nexo.Tray.Demo` tras mover `RutasParaRevisar` (solo Windows; compila en Linux con 0/0).
- **Pestaña «Disco» (hecha), y la salud del disco en el servicio (nuevo):**
  - **Servicio:** `ModuloSaludDisco` con `disco.estado` y `disco.leer` (los métodos pasan de 24 a 26). La lógica es portable,
    `Nexo.Modules.Cleanup/Disco/VigiaDeSalud.cs`: lee al arrancar y cada `Nexo:Disco:IntervaloHoras` (6 por omisión) con el
    `MonitorDeSalud` de siempre (`FuenteSmartWmi` + `HistorialDeSalud` en `ProgramData\Nexo\salud-disco.json`, configurable con
    `Nexo:Disco:Historial`). **`disco.estado` no lee los discos**: devuelve lo guardado (WMI tarda y cada lectura deja una nota por
    disco en el vault). `disco.leer` pide una lectura nueva en segundo plano, **como mucho una cada 5 min** (la marca se pone dentro
    del cerrojo: dos pedidos seguidos no lanzan dos lecturas). Encendido por omisión porque solo lee; `Nexo:Disco:Activo = false`
    lo apaga y entonces el servicio contesta `estado: "apagado"` (`ModuloSaludDiscoApagado`), no «método desconocido».
  - **Una lectura fallida** deja `estado: "fallido"` con el motivo, y los discos de la última lectura buena **con su fecha**.
  - **El JSON** sale de `VigiaDeSalud.ParaJson`, y las pruebas de la ventana lo usan tal cual (con las opciones del pipe, sin nulos):
    es la primera pestaña cuyo JSON de prueba no está escrito a mano. `Nexo.Desktop.Demo` referencia `Nexo.Modules.Cleanup` para eso.
  - **Ventana:** cabecera (lo más grave de todos los discos), cuándo se leyó y cuándo se lee otra vez, «Volver a leer», y una fila por
    disco con estado, temperatura, desgaste, horas, las alertas del evaluador y las limitaciones. Se consulta al entrar, con F5 y
    cada 5 s mientras se mira (barato: no lee los discos). La fila «Salud del disco» de «Estado» ya no dice «Sin consultar»: usa
    lo mismo, y si un disco está en alerta manda en la cabecera.
  - **Reglas:** «Sin alertas» solo si se leyó la bandera de fallo o alguno de los 5 atributos clave (05, 187, 188, 197, 198), y dice
    cuáles. Un disco del que solo hay temperatura, desgaste u horas (NVMe típico) es **«Sin evaluar»**, gris; sin nada, «Sin datos».
    Una lectura fallida es al menos «atención» aunque los datos anteriores estuvieran bien. Severidad desconocida: no se interpreta.
  - Pruebas: +32 en `Nexo.Desktop.Demo` (el vigía real con discos falsos: SATA sano, NVMe, 197 > 0, USB; el límite de 5 min, la
    lectura fallida, el lector, la fila de Estado, el modelo y la pestaña cargada) y +2 en `Nexo.Service.Demo` (sin ejecutar: solo
    Windows; usa una fuente S.M.A.R.T. falsa y el historial junto al vault de prueba). Rota a propósito «solo temperatura no es sin
    alertas»: fallan 4.
  - **SIN PROBAR:** con WMI real dentro del servicio (como SYSTEM debería ver los atributos ATA que sin administrador no se ven) y la
    pestaña contra el servicio real. **Hueco:** el evaluador no mira temperatura ni desgaste (un NVMe al 100 % de desgaste sale
    «sin evaluar», no «alerta»); decidir umbrales es trabajo aparte.
- **Siguiente:** las 7 pestañas están hechas. Lo que falta es probar la ventana en Windows contra el servicio real (§2l, todos los
  «SIN PROBAR»).

---

## 2m. Motor YARA (2026-11-05)

`MotorYara : IMotorDeFirmas` (`src/Nexo.Modules.Threats/Escaner/MotorYara.cs`), con el ejecutable de línea de comandos `yara64.exe`
(BSD-3, así que ejecutarlo no tiene el problema de licencia de libclamav). Se elige con `Nexo:Motor = yara` en `appsettings.json`;
por omisión sigue siendo `clamd`.

- **Comprobado con `yara64.exe` 4.6.0** (zip oficial `yara-4.6.0-2443-win64.zip`, SHA-256 `5e7124f1…81e6dc`, el mismo que publica
  GitHub), antes de escribir código:
  - **No lee stdin en Windows**: `reglas.yar -` y `CON` fallan con `could not open file`. Solo escanea rutas de archivo.
  - **Código de salida 0 tanto si encuentra algo como si no**; 1 para cualquier error (archivo inexistente, regla rota). La detección
    se lee de la salida estándar: una línea `Regla ruta` por regla. Los errores salen por stderr.
  - Opciones usadas: `-N` (no seguir enlaces), `-w` (sin advertencias), `-a N` (tiempo máximo).
- **Decisión (la tomó el usuario, 2026-11-05):** como `AnalizarAsync` recibe un `Stream` y YARA solo lee rutas, el contenido se
  vuelca a una **copia temporal privada** que se borra al terminar. Descartadas: añadir un camino por ruta a la interfaz (se pierde
  la garantía de analizar el mismo archivo que se abrió) y enlazar `libyara.dll` (el zip oficial no la trae; habría que compilarla).
  - Copia: `ProgramData\Nexo\yara-tmp` (la carpeta Nexo ya queda restringida a SYSTEM y Administradores, como la cuarentena), nombre
    aleatorio, `FileMode.CreateNew`, tope de tamaño (100 MB; pasarse es **error**, no limpio), borrada en un `finally` (también si se
    cancela o YARA se cuelga) y barrido de restos de más de 1 h al construir el motor.
  - **Regla del proyecto:** ante la duda, nunca «limpio». Código distinto de 0, salida que no es «regla + la ruta de la copia»,
    mensajes en stderr aunque el código sea 0, tiempo agotado, ejecutable o reglas inexistentes: todo es `Error`, y el escáner lo
    cuenta como omitido (el escaneo no se da por «completamente limpio»).
  - Firma: `YARA.Regla` (hasta 5 reglas, separadas por coma).
- **Configuración** (`Nexo:Yara:*`): `Ejecutable` y `Reglas` (rutas absolutas, obligatorias), `CarpetaTemporal`, `TimeoutSegundos` (30),
  `MaximoMB` (100). Si `Nexo:Motor = yara` y falta alguna de las dos rutas, se usa clamd y se avisa en la nota de arranque.
- **Pruebas:** +42 en `Nexo.Scan.Demo`: 35 portables con un yara **falso** (el propio ejecutable de la prueba, lanzado con
  `--yara-falso`: veredictos, errores, tiempo, tope, cancelación, restos y el motor dentro del escáner) y 7 contra el `yara64.exe`
  **real**, que solo corren si `NEXO_YARA_EXE` apunta a él (si no, salen como «OMITIDA», no como pasadas). Corrieron en Windows con el real: todas OK.
- **Probado después (§2n):** `Nexo:Motor = yara` dentro del servicio real, con la ventana.
- **SIN PROBAR:** un archivo de reglas real de verdad (solo se probó con dos reglas de prueba); el rendimiento de volcar y lanzar un
  proceso por archivo (con el escaneo en paralelo habrá un `yara64.exe` por archivo; no se midió).
- **Hueco:** YARA y ClamAV no se pueden usar a la vez: el motor es uno u otro. Combinarlos pide leer el `Stream` una sola vez y
  pasarlo a los dos.

---

## 2n. La ventana contra el servicio real (2026-11-05, en el HP)

Primera vez que la ventana (§2l) habla con el servicio de verdad. Se arrancó `nexo-service` en consola (no como SYSTEM; sin
administrador) con el vault, la cuarentena y el historial en una carpeta temporal, `Nexo__Motor=yara` y `yara64.exe` real, y se abrió
`nexo-desktop --pipe NexoPrueba`. Se recorrieron a mano las 7 pestañas.

- **Qué ejecutable:** la ventana tiene dos compilaciones. **`bin\Debug\net8.0-windows\nexo-desktop.exe` es la que habla con el servicio;**
  la de `net8.0` es la de Linux y dice «Sin conexión… esta compilación no incluye la conexión con el servicio». Con `dotnet run` en
  Windows se usa la buena; al abrir el `.exe` a mano hay que mirar la carpeta.
- **Estado, Escaneo, Tiempo real, Firewall, Limpieza, Disco y Cuarentena cargan datos reales.** El firewall real se leyó (3 perfiles
  activados, 0 reglas de Nexo). El catálogo de limpieza cargó. Los 4 discos se listaron.
- **Escaneo con YARA real, de punta a punta:** una carpeta con un archivo limpio y otro con la cadena marcadora → «Analizados: 2»,
  «1 detección» `YARA.Prueba_Cadena` (20 B). Los archivos quedaron intactos, la cuarentena vacía y **ninguna copia temporal** en
  `yara-tmp`.
- **Disco:** «Sin datos» en los 4 discos con el motivo «Sin permisos de administrador: no se pudo leer root\wmi». Es lo esperado sin
  SYSTEM/administrador, y el mensaje es honesto. Como SYSTEM sí se leen (ver abajo).
- **Disco como SYSTEM (2026-11-05):** el servicio se ejecutó como SYSTEM con una tarea programada temporal (ya borrada) y se consultó
  `disco.estado` por el pipe. El SATA ST1000LM035 salió con **23 atributos ATA reales** (los 5 clave leídos), 29 °C, 18 407 h,
  severidad **«alta»** y la alerta «Errores incorregibles reportados (187): 90». El NVMe salió con temperatura (41 °C) y desgaste
  0 % («info», sin atributos ATA, con el motivo); los dos puentes USB, «info» con su limitación. Es decir: **SYSTEM ve lo que un
  usuario sin administrador no ve**, que era el motivo de que el servicio lea los discos. No se hizo por la ventana (un juego a
  pantalla completa tapó la ventana): se usó una sonda que habla con el pipe con `Nexo.Ipc`.
- **Fallo encontrado y corregido:** la barra inferior decía «Motor clamd: listo» aunque el motor era YARA (el texto estaba escrito a
  mano). Ahora usa el nombre que da el servicio; ClamAV sigue diciendo «clamd». +3 pruebas en `Nexo.Desktop.Demo`.
- **Acciones que cambian algo, desde la ventana (2026-11-05, con clics reales):** con la aprobación en modo `ninguna` (ver abajo).
  - **Cuarentena:** vista previa (regla, tamaño, ruta, «se cifran, no se eliminan») → el archivo salió de su carpeta y quedó como
    `.nxq` + `.json` en la carpeta de cuarentena; el vecino limpio no se tocó; sin copias en `yara-tmp`. **Restaurar:** aviso claro
    («Es tu decisión») → el archivo volvió con el contenido idéntico y la cuarentena quedó vacía.
  - **Firewall (servicio como SYSTEM):** «Bloquear programa» → vista previa con las 2 reglas → **2 reglas reales** en el firewall de
    Windows (grupo «Nexo Security Suite», bloquear entrante y saliente, verificado con `netsh`) → «Quitar regla» una a una → 0
    restantes. Sin administrador el servicio las **omite** («0 cambios aplicados. 2 omitidos.») y el firewall queda intacto.
    **Ojo:** `Get-NetFirewallRule` sin administrador devuelve 0 reglas siempre; para comprobar desde un usuario normal hay que usar
    `netsh advfirewall firewall show rule name=all`.
  - **Limpieza (modo `simulado`):** vista previa (tarda ~1 min con un perfil grande; «15.3 GB, 36 149 archivos», con los omitidos y
    los motivos) → escribir BORRAR → «Simular limpieza». No se borró nada. **No se probó el borrado real** desde la ventana a
    propósito: `%TEMP%` es una categoría del catálogo y ahí vive la carpeta de trabajo de la sesión.
  - **Dos protecciones de la aprobación (por diseño, §2i), que explican por qué no se pudo probar el UAC:** (1) la ventana pide la
    aprobación a `nexo-tray.exe`, que debe estar **junto a ella** (la compilación de desarrollo no lo copia); (2) Nexo **no eleva un
    ejecutable que el usuario pueda modificar** (Escritorio, `bin\Debug`…): solo desde una ubicación tipo Program Files. Con la
    aprobación por omisión («elevada») la ventana dice «No se aprobó: no se encontró nexo-tray.exe junto a la ventana… No se ha
    cambiado nada», que es el fallo seguro. Para las pruebas se usó `Nexo:Aprobacion:Modo = ninguna`.
  - **Defectos encontrados y corregidos** (+12 pruebas en `Nexo.Tray.Demo`): la limpieza simulada decía «36149 archivos limpiados»
    (ahora «SIMULACION: … se habrían limpiado… No se borró nada», con el campo `modo` en la respuesta de `limpieza.aplicar`);
    «1 archivos» / «1 cambios» (singular); y «2 omitidos» sin motivo (ahora, «El primero: …»).
  - **Defectos pequeños que quedan:** los botones de los avisos salen en inglés («Yes»/«No»); tras poner en cuarentena la lista de
    Escaneo sigue mostrando el archivo ya movido; en la pestaña Cuarentena la ruta larga empuja las columnas Amenaza/Desde/Vence
    fuera de la vista.
- **UAC real, probado (2026-11-05, 23:22).** `nexo-desktop` + `nexo-tray` copiados a `C:\Program Files\NexoPrueba\` y `nexo-service`
  como SYSTEM (tarea programada temporal, ya borrada) con la aprobación por omisión (sin `Nexo:Aprobacion:Modo`), YARA y la
  ventana contra su tubería. Escaneo → 1 detección → «Poner en cuarentena» → confirmación → **aviso de UAC en el escritorio
  seguro** (lo aceptó el usuario) → `nexo-tray.exe` elevado aplicó el plan con el mismo token → `malo.txt` salió de su carpeta y
  quedó como `.nxq` + `.json`; el vecino limpio y el `.exe` no se tocaron; el vault registró la amenaza y la cuarentena.
  - **Con el servicio como usuario normal** (sin SYSTEM) el proceso elevado muestra «No se aplicó: el servicio no puede actuar con
    tu identidad (conecta con nivel de suplantación)…». Es el comportamiento correcto: sin `SeImpersonatePrivilege` el servicio no
    puede suplantar un token elevado y no recurre a SYSTEM. Para probar la aprobación hace falta el servicio como SYSTEM.
  - **No se vio** el cuadro de resultado del proceso elevado (la captura no lo recogió); la comprobación fue por el efecto en
    disco y el vault.
  - **Observación sin investigar:** el `.json` de cada entrada de cuarentena guarda la `Clave` (32 bytes en base64) junto al
    `.nxq`. Puede ser intencional (cifrar evita ejecuciones accidentales, no guarda un secreto); confirmar y dejarlo escrito.
  - **Escaneo programado:** ver la entrada siguiente (probado).
- **Tiempo real con carpetas vigiladas, probado (2026-11-05, 23:25).** Servicio como usuario normal (fuente `watcher`, sin
  administrador; la fuente `usn` sigue sin probarse en real), `Nexo:TiempoReal:Activo=true` y `Raices` = una carpeta de prueba, motor
  YARA real, ventana (`bin\Debug\net8.0-windows`) contra su propia tubería. La pestaña «Tiempo real» mostró la carpeta como
  «Vigilada», motor «YARA — responde» y los contadores.
  - `.txt` → **ignorado a propósito**: solo se analizan extensiones de riesgo (`.exe .dll .ps1 .bat .js .lnk .iso`…, ver
    `OpcionesDeTiempoReal.Extensiones`). La primera prueba con `.txt` dio «Cambios vistos: 4 · Analizados: 0» y parecía un fallo; no
    lo era. **Confusión posible:** la ventana no muestra cuántos cambios se descartaron por extensión.
  - `sospechoso.ps1` (cadena marcadora) → «1 detección del tiempo real», `YARA.Prueba_Cadena`, 15 B, **archivo sin tocar**, evento
    de amenaza en el vault. `limpio.bat` → analizado y limpio.
  - **Se reanaliza si cambia:** se añadió la cadena a `limpio.bat` ya dado por limpio → segunda detección y su evento.
  - `enorme.exe` (30 MB, por encima del límite de 25 MB) → «Sin analizar: 1», con «Último aviso: mayor que el límite del motor».
    **Nunca como limpio.** Como no se arregla reescaneando, «Por revisar» queda en «Nada por revisar» (diseño del vigilante). Ojo:
    el único rastro de ese archivo es el «Último aviso», que otro aviso sobrescribe.
  - Sin copias sobrantes en `yara-tmp`. **Sin probar:** carpetas por revisar tras perder eventos reales (desborde), motor caído en
    pleno vuelo, y la fuente USN.
- **Escaneo programado, probado (2026-11-05, 23:27).** Servicio como usuario normal, `Nexo:EscaneoProgramado:Activo=true`,
  `IntervaloHoras=0.02` (el servicio lo sube al mínimo de 1 min), `Raices` = la carpeta de prueba, `Registro` en el scratchpad (sin
  `ProgramData`), YARA real; se mira la fila «Escaneo programado» de la pestaña Estado.
  - **Antes del primer escaneo:** «Vencido · Nunca terminó uno completo» (no «Al día»), con la espera inicial de 2 min.
  - **Tras el primero:** «3 detecciones · En el último escaneo completo (05/11 23:30)» y el estado general pasó a rojo «Alerta en
    Escaneo programado: 3 detecciones». Encontró las 3 (`.txt`, `.ps1`, `.bat`): el escaneo completo mira todas las extensiones, el
    tiempo real no. Se guardó `ultimo_completo` en el registro.
  - **Reinicio del servicio** (intervalo 24 h): «**Resultado desconocido** · Último completo: 05/11 23:30, pero el servicio no
    recordaba su resultado». Honesto: no aparece «Al día» aunque la fecha sea reciente. **Pero** las 3 detecciones se olvidan hasta
    el siguiente escaneo (solo se guarda la fecha); un reinicio las borra de la ventana. Sigue en el vault.
  - **Hueco de la ventana:** el servicio ofrece `escaneo-programado.detecciones`, pero la ventana solo muestra la fila de Estado: no
    lista esos archivos ni permite ponerlos en cuarentena desde ahí (no se probó otro camino).
  - **Error mío (sin consecuencia grave):** arranqué un servicio sin mis variables de entorno y creó notas de salud de disco en
    `C:\ProgramData\Nexo\Vault` (esa carpeta ya existía de antes). Las variables no persisten entre llamadas de shell.
  - **Sin probar:** que el escaneo programado se reintente a la hora tras un fallo/incompleto, y la espera inicial tras un equipo
    apagado largo (solo se vio la de «nunca»).

---

## 2o. Cierre de huecos de la ventana (2026-11-06, en el HP)

Todo con pruebas en `Nexo.Desktop.Demo` (rotas a propósito para ver que fallan sin el arreglo).

- **Detecciones del escaneo programado en la ventana** (el hueco de §2n): la pestaña «Escaneo» tiene un bloque «Escaneo programado»
  que lee `escaneo-programado.detecciones`, lista los archivos y ofrece «Poner en cuarentena...» por el flujo de siempre (vista previa
  + token) con el id `programado`. Solo aparece si hay algo que mostrar o si **no se pudo leer** (en ese caso lo dice, no lo da por
  limpio). Se lee al abrir, al entrar en la pestaña, con F5 y en cada sondeo mientras se mira la pestaña.
  - Una detección cuyo archivo **ya no existe** deja de listarse; si sigue en su sitio (no se pudo mover, o la aprobación está
    pendiente) se queda: no se da nada por resuelto sin mirarlo.
  - ~~**Sigue pendiente (servicio, no ventana):** un reinicio del servicio olvida las detecciones.~~ Hecho: el registro del escaneo
    programado guarda también las detecciones (ruta, firma, tamaño, hash; máximo 500) y `CargarEstado` las recupera. Lo recordado se
    marca **incompleto** a propósito (nunca se lee como «limpio») y el resultado sigue «desconocido»; un escaneo posterior las
    reemplaza (si salió limpio, las borra). Detecciones guardadas ilegibles: 0 y un aviso. Rotas a propósito: 4 fallos (sin
    restaurar). Solo servicio; sin commit aún.
  - Rotas a propósito: id equivocado (1 fallo) y no filtrar lo inexistente (3 fallos).
- **La lista de «Escaneo» se refresca tras la cuarentena** (`RetirarLasQueYaNoEstan`, mismo criterio: el archivo ya no está). Rotas a
  propósito: 2 fallos.
- **Cuarentena con ruta larga:** la ruta se recorta con «…» (tooltip con la completa) y la lista no tiene barra horizontal, así que ya
  no empuja las otras columnas. Es solo XAML: **no se comprobó a ojo**, solo que compila y que la ventana abre.
- **Botones de los avisos de la bandeja en español:** `Dialogo` (WinForms) sustituye a `MessageBox`, que ponía «Yes/No/OK» según el
  idioma de Windows. Solo admite Aceptar y Sí/No (los únicos usados). **No se vio en pantalla** (solo compila y pasa `Nexo.Tray.Demo`).
- **Observación cerrada:** el `.json` de la cuarentena guarda la `Clave` junto al `.nxq` a propósito (§2e): el cifrado es para que
  ningún antivirus re-detecte el archivo, no para ocultarlo.
- **`Nexo.Cleanup.Windows.Demo` como administrador (2026-11-07, HP): todas las verificaciones pasaron.** Escribe en `HKLM` y limpia
  la subclave temporal de `HKCU`; impacto de arranque real (37 arranques, mediana 98444 ms, 21 retrasos, 0 sin interpretar); 47
  tareas de inicio en 240 archivos, 0 ilegibles; Papelera y archivo bloqueado (`0x20`) correctos. Quedan 3 archivos sintéticos
  `nexo-demo-*` en la Papelera (esperado). El SATA ST1000LM035 sigue con el atributo 187 = 90 (evaluación «Alta»). Sin commit aún.
- **Eventos 5157 reales PROBADOS como administrador (2026-11-07, HP):** `Nexo.Firewall.Windows.Demo` pasa entera (874 eventos en
  7 días, 36 grupos, 0 sin interpretar; la auditoría se lee como activa). `nexo-firewall bloqueos --horas 1` tras bloquear un
  `curl.exe` copiado a una carpeta temporal: `3x saliente TCP 1.1.1.1:80 ...\curl-nexo.exe`, ruta ya traducida a `C:\...`, y `3x
  entrante ICMP 192.168.1.1:0 System` (el router; coincide con el modo sigiloso de la prueba, no se verificó la causa). La
  auditoría de fallos ya estaba activa en el HP antes de la prueba (`Errores`), así que no se tocó ni se revirtió. Ojo para quien
  repita la prueba: en Windows en español `auditpol` rechaza el nombre en inglés de la subcategoría (`0x57`); usar el GUID
  `{0CCE9226-69AE-11D9-BED3-505054503030}`. El código de Nexo no depende del nombre (lee con `AuditQuerySystemPolicy`). Sin commit aún.
- **No probado contra el servicio real:** el bloque nuevo de la ventana (solo servicio falso y la ventana sin pantalla).

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
  real en una VM). Pendiente de ese paso: probar `MotorYara` en el servicio real (§2m).
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
