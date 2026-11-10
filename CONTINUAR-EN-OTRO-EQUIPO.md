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
- **Fuente USN de punta a punta, probada (2026-11-07, HP, administrador).** `nexo-service` real con `Nexo:TiempoReal:Fuente=usn`,
  YARA real, tubería y vault propios en `%TEMP%`, consultado con `nexo-rpc`. `sospechoso.ps1` → `YARA.Prueba_Cadena`; `limpio.bat`
  analizado y limpio; `nota.txt` descartado por extensión (3 vistos, 2 analizados, 1 descartado). Ráfaga de 300 `.exe` + 1 con
  marcador: 304 vistos, 303 analizados, `final-malo.exe` detectado, 0 perdidos, 0 desbordes, 0 sin analizar, `cobertura_completa`
  true. Un archivo con marcador **fuera** de la raíz no aparece. **No cubre** el error 1181 (el diario sobrescribe lo pendiente):
  300 archivos no bastan para provocarlo; ni Defender y Nexo leyendo a la vez, ni carpetas como Descargas o Temp con tráfico real.
  Sin commit aún.
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

## 2p. AMSI como consumidor (2026-11-07, en el HP)

AMSI no existía en el código (solo en el diseño de «Salida 0»); se construyó hoy. **Estado: compila y pasa las pruebas portables; el AMSI real
PROBADO en el HP (ver abajo); el servicio con AMSI real sigue sin probar.** Sin commit.

- **`Nexo.Native/Amsi/ContextoAmsi`**: único P/Invoke (`AmsiInitialize`/`AmsiScanBuffer`/`AmsiUninitialize`), con `SafeHandle` y cerrojo. No lanza:
  devuelve el motivo. Nexo es solo consumidor: no registra proveedores.
- **`MotorAmsi`** (`Nexo.Modules.Threats/Escaner`, portable, `IMotorDeFirmas`). **Regla clave:** AMSI responde «no detectado» (1) tanto si el contenido
  está limpio como si NO HAY proveedor activo; por eso, antes de dar «limpio», comprueba que el proveedor responde escaneando la cadena de prueba
  oficial de AMSI (debe devolver ≥ 32768). Si no la marca → `Error` (no concluyente), nunca `Limpio`. La comprobación caduca a la hora (`Nexo:Amsi:ValidezMinutos`, ver abajo) y se repite en el acto tras cualquier escaneo fallido y una comprobación fallida no se cachea. Códigos: 0 y 1 → Limpio (con proveedor verificado); ≥ 32768 →
  `Infectado` (`AMSI.Detectado`); 16384–20479 (bloqueado por el administrador) → Error; cualquier otro → Error. Tope de 25 MB (más → Error).
- **`MotorCombinado`**: Infectado si ALGUNO marca; Limpio solo si TODOS dan limpio; si alguno no pudo y ninguno marca → Error (dice cuál).
- **Servicio:** `Nexo:Amsi:Activo` (apagado por omisión). AMSI se SUMA al motor de firmas, no lo sustituye, y solo si la autocomprobación pasa al
  arrancar; si no, no se suma y lo dice la nota de arranque («se analiza solo con X»). **Sin probar el cableado del servicio con AMSI real.**
- **La cadena de prueba nunca se escribe a disco ni queda contigua en el binario** (se arma en trozos en tiempo de ejecución). Hallazgo real: al
  mutar el código para dejarla contigua, **Defender bloqueó el archivo fuente** (`CS1504 ... contiene un virus`) y los temporales de `/tmp`
  dieron «Permission denied». No se debe poner esa cadena literal en ningún archivo del repo.
- **Probado (portable, `tools/Nexo.Amsi.Demo`, 44 comprobaciones):** sin proveedor nunca es Limpio, cada código, tope, caducidad, combinado, y que el
  GUID no está en las DLL. Con dientes: sin la autocomprobación fallan 5; con `2` tratado como limpio falla 1; la cadena contigua la frenó Defender.
- **AMSI real PROBADO (2026-11-07, HP, sin administrador, nada a disco; `Nexo.Amsi.Windows.Demo` pasa entero):** `AmsiInitialize` abre, el proveedor
  (Defender) marca la cadena de prueba oficial (código 32768), un script inofensivo no se marca, 100 análisis desde 4 hilos sin errores, y el
  combinado con un motor que dice siempre «limpio» sigue marcándola. **HALLAZGO IMPORTANTE:** la misma cadena enterrada entre 10000 caracteres
  dio **Limpio**: AMSI/Defender la reconoce cuando es todo el buffer, no dentro de contenido mayor. Por tanto el «Limpio» de `MotorAmsi` solo
  significa «el proveedor responde y no marcó este buffer», NO «no hay nada»: sirve como opinión adicional junto a YARA/clamd, nunca sola. Un
  buffer vacío hace fallar `AmsiScanBuffer` (por eso Nexo no lo envía).
- **Cada autocomprobación deja una detección en Defender (2026-11-07):** la cadena de prueba hace que Seguridad de Windows registre
  `Virus:Win32/MpTest!amsi` (la detección de prueba de Microsoft, inofensiva, con severidad máxima por convención). Visto en el HP tras las pruebas:
  una entrada por cada arranque del servicio y de la demo (y por los archivos temporales de la mutación). Con la validez de 5 min el servicio habría
  generado una «amenaza» nueva cada 5 min; por eso la validez por omisión pasó a **60 min** (`MotorAmsi.ValidezPorDefecto`, configurable con
  `Nexo:Amsi:ValidezMinutos`, mínimo 1) y, si un escaneo falla, se vuelve a comprobar **sin esperar**. Con dientes: sin esa invalidación falla 1
  comprobación. Aun así, **cada arranque del servicio con AMSI activo dejará una entrada de prueba en Defender**: avisar al usuario. Servicio real con
  `YARA+AMSI` + fuente USN probado (motor `YARA+AMSI`, 304 vistos / 303 analizados / 0 sin analizar, YARA sigue detectando, sin avisos de arranque).
- **Por probar:** el camino «AMSI no operativo al arrancar» contra un Windows real (exigiría apagar Defender, que Nexo no hace) y la detección de AMSI de punta a punta por el servicio (exigiría escribir la cadena de prueba a disco, que Defender bloquea). No se sabe aún si Defender vía AMSI detecta ejecutables arbitrarios o EICAR (AMSI mira contenido de scripts sobre todo):
  no asumir que AMSI cubre archivos binarios.

## 2q. Módulo de identidad: la bóveda de contraseñas (2026-11-07, en el HP)

Primer paso del módulo M3 (`Nexo.Modules.Identity`, portable `net8.0`). **Hecho: el núcleo de la bóveda; falta todo lo demás de M3.** Sin commit.

- **Cifrado:** AES-256-GCM, clave derivada con **Argon2id** (`Konscious.Security.Cryptography.Argon2` 1.3.1, MIT; el id del paquete lleva `.Argon2`). Parámetros
  por omisión 64 MiB / 3 iteraciones / 2 hilos (~170 ms en el HP); mínimos para crear (OWASP: 19 MiB, t=2); techos al LEER (1 GiB, 12 iteraciones, 8 hilos)
  para que un archivo hostil no agote memoria ni tiempo. La contraseña se normaliza NFKC antes de derivar (la misma contraseña en NFC/NFD abre igual).
  Contraseña maestra: mínimo 10 caracteres. **No hay recuperación de la contraseña maestra, a propósito.**
- **Formato `.nxv`:** `NXV1 | versión | kdf | memoria | iteraciones | paralelismo | sal[16] | nonce[12] | largo | cifrado | etiqueta[16]`. Toda la cabecera va como
  datos autenticados. La longitud declarada debe coincidir EXACTA con el archivo; valores que darían negativo al pasar a `int` se rechazan antes de convertir.
- **Guardado:** nonce nuevo en cada guardado, temporal + `File.Replace` + **verificación de lo escrito** (si no descifra, restaura); **no queda copia vieja**: lo
  eliminado desaparece del disco. Un guardado a la vez (semáforo). Cada cambio (alta, edición, baja) se guarda en el acto y se revierte en memoria si falla.
- **Apertura:** estados claros (`NoExiste`, `ArchivoIlegible`, `VersionNoSoportada`, `ParametrosFueraDeRango`, `ErrorDeLectura`) y uno honesto,
  `ContrasenaIncorrectaOArchivoAlterado`: AES-GCM no distingue las dos cosas y Nexo no finge saberlo.
- **Bloquear** sobrescribe con ceros el arreglo de la clave. **Límite no resoluble:** las cadenas de .NET (sitio, usuario, contraseña) no se pueden borrar de la
  memoria a voluntad; no se promete.
- **Cambiar la contraseña maestra:** exige la actual (comparada en tiempo constante), sal nueva, archivo reescrito; no queda copia con la clave vieja.
- **Generador** (`GeneradorDeContrasenas`): `RandomNumberGenerator`, sin sesgo, una de cada clase pedida en posiciones aleatorias, filtro de caracteres ambiguos.
- **Eventos sin secretos** (`EventosDeBoveda`): creada, desbloqueada (con conteo), intento fallido (severidad media). **Nunca** sitio, usuario, contraseña, notas,
  maestra ni ruta: las notas del vault de reportes son texto plano. Constantes nuevas en `TipoEvento`. Si el reporte falla, la bóveda abre igual.
- **Probado (portable, `tools/Nexo.Identity.Demo`, 61 comprobaciones):** vector oficial RFC 9106 de Argon2id; ningún secreto en claro en el archivo (con control);
  **612 variantes de un bit cambiado** y **todos los truncados**: ninguna abre ni lanza; parámetros hostiles (4 GiB, 2 mil millones de iteraciones, paralelismo
  0/10 000, longitud de 4 GiB) rechazados en milisegundos; 20 nonces distintos; 20 altas simultáneas; borrado real. **Con dientes** (5 roturas a propósito, 7 fallos):
  nonce fijo, copia vieja sin borrar, clave sin poner a ceros, sin garantizar clases, sin normalizar Unicode.
- **No cubierto:** ningún cableado al servicio, ventana ni bandeja; sin Windows Hello; sin portapapeles con auto-borrado (30 s); sin bloqueo automático por
  inactividad; sin permisos NTFS del archivo (hereda los de la carpeta); sin importar/exportar; sin comprobación de contraseñas filtradas (Pwned Passwords, el
  siguiente paso); sin prueba de que sobreviva a un corte de luz real en medio del guardado (solo el diseño: temporal + reemplazo + verificación).

## 2r. Contraseñas filtradas: Pwned Passwords (2026-11-07, en el HP)

Segundo paso de M3, en `Nexo.Modules.Identity/Filtraciones`. **Gratuito: la API de rangos no pide clave ni cuenta.** Sin commit.

- **K-anonimato:** el SHA-1 se calcula en el equipo (bytes UTF-8 de la contraseña tal como se escribió, sin normalizar: así lo calcula el servicio) y a
  `https://api.pwnedpasswords.com/range/XXXXX` solo sale el prefijo de **5 caracteres**. Ni la contraseña ni el hash completo salen jamás; la comparación del
  sufijo se hace aquí. Cabecera `Add-Padding: true` (relleno con cantidad 0 que se ignora, para ocultar cuántos resultados reales hay).
- **Tres estados honestos:** `Filtrada` (con su cantidad), `NoEncontrada` (solo si llegó un listado bien formado; significa «no aparece en las filtraciones
  conocidas», NO «es buena») y `NoSePudoComprobar` (sin red, HTTP distinto de 200, redirección, 429, portal cautivo con HTML, respuesta vacía, más de 1 MiB,
  tiempo agotado, línea inválida sin hallazgo). **Un fallo nunca es «no encontrada».** Un hallazgo no se descarta por una línea basura posterior.
  Cantidades de 13 o más dígitos = línea inválida.
- **Cliente HTTP** (`ConsultaDeRangosHttp`): servidor fijo y solo HTTPS, sin redirecciones ni cookies, prefijo validado con regex (`^[0-9A-F]{5}$`, nada de `/` ni `?`),
  tope de 1 MiB leyendo en flujo (un flujo infinito se corta), 20 s de tiempo, cancelación propagada, nada se registra.
- **Auditoría de la bóveda** (`AuditoriaDeBoveda.AuditarAsync`): una consulta por contraseña distinta, máximo 4 a la vez; separa `Filtradas`, `SinComprobar`,
  `SinContrasena` y `NoEncontradas`; `TodoComprobadoYLimpio` solo es true si TODO se comprobó y nada apareció. Un evento `brecha-detectada` solo con conteos
  (Alta si hay filtradas; **Media** si no hay pero algo quedó sin comprobar; Info si todo limpio). Nunca sitios, usuarios ni contraseñas.
- **Probado:** secciones 12 a 14 de `Nexo.Identity.Demo` (vectores oficiales `password` → 5BAA6 y `123456` → 7C4A8; las defensas de arriba; concurrencia acotada), y
  **contra el servicio real** (`dotnet run --project tools/Nexo.Identity.Demo -- --real`: `password` → 52 372 427 apariciones; una cadena aleatoria → no encontrada;
  solo salen prefijos de prueba). Con dientes: enviar el hash completo, contar el relleno, devolver «no encontrada» ante un fallo, y contar lo no comprobado
  como limpio hacen fallar 14 comprobaciones.
- **No cubierto:** nada conectado al servicio ni a la ventana; no comprueba al teclear una contraseña nueva; no hay comprobación de correos (HIBP de pago, omitido
  por la restricción de costo cero); un servicio caído no tiene reintentos; sin caché (cada auditoría vuelve a consultar).

## 2s. Vulnerabilidades del sistema, 5b: cuentas y contraseñas (2026-11-07, en el HP)

Primer paso del bloque de vulnerabilidades (funciones 5a/5b/5c del plan; aquí solo **5b**). Código en `Nexo.Modules.Threats/Vulnerabilidades` (portable),
`Nexo.Modules.Threats.Windows/LectorDeCuentasWindows` y `Nexo.Native/Accounts/CuentasLocales`. Sin commit.

- **Qué lee (sin administrador, sin red, solo metadatos):** cuentas locales con `NetUserEnum` nivel 20 (nombre, banderas `UF_*`, RID), política local con
  `NetUserModalsGet` niveles 0 y 3 (longitud mínima, caducidad, historial, umbral de bloqueo) e inicio automático por el registro (Winlogon).
- **Líneas rojas respetadas:** no toca la SAM, no lee contraseñas ni hashes. Del autologon solo mira si EXISTE el valor `DefaultPassword`, **nunca su contenido**;
  el modelo (`EstadoDeAutologon`) ni siquiera tiene dónde guardarlo (comprobado por reflexión en las pruebas). Límite: el autologon que guarda la clave como
  secreto de LSA (Sysinternals Autologon) no es visible desde aquí.
- **Reglas (`AnalizadorDeCuentas`):** autologon con contraseña en texto plano (Alta); autologon activo (Media); Invitado habilitada (Media, **detectada por
  RID 501, no por nombre**: el nombre cambia con el idioma); «contraseña no requerida» (Media; **Alta** si es el Administrador integrado; el texto aclara que NO
  significa que no tenga contraseña); Administrador integrado habilitado (Baja); contraseña que no caduca (solo Info: hoy no se recomienda forzar la caducidad);
  cuenta bloqueada (Baja); política con longitud mínima 0 (Media) o < 8 (Baja); sin bloqueo por intentos (Baja). Las cuentas deshabilitadas no dan hallazgos.
- **Honestidad:** cada parte que no se pudo leer es «no evaluado» y `Completo` pasa a false; una revisión incompleta sin hallazgos se publica con severidad
  **Media** y dice «incompleta», nunca «sin hallazgos». `EventosDeVulnerabilidades.RevisionDeCuentas` publica una tabla; los nombres con `|` o saltos de línea no
  rompen la tabla.
- **Probado:** `Nexo.Vuln.Demo` (portable, 43 comprobaciones; con dientes: 5 roturas, deshabilitadas, Invitado por nombre, `Completo` siempre true, incompleta como
  Info y autologon apagado marcado hacen fallar las pruebas). **Contra el HP real** (`Nexo.Vuln.Windows.Demo`, sin administrador): 5 cuentas (Administrador 500,
  alvar 1032, DefaultAccount 503, Invitado 501, WDAGUtilityAccount 504), cruzadas con `Get-LocalUser` y `net accounts`: mismas cuentas y RID, política idéntica
  (longitud mínima 0, caducidad 42 días, sin historial, bloqueo a los 10 intentos).
- **Hallazgos reales en el HP:** (1) **la política local no exige longitud mínima (0)** — Media; (2) la contraseña de `alvar` no caduca — Info. Autologon inactivo.
  Ninguna cuenta con «contraseña no requerida» habilitada.
- **No cubierto:** sin cableado a servicio/ventana/bandeja; no mira pertenencia a grupos (quién es administrador además del RID 500); no revisa complejidad de
  contraseñas (requiere `secedit` como administrador); no cubre cuentas de dominio ni Microsoft Account en línea; faltan 5a (aplicaciones desactualizadas) y 5c (Wi-Fi).

## 2t. Vulnerabilidades 5c: Wi-Fi inseguro (2026-11-07, en el HP)

Segundo paso del bloque de vulnerabilidades. Código: `Nexo.Native/Wifi/WlanNativo`, `Nexo.Modules.Threats/Vulnerabilidades/ModeloWifi` (parser de perfiles y
reglas, portable), `Nexo.Modules.Threats.Windows/LectorDeWifiWindows`, y `RevisionDeWifi` en `EventosDeVulnerabilidades`. Sin commit.

- **Qué lee (solo lectura, sin administrador, sin red):** adaptadores, perfiles guardados y conexión actual con la Native Wifi API. **Nunca pide la clave**: la
  bandera de lectura es siempre 0 (jamás `WLAN_PROFILE_GET_PLAINTEXT_KEY`); el XML puede traer la clave CIFRADA y el parser **salta `keyMaterial` sin leer su
  texto**. `PerfilWifi` no tiene ningún campo para una clave (comprobado por reflexión). Nunca modifica perfiles ni conecta/desconecta.
- **Parser del XML** (`ParserDePerfilWifi`): se trata como no confiable (sin DTD ni entidades, tope de 64 K caracteres), usa solo el nombre local de los elementos
  (v1/v2/v3), extrae cuatro datos (autenticación, cifrado, modo auto/manual, red oculta) y devuelve null si falta autenticación o cifrado: no se adivina.
- **Reglas:** red abierta que se conecta sola (Alta) / abierta manual (Media); WEP, también con autenticación abierta (Alta); TKIP (Media); red oculta (Baja: delata
  la red y no mejora la seguridad); conexión actual sin cifrado (Alta), con WEP (Alta), con TKIP (Media). WPA2-AES, WPA3 y OWE no dan hallazgos. **Una combinación
  que Nexo no reconoce (p. ej. `open` con AES) queda como «no evaluado»**, no como buena.
- **«Sin Wi-Fi» ≠ «no pude leer»:** para saber si el equipo tiene adaptador se usan los adaptadores de red de .NET (`NetworkInterfaceType.Wireless80211`), sin
  depender del servicio WLAN. Sin adaptador = hecho (Info, completo). Con adaptador y servicio parado, o error de la API = «no evaluado» (Media, «incompleta»).
- **Probado:** `Nexo.Vuln.Demo` secciones 7–11 (portable; 625 cortes del XML sin excepción; DTD, bomba de entidades, tope; keyMaterial falso ANTES de la seguridad real;
  clave sentinela que nunca sale a un evento). **Con dientes** (6 roturas: DTD permitido, leer dentro de keyMaterial, TKIP como moderno, servicio parado como completo,
  combinación desconocida como buena, conexión sin cifrado ignorada). Al revisarlas detecté dos pruebas débiles (la bomba de entidades daba null por no traer
  autenticación, y el keyMaterial falso venía después de la real) y las rehíce antes de comprobar los dientes.
- **Contra el HP real** (`Nexo.Vuln.Windows.Demo`, sección 3): adaptador Realtek RTL8822BE, **16 redes guardadas, las 16 leídas e interpretadas**, todas
  WPA2-Personal/AES salvo una WPA3-SAE; **0 hallazgos**. Cruzado con `netsh wlan show profiles` (16 perfiles), `show interfaces` (desconectado) y
  `show profile name=…` de 3 redes (mismo modo auto/manual y mismas autenticación/cifrado; ninguna es oculta).
- **SIN PROBAR con datos reales:** el camino de «conexión actual» (`WlanQueryInterface` + `WLAN_CONNECTION_ATTRIBUTES`): el HP estaba desconectado del Wi-Fi.
  Solo se comprobó que la estructura mide 604 bytes (8 + 512 + 68 + 16; un primer cálculo mío de 608 estaba mal, no la estructura). **Repetir con el Wi-Fi conectado.**
- **No cubierto:** categoría de red (Pública/Privada, `INetworkListManager`); redes de WPA empresarial (802.1X) más allá de leer su autenticación; sin cableado a
  servicio/ventana/bandeja. Falta 5a (aplicaciones desactualizadas).

## 2u. Vulnerabilidades 5a: aplicaciones desactualizadas (2026-11-07, en el HP)

Tercer y último paso del bloque de vulnerabilidades. Código: `Nexo.Modules.Threats/Vulnerabilidades/ModeloDeAplicaciones` (parser, reglas; portable),
`Nexo.Modules.Threats.Windows/LectorDeWingetWindows` y `RevisionDeAplicaciones` en `EventosDeVulnerabilidades`. Sin commit.

- **Solo español (decisión del usuario):** el parser exige el encabezado exacto `Nombre Id Versión Disponible Origen` y la línea de guiones. Con cualquier otro
  idioma, o un error de winget (no poder abrir el origen…), el resultado es **«no evaluado»** con el motivo, nunca «sin actualizaciones». Las columnas se cortan por la
  posición de cada título (los nombres llevan espacios). Una fila con el Id truncado (`…`), campos vacíos o más corta que la columna Origen no se adivina: es ilegible
  y hace la revisión incompleta. **El recuento final («N actualizaciones disponibles.») debe cuadrar con las filas**; si falta, no cuadra, o winget añade texto
  después (otra tabla de paquetes que no pudo comparar), se avisa. Guarda explícita: las posiciones de columna deben ser estrictamente crecientes (sin ella, una
  rotura a propósito hizo lanzar `Substring`).
- **Lector real:** `winget upgrade --accept-source-agreements --disable-interactivity` por `Process` (UTF-8, entrada cerrada para que no espere respuesta, tope de
  120 s con `Kill` del árbol de procesos, tope de 2 MiB). **Solo consulta: jamás instala ni actualiza.** winget necesita sesión de usuario: lanzado desde el servicio
  como SYSTEM normalmente no funciona; está pensado para la ventana o la consola.
- **Reglas:** un programa de una lista corta de «muy atacados» (Java/JDK, WinRAR, 7-Zip, Chrome, Firefox, Edge, Adobe Acrobat, Zoom, VLC; se compara el **prefijo** del Id,
  sin distinguir mayúsculas) desactualizado = **Media**, con el comando exacto `winget upgrade --id …`; el resto, un solo hallazgo **Baja**. **Una versión más nueva NO significa
  «vulnerable»**: no hay cruce con CVE y los textos lo dicen. El evento declara su alcance: winget solo comprueba lo que sabe identificar, no todo el software instalado.
- **Probado:** `Nexo.Vuln.Demo` secciones 12–14 usando como dato la **salida real de tu winget copiada tal cual** (21 filas, incluida `< 175.1.0.13416` y un nombre que llena
  la columna). Con dientes (6 roturas: encabezado en inglés aceptado, recuento ignorado, Ids truncados aceptados, error tomado por «sin actualizaciones», Id por «contiene» en
  vez de prefijo, texto extra sin avisar). **Contra el HP real** (`Nexo.Vuln.Windows.Demo`, sección 4): winget v1.29.380, 21 aplicaciones leídas, recuento coincide, **Java 8
  Update 401 y WinRAR 7.01 marcados Media** + 19 en el hallazgo Bajo; con un límite de 1 ms devuelve `TiempoAgotado` y no una tabla a medias.
- **SIN PROBAR con winget real:** el mensaje de «nada que actualizar» en español (el reconocimiento `No se encontr… actualizaci…` se probó solo con texto sintético; hay que
  verlo la primera vez que el HP no tenga nada pendiente), y qué pasa con tablas adicionales de winget (paquetes con versión no determinada), que hoy solo avisan.
- **No cubierto:** sin cruce con CVE (OSV.dev, gratuito: posible siguiente paso); sin inventario del registro (aplicaciones que winget no reconoce quedan fuera y no se dice
  cuántas son); ejecución desde el servicio; sin cableado a ventana/bandeja.

## 2v. Ventana: pestaña «Seguridad» (2026-11-07, en el HP)

Primer paso del cableado de los módulos nuevos a la ventana (`src/Nexo.Ui.Desktop`). **Hecho: la pestaña «Seguridad» (8.ª pestaña).** Falta la pestaña «Contraseñas»
(bóveda). Sin commit.

- **Decisión de arquitectura: corre en el proceso de la ventana, con el usuario, NO por el servicio.** `winget` necesita sesión de usuario; la bóveda (siguiente paso) no debe
  pasar nunca por un proceso SYSTEM; y nada de esto necesita privilegios. Por eso no hay métodos nuevos en el pipe. Consecuencia: **nada se publica al vault de reportes
  desde la ventana** (el `ReportWriter` es del servicio); los eventos `RevisionDeCuentas/Wifi/Aplicaciones` existen pero la ventana aún no los escribe.
- **Mismo patrón que las demás pestañas:** `Nucleo/Seguridad.cs` (`IServicioDeSeguridad`, `ServicioDeSeguridadNoDisponible`, y `ServicioDeSeguridadLocal` solo con `#if WINDOWS`),
  `SeguridadModelo.cs` (modelo + `ResumirSeguridad`), XAML en `MainWindow.axaml` (estilo clásico: grupos con encabezado, cuadrado de color + texto, tablas gris/blanco) y
  `Fuentes.SeguridadPorDefecto()`. `Nexo.Ui.Desktop` referencia ahora `Nexo.Modules.Threats` (todos los destinos) y `Nexo.Modules.Threats.Windows` (solo Windows).
- **Solo lectura y a petición:** «Revisar todo» y un «Revisar» por sección. **Entrar en la pestaña NO revisa nada** (la de aplicaciones consulta Internet con winget).
- **Reglas de la pestaña (probadas):** nunca se muestra un resultado anterior como el actual (al revisar de nuevo se borra y, si falla, se dice por qué y NO reaparece el viejo);
  nunca verde si no se sabe (revisión incompleta, fallida, parcial o sin revisar); el peor manda (alerta > atención > no se sabe > correcto); el general solo es verde si las
  **tres** se revisaron y salieron bien («Sin problemas en lo que se pudo revisar», y aclara que no es una garantía); solo notas informativas = «sin problemas» con la nota visible
  y sin color de alarma; «sin adaptador Wi-Fi» = «No aplica» (un hecho); un segundo clic durante una revisión vuelve al instante y no lanza otra.
- **Probado:** `Nexo.Desktop.Demo` (portable, ventana de verdad sin pantalla con Avalonia.Headless): modelo (≈35 comprobaciones), pestaña cargada, 8 pestañas, y captura
  (`--captura f.png` → `f-seguridad.png`). **Con dientes** (8 roturas): verde con revisión parcial, orden de gravedad, revisar sola al entrar, incompleta como completa, no borrar
  lo anterior, quitar la guarda del doble clic (hizo COLGAR la prueba; se reescribió para que falle en vez de colgarse). Una rotura (notas informativas) no hace fallar nada: es
  código redundante (la nota cae en la rama «sin problemas» del `switch`), no una prueba débil. **Contra el HP real, a través del modelo con el adaptador real**
  (`Nexo.Vuln.Windows.Demo`, sección 5): 5 cuentas, 16 redes, 21 aplicaciones; hallazgos reales (política sin longitud mínima, Java 8 y WinRAR Media); general «Hay cosas que revisar».
- **Pulido de textos HECHO (2026-11-07):** los textos de los módulos de vulnerabilidades (`ModeloDeCuentas`, `ModeloWifi`, `ModeloDeAplicaciones`, `EventosDeVulnerabilidades`; 82 cadenas)
  ahora llevan tildes y eñes («contraseña», «política», «está desactualizado»). Se hizo con un script que **solo toca el interior de las cadenas normales de C#** (no comentarios, no
  expresiones regulares, no la salida real de winget copiada en las pruebas) y con reglas de frase para los ambiguos: «este equipo» y «olvida esta red» (demostrativos) NO llevan tilde;
  «donde esté», «que esté completa» (subjuntivo), «Estás conectado», «fuiste tú» y «winget falló» SÍ. Solo 12 comprobaciones dependían de frases; se actualizaron. **Prueba nueva**
  (`Nexo.Vuln.Demo` §15, `TextosPruebas.cs`): recorre los 331 textos que producen las tres revisiones en todos sus casos y falla si aparece una forma siempre incorrecta sin tilde
  (lista de ~55 palabras); con dientes (una palabra sin tilde a propósito la detecta). El vault de reportes conserva tildes y eñes por diseño (`NoteNaming.Sanear`).
  **Aún sin tildes:** los módulos de Identidad (bóveda, Pwned Passwords): se pulen al construir su pestaña. Y los mensajes de los arneses de prueba (no son interfaz).
- **SIN PROBAR:** la ventana real con pantalla (solo sin pantalla y con captura); el botón «Revisar» dentro de la plantilla (el manejador de eventos en una `DataTemplate` se
  resuelve en la ventana: compila y carga, pero no se simuló un clic real).

## 2w. Ventana: pestaña «Contraseñas» (la bóveda) (2026-11-07, en el HP)

Segundo paso del cableado (`src/Nexo.Ui.Desktop`): la 9.ª pestaña. Sin commit.

- **Corre en el proceso de la ventana, con el usuario; NUNCA por el servicio (SYSTEM).** Archivo por omisión `%LOCALAPPDATA%\Nexo\boveda.nxv` (perfil del usuario, no `ProgramData`);
  `--boveda <ruta>` lo cambia. Hereda los permisos NTFS de esa carpeta (no se fijan permisos propios). Nada se publica al vault de reportes desde la ventana (el `ReportWriter` es del servicio).
- **Tres estados:** «sin bóveda» (crear: maestra de ≥ 10 caracteres, repetida; avisa que no hay recuperación), «bloqueada» (desbloquear) y «abierta» (lista con búsqueda, detalle,
  alta/edición/baja con confirmación, generador de 20 caracteres, copiar, comprobar filtraciones, cambiar la maestra). Archivos: `Nucleo/Contrasenas.cs` (`IPortapapeles`, `FaseDeBoveda`),
  `ContrasenasModelo.cs` (toda la lógica, portable), `PortapapelesDeAvalonia.cs` y el XAML.
- **Reglas (todas con prueba):** la maestra solo viaja como argumento (ninguna propiedad ni campo de texto del modelo la guarda, comprobado por reflexión, ni sale en ningún mensaje);
  bloquear (a mano, por **5 min de inactividad** con teclado/ratón como actividad, o al cerrar la ventana) cierra la bóveda, pone la clave a ceros y olvida lista, selección, filtro,
  formulario y resultados de filtraciones; la contraseña se muestra oculta siempre con los MISMOS 8 puntos (no se adivina el largo) y **vuelve a ocultarse al guardar** (un defecto real
  que encontró la prueba: tras «Generar» quedaba a la vista); «contraseña incorrecta o archivo alterado» no se distingue y el texto lo dice; archivos truncados, de versión futura o con
  parámetros hostiles (4 GiB) se rechazan con su explicación en milisegundos.
- **Portapapeles:** copiar una contraseña la borra a los **30 s solo si el portapapeles sigue teniendo lo que puso Nexo** (si el usuario copió otra cosa, no se toca y se dice); dos copias
  seguidas: la espera de la primera ya no borra la segunda; **bloquear o cerrar borra al instante** (el cierre espera a que se borre); copiar el usuario no programa nada; si el
  portapapeles falla lo dice y no finge. Con dientes: sin la guarda de «sigue siendo lo mío» y sin el borrado al bloquear fallan las pruebas.
- **Comprobar filtraciones (Pwned Passwords):** solo cuando el usuario pulsa; sale a Internet un prefijo de 5 caracteres por contraseña distinta. Resultado por entrada («Filtrada (52.372.427
  veces)», «No aparece en filtraciones conocidas», «Sin comprobar», «Sin contraseña»); **sin Internet = «Sin comprobar» + atención, nunca bien**; todo limpio = correcto pero aclara «no significa
  que sean fuertes»; bóveda vacía = «No hay contraseñas que comprobar»; **editar una contraseña borra su resultado** (ya no vale); bloquear borra todos los resultados.
- **Defecto latente de TODA la ventana, corregido:** `Pestanas.SelectionChanged` recibía también los eventos de selección de los `ListBox` de dentro de las pestañas (el evento SUBE por el árbol).
  Al elegir una fila de mi lista se ejecutaba «entré en la pestaña Contraseñas», que reconstruía la lista, que cambiaba la selección, que volvía a subir el evento: **recursión infinita (desbordamiento
  de pila)**. En las otras pestañas ocurría en silencio: elegir una fila de Cuarentena o de Firewall relanzaba su consulta al servicio. Ahora el manejador solo reacciona si `e.Source` es la propia
  barra de pestañas (`MainWindow.axaml.cs`). Quitar esa guarda hace caer la prueba. Además la lista no se reconstruye al cambiar de fila ni al abrir el formulario, y se ignora el `null` que el
  `ListBox` empuja al recibir una lista nueva. También se arregló un comentario pegado a una línea de código del cambio anterior.
- **Defecto de diseño encontrado en la captura:** las cajas de la maestra en una rejilla con `Width` + `HorizontalAlignment` salían como una raya de 6 px; se pasaron a `StackPanel` en fila (como «Desbloquear»).
- **Textos de Identidad pulidos** (25 cadenas: «bóveda», «contraseña», «débiles», «máximo»…) con el mismo script (ahora protege los nombres de campo con guion bajo, p. ej. `sin_contrasena`).
- **Probado:** `Nexo.Desktop.Demo` (portable; modelo ≈ 95 comprobaciones + la ventana de verdad sin pantalla con clics en los botones y 4 capturas: crear, abierta, edición, bloqueada); con
  dientes (12 roturas, incluidas: portapapeles al bloquear, «sigue siendo lo mío», guarda de generación, contraseña siempre visible, largo real, inactividad doble, resultados al bloquear, lo no comprobado
  como bueno, editar sin invalidar, y la guarda de eventos). Una regresión que dejaba una espera abierta COLGABA la prueba: ahora las esperas del portapapeles tienen límite y fallan. **En el HP real**
  (`Nexo.Vuln.Windows.Demo` §6): parámetros de producción (crear ~0,5 s, abrir ~0,17 s), el archivo no contiene sitio ni contraseña, Pwned Passwords real (`password` → 52.372.427 veces; una cadena aleatoria no
  aparece), copiar/bloquear/desbloquear, y sin resultados de filtraciones tras reabrir.
- **SIN PROBAR:** el portapapeles real de Avalonia/Windows (las pruebas usan uno falso; `PortapapelesDeAvalonia` solo compila); la ventana con pantalla real y un clic de verdad; el bloqueo por inactividad con el
  temporizador real de 10 s (se probó la lógica con reloj falso); cerrar la ventana real con una contraseña copiada. Limitación declarada en la propia pestaña: las cadenas de .NET no se borran de la memoria.
- **No cubierto:** Windows Hello; importar/exportar; copia de seguridad (HECHA después, ver §2x); bloquear al minimizar o al bloquear Windows;
  eventos al vault de reportes desde la ventana.

## 2x. Copia de seguridad de la bóveda y restauración (2026-11-07, en el HP)

Cierra la mayor debilidad práctica de la bóveda: es UN archivo, y si se pierde o se daña se pierde todo. Sin commit.

- **Principio:** una copia NO puede romper la garantía de borrado de la bóveda (lo eliminado desaparece del disco). Por eso la copia es **siempre una acción explícita del usuario**, con destino que él
  elige; no hay copias automáticas ni `.bak` permanente. La pestaña lo advierte: una copia conserva lo que había en ese momento, **incluso lo que borres después**; cuídala como la bóveda.
- **`Boveda.ExportarCopiaAsync(destino, sobrescribir)`** (`Nexo.Modules.Identity`): exporta el estado ACTUAL con un nonce nuevo y **verifica que descifra** antes de darlo por bueno (reutiliza la escritura
  atómica con verificación de siempre, ahora parametrizada por ruta; `ConstruirArchivo` extraído). Nunca sobrescribe sin permiso expreso; **jamás acepta como destino el propio archivo de la bóveda**
  (ni con permiso); crea la carpeta si falta; no deja temporales ni `.bak`; con la bóveda bloqueada no hace nada. Se abre con la contraseña maestra ACTUAL.
- **`Boveda.RestaurarAsync(copia, contraseñaDeLaCopia, destino)`:** **primero comprueba que la copia abre** con su contraseña (no se instala algo inservible: contraseña equivocada, truncada, un bit
  cambiado, versión futura o parámetros hostiles se rechazan sin tocar nada); si ya hay una bóveda en el destino, **NO se borra: se aparta** como `boveda.nxv.anterior-AAAAMMDD-HHMMSS` (con sufijo si
  chocan dos en el mismo segundo); escribe la copia, la **vuelve a abrir** para comprobarla, y si no abre o algo falla (p. ej. otro programa tiene el destino abierto) devuelve todo a su sitio.
- **Interfaz** (pestaña Contraseñas): en la bóveda abierta, «Copia de seguridad» con **«Guardar copia...»** (selector de archivo con aviso de sobrescritura del sistema, nombre sugerido
  `boveda-copia-AAAAMMDD.nxv`) y un recordatorio: «Todavía no guardaste ninguna copia en esta sesión» / «Última copia de esta sesión: dd/MM HH:mm.». Con la bóveda cerrada (o sin bóveda),
  «Restaurar desde una copia»: escribes la contraseña de la copia, eliges el archivo, y si ya hay bóveda se pregunta antes (se aparta, no se borra). La restaurada queda **bloqueada**: se abre con la
  contraseña de la copia. Restaurar con la bóveda abierta no existe. `ContrasenasModelo.GuardarCopiaAsync/RestaurarAsync/TextoDeCopia/PuedeRestaurar/ExisteBoveda`.
- **Defecto corregido de paso:** los mensajes mostraban el sufijo técnico de .NET («… (Parameter 'destino')» / «(Parámetro 'x')») al usuario; ahora un único ayudante (`Motivo`) lo quita en todos los
  mensajes de la pestaña (afectaba, p. ej., a «sitio demasiado largo»). También se renombró `BotonRestaurar` → `BotonRestaurarCopia` (chocaba con el de Cuarentena).
- **Probado:** `Nexo.Identity.Demo` §16–17 (≈ 33 comprobaciones: copia abre con la misma maestra, nonce distinto, nada en claro, lo borrado después sigue en la copia, no sobrescribe, no acepta la propia
  bóveda, bloqueada no exporta, exportar mientras se escribe, restaurar en destino vacío / sobre una bóveda (apartada idéntica y abriendo con SU contraseña) / dos seguidas sin pisarse, 6 rechazos que dejan
  el destino intacto, destino abierto por otro programa); `Nexo.Desktop.Demo` (modelo + ventana: paneles según el estado, «Restaurar» oculto con la bóveda abierta, textos con tildes); **con dientes** (9
  roturas: sin comprobar la copia, borrar en vez de apartar, exportar sobre la propia bóveda, sobrescribir sin permiso, recordatorio sin actualizar, restaurar con la bóveda abierta, ocultar que se apartó,
  no olvidar la copia al bloquear, sufijo técnico). **En el HP real** (`Nexo.Vuln.Windows.Demo` §6, parámetros de producción): guardar ~12 ms, restaurar ~0,3 s, la restaurada abre con la contraseña de la
  copia y no con la posterior, la posterior queda apartada y sigue abriendo con la suya.
- **SIN PROBAR:** los selectores de archivos de verdad (`SaveFilePickerAsync`/`OpenFilePickerAsync`: solo compilan; los manejadores hacen el selector y llaman al modelo, que sí está probado); la ventana
  con pantalla real. **No cubierto:** copia automática programada (a propósito: ver el principio); copia a un destino remoto; cifrar la copia con otra contraseña distinta de la maestra.

## 2y. Prueba con pantalla REAL de la ventana y diálogos en español (2026-11-07, en el HP)

Lo que faltaba de la pestaña Contraseñas: probarla en la ventana de verdad, con clics y teclado reales. Sin commit.

- **Método (seguro):** `nexo-desktop.exe` (`net8.0-windows`) lanzado con `--pipe` inexistente (sin servicio) y `--boveda` apuntando a una carpeta temporal propia (jamás la bóveda del usuario). Un
  ayudante de PowerShell (scratchpad, no está en el repo) hace clics y teclea **solo si la ventana al frente es de Nexo** (comprueba el PID, así también valen sus diálogos de archivo); si es otra
  cosa (un juego, AnyDesk…) no envía nada. Solo se capturó el rectángulo de la ventana de Nexo. Se guardó y devolvió el portapapeles de texto del usuario, y se borró la carpeta temporal. Pantalla a
  100 % (900×620); con otro escalado habría que recalcular las coordenadas. Antes se pidió permiso al usuario.
- **Verificado en la ventana REAL:** crear la bóveda tecleando la maestra (archivo de 93 bytes); alta de una entrada (322 bytes, sin sitio ni clave en claro; contraseña oculta con 8 puntos aunque tiene 22 caracteres);
  **portapapeles real de Windows**: copiar la pone y **se borra sola a los 29,2 s**; **bloquear la borra al instante**; **cerrar la ventana (Alt+F4) con una contraseña copiada** la borra y el proceso termina;
  contraseña equivocada → mensaje honesto, la correcta abre; **la bóveda persiste al cerrar y reabrir el proceso**; elegir una fila con el mouse ya no cuelga (el bucle de `SelectionChanged` está corregido de verdad);
  **«Guardar copia...» con el diálogo NATIVO de Windows** (copia de 322 bytes, mensaje y recordatorio «Última copia de esta sesión»); **«Restaurar desde una copia» con el diálogo nativo de abrir** (la bóveda se
  reemplaza y la anterior queda como `boveda.nxv.anterior-AAAAMMDD-HHMMSS`, sin borrarse); **bloqueo por inactividad con el temporizador real**: a los 5 min quieta, «La bóveda se bloqueó por inactividad».
- **Defecto encontrado y corregido: los cuadros de confirmación tenían los botones en INGLÉS («Yes» / «No» / «Ok»).** Venían de `MessageBox` de `Classic.CommonControls`, que no permite cambiar los textos.
  Afectaba a TODA la ventana (cuarentena, restaurar, purga, firewall, limpieza, eliminar entrada, copia). Ahora todo pasa por `DialogoEnEspanol` (`PreguntarAsync` / `InformarAsync`): «Sí» / «No» / «Aceptar».
  **Decisión de seguridad:** en las preguntas el botón por omisión es **«No»**; Enter no confirma una acción destructiva; Esc y la «X» equivalen a «No». Probado en la ventana real: Enter y Esc conservan la entrada;
  «Sí» la elimina y el archivo baja de 322 a 93 bytes (borrado real). `Nexo.Desktop.Demo` (`DialogosPruebas.cs`): textos exactos de los botones, botón por omisión, Esc, «X», un texto larguísimo no ensancha el cuadro, y una
  **guarda que falla si `MainWindow.axaml.cs` vuelve a contener «MessageBox»**; con dientes (botón en inglés, «Sí» por omisión, Esc sin efecto).
- **Observaciones:** tras reabrir el proceso, mi primer clic solo dio foco a la ventana y la maestra no llegó a teclearse (fallo de mi guion, no de Nexo; la bóveda seguía bloqueada y con sus datos). La ventana no recuerda
  su posición entre sesiones. Los diálogos nativos de archivo abren en `Documentos` del usuario (muestran sus carpetas: no se debe publicar una captura de ellos).
- **SIN PROBAR todavía:** otros escalados de pantalla (125 %/150 %); que mover el mouse cuente como actividad para el bloqueo (solo se probó la inactividad total y la lógica con reloj falso); Windows 11 (bordes redondeados);
  el resto de pestañas en la ventana real (solo se vio «Contraseñas» y un vistazo a «Estado»).

## 2z. Cruce de aplicaciones con fallos conocidos (CVE) sobre NVD (2026-11-07, en el HP)

Convierte «una versión más nueva» en «tu versión tiene estos fallos». Gratuito y sin cuenta. Subido en `d58359b`; los ajustes finales de pruebas, SIN commit al escribir esto.

- **Por qué NVD y no OSV.dev:** OSV devuelve `{}` tanto para «versión limpia» como para «paquete desconocido»: no distingue, así que es inservible para programas de escritorio. NVD sí (CPE + CVE por versión).
- **Piezas:** `Nexo.Modules.Threats/Vulnerabilidades/CruceConCve.cs` (mapa curado winget→CPE `MapaDeProductos`, `ParserDeNvd`, `CruceConCve.CruzarAsync/Analizar`) y `ConsultaNvdHttp.cs`.
  En la ventana: cuarta sección «Fallos de seguridad conocidos (NVD)», botón «Consultar NVD», con aviso previo (por omisión «No»).
- **Reglas de honestidad:** «Sin fallos conocidos» SOLO si el producto está en el mapa curado, la versión se tradujo con certeza, el servidor dio 200 y la respuesta se leyó entera. Todo lo demás es «no se pudo comprobar» con su motivo
  (sin red, 403/429, otro código HTTP, JSON ilegible, página llena sin ningún fallo que afecte, versión rara). El código HTTP manda sobre el cuerpo. Ante 403/429 se PARA. Lo que no está en el mapa no se consulta y se declara.
  El texto dice «no lista fallos», nunca «seguro».
- **Privacidad:** solo sale el CPE (`proveedor:producto:versión`); User-Agent genérico; servidor fijo, HTTPS, sin redirecciones ni cookies; CPE validado antes de armar la URL. Solo con su botón; **«Revisar todo» NO lo ejecuta** (probado).
  7 s entre consultas (sin clave ≈ 5 por 30 s). Releer las aplicaciones borra el cruce anterior.
- **Mapa curado (9):** WinRAR (quita ceros finales: `7.01.0`→`7.01`), 7-Zip, Chrome, Firefox, Edge (`edge_chromium`), VLC, Git, Node.js y **Java 8** (`oracle:jre`). Cada CPE se comprobó contra NVD con una versión vieja conocida (debe devolver fallos).
  **Java 8:** NVD lo lista por actualización exacta (`1.8.0` + `update401`; con guion bajo `update_401` da 0, trampa evitada). winget da `8.0.4010.10` = 8u401 (tercer número = actualización × 10); solo se traduce la forma exacta `8.0.<N>0.<compilación>`,
  el resto (Java 11/17, formas raras) no se adivina. El criterio de NVD debe nombrar la MISMA actualización (402 no hereda los fallos de 401; no por prefijo). Java 8u401 del equipo: 9 fallos reales (CVE-2023-41993 explotado, y ocho de Oracle 2024).
  Solo versiones puramente numéricas de 2 a 4 partes (Java 8 aparte).
- **Hallazgo real (importante):** NVD devuelve también CVE que solo nombran al producto como PLATAFORMA (`vulnerable:false`). Node.js 24.15.0 daba 8, pero 2 eran de Next.js (CVE-2021-43803, CVE-2022-36046): falsa alarma de «crítico explotado».
  Ahora un CVE cuenta solo si un `cpeMatch` con `vulnerable:true` es de ESTE producto y su rango de versiones incluye la instalada (límites incluidos/excluidos probados). Quedan 6 reales (el de Brotli CVE-2026-111497 está en la lista CISA).
  También: puntaje CVSS primario preferido sobre el secundario; CVE «Rejected» no cuentan; un explotado sube a Alta como mínimo.
- **Páginas parciales:** Chrome 100 tiene 4776 coincidencias; se piden 2000. Una página llena legítima (primera, `resultsPerPage` = recibidos) se acepta como PARCIAL («Al menos N…»); cualquier otro desajuste es respuesta cortada. Página llena sin ningún afectado → «no se pudo comprobar».
- **Pruebas:** `Nexo.Vuln.Demo` §16–21 con respuestas REALES de NVD embebidas (`Datos/nvd-winrar-7.01.json`, `nvd-nodejs-24.15.0.json`); `Nexo.Desktop.Demo` (`SeguridadCvePruebas.cs`); todas las reglas con dientes (rotas a propósito: 27). Se descubrió con la rotura que `\d` de .NET acepta dígitos Unicode y `$` acepta un `\n` final: ahora `[0-9]` y `\z`.
- **Prueba REAL (HP):** `dotnet run --project tools/Nexo.Vuln.Windows.Demo -- --nvd` (sale a Internet, ~2,5 min). 8 controles con versión vieja → todos con fallos; este equipo: WinRAR 7.01 → CVE-2025-8088 y CVE-2025-6218 (explotados) y CVE-2025-31334; Node.js 24.15.0 → 6; Git 2.54.0 → ninguno. 18 de 21 aplicaciones no están en el mapa.
- **SIN PROBAR / límites:** la ventana real con el botón (solo modelo y pantalla simulada); Java 11/17 y el JDK de Oracle no se cruzan todavía; un CPE de NVD puede cambiar y devolver 0 (los controles `--nvd` lo detectan: repetirlos de vez en cuando); sin clave de NVD el límite es estricto.
  El usuario tiene WinRAR 7.01 con fallos explotados: debe actualizar con `winget upgrade --id RARLab.WinRAR` (Nexo no lo actualiza).

## 2aa. La bóveda se bloquea al minimizar y al bloquear Windows (2026-11-07, en el HP)

Antes la bóveda solo se bloqueaba a mano, al cerrar o tras 5 min sin usar la ventana. Ahora también cuando el equipo deja de estar a la vista.

- **Disparadores:** minimizar la ventana (`MainWindow`, cambio de `WindowState`) y, en Windows, `VigilanteDeSesionWindows` (`Nucleo/VigilanteDeSesion.cs`, escucha `SystemEvents`): sesión bloqueada, cierre de sesión, desconexión (consola o escritorio remoto) y suspensión.
  Desbloquear la sesión, reanudar, conectar o cambiar batería/corriente NO bloquean. Restaurar la ventana NO desbloquea la bóveda.
- **Modelo:** `ContrasenasModelo.BloquearPorSeguridad(motivo)`: solo actúa con la bóveda abierta. Si hay una operación en curso (guardar, copia…) NO la interrumpe: queda pendiente y bloquea al terminar. Bloquear borra el portapapeles si sigue siendo lo que puso Nexo (como siempre).
- **Dependencia nueva (gratuita, oficial de Microsoft, solo `net8.0-windows`):** `Microsoft.Win32.SystemEvents` 8.0.0. Sin P/Invoke propio.
- **Pruebas:** `Nexo.Desktop.Demo` (modelo con operación en curso, ventana minimizada con contraseña copiada, restaurar no desbloquea, motivo de sesión) y `Nexo.Vuln.Windows.Demo` §8 (mapeo de eventos y suscripción REAL a `SystemEvents`); todas las reglas rotas a propósito (8). Se quitó una línea redundante que la rotura demostró sin efecto.
- **SIN PROBAR:** un bloqueo REAL de la sesión de Windows o una suspensión real (lo haría el usuario: Win+L con la bóveda abierta debería mostrarla bloqueada al volver); minimizar con clic real en la ventana. Un minimizado por «Mostrar escritorio» (Win+D) debería contar igual; sin comprobar.

## 2ab. Rastro de la ventana en el vault de reportes (2026-11-07, en el HP)

Las revisiones de Seguridad y la bóveda corrían en el proceso de la ventana y no dejaban nada en el vault. Decisión del usuario (AskUserQuestion): que la ventana avise al servicio por el pipe y el servicio escriba.
La ventana NO escribe en el vault (es del servicio, de SYSTEM): dos procesos en la misma nota y cualquier programa podría colar eventos falsos.

- **Servicio:** `ModuloRastroDeVentana` (`ventana.registrar`, ya cableado en `NexoWorker`; `estado` ahora lista 27 métodos). El cliente solo envía una CLAVE de un catálogo fijo y pocos campos acotados; el TEXTO del evento lo pone siempre el servicio.
  Claves: `seguridad.cuentas|wifi|aplicaciones|fallos_conocidos` (hallazgos 0–1000, gravedad máxima, completa) y `boveda.creada|desbloqueada(entradas)|bloqueada(motivo: manual/inactividad/minimizar/sesion/cierre)|fallo_de_desbloqueo|copia_guardada|restaurada|auditoria(comprobadas, comprometidas)`.
  Se rechaza (no se ignora) todo campo que el tipo no admite, valores fuera de rango o de otro tipo, gravedad sin hallazgos, más comprometidas que comprobadas. Tope: 2 s entre avisos iguales y 120 por hora; lo no registrado se dice (`registrado: false`).
  Cada nota dice «informado por la ventana; el servicio no lo comprobó» (un proceso del mismo usuario podría mentir). Tipos nuevos en `TipoEvento`: `BovedaBloqueada`, `BovedaCopiaGuardada`, `BovedaRestaurada`, `BovedaAuditada`.
- **Ventana:** `IRastroDeVentana` (`Nucleo/Rastro.cs`; `RastroPorPipe` en Windows, `RastroNulo` sin servicio). Mejor esfuerzo, en segundo plano, se traga cualquier fallo: sin servicio simplemente no queda rastro (la ventana no lo presenta como registrado). `SeguridadModelo` avisa al terminar cada revisión
  (una revisión que falla se avisa como incompleta: lo desconocido no es «bien»; las notas Info no cuentan como hallazgos); `ContrasenasModelo` avisa creación, desbloqueo, intento fallido, bloqueo con su motivo, copia, restauración y auditoría. **Nunca** sitios, usuarios, contraseñas, rutas, nombres de redes/cuentas/programas.
- **Defecto encontrado por las pruebas:** `ContrasenasModelo` ya tenía un `Avisar(string)` que notifica cambios de propiedad; mis llamadas sin datos caían ahí en silencio. Renombrado a `AvisarRastro`. Moraleja: los avisos sin campos de un método con el mismo nombre se resuelven al más específico.
- **Pruebas:** `Nexo.Service.Demo` (módulo con 30+ casos, escritura en vault REAL, y de punta a punta por el pipe real), `Nexo.Desktop.Demo` (`RastroPruebas.cs`: qué se avisa, que no se filtra contenido, que un rastro que lanza no rompe nada); 15 reglas rotas a propósito (la de «contar Info» se detecta por caída del proceso).
- **SIN PROBAR:** `RastroPorPipe` contra el servicio real instalado como SYSTEM con la ventana real (solo el módulo por el pipe de la prueba y el modelo con un rastro falso); que las notas se lean bien en Obsidian; si hace falta permitir el método a usuarios no administradores (el pipe ya admite al usuario; sin comprobar con una cuenta estándar).

## 2ac. Códigos 2FA (TOTP) en la bóveda (2026-11-07, en el HP)

Cada entrada puede guardar la clave 2FA del sitio y la ventana copia el código de 6 dígitos del momento. Todo local, gratuito, sin red. No venía en el Prompt 3; lo pidió la recomendación (gestor moderno).

- **Núcleo:** `GeneradorDeTotp` (`Nexo.Modules.Identity/Boveda`): HOTP (RFC 4226) y TOTP (RFC 6238) con SHA1/SHA256/SHA512, 6–8 dígitos, periodo 15–120 s; acepta la clave en base32 (sin distinguir mayúsculas, ignora espacios y guiones) o el enlace `otpauth://totp/...`.
  **Se rechaza (no se adivina):** HOTP por contador, algoritmo o dígitos o periodo fuera de lo admitido, parámetros repetidos, clave no base32, de menos de 10 bytes o de más de 128. Un código calculado con parámetros distintos sería uno que no funciona y nadie sabría por qué.
- **Bóveda:** `EntradaDeBoveda.Totp` (campo opcional con valor por omisión: las bóvedas anteriores se leen con el 2FA vacío; formato del archivo SIN cambio de versión). `AgregarAsync(..., totp)` y `ActualizarAsync(..., totp)`: `null` conserva, `""` quita; una clave inválida se rechaza al guardar. Va cifrada como todo (comprobado que no aparece en el archivo).
  **Aviso para bajar de versión:** un Nexo anterior ignoraría el campo y lo perdería al volver a guardar.
- **Ventana:** campo «Clave 2FA» en el formulario (enmascarado, sigue el botón «Mostrar») y botón «Copiar código 2FA» (solo si la entrada tiene clave). El código se calcula al pulsar (no se guarda), se borra del portapapeles a los 30 s como la contraseña (y al bloquear), y el mensaje dice cuántos segundos le quedan, con aviso si faltan 5 o menos. El mensaje NO repite el código ni la clave.
- **Pruebas:** `Nexo.Identity.Demo` (vectores OFICIALES: RFC 4226 contadores 0–9; RFC 6238 SHA1/SHA256/SHA512 en 6 instantes; RFC 4648 base32; rechazos; bóveda con persistencia, cifrado y compatibilidad) y `Nexo.Desktop.Demo` (`TotpPruebas.cs`); 17 reglas rotas a propósito, todas detectadas
  (dos pruebas mías flojas se encontraron así: una comprobación vacía con `|| true` y un reinicio del formulario que nunca se ejercitaba).
- **SIN PROBAR:** contra un sitio real (comparar con el código de una app como Google Authenticator con la misma clave: es la prueba definitiva y la haría el usuario); el botón con clic real; relojes del equipo desajustados (el código usa la hora del equipo: si está atrasada, los sitios lo rechazan).
  No hay lectura de códigos QR (el usuario pega la clave o el enlace); no hay formato de Steam ni HOTP.

## 2ad. Cámara y micrófono: qué programas los usaron (2026-11-07, en el HP)

Quinta sección de la pestaña «Seguridad» («Cámara y micrófono»). Solo LECTURA del registro de uso que Windows lleva (`HKCU\...\CapabilityAccessManager\ConsentStore\webcam|microphone`), local, sin red; entra en «Revisar todo». Del módulo de privacidad (Prompt 2, punto 5).
**Nexo no bloquea nada**: cambiar el permiso de un dispositivo se hace en Configuración de Windows > Privacidad (el Prompt pide «consultar y restringir», pero restringir exige tocar permisos del sistema y no se hace sin vista previa; queda como hueco).

- **Piezas:** `Nexo.Modules.Threats/Vulnerabilidades/ModeloDeDispositivos.cs` (`AnalizadorDeDispositivos`, portable) y `Nexo.Modules.Threats.Windows/LectorDeDispositivosWindows.cs` (registro; por usuario: corre en la ventana, NO por el servicio SYSTEM, que vería su propio perfil).
  Rastro: `seguridad.dispositivos` (módulo Privacidad, `TipoEvento.AccesoDispositivo`).
- **Formato real observado:** programas normales en `...\NonPackaged\<ruta con «#» en vez de «\»>`; aplicaciones de la Tienda por nombre de familia del paquete; valores `Value` (Allow/Deny/Prompt) y `LastUsedTimeStart/Stop` (QWORD FILETIME). Permiso global: HKCU y HKLM (si cualquiera está en Deny, está apagado).
- **Hallazgos:** `DISP-RECIENTE` (Info: cuántos programas usaron el dispositivo en 7 días, con nombres, sin repetir), `DISP-CARPETA-RARA` (Media: lo usó en los últimos 30 días y vive en Temp/Descargas/Papelera/carpeta pública; dice que NO prueba que sea malicioso),
  `DISP-EN-USO` (Info) y `DISP-BLOQUEADO` (Info: apagado en Windows).
- **Hallazgo real que cambió el diseño:** `fin = 0` NO basta para «en uso ahora». En este equipo había 4 filas con fin = 0 de versiones viejas de Discord (junio a octubre) con Discord abierto: Windows nunca cerró esas filas.
  Ahora «en uso» exige fin = 0 Y inicio en las últimas 24 h, y un aviso por programa (no por ruta). Hoy: 0 en uso, 8 programas con el micrófono esta semana, ninguno con la cámara.
- **Honestidad:** nunca «nadie la usó» (Windows apunta lo que ve; un programa que no pase por ahí puede no figurar); almacén ausente o error = «no evaluado»; entradas ilegibles = revisión incompleta; un FILETIME imposible o en el futuro se ignora;
  gramática por dispositivo («la cámara», «el micrófono»; las pruebas cazaron «la micrófono»).
- **Pruebas:** `Nexo.Vuln.Demo` §22 (FILETIME REALES, el caso Discord, límites de 7 días / 24 h / 30 días, rutas raras y normales, fechas imposibles, tildes) con 11 reglas rotas a propósito;
  `Nexo.Vuln.Windows.Demo` §9 contra el registro real y cruzado con PowerShell (cámara 9, micrófono 69 = 13 de la Tienda + 56 normales, 9 filas recientes, 4 sin fin: coincide).
- **SIN PROBAR / huecos:** con la cámara realmente en uso (la tendría que activar el usuario: abrir la app Cámara y ver si sale «en uso ahora»); que un programa que accede por otro camino (controlador propio) figure; restringir permisos por programa (no hecho);
  las aplicaciones de la Tienda no tienen ruta y no se evalúan por carpeta.

## 2ae. Anti-phishing: revisar un mensaje o un enlace (2026-11-09, en el HP)

Pestaña nueva «Enlaces» (la décima, al final). Del módulo de privacidad (Prompt 2, punto 3, en su «versión reducida y realista»: reglas y listas, sin modelo de deepfakes). Se pega un SMS, correo o mensaje de WhatsApp (o un enlace suelto) y Nexo dice Peligroso / Sospechoso / Sin señales conocidas, enlace por enlace.
**Nexo nunca abre el enlace, no lo resuelve (DNS) ni pregunta a ningún servidor por él**: todo se compara en el equipo. El texto pegado no se guarda. Corre en el proceso de la ventana, con el usuario (no por el servicio).

- **Listas (gratis, sin cuenta; comprobado el 2026-11-09):** Phishing Army (`phishing.army`, 144 115 dominios, recopila PhishTank, OpenPhish, CERT.PL y otras; uso personal) y el feed comunitario de OpenPhish (300 direcciones; uso no comercial), pedido directo a `raw.githubusercontent.com/openphish/public_feed/...` porque `openphish.com/feed.txt` redirige allí y no se siguen redirecciones.
  **URLhaus ya NO sirve sin cuenta** (los feeds de texto devuelven 410: abuse.ch ahora exige clave). PhishTank no admite registros nuevos. Google Safe Browsing se descartó (cuenta de Google Cloud; y la Salida 6 ya decía que aporta poco porque Chrome/Edge lo traen).
- **Descarga:** solo con «Actualizar listas», con aviso previo (por omisión «No»). Direcciones fijas, HTTPS, sin redirecciones ni cookies, User-Agent genérico, tope de 32 MB. Lo único que sale es la petición de la lista entera. No se vuelve a pedir una lista bajada hace menos de 1 h.
  Se guardan tal cual en `%LOCALAPPDATA%\Nexo\listas\` (escritura atómica + `.fecha`). Es estado, no un log.
- **Validación (una lista que no pasa se rechaza ENTERA y se sigue usando la anterior):** Phishing Army exige «Format: domains» y que los dominios válidos sean EXACTAMENTE los de «Entries: N» (así se detecta una descarga cortada), y un mínimo de 1000; una fecha «Generated» en el futuro no se cree. OpenPhish: más del 2 % de líneas que no son direcciones web (p. ej. una página HTML servida con 200) o menos de 20 direcciones = rechazada. Al cargar de disco se vuelve a validar.
- **Piezas:** `Nexo.Modules.Threats/Enlaces/` (portable): `ExtractorDeEnlaces` (http/https, «www.» y el nombre suelto de los SMS, este último solo si termina en una terminación real de la lista de IANA embebida en `Datos/tlds-iana.txt`, versión 2026110900, para no tomar «p.ej.» o «EE.UU.» por enlaces; quita la puntuación de fin de frase; tope de 20 000 caracteres y 50 enlaces),
  `NormalizadorDeEnlaces`, `ListasDePhishing`/`ParserDeListas`, `CatalogoDeMarcas` (29 marcas suplantadas en Chile con sus dominios oficiales; NO exhaustiva), `AnalizadorDeMensajes`, `AlmacenDeListas` y `DescargaDeListasHttp`. Ventana: `EnlacesModelo.cs` (+ `ResumirEnlaces`).
  Rastro: `enlaces.revision` (Privacidad, `TipoEvento.MensajeRevisado`), solo conteos y gravedad: nunca el texto, los enlaces ni los sitios.
- **Reglas por enlace:** en Phishing Army (el sitio o un dominio que lo contiene, sin subir nunca a «com» ni a «co.uk»/«com.ar») o dirección exacta en OpenPhish = Alta; otra página del mismo sitio en OpenPhish = Media; «@» que esconde el sitio real = Alta; imita una marca (nombre tal cual en un sitio ajeno, números por letras «paypa1», «rn» por «m», letras cirílicas/griegas gemelas) = Alta;
  a una letra de una marca larga («steamcomunity») = Media; la marca exacta con otra terminación de país («santander.de») = solo nota, salvo terminaciones de estafa («santander.tk» = Alta); letras de alfabetos mezclados = Alta; `xn--` inválido = Media; IP en vez de nombre (también en decimal/hex/octal: .NET las normaliza) = Media; acortador = Media (no se abre para averiguar el destino: avisaría al estafador);
  `http://` escrito = Baja (si el usuario no escribió esquema no se le acusa); puerto raro y terminaciones baratas (.top, .xyz, .tk…) = Baja. Un dominio oficial lleva una nota Info que recuerda que el mensaje puede mentir.
- **Reglas del mensaje (solo español, sin tildes ni mayúsculas):** pide claves/códigos/datos + enlace = Alta; sin enlace = Media. Si el mensaje ADVIERTE («nunca te pediremos tu clave») o todos sus enlaces son oficiales baja a Media, y si pasan las dos cosas (el SMS real típico del banco) a Baja; no se quita, porque un estafador puede copiar la advertencia (probado: sigue Peligroso por el enlace).
  Presión: dos o más de urgencia / pagos-envíos retenidos / premios = Media; una sola = Baja. Las frases se citan enteras. «clave de sol» cuenta como clave (límite conocido: no se entiende el sentido).
- **Honestidad:** nunca verde, tampoco por enlace («Sin señales conocidas (esto NO prueba que sea seguro)», en gris). Sin listas o con listas de más de 7 días = revisión incompleta (manda la fecha de la propia lista, no la de descarga). Enlace ininterpretable = se nombra. Si el texto cambia, o se actualizan las listas, el veredicto anterior desaparece. La pestaña dice que no analiza audio ni video (deepfakes).
- **Pruebas:** `tools/Nexo.Enlaces.Demo` (nuevo, 117) con el feed REAL de OpenPhish del 2026-11-09 embebido y casos reales («www.roblox.com.ml», «hkdiscord.antsoon.com», «…mail.santander-serfin.com»); 13 reglas rotas a propósito, todas cazadas. `Nexo.Desktop.Demo` (`EnlacesPruebas.cs`: modelo y pestaña real sin pantalla, con captura), 3 reglas rotas a propósito;
  una rotura inicial «sin dientes» (enlace «sin señales» en verde) llevó a añadir la comprobación del color por enlace. Las pruebas cazaron un defecto real: la pestaña decía «sin leer todavía» tras leer las listas (la marca se calculaba dentro de la tarea de carga, que aún no figuraba como terminada).
- **Prueba REAL (HP):** `dotnet run --project tools/Nexo.Enlaces.Demo -- --real` (sale a Internet): las dos listas reales se bajan, validan, guardan y recargan (≈0,1 s); una dirección de la lista de hoy pegada en un mensaje sale Peligrosa con revisión completa. Lección: la lista trae `amiprotected.it` Y `www.amiprotected.it` (gana la más específica).
  Ninguno de los 32 dominios oficiales del catálogo (ni sus subdominios) está en la lista real: sin falsas alarmas por ese lado.
- **Prueba con PANTALLA REAL (HP, 2026-11-09, con permiso del usuario):** `nexo-desktop.exe --pipe NexoPruebaEnlaces` (sin servicio a propósito), manejada por UI Automation (botones por nombre dentro del proceso de Nexo; sin ratón ni coordenadas; ayudante `uia.ps1` en el scratchpad de esa sesión).
  Sin listas: SMS falso de Correos = Peligroso + «revisión incompleta». Diálogo real «Actualizar listas» en español (Sí/No): con «No» no descarga ni crea la carpeta y el resultado sigue; con «Sí» bajó 144 115 + 300 a `%LOCALAPPDATA%\Nexo\listas` (se quedan ahí para uso real) y borró el veredicto anterior avisando.
  Con listas: una dirección real de OpenPhish de ese día coincidió en las DOS listas (Peligroso) y `www.bancoestado.cl` salió gris como oficial, revisión completa; cambiar el texto devuelve «Sin revisar»; «Borrar» vacía la caja. Lecciones del ayudante: `InvokePattern.Invoke` de un botón que abre un diálogo modal bloquea (lanzarlo en un hilo de C#, no en un bloque de PowerShell sin runspace); en PowerShell `$t` y `$T` son la misma variable.
- **SIN PROBAR / huecos:** el rastro en el vault con el servicio real (la prueba se hizo sin servicio); la lista de marcas es corta y los dominios oficiales hay que revisarlos de vez en cuando; la lista de IANA embebida se actualiza a mano; no hay revisión de remitente (número o correo) ni del portapapeles automático; un sitio de phishing nuevo no está en ninguna lista durante horas o días.

## 2af. Anti-phishing: quién lo envía y «dice ser X, pero el enlace no es de X» (2026-11-09, en el HP)

Amplía §2ae. Campo opcional «Quién lo envía» (número o correo) en la pestaña «Enlaces». Sigue todo local.

- **«Dice ser»:** cada marca del catálogo tiene ahora `Menciones` (cómo se nombra en un mensaje que dice venir de ella: «bancoestado», «banco estado», «cuentarut», «correos de chile», «sii», «impuestos internos», «mach», «cmr»…), buscadas sin tildes y como palabra entera.
  Las plataformas que se nombran a diario (WhatsApp, Google, Instagram, Facebook, Discord, Roblox, Riot) NO tienen menciones: nombrarlas no es decir ser ellas. **Los enlaces se quitan del texto antes de buscar menciones** (un enlace a bancoestado.cl no es «decir ser» BancoEstado; lo detectó el diseño antes de que saliera en pruebas). Un remitente de SMS cuyo nombre es exactamente una marca también cuenta como «dice ser».
- **`ENL-NO-ES-DE-LA-MARCA` (Media):** el mensaje dice ser X y el enlace no es de X ni de otra marca conocida. Es lo que delata a un sitio NUEVO que aún no está en ninguna lista (antes salía «sin señales»). No se repite si el enlace ya «imita» a la marca.
  Se dejó en Media a propósito (no Alta): las tiendas mandan promociones legítimas con enlaces de servicios de envío externos y con urgencia. Si además pide claves, ya sale Peligroso por `MSJ-PIDE-CLAVES`.
- **Remitente (`AnalizadorDeRemitente`):** correo (con o sin «Nombre <correo>»), celular chileno (+56 9, 9 cifras o 56…), extranjero (+ sin 56), número corto (3-6 cifras), otro número, o nombre de SMS. Hallazgos: correo desde un dominio de la lista = Alta; correo gratuito (gmail, hotmail, outlook, yahoo, icloud, proton…) que dice ser una empresa = Alta (sin decir ser nadie: nada);
  dominio que imita una marca = Alta (a una letra = Media); dice ser X desde otro dominio = Media (hay envíos externos legítimos, y se dice); dominio oficial de la marca que dice ser = solo Info, recordando que **el remitente se puede falsificar y Nexo no puede comprobarlo** (no ve SPF/DKIM ni la red del operador);
  celular común que dice ser una empresa = Media; extranjero = Baja (Media si dice ser una empresa); nombre de SMS = Info «se puede falsificar» (los estafadores logran caer en la misma conversación que el banco), o Alta si imita («BancoEstad0»). Un remitente que no se entiende = «no evaluado».
- **Pruebas:** `Nexo.Enlaces.Demo` §12-13 (152 en total), con casos que NO deben saltar (gmail o celular de una persona, «los correos de ayer», «Machuca» no es MACH, un enlace oficial de otra marca en una compra); 11 reglas rotas a propósito, todas cazadas. `Nexo.Desktop.Demo` (576): el campo en el modelo y en la pestaña real sin pantalla; cambiar el remitente borra el resultado; «Borrar» vacía las dos cajas.
- **SIN PROBAR:** el campo nuevo con pantalla real (la prueba real de §2ae fue antes de añadirlo); que las menciones cubran cómo escriben de verdad los estafadores (faltan ejemplos reales de SMS chilenos para afinar).

## 2ag. Anti-phishing: códigos QR y lo que un QR puede hacer (2026-11-09, en el HP)

Botón «Revisar un QR (imagen)...» en la pestaña «Enlaces»: se elige una captura o foto, Nexo lee sus QR en el equipo y pone el contenido en la caja del mensaje («Esto es lo que contiene el código QR de «x.png» (Nexo no lo abrió):») y lo revisa con las mismas reglas. Contra el «quishing» (QR pegados encima de los reales, QR en correos).

- **Piezas:** `Nexo.Modules.Threats/Enlaces/LectorDeQr.cs` (ZXing.Net 0.16.11, Apache-2.0, sin dependencias; recibe píxeles BGRA, así el módulo no depende de ninguna librería gráfica) y `Nexo.Ui.Desktop/ImagenDeQr.cs` (abre PNG/JPG/BMP/GIF/WEBP con SkiaSharp 2.88.9, que ya venía con Avalonia). `EnlacesModelo.RevisarQrAsync` y `OrigenDelTexto`.
- **Defensas ante imágenes hechas para dañar:** archivo de más de 25 MB se corta al pasar el tope (no se lee entero); el tamaño en píxeles se mira con `SKCodec` ANTES de decodificar (tope 40 MP: un PNG de 53 bytes que declara 20 000 × 20 000 se rechaza sin reservar 1,6 GB); datos más cortos que la imagen que dicen ser = rechazo; imagen cortada sin QR = se dice. Hasta 5 códigos por imagen y 4000 caracteres por código.
- **Hallazgo real:** `TryInverted` de ZXing NO se aplica al leer varios códigos (`DecodeMultiple`): un QR blanco sobre negro no salía. Ahora hay un segundo intento con la imagen invertida.
- **Lo que un QR (o un mensaje) puede hacer además de abrir un enlace** (`AnalizadorDeMensajes.RevisarAcciones`): unirse a una red Wi-Fi (`WIFI:`; abierta o sin tipo = Media, WEP = Media, WPA = nota; **la contraseña jamás se muestra**; entiende `\;` y campos en cualquier orden), enviar un SMS (`SMSTO:`/`SMS:`, Media: puede cobrar o suscribir), llamar (`tel:`, Baja) y pagar con criptomonedas (`bitcoin:`… con dirección, Media). Hablar de «wifi», «tel:» o «bitcoin:» en un texto normal no salta.
- **Honestidad:** sin QR, el texto que había no se toca y se dice por qué; si el usuario edita el texto, deja de presentarse como «lo que decía el QR»; leer un QR no descarga nada ni abre nada.
- **Pruebas:** `Nexo.Enlaces.Demo` §15-16 (QR generados con el escritor de ZXing: normal, invertido, girado 90°, dos en una imagen, con tildes; rechazos), 171 en total; `Nexo.Desktop.Demo` (`QrVentanaPruebas.cs`, 589): PNG y JPG reales, archivo que no es imagen, la trampa de 20 000 × 20 000, PNG cortado, más de 25 MB, y el modelo.
  **QR REALES de otro generador** (api.qrserver.com, no ZXing) embebidos en `tools/Nexo.Desktop.Demo/Datos/`: un PNG de 1 bit con paleta y un JPG de Wi-Fi; se leen los dos. 6 reglas rotas a propósito, todas cazadas. NO se rompió el tope de píxeles a propósito (la prueba intentaría reservar 1,6 GB); lo cubre la prueba directa de la imagen trampa.
- **Prueba con PANTALLA REAL (HP, 2026-11-09, con permiso del usuario; también cubre el remitente de §2af):** misma forma que en §2ae (UI Automation, sin ratón, sin servicio). Remitente `soporte.bancoestado@gmail.com` + «su clave vence hoy» + un sitio que no está en ninguna lista: Peligroso, con «dice ser BancoEstado desde un correo gratuito» (Alta) y el enlace ajeno «Sospechoso».
  Botón «Revisar un QR (imagen)...» con el **selector de archivos nativo** de Windows: el JPG de Wi-Fi del generador externo puso `WIFI:S:Cafe Libre;T:nopass;;` en la caja, con la línea de origen, y salió Sospechoso (red abierta); el PNG oficial de BancoEstado salió «Sin señales conocidas (esto NO prueba que sea seguro)». «Borrar» quita también la línea de origen.
  Cambio tras verlo en pantalla: la línea de origen decía «Esto es lo que contiene el código QR…:» apuntando hacia abajo, pero el contenido está ARRIBA (en la caja); ahora «Arriba está lo que contiene…».
  Lecciones del ayudante: en el selector nativo los controles salen como «panel» sin patrón de texto, y en su lista de archivos hay elementos con id «1», «2» como los botones: hay que buscar por clase Y id (`Edit` 1148, `Button` 1 con nombre «Abrir») y usar WM_SETTEXT/BM_CLICK sobre esos dos controles; si se pulsa «Abrir» justo al aparecer el selector, se ignora (esperar a que termine de cargar).
  Ojo: UI Automation puede pulsar botones de la ventana principal aunque haya un diálogo modal abierto (una persona no podría); no es un fallo de Nexo, pero una prueba automática puede hacer cosas imposibles a mano.
- **SIN PROBAR:** fotos de QR hechas con cámara (perspectiva, reflejos, desenfoque); pegar una imagen desde el portapapeles (no hecho).
- **Descartado por ahora (anotado para no repetir el análisis):** restringir la cámara/micrófono por programa (Windows solo aplica el permiso por aplicación a las de la Tienda; para los programas de escritorio hay un único interruptor global, así que prometerlo sería engañoso); bloquear rastreadores con el archivo `hosts` (Defender marca esas modificaciones como `HostsFileHijack` y un `hosts` grande ralentiza la resolución de nombres de Windows).

## 2ah. VPN, paso 1: revisar archivos de WireGuard y ver el estado (2026-11-09, en el HP)

Pestaña nueva «VPN» (la undécima). Del módulo de privacidad (Prompt 2, punto 1). Decisión ya tomada (memoria del proyecto): **Nexo es solo el cliente**; usa el WireGuard oficial para Windows (gratuito, MIT) y un archivo `.conf` del proveedor que elija el usuario. Sin servidor propio ni nada de pago. Este paso es de **SOLO LECTURA**: conectar/desconectar (necesita administrador) será el paso 2, por el servicio con aprobación.

- **Fuentes (leídas el 2026-11-09):** documentación oficial `docs/enterprise.md` y `docs/adminregistry.md` (túneles con `wireguard /installtunnelservice <ruta.conf>` y `/uninstalltunnelservice <nombre>`, servicio `WireGuardTunnel$nombre`; PreUp/PostUp solo corren con `HKLM\Software\WireGuard\DangerousScriptExecution`, y entonces como SYSTEM; `wg show` exige administrador) y el código de wireguard-windows `conf/parser.go` y `conf/name.go`.
- **`ParserDeWireGuard` (portable, `Nexo.Modules.Threats/Vpn/`) con las MISMAS reglas que WireGuard para Windows:** claves y secciones sin distinguir mayúsculas; clave desconocida, línea fuera de sección o valor vacío = error (WireGuard no los ignora); claves base64 de exactamente 32 bytes; MTU 576-65535; keepalive «off» o 0-65535; Table off/auto/main/entero; nombre de túnel `^[a-zA-Z0-9_=+.-]{1,32}$`, sin nombres reservados de Windows (también «nul.algo»), sin empezar ni terminar en punto.
  Errores con número de línea. **La clave privada y la compartida NO se guardan**: se validan y se descartan (probado serializando todo el resultado y buscándolas). El nombre mal es aparte del contenido (basta renombrar el archivo).
- **`AnalizadorDeVpn`:** comandos PreUp/PostUp/PreDown/PostDown = Alta (se muestran; dice que WireGuard no los ejecuta salvo con la clave del registro, y que entonces serían SYSTEM); todo IPv4 sin IPv6 (`0.0.0.0/0` o las dos mitades `/1`, sin `::/0`) = Media «el IPv6 puede salir por fuera»; todo por la VPN sin DNS = Media; túnel parcial = nota (no se acusan fugas en una VPN de trabajo); peer sin Endpoint = Media;
  servidor en la lista de phishing = Alta; varios servidores, MTU < 1280 (Baja), y siempre: «te conectarás a X: ese servidor ve todo; una VPN no te hace anónimo» y «el archivo contiene tu clave privada». Las fugas se describen como lo que el archivo PERMITE, no como algo medido en la red.
- **`LectorDeWireGuardWindows` (Threats.Windows, paquete oficial `System.ServiceProcess.ServiceController` 8.0.1, MIT):** `wireguard.exe` en Archivos de programa (+ versión) y servicios `WireGuardTunnel$*` con su estado; sin administrador, no ejecuta nada. «Activo» = lo que Windows dice del servicio; que el servidor responda no se afirma (gris, nunca verde). Un error al leer servicios = «no se pudo saber», nunca «no instalado».
- **Ventana:** `VpnModelo.cs` (+ `ResumirVpn`): estado al entrar en la pestaña; «Elegir archivo .conf...» (selector nativo) revisa sin instalar, copiar ni conectar; el servidor se cruza con las listas de phishing ya cargadas por «Enlaces» (`EnlacesModelo.ListasActuales`). Rastro `vpn.revision` (Privacidad, `TipoEvento.ConfiguracionVpnRevisada`), solo conteos.
- **Pruebas:** `tools/Nexo.Vpn.Demo` (nuevo, 55) con 10 reglas rotas a propósito, todas cazadas (dos pruebas se reforzaron por la rotura: la de las mitades IPv4 sola y la de nombres reservados, que se caía en vez de informar); `Nexo.Desktop.Demo` (`VpnPruebas.cs`, 608 en total) con 2 roturas cazadas; `Nexo.Vuln.Windows.Demo` §10 contra el equipo real: WireGuard NO instalado, 0 túneles, cruzado con PowerShell (`Get-Service WireGuard*` = 0).
- **SIN PROBAR:** con WireGuard instalado y túneles reales (no está instalado en el HP); con un `.conf` real de un proveedor (las pruebas usan la forma típica con claves aleatorias); la pestaña con pantalla real.
- **Paso 2 (pendiente):** conectar/desconectar por el servicio (SYSTEM) con vista previa, token y aprobación: copiar el `.conf` validado a una carpeta solo de SYSTEM/administradores (la documentación no dice si `/installtunnelservice` relee el archivo en cada arranque: no dejarlo en una carpeta que el usuario pueda modificar), `wireguard /installtunnelservice`, y estado con `wg show` como SYSTEM. Requiere instalar WireGuard (preguntar al usuario).

## 2ai. VPN, paso 2: conectar y desconectar por el servicio, con aprobación (2026-11-09, en el HP)

Mismo camino que el firewall: `vpn.previsualizar` (no cambia nada; token de 10 min) → la ventana muestra el plan y pide confirmar → `vpn.aplicar` con el token, exigiendo la aprobación (UAC) ANTES de gastarlo y volviendo a mirar el estado. Nuevo `TipoDeAccion.Vpn` en `AccionesDelServicio` (la bandeja elevada lo aplica igual que los demás).

- **Reglas (`PlanificadorDeVpn`, portable):** sin WireGuard o sin saber su estado, nada. Solo se conecta un archivo que WireGuard aceptaría, con nombre válido, **sin comandos** (PreUp/PostUp…: rechazado aunque WireGuard no los ejecute) y sin hallazgos Alta (p. ej. servidor en la lista de phishing). No se pisa un túnel existente con el mismo nombre (sin distinguir mayúsculas). Lo Media (fuga IPv6, sin DNS) y otro túnel activo NO impiden conectar, pero se avisan en la vista previa.
  **Solo se desconectan los túneles que instaló Nexo** (su archivo está en la carpeta de Nexo); los demás, desde WireGuard. Al aplicar se vuelve a mirar: si mientras tanto apareció un túnel con ese nombre, WireGuard se desinstaló, o el túnel dejó de existir o de ser de Nexo, no se toca nada y se dice.
  La vista previa dice dónde se guarda la copia, qué servicio se crea (`WireGuardTunnel$nombre`) y por dónde pasará el tráfico («que lo verá todo»), o qué redes si el túnel es parcial.
- **`EjecutorDeWireGuardWindows` (Threats.Windows, corre como SYSTEM en el servicio):** guarda el archivo en `%ProgramData%\Nexo\vpn\<túnel>.conf` con un DACL **protegido** (sin herencia) solo para SYSTEM y Administradores (la documentación no dice si el túnel relee el archivo en cada arranque: no puede quedar donde el usuario lo cambie); si no puede fijar esos permisos, no instala.
  Ejecuta `wireguard.exe` de Archivos de programa **sin shell y con argumentos separados** (`/installtunnelservice <ruta>`, `/uninstalltunnelservice <nombre>`), tope de 60 s, vuelve a validar el nombre; tras instalar comprueba que el servicio exista (y si está en marcha); si falla, borra la copia. «En marcha» no es «el servidor responde» y se dice.
- **`ModuloVpn` (servicio):** `vpn.estado` (con qué túneles son de Nexo), `vpn.previsualizar` (`conectar` con `conf` ≤ 64 KB y `archivo`, o `desconectar` con `tunel`), `vpn.aplicar`. Parámetros validados (tipo, texto, largos). Deja en el vault «VPN conectada/desconectada: túnel» (`TipoEvento.ConexionVpn`) con el resultado; **el archivo (con la clave privada) nunca va al vault** ni a las respuestas. El texto del archivo vive en memoria del servicio solo hasta que se aplica o caduca el token.
- **Ventana:** «Conectar con este archivo...» (solo con un archivo válido) y «Desconectar...» por túnel. El texto del archivo queda en un campo PRIVADO del modelo (ninguna propiedad lo expone) solo para enviarlo al servicio; se olvida al revisar otro, al olvidar este y tras conectar (salvo si se abrió el aviso de UAC: aún no se sabe si se aprobó).
- **Pruebas:** `Nexo.Vpn.Demo` §7-8 (planes y aplicar, 79 en total), `Nexo.Service.Demo` (`VpnPruebas.cs`: token, UAC exigido antes de gastar el token, un solo uso, parámetros, vault sin clave; 280 en total), `Nexo.Desktop.Demo` (620). 9 reglas rotas a propósito, todas cazadas.
  **Hallazgo en las propias pruebas:** la comprobación «la clave no aparece» buscaba la clave en JSON, pero System.Text.Json escribe «+» como `+`: con claves aleatorias que tienen «+», la prueba fallaba al azar y, peor, podía NO detectar una fuga. Ahora busca también la forma escapada, con una prueba fija que lo confirma. También se quitaron `.Single()` que tiraban el programa en vez de informar el fallo.
- **SIN PROBAR (nada de esto se ejecutó de verdad):** instalar/quitar un túnel real con `wireguard.exe` como SYSTEM, los permisos reales de la carpeta, el código de salida y la salida de error reales de `wireguard.exe` (es un programa de ventana: puede no escribir nada en la consola), y la aprobación UAC de punta a punta. Requiere: instalar WireGuard (`winget install WireGuard.WireGuard`), un `.conf` real de un proveedor, el servicio de prueba como SYSTEM (tarea programada que lanza el usuario, como en §2n) y la ventana + bandeja en Archivos de programa. Preguntar antes.

## 2aj. Alertas de intrusión: registros de Seguridad y de Sistema (2026-11-09, en el HP)

Punto 14 de la Salida 0 («alertas de robo de identidad»), con datos reales y no genéricos. Sexta sección de «Seguridad»: «Accesos y cuentas (registro de Seguridad de Windows)», dentro de «Revisar todo» (no usa Internet). La hace el **servicio** (`alertas.revisar`), porque el registro de Seguridad exige administrador. SOLO LECTURA: no cambia la política de auditoría.

- **Piezas:** `Nexo.Modules.Threats/Alertas/` (portable): `ParserDeEventoDeWindows` (XML de cualquier evento, con las defensas del 5157: sin DTD, tamaños acotados, caracteres de control limpiados) y `AnalizadorDeAlertas`. `Nexo.Modules.Threats.Windows/LectorDeAlertasWindows` (4 consultas con tope de 2000; el 4624 se filtra en el propio XPath por `LogonType=10`; auditoría con `PoliticaDeAuditoria` de `Nexo.Native`).
  `Nexo.Service/ModuloAlertas` (`alertas.revisar`, `dias` 1-30, 7 por omisión; tope de una revisión cada 10 s; nota en el vault `TipoEvento.AlertaIdentidad`, módulo Identidad). Ventana: `Nucleo/Alertas.cs` (`LectorDeAlertasDelServicio`: una gravedad desconocida o un campo que falta invalida la respuesta ENTERA) y `SeccionDeSeguridad.Accesos`; la ventana no deja rastro aparte (ya lo deja el servicio).
- **Decide sin depender del idioma:** número de evento, proveedor, SID y tipo de inicio de sesión. **Hallazgo real:** en el 7045 de este Windows, `ServiceType`/`StartType` vienen traducidos («inicio por solicitud»), y el grupo Administradores se llama «Administradores»: por eso se usa `TargetSid = S-1-5-32-544` y nunca el nombre (probado: un grupo LLAMADO «Administrators» con otro SID no cuenta).
- **Reglas:** 1102/104 del proveedor `Microsoft-Windows-Eventlog` (registro borrado; de otro proveedor no cuenta) = Alta; añadido a Administradores = Alta; activada la cuenta integrada de Administrador (RID 500) o Invitado (501) = Alta (otra cuenta = Baja); cuenta creada (4720) = Media; otra cuenta restableció una contraseña (4724, no SYSTEM ni uno mismo) = Media; añadido a «Usuarios de escritorio remoto» (S-1-5-32-555) = Media;
  Escritorio remoto (4624 tipo 10) = Media, un aviso por cuenta y origen con el recuento; 20+ contraseñas fallidas (4625) = Media, 100+ = Alta, con los orígenes; cuenta bloqueada (4740) = Media; tarea creada (4698) y servicio instalado (7045) = nota, o Media si corren desde Temp/AppData/Descargas/Users\Public/ProgramData (menos Defender) o con comandos típicos de malware (`powershell -enc`, `mshta`, `certutil -urlcache`…). El comando de la tarea sale de `TaskContent`.
- **Hallazgo real (como el de Discord en §2ad):** 30 días de este equipo = 61 eventos 7045 de pocos servicios («Claude» 12 veces, una por actualización, cada una desde una carpeta con la versión en el nombre; EasyAntiCheat 11). Ahora un aviso por NOMBRE de servicio (y por «raro o no»), con el recuento y la ruta de la última vez: unos 20 avisos, ninguno sospechoso.
- **Honestidad:** cada subcategoría de auditoría apagada o que no se pudo consultar es «no evaluado» con su consecuencia (sin auditar fallos no se ven contraseñas fallidas; las tareas no se auditan por omisión en Windows); sin poder leer el registro = incompleta, NUNCA «sin alertas»; eventos que no se pudieron interpretar = incompleta; tope alcanzado = se dice. Un hallazgo no prueba una intrusión (muchas cosas las hace el propio usuario) salvo, por sí solo, el borrado del registro.
- **Pruebas:** `Nexo.Vuln.Demo` §23 (33, con el 7045 REAL de Chrome con el nombre del equipo cambiado, `Datos/evento-7045-real.xml`); 10 reglas rotas a propósito, todas cazadas (dos pruebas se rehicieron: la del DTD, que no probaba nada porque el XML ya se rechazaba por otro motivo, y los `.Single()`, que tiraban el programa en vez de informar).
  `Nexo.Service.Demo` (`AlertasPruebas.cs`), `Nexo.Desktop.Demo` (`AlertasVentanaPruebas.cs` + recuentos de 6 secciones). `Nexo.Vuln.Windows.Demo` §11 contra el equipo REAL como usuario normal: Sistema leído (61 eventos 7045, 0 descartados), Seguridad declarado no leído (3 consultas) y la auditoría «no se pudo saber».
- **SIN PROBAR:** con administrador / el servicio como SYSTEM contra el registro de Seguridad REAL (los eventos de Seguridad de las pruebas usan los nombres de campo documentados por Microsoft, no eventos sacados de este equipo); la sección en la ventana con el servicio real.

## 2ak. Anti-ransomware, paso 1: las carpetas protegidas de Windows (2026-11-09, en el HP)

Submódulo 2 del Prompt 1. Decisión de la Salida 0 §2: el bloqueo de verdad lo hace el **acceso controlado a carpetas** (CFA) de Microsoft Defender; Nexo no lo reimplementa (sin minifiltro no podría bloquear), lo **mira y lo explica**. Séptima sección de «Seguridad»: «Protección contra ransomware (carpetas protegidas de Windows)», dentro de «Revisar todo» (local, sin red). Corre en el proceso de la ventana con el usuario: **no hace falta administrador** (comprobado). SOLO LECTURA: no activa nada.

- **Fuentes, todas comprobadas en este equipo:** WMI `root\Microsoft\Windows\Defender` (`MSFT_MpPreference.EnableControlledFolderAccess` es `UInt8` 0-4; `MSFT_MpComputerStatus.AMRunningMode`/`RealTimeProtectionEnabled`), las mismas clases que `Get-MpPreference`; y el registro `Microsoft-Windows-Windows Defender/Operational`. Los nombres de campo de los eventos se sacaron del **manifiesto de este Windows** (`Get-WinEvent -ListProvider`): 1123/1124/1127/1128 traen `Path` y `Process Name`; el 5007, `Old Value`/`New Value` con la ruta del registro (`...\Controlled Folder Access\EnableControlledFolderAccess = 0x1`).
- **Hallazgo real:** sin administrador, Defender devuelve la lista de programas con permiso como UN texto, «N/A: Must be an administrator to view exclusions» (en inglés aunque Windows esté en español). `ListaLegible` lo convierte en «no leído», nunca en «lista vacía». Solo deja la revisión incompleta si la protección está activada (si está apagada, esa lista no importa).
- **Piezas:** `Nexo.Modules.Threats/Ransomware/CarpetasProtegidas.cs` (portable: `LecturaDeCarpetasProtegidas`, `AnalizadorDeCarpetasProtegidas`, `CambioDe` para el 5007), `Nexo.Modules.Threats.Windows/LectorDeCarpetasProtegidasWindows.cs` (+ paquete `System.Management` 8.0.0, MIT, el mismo que ya usa Cleanup.Windows; 30 días, tope 2000 por consulta). Ventana: `SeccionDeSeguridad.Ransomware`. Rastro `seguridad.ransomware` (Amenazas, `TipoEvento.ProteccionRansomwareRevisada`), solo conteos.
- **Reglas:** Defender pasivo/EDR (hay otro antivirus) = nota + «no se sabe si tu otro antivirus protege» (no se acusa «apagado»); modo del motor desconocido o no leído = no evaluado; tiempo real apagado = **Alta**; CFA 0 = Media; auditoría (2) = Baja; solo discos (3/4) = Media; activado (1) = nota con las carpetas añadidas; valor desconocido = no evaluado. Apagado hace poco (último 5007 del modo: de ≠0 a 0, y hoy sigue apagado) = Media, «Windows no dice quién». Bloqueos: un aviso por programa y tipo de evento con recuento y el último archivo; bloqueo desde Temp/Descargas/Public/papelera = **Alta**, auditoría desde ahí = Media, bloqueo normal = Baja, auditoría normal = nota, disco = Media/Baja. AppData en general NO es raro (Discord, Teams). Programa con permiso en carpeta rara = Media; permiso NUEVO según el 5007 = nota (Media si es de carpeta rara); permiso quitado no se avisa. Todo decide por número de evento, proveedor (otro proveedor no cuenta), valores numéricos y rutas, no por textos traducidos. Un bloqueo no prueba ransomware (se dice).
- **Pruebas:** `Nexo.Vuln.Demo` §24 (46, con un 5007 REAL de este equipo, `Datos/evento-5007-real.xml`); 12 reglas rotas a propósito, todas cazadas (dos pruebas se rehicieron: una rotura no compilaba y los `.Single()` tiraban el programa en vez de informar). `Nexo.Desktop.Demo` (7 secciones, 6 en «Revisar todo», rastro de 5). `Nexo.Vuln.Windows.Demo` §12 contra el Defender REAL como usuario normal, cruzado con `Get-MpPreference`/`Get-MpComputerStatus`/`Get-WinEvent`: modo 0, motor Normal, tiempo real encendido, 0 bloqueos, 514 eventos 5007 (0 de CFA, 0 descartados), permisos «no leídos» igual que PowerShell. Resultado en este equipo: **«Las carpetas protegidas contra ransomware están apagadas» (Media)**.
- **SIN PROBAR:** eventos 1123/1124 REALES (no hay ninguno: CFA nunca estuvo activado aquí) y el 5007 real de un cambio de CFA (la forma de la ruta es la del 5007 real de otro ajuste, no observada para CFA); con Defender en modo pasivo; la sección en la ventana con pantalla real.
- **Siguiente (paso 2, HECHO en §2al):** activar CFA desde Nexo por el servicio, con vista previa, token y aprobación (como el firewall), y después la prueba real: con CFA activado, un programa de prueba sin firma que intente escribir en Documentos genera un 1123 real. Cambia la configuración de Defender del usuario: **preguntar antes**. Luego: archivos canario (HECHO en §2am, por sondeo y número de archivo en vez de USN) y copia versionada (Salida 0, fila 2).

## 2al. Anti-ransomware, paso 2: activar las carpetas protegidas desde Nexo (2026-11-09, en el HP)

Mismo camino que el firewall y la VPN: `cfa.previsualizar` (`modo` = `activar` o `auditar`; no cambia nada; token de 10 min) → la ventana muestra el plan y pide confirmar (por omisión «No») → `cfa.aplicar` con el token, exigiendo la aprobación (UAC) ANTES de mirar el token. Nuevo `TipoDeAccion.CarpetasProtegidas` (`--aplicar CarpetasProtegidas` en la bandeja elevada).

- **Reglas (`PlanificadorDeCarpetasProtegidas`, portable, `Ransomware/PlanDeCarpetasProtegidas.cs`):** regla del proyecto, **Nexo no apaga ni debilita Defender**: solo activar (desde 0, 2, 3 o 4) o auditoría (solo desde 0). No hay método para apagar; un plan fabricado a mano para apagar se rechaza al aplicar (Aplicar vuelve a preparar con las mismas reglas). Sin saber el motor, el tiempo real o el modo, o con Defender pasivo o el tiempo real apagado: nada (Nexo no enciende el tiempo real). Al aplicar se vuelve a leer: si el estado cambió desde la vista previa, no se toca. **Tras la orden se vuelve a leer**: si Windows la acepta pero el valor no cambió (directiva, protección contra alteraciones) = fallo, nunca «activado»; si no se puede leer = «no se pudo comprobar».
- **`EjecutorDeCfaWindows`:** método estático `MSFT_MpPreference.Set` (`EnableControlledFolderAccess`, UInt8; comprobado en este Windows con `Get-CimClass`), el mismo que usa `Set-MpPreference`. Solo recibe un valor del enum. `LectorDeEstadoDeCfaWindows` lee solo modo/motor/tiempo real.
- **`ModuloCarpetasProtegidas` (servicio, registrado en `NexoWorker`):** vault `TipoEvento.ProteccionRansomwareCambiada` (Amenazas) con modo anterior, final y resultado; «(no se aplicó)» si falló. La bandeja y la ventana usan el «exito» de la respuesta (una llamada correcta con `exito: false` = no aplicado).
- **Ventana:** botón «Activar la protección...» en la sección de ransomware, solo con CFA-APAGADO/AUDITORIA/SOLO-DISCOS y nunca con tiempo real apagado u otro antivirus. Tras aplicar se vuelve a revisar; si se abrió el UAC (el cambio lo hace otro proceso, más tarde) la sección queda «Sin revisar». Texto de «Qué se revisa» actualizado.
- **Pruebas:** `Nexo.Vuln.Demo` §25 (26), `Nexo.Service.Demo` (`CarpetasProtegidasPruebas.cs`, incl. «la aprobación antes que el token» con un token inventado; 33 métodos en `estado`), `Nexo.Desktop.Demo` (`SeguridadRansomwarePruebas.cs`, 15), `Nexo.Tray.Demo` (resumen y un servidor de pipe falso que contesta `exito: false`). 14 reglas rotas a propósito, todas cazadas (tres pruebas se añadieron por roturas que pasaban: aprobación antes del token, `exito` por el pipe, y una rotura mal escrita). Se corrieron las suites afectadas (Vuln, Service, Desktop, Tray), no la batería completa de `tools/` al final.
  Hueco visto de paso: la prueba de la VPN no comprueba la aprobación con un token inventado (la de CFA sí); conviene añadirla.
- **SIN PROBAR (nada se ejecutó contra Defender de verdad):** `MSFT_MpPreference.Set` como SYSTEM, si la protección contra alteraciones (activa en este equipo) deja cambiar el CFA, y el UAC de punta a punta. Prueba real pendiente, **cambia el Defender del usuario: preguntar antes**: servicio de prueba como SYSTEM (§2n) + ventana/bandeja en Archivos de programa → activar → comprobar con `Get-MpPreference` → un ejecutable sin firma escribe en Documentos → evento 1123 real (cruzarlo con §2ak) → volver a dejarlo como quiera el usuario (apagarlo, si lo pide, lo hace él en Seguridad de Windows).

## 2am. Anti-ransomware, paso 3: señuelos (archivos canario) (2026-11-09, en el HP)

Salida 0, fila 2: «archivos canario vigilados». Nexo deja en Documentos, Escritorio e Imágenes de cada perfil dos archivos que nadie debería tocar: `!nexo-señuelo.docx` (el «!» se ordena antes que letras y cifras) y `zz-nexo-señuelo.xlsx` (al final), porque muchos programas de cifrado recorren las carpetas en orden. Contenido: 40-96 KB al azar que empieza como un ZIP (`PK\3\4`), huella SHA-256 guardada. El servicio los revisa cada 30 s; si uno cambia, desaparece o se renombra, avisa. **No impide nada** (sin minifiltro no se puede: eso lo hace el CFA de §2ak/§2al) **y no sabe qué programa fue** (se dice siempre).

- **Decisión: revisar por sondeo, no por el diario USN.** Cada 30 s se lee cada señuelo (pocos KB) y se compara tamaño + huella. Si no está en su sitio se busca por su **número de archivo de NTFS** (`OpenFileById`, NO exige administrador: comprobado), que no cambia al renombrar: así se distingue «renombrado a `x.locked`» de «borrado». Más simple y sin administrador; el USN serviría para avisar en 1 s en vez de 30, cosa que no cambia lo que puede hacer una persona.
- **Reglas (`Nexo.Modules.Threats/Ransomware/Senuelos.cs`, portable):** nunca se sobrescribe ni se borra: si el nombre está ocupado, esa carpeta queda «sin señuelo» con el motivo. «No pude leerlo» (abierto en exclusiva, sin permiso) = **no comprobado**, nunca intacto. Hallazgos: Modificado (incl. «ahora es otro archivo con el mismo nombre» si cambió el número), Renombrado (con la ruta nueva y si el contenido cambió), Borrado, Desaparecido (no se pudo buscar por número o no se guardó: no se inventa «borrado»). Enviado a la papelera = Borrado pero **Media** (un programa de cifrado no usa la papelera) y no cuenta para la ráfaga. Cada tocado = evento **Alta**; dos o más en 10 min = evento **Crítico** «puede haber un ransomware cifrando tus archivos» con qué hacer. Un tocado no se re-avisa ni se vuelve a poner solo (es la prueba); **reponer** = plan + token + aprobación: pone uno nuevo (con «(2)» si el nombre sigue ocupado), deja el tocado donde está («Nexo no lo borra») y da el aviso por visto. Al aplicar se vuelve a planear: si el nombre previsto se ocupó, se pide previsualizar otra vez. Lista en `%ProgramData%\Nexo\senuelos.json` (atómica; dañada = se aparta como `.corrupto` y los archivos viejos NO se adoptan).
- **Carpetas (`CarpetasParaSenuelos`, portable + `LectorDePerfilesWindows`):** perfiles reales de `ProfileList` (S-1-5-21-…); si el perfil está abierto, sus «User Shell Folders» (carpetas movidas, `%USERPROFILE%` sin expandir); si no, las de siempre. Se descartan con motivo: OneDrive (se subiría a la nube), red/UNC, variables que el servicio no puede resolver. Se vuelven a buscar cada 10 min (un usuario que inicia sesión trae sus carpetas reales).
- **Windows:** `Nexo.Native/Files/NumeroDeArchivo` (`GetFileInformationByHandle`, `OpenFileById`, `GetFinalPathNameByHandleW`), `AccesoASenuelosWindows` (`FileMode.CreateNew`, oculto opcional).
- **Servicio:** `ModuloSenuelos` (`senuelos.estado`, `senuelos.previsualizar`, `senuelos.reponer`; 36 métodos en `estado`). **Apagado por omisión** (pone archivos en carpetas del usuario): `Nexo:Senuelos:Activo`, `Carpetas` (sustituye a las de los perfiles), `SegundosEntreRevisiones` (30, mínimo 5), `Ocultos` (true). Sin métodos para apagarlo ni cambiar carpetas (como el tiempo real). «todo_en_orden» solo si ya se revisó, hay señuelos, ninguno tocado ni sin comprobar y la última vuelta no falló.
- **Hallazgos REALES (en el HP):**
  1. **Defecto propio cazado por la prueba real:** `BY_HANDLE_FILE_INFORMATION` con los FILETIME como `long` sin `Pack = 4` metía un relleno y el número de archivo salía corrido (mitad baja = 0); `OpenFileById` daba 87 y, como 87 se traduce a «no existe», todo renombrado habría salido como «borrado». Arreglado; la prueba «RutaPorNumero encuentra la ruta nueva» lo vigila.
  2. **Windows niega reescribir un archivo OCULTO con CREATE_ALWAYS** (`File.WriteAllBytes`): acceso denegado. Un programa de cifrado que reescriba así fallaría y el señuelo oculto no saltaría (abrir y escribir encima, renombrar o borrar sí funcionan). Decisión: ocultos por omisión igualmente (un archivo raro visible en el Escritorio estorba y acaba borrado: falsas alarmas), con `Nexo:Senuelos:Ocultos = false` para quien prefiera más detección. Fijado en una prueba.
- **Pruebas:** `Nexo.Vuln.Demo` §26-28 (60, disco falso en memoria), `Nexo.Vuln.Windows.Demo` §13 (33, disco REAL en una carpeta temporal propia, sin administrador: crear, oculto, «ñ», ocupado intacto, abierto en exclusiva = no comprobado, renombrar+cifrar a `.locked`, escribir encima, borrar, reinicio, reponer, visibles; perfiles reales cruzados con `SHGetKnownFolderPath`), `Nexo.Service.Demo` (21, incl. la aprobación antes que el token con uno inventado). Roturas a propósito: 14 en las reglas y 4 en el módulo, todas cazadas (dos pruebas se añadieron por roturas que pasaban: «un tocado borrado no se vuelve a poner solo» y «puestos sin revisar no es todo en orden»).
- **SIN PROBAR:** el servicio de verdad como SYSTEM poniendo señuelos en las carpetas reales del usuario (y si con CFA activado Defender bloquea que Nexo los cree: entonces la carpeta queda «sin señuelo» con el motivo, pero no está observado); la papelera real (no se quiso ensuciar la papelera del usuario; la regla se prueba con una ruta `$Recycle.Bin` simulada); un ransomware real o un simulador.
- **Siguiente:** ventana y bandeja (HECHO en §2an); después, la copia versionada (Salida 0, fila 2).

## 2an. Señuelos en la ventana y en la bandeja (2026-11-09, en el HP)

Lo que faltaba de §2am: que la persona se entere. Antes un señuelo tocado solo quedaba en el vault y en `senuelos.estado`.

- **Servicio:** `senuelos.estado` añade `rafaga` (dos o más tocados en 10 min, sin contar la papelera; mismo cálculo que el evento Crítico, `VigilanteDeSenuelos.Recientes`) y `severidad` por hallazgo (`SeveridadDe`: Media si fue a la papelera, si no Alta).
- **Bandeja:** consulta también `senuelos.estado` cada 5 s (`ConsultorDelServicio.LeerSenuelos`, portable). Señuelo tocado = **rojo**, por delante de las detecciones («Nexo: señuelo contra ransomware tocado»; con ráfaga, «POSIBLE RANSOMWARE»). Globo una sola vez por señuelo (clave ruta + momento; si no se pudo leer, se conservan los ya avisados para no repetir). Pulsar el globo o «Señuelos tocados (n)…» explica qué hacer y ofrece reponer (plan del servicio → confirmar → `TipoDeAccion.Senuelos` con UAC). Abrir las detecciones NO apaga la alerta de los señuelos: solo reponer. **No poder leer el estado de los señuelos = naranja**, nunca verde (hallazgo de esta sesión: la primera versión se ponía en verde con una respuesta no reconocida). Apagados = no cuenta (son opcionales).
- **Ventana:** octava sección de «Seguridad», «Señuelos contra ransomware (archivos cebo que vigila Nexo)», dentro de «Revisar todo» (pipe local, sin red). `LectorDeSenuelosDelServicio` (portable): cada tocado = hallazgo con su gravedad, la ruta y qué hacer; ráfaga = hallazgo **Crítico** el primero; carpeta sin señuelo = nota Info; no comprobado, sin ninguna revisión, aviso del servicio o ningún señuelo puesto = **no evaluado** (nunca verde); apagados = «No aplica» con dónde activarlos. Forma desconocida o gravedad rara = toda la respuesta inválida. Botón «Reponer señuelos...» solo con señuelos tocados; tras aplicar se vuelve a revisar, y con UAC la sección queda «Sin revisar». El servicio ya registra en el vault: la ventana no duplica el rastro.
- **Arreglo de paso:** `nexo-tray --aplicar 99 <token>` llegaba a `MetodoDeAplicar` y lanzaba (`Enum.TryParse` acepta números); ahora `Enum.IsDefined`.
- **Pruebas:** `Nexo.Tray.Demo` (20, con el JSON REAL de `ModuloSenuelos`, incluido un contrato de los campos que leen la ventana y la bandeja), `Nexo.Desktop.Demo` (21 nuevas; cuentas de secciones 7→8). 11 roturas a propósito en la bandeja y la ventana, todas cazadas (incluida la del verde con respuesta no reconocida).
- **SIN PROBAR:** el globo y el menú con pantalla real, y todo contra el servicio instalado como SYSTEM con señuelos activos.

## 2ao. Autocompletado de la bóveda: núcleo y host nativo (2026-11-10, en el HP)

Fila 12b, como extensión (decisión del usuario en §6). Camino: extensión MV3 → navegador → `nexo-autocompletar.exe` (lo lanza el navegador por *native messaging*) → pipe → **ventana** de Nexo (la bóveda vive ahí, no en el servicio) → y vuelta. El host no sabe de contraseñas: reenvía.

- **Paso 1, núcleo portable (`src/Nexo.Modules.Identity/Autocompletado/`):** `SitioDeEntrada` (¿la entrada es de esta página? Solo https; página = el sitio o un subdominio, nunca al revés; comparación en punycode; nada de terminaciones solas como `com.ar`/`gob.cl`; IP solo consigo misma; `https://banco@malo` rechazado), `MensajeNativo` (4 bytes LE + JSON; entrada ≤ 64 KB, salida ≤ 1 MB), `PuenteDeAutocompletado` (tipos `estado`/`emparejar`/`buscar`/`rellenar`; sin emparejar no sale nada; emparejar = confirmar en Nexo un código de 6 cifras que la extensión calcula igual, de uno en uno y 30 s de espera tras un «no»; `buscar` da usuarios, NUNCA contraseñas; `rellenar` da UNA y vuelve a comprobar el sitio; tope 20 por minuto; bóveda bloqueada = `bloqueada`). `NavegadoresEmparejadosJson` guarda solo la huella SHA-256 de cada clave (dañado = se aparta y hay que emparejar de nuevo). Límite dicho en el código: un programa con TU usuario puede leer la clave del perfil del navegador y hacerse pasar por él (como con KeePassXC/Bitwarden).
- **Paso 2, canal (`CanalDeAutocompletado.cs`):** pipe `nexo-autocompletado-<huella del usuario>` con `PipeOptions.CurrentUserOnly` en los dos lados (el servidor solo admite a tu usuario; el cliente comprueba que el servidor también es tuyo). API administrada, sin P/Invoke, portable. `ServidorDeAutocompletado` (lado ventana: 4 conexiones, cierra a quien no habla en 30 s, 2 min por petición porque emparejar espera a la persona, respuesta > 1 MB = error). `RelevoNativo` (lado host: ventana cerrada = contesta él «sin_nexo» tras 2 s; trama mala del navegador = sale con 2 sin escribir; respuesta que no es un objeto JSON = no se pasa; tope propio de 2 min 10 s).
- **Paso 2, registro (`InstaladorDeHostNativo.cs`, portable tras `IRegistroDeUsuario`):** host `com.nexo.autocompletado`; manifiesto en `%LOCALAPPDATA%\Nexo\autocompletado\` con ruta absoluta y `allowed_origins` = SOLO la extensión de Nexo. Claves HKCU, sin administrador: `Software\Google\Chrome\NativeMessagingHosts\…` (**Brave usa la de Chrome en Windows**, comprobado en el instalador de KeePassXC) y `Software\Microsoft\Edge\NativeMessagingHosts\…` (Edge mira la suya y luego la de Chrome; documentación de Microsoft). Desinstalar solo borra claves que apuntan a NUESTRO manifiesto. `Revisar` dice «listo» solo si clave → manifiesto legible de Nexo → exe existente → autoriza el ID.
- **ID fijo de la extensión:** `kffjcngenealkjoecfdcliemblgbihpc`, sale de `ClavePublicaDeLaExtension` (irá en el `"key"` del manifest.json; una prueba recalcula el ID). La clave privada NO se guardó: no hace falta para cargarla «sin empaquetar» ni para la tienda de Edge (que firma y da OTRO ID: habrá que añadirlo a `allowed_origins`).
- **Exe (`src/Nexo.Autocompletado.Host`, `nexo-autocompletar.exe`, consola):** `chrome-extension://ID/ [--parent-window=N]` = modo navegador (stdout solo protocolo; origen mal formado = sale con 3); `--instalar`, `--desinstalar`, `--estado`; para pruebas `--raiz-de-pruebas Software\X` y `--manifiesto RUTA`.
- **Pruebas:** `Nexo.Identity.Demo` (todo verde; canal con pipes reales: ida y vuelta con el puente real, 10 a la vez, tramas malas, cada tope; instalador con registro en memoria). 11 roturas a propósito en canal e instalador, todas cazadas (dos pruebas se reforzaron por roturas que pasaban: «respuesta que no es JSON» tumbaba el arnés en vez de fallar, y el tope del host pasaba porque al final contestaba el servidor). `Nexo.Autocompletado.Windows.Demo` (22, en el HP): registro REAL bajo `HKCU\Software\NexoPruebas-…` (REG_SZ, borrado al final), el exe con `--instalar/--estado/--desinstalar`, y el exe lanzado como Chromium (stdin/stdout binarios, pipe real del usuario: tres mensajes en orden, UTF-8 intacto, ni un byte de más, ~107 ms). Comprueba al final que las claves de Brave/Chrome/Edge quedaron como estaban (no existían).
- **Paso 3, la extensión (`src/Nexo.Autocompletado.Extension/`, MV3, sin dependencias ni compilación):** `manifest.json` (con `"key"` → ID fijo), `fondo.js` (service worker: lo ÚNICO que habla con Nexo, por `connectNative`, que lo mantiene vivo mientras se espera el emparejamiento; y lo único que inyecta), `nucleo.js` (toda la lógica, sin APIs del navegador), `rellenar.js` (se inyecta al elegir una entrada), `ventana.html/js/css` (la ventanita del botón; atajo Alt+Mayús+N).
  - **Decisiones de seguridad:** SOLO cuatro permisos (`nativeMessaging`, `activeTab`, `scripting`, `storage`); **sin `host_permissions` ni `content_scripts`**: la extensión no puede leer ninguna página hasta que pulsas su botón (`activeTab`), y no pone botones dentro de las páginas (una página no puede imitarlos ni pulsarlos). Ni webs ni otras extensiones pueden hablarle; el SW solo atiende a su propia `ventana.html`. La URL sale de `chrome.tabs.get` (el navegador), nunca de un mensaje; se vuelve a leer en cada «rellenar», y `rellenar.js` comprueba otra vez `location.hostname` exacto y https antes de escribir. Solo marco principal (los formularios en iframes no se rellenan). La contraseña va Nexo → SW → página y **nunca vuelve a la ventanita**; `buscar` se queda solo con id/usuario/sitio aunque llegara más. Clave de emparejamiento: 32 bytes en `chrome.storage.local` (NUNCA `.sync`); nombre «brave-3f9a» (tipo + sufijo por perfil, para que dos perfiles no se pisen). Respuesta desconocida = error, nunca «ok». Todo el texto con `textContent`.
  - **Qué rellena:** la primera contraseña visible que no sea `new-password` y el campo de usuario visible más cercano antes, en su mismo formulario; salta campos ocultos, transparentes o de 0×0 (trampas); un formulario solo con `new-password` = «registro», no se rellena; sin contraseña y con `autocomplete=username`/email = solo el usuario (páginas en dos pasos). Usa el setter NATIVO de `value` y dispara `input`/`change` (funciona con React).
  - **Pruebas (`node tools/Nexo.Autocompletado.Extension.Pruebas/correr.mjs`, 111 OK):** lógica pura; el atendedor con dobles del navegador; manifiesto y código (permisos exactos, `key` → ID igual al de C#, sin `innerHTML`/`eval`/`storage.sync`/red); `rellenar.js` en **Edge REAL sin ventana** (perfil temporal propio, página por https en 127.0.0.1 con certificado de usar y tirar hecho en memoria, 18 casos); y la **extensión cargada en Edge real** (sin host registrado: carga con el ID fijo, el SW arranca y la ventanita dice en rojo «no está instalado»; se lee por el protocolo de depuración). Vector compartido C#/JS: la clave 0..31 da el código «915 824» (en las dos baterías). 18 roturas a propósito, todas cazadas. `--sin-navegador` salta las partes con Edge.
  - **Cargarla en Brave:** `brave://extensions` → «Modo de desarrollador» → «Cargar descomprimida» → la carpeta `src\Nexo.Autocompletado.Extension`. El ID debe salir `kffjcngenealkjoecfdcliemblgbihpc`.
- **Paso 4, la ventana (`src/Nexo.Ui.Desktop/AutocompletadoModelo.cs`, panel «Autocompletar en el navegador» en la pestaña Contraseñas):** al abrirse la ventana se abre el canal (`IniciarAsync`) con el `PuenteDeAutocompletado` sobre `ContrasenasModelo.EntradasParaAutocompletar()` (la lista solo con la bóveda ABIERTA; lectura sin cerrojo porque la lista nunca se modifica, solo se reemplaza, y al bloquear se vacía antes de cambiar la fase). Lista de emparejados en `navegadores-emparejados.json` junto a la bóveda.
  - **Decisión: emparejar solo si lo pides en Nexo.** El puente recibió `motivoParaNoEmparejar`: fuera de los **2 minutos** tras pulsar «Emparejar un navegador…» NO se pregunta nada (un programa con tu usuario no puede hacer saltar la pregunta para que la aceptes sin querer), contesta «rechazado» con el motivo, **no** activa la espera de 30 s, y la ventana avisa «algo pidió emparejarse sin que pulsaras…» (rastro `autocompletado.no_solicitado`, **Media**). Tras un «Sí» o un «No» el plazo se cierra. La pregunta es un `DialogoEnEspanol` («No» por omisión) con el navegador y el código; trae la ventana al frente y va a Contraseñas; tiene plazo (`PreguntarAsync(..., ct)`): si el navegador deja de esperar, se cierra sola como «No».
  - **Otras reglas:** lo que pide el navegador NO cuenta como actividad (la bóveda se bloquea sola igual). Si el canal ya lo atiende alguien (otra ventana de Nexo u otro programa con tu usuario), esta ventana NO se suma y lo dice («…si no tienes otra abierta, algo más está ocupando el canal»). Al rastro del servicio van 5 claves nuevas (`autocompletado.emparejado/rechazado/no_solicitado/olvidado/rellenado`) SIN campos: ni navegador ni sitio (el servicio rechaza cualquier campo). La ventana sí enseña localmente «Último rellenado: «brave-3f9a» en github.com».
  - **Pruebas:** `Nexo.Desktop.Demo` (27 del modelo con pipe real y reloj de prueba, incluida la bóveda real que se bloquea sola aunque el navegador pregunte; 18 de la ventana sin pantalla: emparejamiento real por el pipe → la pregunta aparece EN la ventana → «Sí»/«No» → lo que recibe el navegador, la lista, «Quitar», el plazo que cierra la pregunta), `Nexo.Identity.Demo` (el filtro del puente y sus eventos), `Nexo.Service.Demo` (los 5 eventos, Media/Info, y que no admiten campos). Hallazgo de la prueba: la cuenta atrás truncaba («1:59» recién pulsado); ahora redondea hacia arriba. 13 roturas a propósito, todas cazadas (una, «el plazo no se cierra en el `finally`», pasaba al principio porque los avisos de «Sí»/«No» también cierran el plazo; se añadió la prueba del caso que solo cubre el `finally`: el navegador deja de esperar a mitad de la pregunta).
- **Paso 5, Brave REAL de punta a punta (2026-11-10, con permiso del usuario):** `nexo-autocompletar --instalar` de verdad (claves de Chrome y Edge en HKCU → manifiesto en `%LOCALAPPDATA%\Nexo\autocompletado\`, apuntando al exe de `bin\Debug`; el usuario ya tenía otros hosts registrados, no se tocaron). Ventana abierta con una **bóveda de PRUEBA aparte** (`--boveda`, en el scratchpad; la del usuario no se tocó) con una sola entrada: `the-internet.herokuapp.com`, `tomsmith` / `SuperSecretPassword!` (credenciales públicas de ese sitio de pruebas). El usuario cargó la extensión «descomprimida» en su Brave (ID `kffjcngenealkjoecfdcliemblgbihpc`, como se esperaba), emparejó (la extensión se identificó como **`brave-a6bc`**: la detección de Brave funciona; en el JSON solo quedó la huella), rellenó en la página de login del sitio de pruebas e inició sesión, y en `example.com` no se ofreció nada. Comprobado por fuera: el JSON de emparejados y, por UI Automation (solo lectura), «Último rellenado: «brave-a6bc» en the-internet.herokuapp.com». **Confirmado: Brave lee la clave de Chrome en Windows.**
  - **Consecuencia en las pruebas de la extensión:** con el host ya registrado, la sección 5 de `correr.mjs` dejó de recibir «no está instalado» (Edge encontró el host). Ahora mira el registro: registrado y sin ventana de Nexo = debe decir «Nexo no está abierto» (lo que de paso prueba **Edge real → host → canal**); sin registrar = «no está instalado»; con una ventana de Nexo abierta no se comprueba el texto.
  - **Hallazgo real (corregido):** el autocompletado arrancaba DETRÁS de las consultas al servicio al abrir la ventana; sin servicio, el navegador recibía «Nexo no está abierto» durante 5-8 s. Ahora `IniciarAsync` se lanza lo primero en `Opened`; medido con el exe real: atiende a los **2,0 s** de lanzar la ventana (incluye el arranque de la ventana).
- **SIN HACER / SIN PROBAR:** Edge real (debería ir igual: mismo manifiesto y su propia clave), el instalador de Nexo (que registre el host desde `Program Files` y no desde `bin\Debug`), formularios difíciles reales (iframes, páginas de dos pasos con un usuario ya escrito). Mejora posible anotada: hoy la extensión manda su clave en cada petición; un desafío-respuesta (HMAC) evitaría que quien ocupe el canal antes que Nexo se quede con ella (el mismo atacante podría igualmente leerla del perfil del navegador, por eso no es prioritario).

## 2ap. Copia versionada, paso 1: el núcleo (2026-11-10, en el HP)

Salida 0, fila 2: «respaldo versionado». Solo el núcleo portable (`src/Nexo.Modules.Threats/Ransomware/CopiaVersionada.cs`, solo `System.IO`); **aún sin servicio, ventana ni bandeja** y sin ejecutar contra carpetas reales del usuario.

- **Cómo guarda:** `Destino\NexoCopias\contenido\xx\<sha256>` (cada contenido una sola vez) + `instantaneas\<fecha>.json` (lista ruta -> hash, con los omitidos y su motivo). Un archivo que no cambió no se copia otra vez. El hash sale de lo que se escribió en el destino.
- **Reglas:** nunca toca los originales; el destino no puede estar dentro de un origen ni al revés (comparación por carpeta completa: `docs-otra` junto a `docs` no cuenta); enlaces y carpetas-enlace no se siguen; lo que no se pudo copiar (abierto, sin permiso, sobre el tope de 4 GB) queda en `Omitidos` con motivo; no pisa una instantánea del mismo segundo.
- **Anti-ransomware:** si ≥ 50 % de los archivos de la copia anterior cambiaron o desaparecieron (y había ≥ 20), la instantánea sale `Sospechosa` y **no se poda**: justo entonces las versiones viejas son las únicas buenas. Podar tampoco ocurre si algún manifiesto no se pudo leer (no se sabe qué contenido sigue en uso) y solo borra archivos con forma de contenido de Nexo (64 hex) dentro de su carpeta.
- **Restaurar:** solo a una carpeta nueva o vacía, nunca dentro de la carpeta de copias; cada archivo se comprueba contra su hash antes de entregarse (uno dañado queda en `NoRestaurados`); una lista manipulada con `..` no saca archivos de la carpeta. Varios orígenes con el mismo nombre se separan (`Docs`, `Docs-2`). `Verificar` recorre todo el contenido y caza faltantes o alterados.
- **Pruebas:** `Nexo.Vuln.Demo` §29-30 (disco real en carpeta temporal propia), todo en verde. 6 roturas a propósito, todas cazadas (guarda de ruta, sospecha, poda con lista ilegible, hash al restaurar, destino dentro del origen, borrado de contenido en uso). La prueba de la lista manipulada era vacía al principio (el contenido ya estaba dañado por otra prueba) y se rehízo en un escenario limpio.
- **NO hace, y se dirá en la ventana:** no cifra la copia, y no protege el destino de un ransomware que pueda escribir en él: lo ideal es un disco externo que solo se conecta para copiar.
- **Siguiente:** paso 2 = servicio (`copia.estado` / `copia.hacer`, apagado por omisión, orígenes y destino por `Nexo:Copia:*`, con plan+token+aprobación como el resto) y paso 3 = sección en la ventana (elegir carpetas y destino, «Copiar ahora», restaurar a carpeta nueva, avisar de «sospechosa»). Decisión del usuario pendiente: el destino (el disco SATA ST1000LM035 del HP tiene el atributo 187 = 90, así que no conviene copiar al mismo disco).

## 2aq. Copia versionada, paso 2: el servicio (2026-11-10, en el HP)

`src/Nexo.Service/ModuloCopia.cs` (+ `ModuloCopiaApagado`), cableado en `NexoWorker.CrearCopia`. **Apagada por omisión.** Se activa en `appsettings.json`: `Nexo:Copia:Activo`, `Destino` (ruta local con letra de unidad; sin destino válido queda apagada), `Versiones` (7), `CadaHoras` (0 = solo a mano) y `Carpetas` (si falta: Documentos, Escritorio e Imágenes de cada perfil, las mismas que los señuelos, con las mismas descartadas: OneDrive, red).

- **Métodos (38 en `estado`):** `copia.estado` y `copia.hacer`. **No hay `copia.restaurar` a propósito:** el servicio es SYSTEM y no debe escribir donde le diga un proceso cualquiera; restaurar lo hace la ventana con los permisos de la persona (`CopiaVersionada.Restaurar`, ya portable). Tampoco hay métodos para cambiar destino ni carpetas.
- **Reglas:** una copia a la vez (-32012) y un minuto entre copias manuales (-32013). Sin el disco conectado no es un error: «destino no disponible», no copia y **no cuenta como intento** (defecto cazado por la prueba: al principio un intento sin disco gastaba el minuto de espera y bloqueaba la copia al conectarlo). La automática cuenta desde el último intento y solo corre con el destino presente. Carpetas que no existen se ignoran. La copia corre fuera del hilo del pipe.
- **Eventos al vault:** `copia-hecha` (Info), `copia-fallida` (Media), `copia-sospechosa` (Alta, con el motivo y «no restaures ni borres hasta revisar»).
- **Pruebas:** `Nexo.Service.Demo` (21 nuevas, disco real en carpeta temporal y copiador falso para los casos de tiempo/bloqueo). 4 roturas a propósito cazadas (una a la vez, tope de frecuencia, gravedad de «sospechosa», carpetas inexistentes); una quinta (la comprobación de disco en la vuelta automática) no se cazaba porque era código duplicado de `HacerAsync`: se quitó.
- **SIN PROBAR:** el servicio instalado como SYSTEM copiando a `E:\` de verdad (el destino que eligió el usuario: disco USB externo, 465,8 GB, 228,9 GB libres, volumen llamado «Windows»; Nexo solo escribe en `E:\NexoCopias`), y desconectar/conectar el disco en caliente.
- **Siguiente (paso 3):** sección en la ventana: estado, «Copiar ahora», lista de versiones (leídas con `CopiaVersionada.Listar` en el proceso de la ventana), «Restaurar a una carpeta nueva…» y aviso de «sospechosa»; luego la bandeja. Luego la prueba real (preguntar antes de activarla en el servicio real y de escribir en `E:\`).

## 2ar. Copia versionada, paso 3: la pestaña «Copias» (2026-11-10, en el HP)

Duodécima pestaña de la ventana (índice 11), `src/Nexo.Ui.Desktop/CopiaModelo.cs` + `Nucleo/Copia.cs` (`LectorDeCopia`, `ServicioDeCopiaPorPipe`, `IServicioDeCopia`).

- **Reparto:** por el pipe solo `copia.estado` y `copia.hacer` («Copiar ahora»; la espera es solo para conectar, la llamada puede durar minutos). La lista de versiones, «Comprobar copias» (`CopiaVersionada.Verificar`) y «Restaurar a una carpeta nueva…» (`CopiaVersionada.Restaurar` + selector de carpeta + confirmación con «No» por omisión) corren **en el proceso de la ventana, con los permisos de la persona** (el servicio no restaura a propósito, §2aq).
- **Colores (nunca verde por defecto):** gris = sin consultar / sin servicio / apagada; rojo = última copia sospechosa (aunque sea reciente) o fallida; amarillo = disco desconectado, ninguna copia todavía, o última copia de hace más de 7 días; verde = copia correcta, reciente y sin sospecha. Se muestran los omitidos con motivo, la poda suspendida y las carpetas sin copia. Restaurar una copia sospechosa avisa de que puede traer archivos ya cifrados.
- **Defecto evitado:** reconstruir la lista deselecciona la fila y la deselección recalcula (la recursión de la pestaña Contraseñas): la lista solo se rehace al actualizar y `Calcular` no la toca.
- **Pruebas:** `Nexo.Desktop.Demo` (`CopiaVentanaPruebas.cs`, disco real en carpeta temporal para listar, restaurar, verificar con un contenido alterado a propósito) y, en `Nexo.Service.Demo`, la prueba de contrato (el JSON REAL de `ModuloCopia` leído por `LectorDeCopia`; ahora `Nexo.Service.Demo` referencia a `Nexo.Ui.Desktop`). Las pruebas cazaron por sí solas dos choques míos: el nombre de manejador `RestaurarCopia` y el `x:Name="BotonRestaurarCopia"` ya existían en la pestaña Contraseñas. 6 roturas a propósito en el modelo, todas cazadas. Los recuentos de pestañas de las pruebas pasaron de 11 a 12.
- **SIN PROBAR:** la pestaña con pantalla real (clics, selector de carpetas, tamaños) y todo contra el servicio instalado con la copia activada y `E:\` conectado.
- **Falta:** bandeja (rojo/globo si la copia es sospechosa), y la prueba real (preguntar antes: activar `Nexo:Copia` en el servicio real y escribir en `E:\NexoCopias`).

## 2as. Copia versionada, paso 4: la bandeja y la protección de la última versión buena (2026-11-10, en el HP)

- **Hueco del motor, cazado al pensar la bandeja:** tras una copia sospechosa, la copia siguiente se compara con la ya cifrada, sale «normal», poda y se llevaría la única versión buena. Ahora `CopiaVersionada.ProtegidasDeLaPoda`: la poda nunca borra una instantánea sospechosa ni la última buena anterior a ella (el tope de versiones puede superarse; se libera a mano, borrando el manifiesto, y **falta una acción «descartar la sospecha»** en la ventana). Prueba con disco real y rotura cazada.
- **Servicio:** `copia.estado` añade `sospechosas_guardadas` (se lee del disco una vez y tras cada copia; null = no se sabe porque el disco no ha estado conectado desde que arrancó el servicio). Una copia «normal» posterior NO apaga la alarma (prueba).
- **Ventana:** la pestaña «Copias» se queda en rojo mientras haya una sospechosa guardada («Hay una copia sospechosa guardada»).
- **Bandeja:** consulta `copia.estado` junto con lo demás (opcional: servicio viejo, apagada o forma desconocida = sin efecto, no afirma nada). Rojo «Nexo: copia de seguridad sospechosa» (por debajo de un señuelo tocado, por encima de las detecciones), amarillo «la última copia de seguridad falló», un globo por cada sospechosa NUEVA (sin repetir al reconectar), menú «Copia de seguridad sospechosa…» con un diálogo que dice qué hacer (desconectar equipo y disco, no borrar nada del disco de copias, restaurar la última buena desde la pestaña «Copias») y sus límites. La bandeja no restaura ni borra nada.
- **Pruebas:** `Nexo.Tray.Demo` (`CopiaBandejaPruebas.cs`, con el JSON REAL de `ModuloCopia`), `Nexo.Service.Demo`, `Nexo.Desktop.Demo`, `Nexo.Vuln.Demo`: todo en verde. 5 roturas cazadas en la bandeja (una sexta, equivalente, descartada).
- **SIN PROBAR:** el globo y el menú con pantalla real, y todo contra el servicio instalado con `Nexo:Copia` activo y `E:\` conectado.
- **Siguiente:** acción «descartar la sospecha» (ventana, con confirmación), prueba real (preguntar antes), y luego el instalador.

## 2at. Copia versionada, paso 5: descartar la sospecha (2026-11-10, en el HP)

Cierra el hueco anotado en §2as: una sospechosa guardada mantenía el rojo para siempre.

- **Motor:** `CopiaVersionada.DescartarSospecha(destino, id)` reescribe SOLO la lista de esa instantánea (temporal + mover; el contenido no se toca) con `Sospechosa = false` y deja constancia en el motivo («Revisada y dada por buena por la persona. Antes: …»). Se niega si no existe o no es sospechosa. Si la lista la escribió el servicio (SYSTEM) y la persona no tiene permiso de escritura en el disco, lo dice. `FirmaDeLasListas` (cuántas listas + última modificación) es una comprobación barata: `ModuloCopia` vuelve a contar las sospechosas cuando cambia, sin releer todo en cada consulta de la bandeja.
- **Ventana:** botón «Descartar la sospecha…» en «Copias», solo con una versión SOSPECHOSA elegida; diálogo con «No» por omisión que explica la consecuencia (Nexo dejará de protegerla y podrá borrarla con la última buena anterior) y pide comprobar antes restaurándola a una carpeta nueva. Nunca es automático.
- **Pruebas:** Vuln.Demo (motor), Service.Demo (el estado pasa a 0 sin hacer otra copia), Desktop.Demo (botón, error de permiso, recarga). 4 roturas a propósito, todas cazadas. Todo en verde, incluido Tray.Demo.
- **SIN PROBAR:** si la persona puede escribir de verdad en las listas que creó SYSTEM en `E:\NexoCopias` (permisos NTFS del disco externo: no observado), y todo con pantalla real.
- **Con esto el código de la copia versionada está completo.** Falta la prueba real (preguntar antes) y el instalador.

## 2au. Anti-criptojacking, paso 1: el núcleo (2026-11-10, en el HP)

Fila 4 de la Salida 0. Solo el núcleo portable (`src/Nexo.Modules.Threats/Criptojacking/VigilanteDeMineria.cs`); **aún sin lectores de Windows, servicio, ventana ni bandeja**, y sin lista real descargada.

- **Entradas (muestras):** procesos con CPU (% del total de la máquina) y si están en primer plano; conexiones TCP por proceso; una `ListaDePools` (IP y dominios; se lee de texto: una entrada por línea, `#` de comentario y formato hosts).
- **Reglas:** CPU ≥ 60 % en segundo plano durante 8 muestras seguidas (unos 4 min a 30 s) = «sostenida»; el primer plano (un juego) y los procesos del sistema (Defender, TiWorker…) no se vigilan; el PID reutilizado por otro programa empieza de cero; una lectura fallida en medio no borra la racha. Hallazgos: CPU sostenida sola = **Baja** (Media si vive en Temp/Descargas/etc.; compiladores y renderizadores también lo hacen, y el texto lo dice); CPU + puerto Stratum (3333, 4444, 5555, 7777, 14433, 14444, 45560, 45700) = **Alta**; IP/nombre de la lista sin CPU = **Alta** con aviso de posible falso positivo (IP compartidas); CPU sostenida + conexión a la lista = **Crítica** (un solo hallazgo). Un puerto «de minería» sin CPU alta no es nada.
- **Honestidad:** procesos o conexiones ilegibles, o lista vacía = «no evaluado», nunca «sin problemas». No detiene nada, no mira GPU ni memoria (YARA sobre procesos queda aparte) y no ve mineros con proxy o dominios que no estén en la lista.
- **Defectos reales cazados por las pruebas:** .NET acepta «1.2.3» como la IP 1.2.0.3 (inventaba una dirección) y luego la pasaba por dominio; ahora un IPv4 exige 4 números y un dominio no termina en etiqueta numérica.
- **Pruebas:** `Nexo.Vuln.Demo` §31-32; 5 roturas cazadas (una sexta, equivalente, descartada).
- **Siguiente (paso 2):** lectores de Windows (CPU por proceso con `Process.TotalProcessorTime`, conexiones con `GetExtendedTcpTable` por PID, primer plano con `GetForegroundWindow`), descarga de la lista pública (CoinBlockerLists, gratuita; **preguntar antes de descargar**) y resolución de sus dominios a IP; luego servicio (`mineria.estado`, apagado por omisión), sección en Seguridad y bandeja.

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

- **DESCARTADO por decisión del usuario (2026-11-10): el navegador seguro (Salida 0, fila 8).** Ya usa otros navegadores
  y no lo necesita. Con él caen también el **bloqueo de rastreadores** (fila 10, que el plan hacía dentro de ese navegador
  con WebView2; el bloqueo por `hosts` ya se descartó en §2ag). No hay que construirlos ni contarlos como pendientes.
- **El autocompletado de la bóveda (fila 12b) SIGUE, pero como extensión** (decisión del usuario, 2026-11-10): una
  extensión Manifest V3 para los navegadores Chromium del usuario (Brave, el de omisión, y Edge; Firefox no está
  instalado) que habla con Nexo por *native messaging*. Gratis: Edge publica gratis; en Brave se carga «sin empaquetar»
  (la tienda de Chrome cobra 5 USD). La extensión comprueba el DOMINIO real de la página antes de rellenar.

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
