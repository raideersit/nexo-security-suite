# Continuar en otro equipo

> Documento de traspaso **vigente** (2026-10-04). Si abres una sesión nueva de
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

**314 comprobaciones automatizadas, todas en verde, en Windows 10** (127 al
traspaso; +7 del historial de S.M.A.R.T., 2026-10-17; +4 de carpeta inaccesible y
+84 del firewall y +67 del escáner, 2026-10-21; +9 de la purga y +5 de reglas ajenas +6 del escaneo en paralelo y +5 de la lista de protegidos, 2026-10-22):

| Arnés | Comprobaciones | Qué cubre |
|---|---|---|
| `tools/Nexo.Reports.Demo` | 13 | Notas, vault, redacción, nombres NTFS |
| `tools/Nexo.Cleanup.Demo` | 96 | Guardia, limpieza, duplicados, triturador, inicio, S.M.A.R.T. e historial (portable) |
| `tools/Nexo.Cleanup.Windows.Demo` | 29 | Tipo de disco, registro de inicio, Papelera, archivos bloqueados, discos reales |
| `tools/Nexo.Firewall.Demo` | 66 | Guardia de reglas, plan/token, reglas ajenas, modo sigiloso (portable) |
| `tools/Nexo.Firewall.Windows.Demo` | 28 | Firewall de Windows real: lectura, reglas por app, sigiloso (como administrador) |
| `tools/Nexo.Scan.Demo` | 82 | Cliente clamd (contra un clamd falso), escáner, cuarentena (portable) |

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

- No lee los **bloqueos** efectivos (evento 5157 del registro de Seguridad, que
  exige activar la auditoría de WFP): `Eventos.Amenazas.Firewall` existe pero
  nadie lo emite todavía. Hoy solo se reportan los *cambios de configuración*.
- Reglas por puerto/IP/protocolo y listas de bloqueo: solo por aplicación.
- ~~Lista de protegidos fija~~ Hecho (2026-10-22): `%LOCALAPPDATA%Nexoirewall-protegidos.txt` (o `--protegidos`) añade nombres; solo suma, nunca quita svchost ni Defender.
- Sin integración en `Nexo.Service` (no existe todavía) ni confirmación desde la UI.
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
- Sin **tiempo real** (USN Journal), sin AMSI, sin escaneo programado.
- ~~La cuarentena no purga~~ Hecho (2026-10-22): `nexo-scan cuarentena purgar` elimina lo que superó los 30 días, con vista previa, token y confirmación `PURGAR`. Es manual: nada la ejecuta sola hasta que exista el servicio.
- Sin exclusión mutua con Defender (añadir la carpeta de cuarentena a sus exclusiones).
- ~~Escaneo secuencial~~ Hecho (2026-10-22): `--paralelo N` (1-8, por defecto 1) analiza N archivos a la vez, una conexión por archivo. No usa `IDSESSION`. Con clamd real falta medir si compensa.
- Archivos > 25 MB no se analizan (quedan como omitidos): ISOs, VMs, instaladores grandes.
- Los archivos comprimidos los abre `clamd`; no hay control de límites de recursión.

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
- **Impacto de arranque** (§1.4): los eventos 100/101 de
  `Microsoft-Windows-Diagnostics-Performance/Operational` no se leen aún.
- ~~**S.M.A.R.T.:** la lectura anterior no se guardaba entre ejecuciones.~~
  Hecho (2026-10-17): `Disco/HistorialDeSalud` la guarda en JSON (escritura
  atómica, serie ya redactada) y `MonitorDeSalud` la usa si se le pasa. Una
  lectura sin atributos no pisa a una anterior que sí los tenía; un archivo
  dañado se aparta como `.corrupto` y el evento dice que no se evaluó el
  crecimiento. Es **estado, no un log**: no rompe la regla de §8. Falta decidir
  la ruta definitiva cuando exista el servicio (p. ej. `%ProgramData%\Nexo`).
- **Servicios y tareas programadas** como fuentes de inicio (§1.4): solo se leen
  `Run` y las carpetas de inicio.
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
