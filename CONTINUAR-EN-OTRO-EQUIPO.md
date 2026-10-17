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

**134 comprobaciones automatizadas, todas en verde, en Windows 10** (127 al
traspaso; +7 del historial de S.M.A.R.T., 2026-10-17):

| Arnés | Comprobaciones | Qué cubre |
|---|---|---|
| `tools/Nexo.Reports.Demo` | 13 | Notas, vault, redacción, nombres NTFS |
| `tools/Nexo.Cleanup.Demo` | 92 | Guardia, limpieza, duplicados, triturador, inicio, S.M.A.R.T. e historial (portable) |
| `tools/Nexo.Cleanup.Windows.Demo` | 29 | Tipo de disco, registro de inicio, Papelera, archivos bloqueados, discos reales |

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
> En el principal falta S.M.A.R.T. con el disco SATA (atributos ATA reales) y
> el USB.

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

- Pasar al firewall por aplicación de `Prompt 1 Módulo de protección contra amenazas.md`,
  que necesita antes la salida del Prompt 0 pegada en su bloque `<arquitectura>`.
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
