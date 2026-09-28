---
titulo: Módulo de limpieza y optimización
tipo: diseno-modulo
modulo: limpieza
version: 1.0
fecha: 2026-09-28
estado: mvp-implementado-parcial
tags: [nexo/modulo/limpieza, nexo/fase-1]
---

# Módulo de limpieza y optimización — `Nexo.Modules.Cleanup`

> Salida del [[Prompt 4 Módulo de limpieza y optimización]], siguiendo [[Salida 0 - Arquitectura general del sistema]] y usando la librería de [[Salida 5 - Modulo de reportes y visualizacion]].
> **Estado: submódulos 1 y 2a implementados, compilados y ejecutados** contra un corpus sintético. Los otros cuatro son diseño. Ver §5.

---

## 0. La decisión que gobierna todo el módulo

Este es el único módulo de Nexo que **destruye datos de forma irreversible**. El riesgo L11 del análisis de viabilidad no es teórico: un fallo de canonicalización o una regla mal escrita en el catálogo borra documentos del usuario, y no hay deshacer.

Por eso el módulo tiene **tres capas de defensa independientes**, y las tres deben pasar para que un byte desaparezca:

```
   Catálogo declarativo          →  qué rutas EXISTEN como limpiables (JSON revisable)
          ↓
   GuardiaDeRutas                →  lista blanca por regla + lista negra global
          ↓
   Vista previa + TokenConfirmación →  el usuario aprueba una lista EXACTA
          ↓
                                    borrado (a Papelera por defecto)
```

**La API no permite expresar "borra sin preguntar".** No existe un método `Limpiar()`. Existen `PrepararVistaPreviaAsync()`, que devuelve qué se borraría junto con un token, y `EjecutarAsync(vista, token)`, que exige ese token. Es la única forma de garantizar la regla del prompt: que ninguna operación de borrado sea irreversible sin confirmación previa.

---

## 1. Los seis submódulos

### 1.1 Limpieza de basura y caché en un clic — **implementado**

`src/Nexo.Modules.Cleanup/Junk/`

| Pieza | Qué hace |
|---|---|
| `Data/cleanup-paths.json` | Catálogo declarativo: 21 reglas. **Es la lista de lo que el programa tiene permiso para destruir.** |
| `CatalogoDeRutas` | Carga y **valida** el catálogo al arrancar |
| `LimpiadorDeBasura` | Escaneo en dos fases, expansión de comodines, reporte |
| `GuardiaDeRutas` | Validación por archivo |
| `TokenConfirmacion` | Prueba de aprobación ligada al contenido |

**El catálogo está en JSON y no en código** porque la lista cambia con cada versión de Windows y cada navegador nuevo, y porque poder revisarla de un vistazo —sin compilar— es parte de la seguridad.

Nunca contiene rutas absolutas. Cada regla se ancla a una base simbólica (`localAppData`, `systemRoot`, `programData`…) que se resuelve en ejecución. Una ruta literal en el catálogo sería un borrado equivocado esperando a ocurrir en el siguiente equipo.

El validador rechaza al cargar: ids duplicados, subruta vacía (apuntaría a la carpeta base completa — *"limpiar todo `%SystemRoot%`"*), `..` en la subruta, y rutas absolutas.

**Comodines en la subruta.** Los navegadores numeran los perfiles (`Default`, `Profile 1`, `Profile 2`…) y Firefox les pone sufijo aleatorio. `Google\Chrome\User Data\*\Cache\Cache_Data` se expande a una carpeta por perfil existente. Si el navegador no está instalado, la expansión da vacío y no es un error.

**Antigüedad mínima.** Cada regla declara cuántos días debe llevar un archivo sin modificarse para ser candidato. `%SystemRoot%\Temp` usa 7 días para no pisar una instalación en curso; la caché de shaders usa 30. Es la defensa contra el caso clásico: borrar el temporal del instalador que está corriendo en ese momento.

### 1.2 Detector de duplicados — **implementado**

`src/Nexo.Modules.Cleanup/Duplicados/DetectorDuplicados.cs`

Tres etapas, cada una más cara que la anterior:

| Etapa | Coste | Qué descarta |
|---|---|---|
| 1. Agrupar por **tamaño** | Solo metadatos, O(n) | ~95% de los archivos: un tamaño único no puede tener duplicado |
| 2. Hash SHA-256 de los **primeros 8 KB** | Una lectura corta | Casi todo lo que sobrevivió a la etapa 1 |
| 3. Hash SHA-256 **completo** | Lectura íntegra | Nada: es la confirmación |

En un disco con 200.000 archivos, la etapa 3 suele tocar unos pocos cientos. Sin la etapa 1 habría que hashear los 200.000 enteros.

**Optimización que importa:** si el archivo cabe entero en los 8 KB de cabecera, la etapa 2 ya comparó todo su contenido y la etapa 3 se salta. Evita leer dos veces la mayoría de los archivos pequeños.

**Nunca por nombre.** La regla del prompt es explícita y el arnés la verifica en los dos sentidos: dos `informe.txt` con el mismo nombre y distinto contenido **no** se agrupan; `copia-vieja.dat` y `respaldo-2024.dat` con contenido idéntico **sí**.

**Suelo de 4 KB.** Un disco tiene decenas de miles de archivos diminutos idénticos (iconos, `__init__.py` vacíos, marcadores). Reportarlos es ruido: el espacio recuperable es irrelevante y el riesgo de borrar algo que una aplicación espera encontrar, no.

**Enlaces simbólicos excluidos.** Un enlace apunta al mismo contenido que su destino; contarlo como duplicado llevaría a "liberar" espacio que no existe.

**El detector no borra nada.** Produce grupos y una nota con acción `pendienteconfirmacion`. Propone conservar el más antiguo —suele ser el original y el que otras aplicaciones referencian— con desempate alfabético para que el resultado sea determinista entre ejecuciones.

### 1.3 Desinstalación de aplicaciones sin uso — **diseño; recomiendo no construirlo**

Inventario: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` + `Wow6432Node` + la rama `HKCU`, más `Get-AppxPackage` para las del Store. Desinstalación con el `UninstallString` de la propia entrada o `winget uninstall --id`.

El problema es **"sin uso"**, y es de fondo:

- `LastAccessTime` **está deshabilitado por defecto en NTFS desde Windows Vista** (`NtfsDisableLastAccessUpdate`). En Windows 10 1803+ pasó a "System Managed", que en volúmenes grandes significa desactivado. Usarlo como señal produce recomendaciones falsas.
- La alternativa real son los archivos de **Prefetch** (`C:\Windows\Prefetch\APP.EXE-XXXXXXXX.pf`): su fecha de modificación es la última ejecución. Requiere admin, y SuperFetch/SysMain puede estar desactivado en SSD.
- **UserAssist** (`HKCU\...\Explorer\UserAssist\{GUID}\Count`, con los nombres en ROT13) registra lanzamientos desde el Explorador, pero no los que vienen de la línea de comandos ni de un servicio.

Ninguna señal es fiable por sí sola, y recomendar desinstalar algo en uso destruye la confianza en toda la herramienta. **Coincide con la recomendación de [[Salida 6 - Analisis de viabilidad del proyecto]] de dejarlo fuera del MVP.** Si se construye, debe presentarse como "no lo he visto ejecutarse desde X", nunca como "sin uso".

### 1.4 Optimización de inicio — **diseño**

Fuentes a enumerar:

| Origen | Ubicación | Permisos |
|---|---|---|
| Registro usuario | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `RunOnce` | usuario |
| Registro máquina | `HKLM\…\Run`, `RunOnce`, y la rama `Wow6432Node` | **admin** |
| Carpeta de inicio | `shell:startup` (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) | usuario |
| Carpeta común | `shell:common startup` | **admin** |
| Tareas programadas | Task Scheduler, disparador de inicio de sesión | **admin** |
| Servicios | `Win32_Service` con `StartMode = Auto` | **admin** |

**La decisión de diseño que importa: deshabilitar, no borrar.**

Windows guarda el estado habilitado/deshabilitado en `…\Explorer\StartupApproved\Run`, `StartupApproved\Run32` y `StartupApproved\StartupFolder`. Es un valor binario de 12 bytes donde el primer byte manda: `0x02`/`0x06` = habilitado, `0x03` = deshabilitado.

Es **el mismo mecanismo que usa el Administrador de tareas**. Escribir ahí es reversible y el usuario ve el cambio reflejado en la pestaña "Inicio" de Windows. Borrar la entrada `Run` original sería irreversible y además invisible: el usuario no sabría qué se quitó.

Para medir impacto, el registro `Microsoft-Windows-Diagnostics-Performance/Operational`, eventos 100 (arranque) y 101 (aplicación que degrada el arranque), con los campos `Name` y `TotalTime`. Requiere admin. Es el mismo dato que alimenta la columna "Impacto de inicio" del Administrador de tareas — no hay que inventar una métrica propia.

### 1.5 Perfiles automáticos de rendimiento — **diseño**

Señales reales, no configuración manual:

| Señal | API |
|---|---|
| Batería / corriente | `GetSystemPowerStatus` → `ACLineStatus`, `BatteryLifePercent` |
| Pantalla completa (juego, vídeo) | `SHQueryUserNotificationState` → `QUNS_RUNNING_D3D_FULL_SCREEN`, `QUNS_PRESENTATION_MODE` |
| Proceso en primer plano | `GetForegroundWindow` + `GetWindowThreadProcessId` |
| Red pública | `INetworkListManager` → `NLM_NETWORK_CATEGORY_PUBLIC` |
| Wi-Fi abierto | `WlanQueryInterface` → algoritmo de autenticación `dot11` |

Aplicación: `PowerSetActiveScheme` con los GUID estándar — Equilibrado `381b4222-f694-41f0-9685-ff5bb260df2e`, Alto rendimiento `8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c`, Economizador `a1841308-3541-4fab-bc81-f71556f20b4a` — más `SetPriorityClass` para el proceso en primer plano. Requiere admin.

**Dos honestidades sobre este submódulo:**

1. **El perfil "Wi-Fi público" no es de rendimiento, es de seguridad.** No debe cambiar el plan de energía: debe poner el firewall en perfil Público, desactivar la detección de redes y sugerir la VPN. Está en este módulo solo porque la señal se detecta aquí; la acción pertenece a M1 y M2.
2. **En portátiles modernos con Modern Standby, forzar planes de energía suele empeorar las cosas.** Windows gestiona la frecuencia mejor que una heurística nuestra. El valor real está en el perfil de juego (subir prioridad, posponer tareas de Nexo) y en el de batería (posponer escaneos), no en pelearse con el gobernador de energía.

### 1.6 Monitoreo de salud del disco (S.M.A.R.T.) — **diseño**

Dos fuentes WMI, ambas con admin:

| Clase | Espacio de nombres | Da |
|---|---|---|
| `MSStorageDriver_FailurePredictStatus` | `root\wmi` | `PredictFailure` (bool) y `Reason` |
| `MSStorageDriver_FailurePredictData` | `root\wmi` | 512 bytes crudos: 30 atributos de 12 bytes (id, flags, value, worst, raw[6]) desde el offset 2 |
| `MSFT_PhysicalDisk` + `MSFT_StorageReliabilityCounter` | `root\Microsoft\Windows\Storage` | `Wear`, `Temperature`, `PowerOnHours`, `ReadErrorsUncorrected` — **más fiable en NVMe** |

**`PredictFailure` es binario y llega tarde.** Cuando se activa, el disco ya está mal. Los atributos que de verdad anticipan el fallo, según el conjunto de datos público de Backblaze, son cinco:

| ID | Atributo | Umbral de alerta |
|---|---|---|
| 05 | Reallocated Sectors Count | `> 0` y creciendo |
| 187 | Reported Uncorrectable Errors | `> 0` |
| 188 | Command Timeout | creciendo |
| 197 | Current Pending Sector Count | `> 0` — el más predictivo |
| 198 | Offline Uncorrectable | `> 0` |

**Limitaciones que hay que decirle al usuario, no esconder:** los puentes USB no suelen pasar los comandos SMART; las controladoras RAID e Intel VMD ocultan los discos físicos; y en NVMe la interfaz ATA no aplica — ahí hay que ir por los contadores de fiabilidad de Storage.

Ninguna métrica se inventa: todo sale de estas clases, tal como pide la regla del prompt.

### 1.7 Triturador de archivos — **diseño**

**Método:** abrir con `FileShare.None`, sobrescribir el largo completo con un patrón, `FlushFileBuffers`, renombrar a un nombre aleatorio varias veces, truncar a 0 y borrar.

**Número de pasadas: una.** NIST SP 800-88 Rev. 1 establece que una sola sobrescritura es suficiente en unidades magnéticas modernas. Las 35 pasadas de Gutmann son de 1996 y atacaban codificaciones MFM y RLL que ya no existen en ningún disco fabricado en este siglo. Ofrecer 35 pasadas es vender teatro y desgastar el disco.

**En SSD no garantiza nada.** El controlador reparte las escrituras (*wear leveling*) y la sobrescritura lógica va a un bloque físico distinto; el original queda intacto en una celda no direccionable. La respuesta correcta en SSD es:

- **BitLocker activado desde antes** de que el archivo existiera, y entonces basta con descartar la clave (cripto-borrado);
- o `ATA Secure Erase` / `NVMe Format` sobre el disco entero, que no es una operación por archivo.

El módulo debe **decir esto en la interfaz**, no esconderlo: `Eventos.Limpieza.Triturado` ya emite un callout `[!warning]` con esta advertencia cuando el volumen es SSD, y un campo `garantia_borrado: parcial`.

**Tres fugas adicionales en NTFS**, ciertas incluso en disco magnético:

1. **Archivos residentes.** Un archivo de menos de ~700 bytes vive dentro de su registro en la `$MFT`. Sobrescribir "el archivo" no toca ese registro.
2. **Instantáneas de volumen (VSS).** Si hay puntos de restauración, existen copias anteriores del archivo.
3. **`$LogFile` y el journal.** Pueden conservar fragmentos de metadatos y de datos pequeños.

Conclusión honesta: **triturar archivos sueltos en NTFS nunca es completo.** Lo que sí garantiza es que las herramientas normales de recuperación no lo encuentren, y ese es el 95% del caso de uso real.

---

## 2. Rutas de Windows cubiertas

Esta es la salida 3 del prompt: el catálogo completo, con la columna de permisos.

### Sin privilegios de administrador — perfil del usuario

| Ruta | Categoría | Riesgo | Nota |
|---|---|---|---|
| `%LOCALAPPDATA%\Temp` | temporales | bajo | Es `%TEMP%`. Los archivos en uso quedan bloqueados y se omiten solos. |
| `%LOCALAPPDATA%\CrashDumps\*.dmp` | volcados | bajo | Solo útiles si estás depurando un cuelgue concreto. |
| `%LOCALAPPDATA%\Microsoft\Windows\INetCache` | caché | bajo | Lo sigue usando cualquier app con WebView embebido. |
| `%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db` | miniaturas | bajo | Se regenera; la primera carpeta con imágenes irá más lenta. |
| `%LOCALAPPDATA%\Microsoft\Windows\WER` | logs | bajo | `ReportArchive` y `ReportQueue`. No afecta al Visor de eventos. |
| `%LOCALAPPDATA%\NVIDIA\DXCache` | caché GPU | bajo | Shaders. Se regenera; el primer arranque de cada juego tarda más. |
| `%LOCALAPPDATA%\D3DSCache` | caché GPU | bajo | Ídem, de DirectX. |
| `%LOCALAPPDATA%\Google\Chrome\User Data\*\Cache\Cache_Data` | caché | bajo | Cierra Chrome antes o quedará bloqueado. |
| `%LOCALAPPDATA%\Google\Chrome\User Data\*\Code Cache` | caché | bajo | JavaScript y WASM compilados. |
| `%LOCALAPPDATA%\Microsoft\Edge\User Data\*\Cache\Cache_Data` | caché | bajo | Mismo formato: Edge comparte motor con Chrome. |
| `%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*\cache2` | caché | bajo | Firefox separa caché (Local) de perfil (Roaming). |
| `%LOCALAPPDATA%\Google\Chrome\User Data\*\Network\Cookies` | cookies | **medio** | Te cierra la sesión en **todos** los sitios. SQLite: todo o nada. Desactivado por defecto. |
| `%LOCALAPPDATA%\Google\Chrome\User Data\*\History` | historial | **medio** | Pierdes historial y sugerencias de la barra. Desactivado por defecto. |
| `%APPDATA%\Microsoft\Windows\Recent\*.lnk` | historial | **medio** | Vacía Acceso rápido y listas de saltos. Solo accesos directos, nunca los documentos. |
| Papelera de reciclaje | papelera | bajo | Vía `SHEmptyRecycleBin`. **Nunca borrando `C:\$Recycle.Bin` a mano.** |

### Requieren administrador

| Ruta | Categoría | Riesgo | Nota |
|---|---|---|---|
| `%SystemRoot%\Temp` | temporales | bajo | 7 días de margen: lo usan instaladores y servicios. |
| `%SystemRoot%\SoftwareDistribution\Download` | actualizaciones | **medio** | **Hay que detener `wuauserv` antes.** Una actualización a medias se volverá a descargar. |
| `%SystemRoot%\Logs\CBS\*.log` | logs | bajo | Llegan a varios GB. Solo se necesitan para diagnosticar DISM o SFC. |
| `%SystemRoot%\Minidump\*.dmp` | volcados | **medio** | Si estás investigando pantallazos azules, esto es justo lo que hay que conservar. |
| `%ProgramData%\Microsoft\Windows\WER` | logs | bajo | Informes de error de todos los usuarios. |

### Nunca — lista negra codificada en `GuardiaDeRutas`

El guardia rechaza cualquier ruta que contenga estos **segmentos completos**, sea cual sea la regla que la propuso:

```
WinSxS · System32 · SysWOW64 · Installer · Program Files · Program Files (x86)
System Volume Information · $Recycle.Bin · Boot · EFI · Recovery · Windows.old
Documents/Documentos · Desktop/Escritorio · Pictures/Imágenes · Videos/Vídeos
Music/Música · Downloads/Descargas · OneDrive · Dropbox · Google Drive · iCloudDrive
```

y estos archivos por nombre exacto:

```
pagefile.sys · hiberfil.sys · swapfile.sys · MEMORY.DMP
ntuser.dat · usrclass.dat · bootmgr · BOOTNXT
```

La comparación es **por segmento, no por subcadena**: `C:\Users\alvaro\Documents` está prohibido, pero un archivo llamado `Documents.log` dentro de `Temp` no lo está.

**Tres de la lista merecen explicación:**

- **`WinSxS`** — borrar aquí rompe Windows Update de forma no reparable. La única manera legítima de reducirlo es `DISM /Online /Cleanup-Image /StartComponentCleanup`.
- **`Installer`** (`$PatchCache$`) — rompe desinstalar y reparar cualquier paquete MSI.
- **`Windows.old`** — se quita con el Liberador de espacio de Windows, que sabe desmontar sus enlaces duros. Borrarlo a mano deja el disco en un estado raro.

---

## 3. El guardia de rutas

`src/Nexo.Modules.Cleanup/Seguridad/GuardiaDeRutas.cs`

Modelo de **lista blanca**, no negra: una ruta solo se acepta si cae dentro de una raíz explícitamente permitida. La lista negra es la segunda barrera, por si una raíz resulta demasiado amplia.

```csharp
// Comparacion por frontera de separador. Sin esto, la raiz "C:\Temp"
// aceptaria "C:\Temporal\importante.docx" por simple prefijo de texto.
private bool DentroDeAlgunaRaiz(string canonica)
{
    foreach (string raiz in _raicesPermitidas)
    {
        if (canonica.Length <= raiz.Length) continue;
        if (!canonica.StartsWith(raiz, _comparacion)) continue;
        char siguiente = canonica[raiz.Length];
        if (siguiente == Path.DirectorySeparatorChar || siguiente == Path.AltDirectorySeparatorChar)
            return true;
    }
    return false;
}
```

Ese `char siguiente` es el bug clásico de los limpiadores: comparar prefijos de texto sin exigir la frontera de separador. El arnés lo verifica con una carpeta `temp-vecino` que comparte prefijo con `temp`.

Lo que comprueba cada validación, en orden:

1. Canonicalización (`Path.GetFullPath`) — colapsa `..` y `.`
2. Dentro de alguna raíz permitida, con frontera de separador
3. Ningún segmento en la lista negra
4. Nombre no está en la lista de archivos prohibidos
5. **No es un directorio**, y existe
6. **No es un punto de reanálisis** (`FileAttributes.ReparsePoint`)
7. No es sistema + oculto a la vez
8. Cumple la antigüedad mínima de la regla

El punto 6 importa más de lo que parece. Un enlace simbólico o una unión (*junction*) dentro de `Temp` puede apuntar a `C:\Users\alvaro\Documents`, y es el vector clásico para convertir un limpiador en una herramienta de borrado arbitrario. El guardia lo rechaza y el arnés lo verifica con un enlace real.

**El guardia se instancia por regla, no globalmente.** Cada regla solo puede borrar dentro de su propia carpeta, así que un error en una regla no puede alcanzar la carpeta de otra.

---

## 4. El token de confirmación

`src/Nexo.Modules.Cleanup/Seguridad/TokenConfirmacion.cs`

No es un booleano. Lleva el SHA-256 de la lista exacta que el usuario aprobó — **ruta, tamaño y fecha de modificación de cada archivo**, ordenados para que la huella no dependa del orden de recorrido del disco.

Cierra dos agujeros a la vez:

1. **TOCTOU.** Entre que el usuario mira la lista y pulsa "Limpiar" pueden pasar minutos. Un archivo pudo cambiar de tamaño, desaparecer o reaparecer. Al ejecutar se recalcula la huella sobre el estado actual y **solo se borra lo que coincide**.
2. **Escalada desde la interfaz.** El servicio corre como LocalSystem y no confía en la UI (regla de [[Salida 0 - Arquitectura general del sistema]]). Un proceso que pida el borrado de otra lista no tiene token válido para ella.

Vigencia: 10 minutos. Pasado ese plazo hay que volver a previsualizar.

La comparación usa `CryptographicOperations.FixedTimeEquals` — no porque un ataque de temporización sea realista aquí, sino porque comparar hashes con `==` es un hábito que se acaba copiando a un sitio donde sí importa.

---

## 5. Verificación — ejecutada, no afirmada

```
$ dotnet tools/Nexo.Cleanup.Demo/bin/Debug/net8.0/nexo-cleanup-demo.dll ./cleanup

1. Guardia de rutas (lista blanca + lista negra)
  [OK]    acepta un archivo dentro de la raiz permitida
  [OK]    rechaza un archivo fuera de la raiz permitida
  [OK]    rechaza 'temp-vecino' pese a compartir prefijo con 'temp'
  [OK]    rechaza un intento de salir con '..'
  [OK]    rechaza un enlace simbolico que apunta fuera
  [OK]    rechaza un subdirectorio dentro de la raiz permitida
  [OK]    rechaza la propia raiz permitida
  [OK]    rechaza 'Documents' aunque la raiz permitida lo incluya
  [OK]    rechaza un archivo modificado hace menos que la antiguedad minima
  [OK]    se niega a aceptar la raiz de un volumen como raiz de limpieza

2. Limpieza: vista previa obligatoria y token
  [OK]    la vista previa encuentra los 5 archivos limpiables
  [OK]    la vista previa no incluye nada de Documents
  [OK]    la vista previa no incluye el archivo fuera de las reglas
  [OK]    el comodin de subruta encontro el perfil 'Profile 1'
  [OK]    rechaza ejecutar con un token que no corresponde a la vista previa
  [OK]    rechaza ejecutar con un token caducado
  [OK]    no borra un archivo que cambio despues de la vista previa (TOCTOU)
  [OK]    borro los 4 archivos restantes
  [OK]    TRAMPA: Documents/importante.docx sigue intacto
  [OK]    TRAMPA: secreto.txt sigue intacto

3. Duplicados: por contenido, nunca por nombre ni tamano
  [OK]    encuentra exactamente 2 grupos
  [OK]    agrupa grande-a y grande-b, y DESCARTA grande-c
  [OK]    grande-c.bin no esta en el grupo
  [OK]    agrupa dos archivos con NOMBRES distintos y contenido igual
  [OK]    NO agrupa dos 'informe.txt' con el mismo nombre y distinto contenido
  [OK]    ignora los archivos por debajo del minimo de 4 KB
  [OK]    solo 3 archivos llegaron al hash completo
  [OK]    ningun grupo repite la misma ruta

TODAS LAS VERIFICACIONES PASARON
```

**28 comprobaciones.** El corpus sintético incluye archivos **trampa** que deben sobrevivir: si alguno desaparece, la verificación falla. Es la única forma de probar que el guardia sirve para algo.

### El caso de prueba que más importa

```
grande-a.bin = [8 KB patrón H][24 KB patrón Q]   ← 32.768 bytes
grande-b.bin = [8 KB patrón H][24 KB patrón Q]   ← idéntico a A
grande-c.bin = [8 KB patrón H][24 KB patrón R]   ← MISMO tamaño, MISMA cabecera
```

Los tres tienen el mismo tamaño (etapa 1 no los separa) y el mismo hash de los primeros 8 KB (etapa 2 tampoco). **Solo el hash completo distingue C de A y B.** El arnés verifica que el grupo resultante tiene exactamente 2 archivos y que `grande-c.bin` no está.

Verifica además que `hasheados_completos == 3`: si el filtrado por etapas se rompiera y pasara a hashear todo, ese número subiría y la prueba fallaría.

### El bug que encontró ejecutarlo

La comprobación "rechaza un directorio" falló en la primera ejecución. **El fallo era del test, no del guardia**: validaba la raíz permitida misma, que se rechaza antes por `FueraDeRaicesPermitidas` (el guardia exige estar *estrictamente dentro* de la raíz). Corregido a un subdirectorio, más una comprobación nueva de que la propia raíz también se rechaza.

### Integración con reportes, verificada

La sesión de limpieza generó esta nota, con la exclusión TOCTOU visible en el detalle:

```yaml
tipo: sesion-limpieza
accion: eliminada
categorias: [cache-navegadores, temporales]
archivos_eliminados: 4
bytes_liberados: 21504
espacio_liberado: 21 KB
confirmado_por_usuario: true
a_papelera: false
archivos_omitidos: 1
reversible: false
```

```markdown
### Archivos omitidos
- `…/temp/a.tmp — cambio de tamano desde la vista previa`
```

**Cero logs propios**: una sola llamada a `IReportWriter`, como exige la regla del prompt.

### Lo que no pude verificar

Este equipo es Linux. **Lo verificado es toda la lógica portable** —guardia, catálogo, token, vista previa, duplicados, reportes— que es donde está el riesgo de destruir datos. Falta en Windows real:

- Las rutas del catálogo (`%LOCALAPPDATA%\…`) contra un perfil de verdad.
- `ShellFileOperations.EnviarAPapelera` — compila (`net8.0-windows`, 0 advertencias) pero no se ha ejecutado.
- El comportamiento con archivos bloqueados por otro proceso, que en Windows es la norma y aquí no ocurre.
- Uniones NTFS (*junctions*), que el guardia trata igual que los enlaces simbólicos por `ReparsePoint`, pero no se ha comprobado.

**Primera ejecución en Windows: con `BorradorSimulado`, no con `BorradorReal`.** Está para eso: recorre el flujo completo y registra qué habría borrado, sin tocar un solo archivo. Cuando la lista que imprima sea la esperada dos o tres veces seguidas, se cambia a `BorradorPapelera`.

---

## 6. Verificación final del prompt

- **(a) Ningún borrado irreversible sin confirmación previa** — la API no expone ningún camino que borre sin una `VistaPreviaLimpieza` y su `TokenConfirmacion`. El token se liga al contenido exacto: rutas, tamaños y fechas. Verificado con tres casos: token ajeno, token caducado y archivo modificado tras la vista previa. Además, el borrador por defecto en Windows es la **Papelera** (`FOF_ALLOWUNDO`); el borrado permanente es una elección explícita.
- **(b) Duplicados por hash de contenido, no por nombre ni tamaño** — tres etapas con SHA-256, verificado en ambos sentidos: mismo nombre + distinto contenido **no** agrupa; distinto nombre + mismo contenido **sí**; y mismo tamaño + misma cabecera de 8 KB + distinto final tampoco agrupa.
- **(c) S.M.A.R.T. por WMI sin métricas inventadas** — `MSStorageDriver_FailurePredictStatus`, `MSStorageDriver_FailurePredictData` y `MSFT_StorageReliabilityCounter`, con los cinco atributos predictivos y sus limitaciones reales declaradas.
- **(d) Triturador con método explícito y salvedad de SSD** — una pasada (NIST SP 800-88), *wear leveling* documentado, más las tres fugas de NTFS. La advertencia llega al usuario en la propia nota, no solo en la documentación.

## Siguiente

Según [[Salida 6 - Analisis de viabilidad del proyecto]]: cerrar M4 con inicio, S.M.A.R.T. y triturador (~55–85 h), o saltar al firewall por aplicación de [[Prompt 1 Módulo de protección contra amenazas]]. Antes de cualquiera de las dos: **montar la VM y ejecutar el arnés en Windows con `BorradorSimulado`** — es el paso 1 de los próximos pasos y sigue pendiente.
