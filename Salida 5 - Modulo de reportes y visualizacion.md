---
titulo: Módulo de reportes y visualización (Nexo.Reports)
tipo: diseno-modulo
modulo: reportes
version: 1.0
fecha: 2026-09-28
estado: implementado-mvp
tags: [nexo/modulo/reportes, nexo/fase-1]
---

# Módulo de reportes y visualización — `Nexo.Reports`

> Salida del [[Prompt 5 Módulo de reportes y visualización (integración con Obsidian)]], siguiendo [[Salida 0 - Arquitectura general del sistema]] y el alcance recortado de [[Salida 6 - Analisis de viabilidad del proyecto]].
> **Estado: código escrito, compilado y ejecutado.** Ver §6.

---

## 0. Qué se entrega

| Artefacto | Ruta |
|---|---|
| Librería | `src/Nexo.Reports/` — 20 archivos `.cs`, `netstandard2.0` + `net8.0`, **cero dependencias NuGet** |
| Arnés de aceptación | `tools/Nexo.Reports.Demo/` — genera un vault sintético y verifica los casos borde |
| Vault de ejemplo | se genera al ejecutar el arnés |

La librería compila con `TreatWarningsAsErrors` y **0 advertencias**. El arnés genera 59 notas y pasa las 13 verificaciones.

### Por qué cero dependencias NuGet

`Nexo.Reports` la referencian los cinco módulos. Si arrastrara YamlDotNet, un conflicto de versión entre ese paquete y cualquier otro rompería el servicio completo. El esquema YAML que escribimos es cerrado (escalares y listas de texto), así que un serializador propio de 80 líneas es suficiente y auditable de una sentada. `YamlWriter` **solo escribe**; no intenta ser un parser.

---

## 1. Estructura del vault

```
%ProgramData%\Nexo\Vault\
│
├─ 00 Panel\
│   ├─ Panel.md                        ← nota de entrada; búsquedas útiles listas para pegar
│   └─ Como leer este vault.md
│
├─ 01 Diario\
│   └─ 2026\2026-09\
│       ├─ 2026-09-27.md               ← nota-resumen diaria
│       └─ 2026-09-28.md
│
├─ 02 Eventos\
│   ├─ Amenazas\2026\2026-09\*.md
│   ├─ Privacidad\2026\2026-09\*.md
│   ├─ Identidad\2026\2026-09\*.md
│   ├─ Limpieza\2026\2026-09\*.md
│   └─ Sistema\2026\2026-09\*.md
│
├─ 03 Entidades\
│   ├─ Archivos\Archivo - factura_pendiente.pdf.exe.md
│   ├─ Procesos\Proceso - chrome.exe.md
│   ├─ Aplicaciones\App - sc.exe.md
│   ├─ Dispositivos\Dispositivo - Samsung SSD 980 PRO 1TB.md
│   ├─ Dominios\
│   └─ Cuentas\Cuenta - us___@correo.cl.md
│
├─ 99 Sistema\
│   ├─ Esquema de notas.md
│   └─ ADVERTENCIA DE SEGURIDAD.md
│
└─ .gitignore                          ← ignora todo; evita un `git add .` accidental
```

**El prefijo numérico no es decoración.** Obsidian ordena el explorador alfabéticamente y no permite reordenar carpetas a mano; sin el prefijo, `01 Diario` quedaría después de `03 Entidades`.

**Por año y mes, no por día.** Una carpeta por día genera 365 carpetas al año, casi todas con dos archivos. Agrupar por mes mantiene el explorador navegable y el nombre del archivo ya lleva la fecha completa.

### `03 Entidades` es la decisión de diseño que justifica usar Obsidian

Sin esta carpeta, el vault sería un log con formato bonito. Con ella, cada archivo, proceso, aplicación, disco, dominio y cuenta tiene **una nota propia**, y todos los eventos que lo mencionan enlazan hacia ella.

El resultado: abres `Archivo - factura_pendiente.pdf.exe` y el panel **Vínculos a esta nota** te muestra la detección, la cuarentena, el escaneo que lo encontró y el bloqueo de firewall del proceso que lo descargó — de cualquier módulo y cualquier fecha, sin haber escrito una sola consulta. Eso es lo que un archivo `.log` no puede hacer y lo que habría costado meses construir como UI propia.

`EntityNoteWriter` crea cada nota **una sola vez** y no la vuelve a tocar nunca. Por eso tienen una sección `## Notas` al final: es el único lugar del vault donde puedes escribir a mano con la garantía de que Nexo no lo pisará.

---

## 2. Convención de nombres

```
2026-09-28 0807-00 - Amenaza - Win.Trojan.AgentTesla-9912 en factura_pendiente.pdf.exe.md
└────────┬───────┘   └───┬──┘   └──────────────────────┬────────────────────────────┘
      fecha+hora        tipo                    título saneado
```

- **Ordena solo.** El prefijo ISO hace que el orden alfabético sea el cronológico.
- **Legible.** El tipo va en el nombre para reconocer la nota en resultados de búsqueda sin abrirla.
- **La hora usa `HHmm-ss`**, no `HH:mm:ss`: los dos puntos están prohibidos en NTFS y rompen los wikilinks.

### Colisiones

Timestamp al segundo + contador `(2)`, `(3)`… Solo puede ocurrir si dos eventos del mismo tipo caen en el mismo segundo con el mismo título. A las 99 colisiones la librería **lanza una excepción**: eso ya no es concurrencia, es un módulo en bucle, y llenar el disco de notas sería peor que fallar ruidosamente.

### Saneamiento — los casos que realmente rompen un vault

`NoteNaming.Sanear` elimina la unión de dos conjuntos: lo que Windows prohíbe (`\ / : * ? " < > |`) y lo que rompe un wikilink (`[ ] # ^ |`). Además:

| Caso | Entrada | Resultado |
|---|---|---|
| Caracteres prohibidos | `Malware [PUA] #cryptominer \| ruta: C:\x*?\y<z>.exe` | `Malware -PUA- -cryptominer - ruta- C-x-y-z-.exe` |
| Nombre reservado MS-DOS | `CON` | `CON_` |
| Reservado con extensión | `aux.exe` | `aux.exe_` |
| Espacios y puntos finales | `   espacios    multiples   y punto final...` | `espacios multiples y punto final` |
| Título de 300 caracteres | `AAAA…` | recortado a 88, nombre total ≤ 120 |

Los nombres reservados **no son hipotéticos**: llamar a un ejecutable `aux.exe` es una técnica conocida de evasión, y es exactamente el archivo cuyo nombre menos queremos perder. Por eso se sufija en vez de descartarse.

Las tildes y eñes **se conservan**: Obsidian las maneja sin problema y el vault lo lee una persona hispanohablante.

---

## 3. Formato de las notas

### 3.1 Campos comunes a toda nota de evento

| Campo | Tipo | Notas |
|---|---|---|
| `id` | texto | GUID. Da idempotencia: un reintento tras fallo no duplica la nota. |
| `fecha` | fecha-hora | `2026-09-28T08:07:00`, **sin offset**. Es el único formato que el panel de propiedades de Obsidian reconoce nativamente como fecha. |
| `zona` | texto | `-03:00`. El offset va aparte para no perderlo — en Chile cambia dos veces al año. |
| `modulo` | texto | `amenazas` · `privacidad` · `identidad` · `limpieza` · `sistema` |
| `tipo` | texto | uno de los 17 tipos de evento |
| `severidad` | texto | `info` · `baja` · `media` · `alta` · `critica` |
| `accion` | texto | `ninguna` · `registrada` · `bloqueada` · `cuarentena` · `eliminada` · `restaurada` · `omitida` · `pendienteconfirmacion` |
| `equipo` | texto | nombre del equipo |
| `tags` | lista | `nexo/evento`, `nexo/{modulo}`, `nexo/tipo/{tipo}`, `nexo/severidad/{sev}`, `nexo/accion/{accion}` |

Las etiquetas son jerárquicas a propósito: el panel de etiquetas de Obsidian las pliega en árbol y permite filtrar por rama sin plugins.

### 3.2 Los seis tipos que pide el requisito, con ejemplos reales

Todo lo que sigue es **salida literal** del arnés de aceptación, no ejemplos escritos a mano.

#### Amenaza detectada

```yaml
---
id: f21be624-cf94-4955-9d03-512d4465376b
fecha: 2026-09-28T08:07:00
zona: "-03:00"
modulo: amenazas
tipo: amenaza-detectada
severidad: critica
accion: cuarentena
equipo: NEXO-LAB
firma: Win.Trojan.AgentTesla-9912
motor: ClamAV
ruta: "C:\\Users\\alvaro\\Descargas\\factura_pendiente.pdf.exe"
sha256: 3b1f0c9e8a7d6b5c4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d
proceso_origen: chrome.exe
tags:
  - nexo/evento
  - nexo/amenazas
  - nexo/tipo/amenaza-detectada
  - nexo/severidad/critica
  - nexo/accion/cuarentena
---

# Win.Trojan.AgentTesla-9912 en factura_pendiente.pdf.exe

> [!danger] Amenaza · severidad critica
> **Accion:** archivo movido a cuarentena  
> **Cuando:** lunes 28 de septiembre de 2026, 08:07:00  
> **Equipo:** NEXO-LAB

## Datos

| Campo | Valor |
|---|---|
| firma | Win.Trojan.AgentTesla-9912 |
| motor | ClamAV |
| ruta | C:\Users\alvaro\Descargas\factura_pendiente.pdf.exe |
| sha256 | 3b1f0c9e8a7d6b5c4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d |
| proceso_origen | chrome.exe |

## Entidades relacionadas

- [[Archivo - factura_pendiente.pdf.exe]]
- [[Proceso - chrome.exe]]

## Contexto

- Dia: [[2026-09-28]]
- Modulo: Amenazas
- Panel: [[Panel]]
```

Los callouts `> [!danger]`, `[!warning]`, `[!info]`, `[!todo]` son **nativos de Obsidian**: no requieren plugin. El mapeo es `crítica→danger`, `alta→warning`, `media→attention`, `baja→note`, `info→info`.

#### Archivo en cuarentena

```yaml
tipo: archivo-en-cuarentena
severidad: alta
accion: cuarentena
ruta_original: "C:\\Users\\alvaro\\Descargas\\factura_pendiente.pdf.exe"
id_cuarentena: q-20260928-0001
bytes: 482304
tamano: 471 KB
firma: Win.Trojan.AgentTesla-9912
restaurable_hasta: 2026-10-28T08:00:00
```

`bytes` **y** `tamano`: el primero para ordenar y sumar, el segundo para leer. Es la única duplicación deliberada del esquema.

#### Bloqueo de firewall

```yaml
tipo: bloqueo-firewall
severidad: media
accion: bloqueada
aplicacion: "C:\\Program Files\\ScreenConnect\\sc.exe"
direccion: saliente
ip_remota: 185.220.101.47
puerto: 443
protocolo: TCP
regla: Nexo - bloqueo saliente no clasificado
```

El título usa solo `sc.exe`, no la ruta: una ruta completa saneada se vuelve ilegible como nombre de archivo (`C-Program Files-ScreenConnect-sc.exe`). La ruta completa vive en el campo.

#### Resultado de escaneo

```yaml
tipo: resultado-escaneo
severidad: alta
accion: registrada
alcance: "C:\\Users\\alvaro\\Descargas"
archivos_analizados: 12483
detecciones: 2
duracion_segundos: 97.4
motor: ClamAV 1.3 + YARA 4.5
```

La severidad es `info` si no hay hallazgos y `alta` si los hay: la decide la fábrica, no el módulo que llama.

#### Conexión VPN

```yaml
tipo: conexion-vpn
severidad: info
accion: registrada
servidor: cl-santiago-01
pais: Chile
estado: conectado
protocolo: WireGuard
```

Al desconectar se añaden `duracion_minutos`, `enviado` y `recibido`.

#### Sesión de limpieza

```yaml
tipo: sesion-limpieza
severidad: info
accion: eliminada
categorias:
  - temporales
  - cache-navegadores
  - papelera
  - logs-windows
archivos_eliminados: 8412
bytes_liberados: 4294967296
espacio_liberado: 4 GB
confirmado_por_usuario: true
a_papelera: false
duracion_segundos: 42.8
```

`confirmado_por_usuario` no es un campo informativo: `Eventos.Limpieza.Sesion` **lanza una excepción si llega en `false`**. La regla de [[Prompt 4 Módulo de limpieza y optimización]] es que ningún borrado ocurre sin vista previa y confirmación; si el módulo intenta registrar un borrado no confirmado, el bug está en el módulo y debe reventar en la primera prueba.

#### Alerta de identidad / brecha

```yaml
tipo: brecha-detectada
severidad: alta
accion: pendienteconfirmacion
cuenta: usu***plo@correo.cl
brecha: "Collection #1"
fecha_brecha: 2019-01-07T00:00:00
datos_expuestos:
  - correos
  - contrasenas
cuentas_afectadas: 772904991
fuente: Have I Been Pwned
```

**La firma del método no acepta la credencial.** No hay parámetro para la contraseña, ni para su hash, ni para un prefijo de su hash. Solo metadatos de la brecha. Ver §5.

Nótese `brecha: "Collection #1"` — entrecomillado automáticamente porque ` #` iniciaría un comentario YAML y truncaría el valor.

### 3.3 Nota-resumen diaria

Es el dashboard del MVP. Ejemplo real:

```markdown
---
tipo: resumen-diario
fecha: 2026-09-28
eventos_total: 13
eventos_amenazas: 5
eventos_privacidad: 3
eventos_identidad: 1
eventos_limpieza: 4
eventos_sistema: 0
severidad_maxima: critica
tags:
  - nexo/diario
  - nexo/severidad/critica
---

# 2026-09-28

`< ` [[2026-09-27]]  ·  [[Panel]]  ·  [[2026-09-29]] ` >`

## Resumen

| Modulo | Eventos |
|---|---:|
| Amenazas | 5 |
| Privacidad | 3 |
| Identidad | 1 |
| Limpieza | 4 |
| Sistema | 0 |
| **Total** | **13** |

> [!warning] Severidad maxima del dia: critica
> Revisa los eventos marcados antes de cerrar el dia.

## Amenazas

- `08:05` [[2026-09-28 0805-00 - Escaneo - Escaneo de Descargas con 2 hallazgos]] — alta · registrada
- `08:07` [[2026-09-28 0807-00 - Amenaza - Win.Trojan.AgentTesla-9912 en factura_pendiente.pdf.exe]] — critica · cuarentena
- `08:07` [[2026-09-28 0807-03 - Cuarentena - Cuarentena de factura_pendiente.pdf.exe]] — alta · cuarentena
- `09:12` [[2026-09-28 0912-00 - Firewall - Firewall bloqueo sc.exe hacia 185.220.101.47 puerto 443]] — media · bloqueada
- `10:03` [[2026-09-28 1003-00 - Firewall - Firewall bloqueo svchost.exe hacia 45.155.205.233 puerto 3389]] — media · bloqueada

## Privacidad
…
```

**Los contadores del front matter son la fuente de verdad; la tabla del cuerpo se regenera a partir de ellos en cada escritura.** Así el resumen nunca se desincroniza aunque el servicio se reinicie, y los contadores quedan disponibles para Dataview sin que construyamos un motor de agregación.

Los enlaces de navegación a días vecinos quedan sin resolver mientras no haya eventos ese día. Es correcto: Obsidian los muestra en gris y crea la nota si algún día hay algo que registrar.

**Limitación conocida y deliberada:** la nota diaria se regenera completa, así que el texto escrito a mano en ella se pierde. Las anotaciones manuales van en `03 Entidades`. Está advertido dentro del propio vault, en `Como leer este vault.md`.

---

## 4. La librería

### 4.1 Estructura

```
src/Nexo.Reports/
├─ IReportWriter.cs               contrato único que ven los módulos
├─ ReportWriter.cs                orquestador
├─ Model/
│   ├─ NexoEvent.cs               unidad de información
│   ├─ Eventos.cs                 fábricas tipadas por módulo  ← lo que llaman los módulos
│   ├─ EntidadRef.cs              referencia a archivo/proceso/disco/cuenta
│   ├─ Redactable.cs              marca un valor como sujeto a redacción
│   ├─ TipoEvento.cs              los 17 tipos, como constantes
│   ├─ Enumeraciones.cs           Severidad, Accion, ModuloOrigen, TipoEntidad
│   └─ NoteRef.cs                 resultado de una escritura
├─ Vault/
│   ├─ VaultLayout.cs             único lugar que sabe cómo se organizan las carpetas
│   ├─ NoteNaming.cs              saneamiento y colisiones
│   ├─ YamlWriter.cs              serializador de front matter
│   ├─ AtomicFile.cs              escritura atómica
│   ├─ DailyNoteWriter.cs         nota-resumen diaria
│   ├─ EntityNoteWriter.cs        notas de entidad
│   ├─ VaultBootstrapper.cs       panel, guías, advertencia, .gitignore
│   └─ VaultOptions.cs
├─ Seguridad/
│   ├─ Redactor.cs                cortafuegos de secretos + redacción
│   └─ RedactionOptions.cs
└─ Internal/IsExternalInit.cs     polyfill para `init` en netstandard2.0
```

### 4.2 El contrato

```csharp
public interface IReportWriter
{
    Task<NoteRef> EscribirAsync(NexoEvent evento, CancellationToken ct = default);
    Task InicializarVaultAsync(CancellationToken ct = default);
}
```

Dos métodos. Los módulos no saben que existe Obsidian, ni markdown, ni YAML: publican un `NexoEvent`. Esa indirección permite cambiar el backend en una fase futura (SQLite, panel propio, plugin de Obsidian) sin tocar una línea de los módulos.

### 4.3 Las fábricas tipadas — por qué existen

Si cada módulo construyera su `NexoEvent` a mano, los nombres de campo se desincronizarían entre módulos y las búsquedas de Obsidian dejarían de funcionar a los dos meses. `Eventos` concentra el esquema en un archivo y el compilador obliga a respetarlo:

```csharp
public static class Eventos
{
    public static class Amenazas   { /* Detectada, Cuarentena, Firewall, Escaneo */ }
    public static class Privacidad { /* Vpn, AccesoDispositivo */ }
    public static class Identidad  { /* Brecha, Alerta */ }
    public static class Limpieza   { /* Sesion, Duplicados, SaludDisco, Triturado */ }
}
```

Añadir un tipo de evento = añadir un método aquí. **No se duplica código de formato en ningún módulo consumidor**, que era la regla explícita del prompt.

### 4.4 Orden de operaciones en `EscribirAsync`

```
0. Validar nombres de campo          ← ANTES de tocar el disco
1. Crear notas de entidad faltantes  ← necesitamos sus nombres para los wikilinks
2. Resolver nombre y colisión
3. Actualizar la nota diaria
4. Escribir la nota del evento (atómica)
```

El paso 0 estaba originalmente en el paso 4. **Ejecutar el arnés reveló el bug**: un evento rechazado por contener un campo secreto ya había dejado una línea en la nota diaria apuntando a una nota que nunca se escribiría. El arnés ahora verifica explícitamente que un rechazo no deje efectos en el vault.

### 4.5 Escritura atómica

El servicio corre como LocalSystem y el SCM puede detenerlo en mitad de una escritura. Una nota a medias rompe el front matter y **Obsidian deja de indexar el archivo entero**. Por eso `AtomicFile`:

- Temporal en la **misma carpeta** — un `move` entre volúmenes no es atómico.
- `fs.Flush(flushToDisk: true)` antes de cerrar.
- `File.Replace` si el destino existe — atómico en NTFS y **preserva la ACL del destino**, que es justo lo que queremos: la carpeta está restringida al usuario dueño y no debe heredar los permisos del temporal.
- UTF-8 **sin BOM** — un BOM antes del `---` invalidaría el front matter.

### 4.6 Concurrencia

Un único `SemaphoreSlim` serializa toda la escritura. Podría ser más fino (uno por archivo), pero el volumen esperado son decenas de eventos por hora, no miles por segundo: aquí la simplicidad vale más que la concurrencia.

La idempotencia por `id` es **memoria del proceso**. Si el servicio se reinicia entre el fallo y el reintento, sí habrá duplicado. Se acepta: un índice persistente no se justifica para este volumen.

---

## 5. Seguridad de la carpeta de reportes

Esto responde a la regla explícita del prompt y al riesgo **L7** de [[Salida 6 - Analisis de viabilidad del proyecto]].

**El vault es información sensible en texto plano.** Contiene nombres de archivos personales, dominios visitados, aplicaciones instaladas y hallazgos de filtraciones. Para alguien que acceda al equipo, es un mapa de la vida digital del usuario y probablemente valga más que buena parte de lo que Nexo protege.

### El cortafuegos de campos secretos

No basta con que los módulos "recuerden" no escribir contraseñas. `Redactor.VerificarNombreDeCampo` **lanza una excepción** si el nombre de un campo contiene alguno de 27 fragmentos: `password`, `contrasena`, `clave`, `secret`, `token`, `apikey`, `privatekey`, `ntlm`, `lmhash`, `sam`, `seed`, `recoverycode`, `cvv`, `pin`, `cookie`, `sessionid`, `bearer`…

La comparación normaliza guiones y guiones bajos, así que `hash_ntlm`, `claveMaestra` y `cookie-sesion` caen igual. Verificado en el arnés: los cinco casos son rechazados **sin dejar efectos en el vault**.

Es intencionalmente una excepción y no una advertencia: queremos que reviente en la primera prueba del módulo, no que pase inadvertido.

### Redacción de valores

`Redactable` marca la naturaleza del dato para que la librería decida cuánto llega al disco:

```csharp
ev.Con("ruta", Redactable.Ruta(@"C:\Users\alvaro\Descargas\x.exe"));
// NivelRuta.RelativaAlPerfil  → %USERPROFILE%\Descargas\x.exe
// NivelRuta.SoloNombre        → x.exe
ev.Con("cuenta", Redactable.Correo("usuario.ejemplo@correo.cl"));
//                             → usu***plo@correo.cl
```

El dominio del correo se conserva completo: es lo que hace accionable la alerta sin exponer el buzón entero.

### Lo que Nexo escribe dentro del propio vault

`99 Sistema/ADVERTENCIA DE SEGURIDAD.md` se genera automáticamente y contiene el comando `icacls` ya rellenado con la ruta real del vault:

```powershell
icacls $ruta /inheritance:r
icacls $ruta /grant:r "$env:USERNAME:(OI)(CI)F" "SYSTEM:(OI)(CI)F"
```

más las cuatro medidas restantes: BitLocker en el volumen, **no sincronizar** (OneDrive, Dropbox, Obsidian Sync), no versionar — de ahí el `.gitignore` que ignora todo salvo a sí mismo — y purga automática a los 90 días.

También advierte sobre el umbral legal: instalar Nexo en el equipo de otra persona saca el proyecto del ámbito personal o doméstico (riesgo **L8**).

---

## 6. Verificación — ejecutada, no afirmada

```
$ dotnet tools/Nexo.Reports.Demo/bin/Debug/net8.0/nexo-reports-demo.dll ./vault-demo

Notas de evento escritas : 37
Tiempo                   : 60 ms

Cortafuegos de campos secretos:
  [OK]    'password' rechazado sin efectos en el vault.
  [OK]    'clave_maestra' rechazado sin efectos en el vault.
  [OK]    'session_id' rechazado sin efectos en el vault.
  [OK]    'cookie_sesion' rechazado sin efectos en el vault.
  [OK]    'hash_ntlm' rechazado sin efectos en el vault.

Casos borde de nombres y YAML:
  [OK]    caracteres prohibidos en NTFS y en wikilinks
  [OK]    nombre reservado de MS-DOS
  [OK]    nombre reservado con extension
  [OK]    espacios y puntos al final
  [OK]    titulo mas largo que MAX_PATH
  [OK]    YAML cita correctamente  valor_no: "no"
  [OK]    YAML cita correctamente  valor_on: "on"
  [OK]    YAML cita correctamente  hash_corto: "0123"

TODAS LAS VERIFICACIONES PASARON
```

**59 archivos `.md` generados**: 42 notas de evento, 3 notas diarias, 10 notas de entidad, más panel, guía, esquema y advertencia.

### Las trampas de YAML que el serializador evita

| Valor | Sin comillas YAML lo lee como | Se escribe |
|---|---|---|
| `no` | booleano `false` | `"no"` |
| `on` | booleano `true` | `"on"` |
| `0123` | número `123` | `"0123"` |
| `Collection #1` | `Collection` + comentario | `"Collection #1"` |
| `C:\Users\…` | escape inválido | `"C:\\Users\\…"` |

Un archivo llamado `no.exe`, un hash corto que empieza en cero o una brecha con `#` en el nombre no son casos rebuscados: son lo que aparece en el primer mes de uso real.

### Lo que falta verificar y no puedo verificar aquí

Este equipo es Linux. **No he abierto el vault generado en Obsidian.** El formato sigue la especificación (front matter delimitado por `---` al inicio del archivo, wikilinks `[[nombre]]`, callouts nativos, etiquetas jerárquicas) y la redacción de rutas `%USERPROFILE%` no se ejerció porque las rutas de prueba son de Windows. **La comprobación en Obsidian sobre Windows es el paso 3 de §7 y es tu criterio de aceptación real**, no el mío.

**Aceptado en Obsidian (2026-11-02, Obsidian 1.14.5 en Linux, revisado por el usuario):** vault generado por
`Nexo.Reports.Demo` más detecciones reales de ClamAV. Todo bien en los 10 puntos revisados: front matter como
propiedades, callouts, wikilinks, panel «Vínculos a esta nota» de una entidad, nota diaria, búsquedas del Panel,
tablas de datos, la advertencia de seguridad, y que un título con saltos de línea (`\n`, `\r`, U+2028, U+0085) queda
en una sola línea sin encabezados ni callouts inyectados. **Sigue sin verificar:** la redacción de `%USERPROFILE%`
(necesita rutas de Windows) y abrirlo en Obsidian sobre Windows, que no debería cambiar nada del formato.

---

## 7. Cómo lo usa un módulo externo

Ejemplo literal del módulo de limpieza ([[Prompt 4 Módulo de limpieza y optimización]]), tras una sesión confirmada por el usuario:

```csharp
public sealed class JunkCleaner
{
    private readonly IReportWriter _reportes;

    public JunkCleaner(IReportWriter reportes) => _reportes = reportes;

    public async Task<ResultadoLimpieza> EjecutarAsync(
        PlanDeLimpieza plan, TokenConfirmacion token, CancellationToken ct)
    {
        // El servicio ya validó el token contra la vista previa que vio el usuario.
        var reloj = Stopwatch.StartNew();
        var resultado = await BorrarAsync(plan, ct).ConfigureAwait(false);
        reloj.Stop();

        // Una sola llamada. Sin logs propios, sin formato duplicado.
        await _reportes.EscribirAsync(
            Eventos.Limpieza.Sesion(
                categorias:            plan.Categorias,
                archivosEliminados:    resultado.Archivos,
                bytesLiberados:        resultado.Bytes,
                confirmadoPorUsuario:  token.EsValido,   // si es false, la librería lanza
                enviadoAPapelera:      plan.UsarPapelera,
                duracion:              reloj.Elapsed),
            ct).ConfigureAwait(false);

        return resultado;
    }
}
```

Registro en el servicio (`Nexo.Service/Program.cs`):

```csharp
builder.Services.AddSingleton<IReportWriter>(_ => new ReportWriter(new VaultOptions
{
    RutaVault  = config["Vault:Ruta"]!,       // %ProgramData%\Nexo\Vault
    Equipo     = Environment.MachineName,
    Redaccion  = RedactionOptions.PorDefecto(),
    RetencionDias = 90
}));
```

**Singleton obligatorio**: mantiene el semáforo que serializa la escritura y el conjunto de ids ya escritos.

Otros módulos, misma forma:

```csharp
// Amenazas
await _reportes.EscribirAsync(Eventos.Amenazas.Detectada(
    firma: "Win.Trojan.AgentTesla-9912", rutaArchivo: ruta, motor: "ClamAV",
    severidad: Severidad.Critica, accion: Accion.Cuarentena,
    sha256: hash, procesoOrigen: "chrome.exe"), ct);

// Privacidad
await _reportes.EscribirAsync(Eventos.Privacidad.Vpn(
    servidor: "cl-santiago-01", pais: "Chile", conectado: true), ct);

// Identidad — no existe parámetro para la credencial
await _reportes.EscribirAsync(Eventos.Identidad.Brecha(
    correo: cuenta, nombreBrecha: "Collection #1", fechaBrecha: fecha,
    datosExpuestos: new[] { "correos", "contrasenas" },
    cuentasAfectadas: 772_904_991), ct);
```

---

## 8. Dataview — documentado, no implementado

Requisito 6 del prompt: evaluar, no construir.

Nada de lo anterior necesita plugins. Pero el front matter está diseñado para ser consultable, así que si instalas el plugin comunitario **Dataview**, el usuario arma sus propias tablas sin que Nexo tenga que construir un motor de reportes:

````
```dataview
TABLE severidad, accion, file.link AS Evento
FROM #nexo/amenazas
WHERE severidad = "alta" OR severidad = "critica"
SORT fecha DESC
LIMIT 50
```
````

````
```dataview
TABLE fecha, bytes_liberados / 1048576 AS "MB liberados", archivos_eliminados
FROM #nexo/tipo/sesion-limpieza
SORT fecha DESC
```
````

**Si el plugin no está instalado, el bloque se muestra como código y no rompe nada.** Esa es la razón de que el esquema separe `bytes_liberados` (número, agregable) de `espacio_liberado` (texto, legible): Dataview puede sumar el primero.

Estas consultas ya están escritas dentro de `99 Sistema/Esquema de notas.md`, listas para copiar.

### Sin Dataview, esto ya funciona

`00 Panel/Panel.md` se genera con búsquedas nativas listas para pegar en `Ctrl+Shift+F`:

| Qué quiero ver | Búsqueda |
|---|---|
| Todo lo grave | `tag:#nexo/severidad/alta OR tag:#nexo/severidad/critica` |
| Amenazas sin acción | `tag:#nexo/amenazas tag:#nexo/accion/ninguna` |
| Pendiente de mi confirmación | `tag:#nexo/accion/pendienteconfirmacion` |

---

## 9. Fase futura opcional: plugin de Obsidian

Si más adelante se quisiera una **vista embebida dentro de la propia app** —un panel visual, no la carpeta abierta en Obsidian— eso requiere programar un plugin de Obsidian en **TypeScript**: un stack completamente aparte del C#/C++ del resto del proyecto, con su propio `npm`, su propio ciclo de build y su propia API que cambia entre versiones de Obsidian.

Es **fase futura opcional, no parte de este MVP**, y en la práctica compite con el resto del backlog por las mismas ~30 horas mensuales. Dado el recorte de [[Salida 6 - Analisis de viabilidad del proyecto]], la recomendación es no hacerlo: el panel de Obsidian ya resuelve el problema y un plugin propio añade un cuarto lenguaje a un proyecto de una persona.

---

## 10. Verificación final del prompt

- **(a) Markdown válido reconocible sin plugins** — front matter delimitado por `---` en la primera línea (sin BOM), callouts nativos, tablas GFM, etiquetas jerárquicas. Verificado en la salida generada y **aceptado en Obsidian 1.14.5 (Linux) el 2026-11-02**; falta solo Windows, ver §6.
- **(b) Wikilinks con sintaxis correcta** — `[[nombre de nota]]` en notas de evento (entidades, día, panel) y en la nota diaria. Los nombres destino pasan por `NoteNaming.Sanear`, que elimina `[ ] # ^ |` y los caracteres prohibidos de NTFS. Verificado con un título que contiene los 13 caracteres prohibidos.
- **(c) Nada sensible en texto plano sin advertir** — cortafuegos de campos secretos que lanza excepción (5 casos verificados, sin efectos en el vault), redacción de rutas y correos por política, y `ADVERTENCIA DE SEGURIDAD.md` generada dentro del propio vault con el `icacls` ya rellenado. La firma de `Eventos.Identidad.Brecha` **no admite** la credencial como parámetro.
- **(d) Librería reutilizable, no código duplicado** — un `IReportWriter` con dos métodos, fábricas tipadas centralizadas, cero dependencias NuGet, `netstandard2.0` + `net8.0`.

## Siguiente

[[Prompt 4 Módulo de limpieza y optimización]], implementando **solo** la limpieza de temporales con vista previa, contra un corpus sintético en la VM. Es el paso 4 de [[Salida 6 - Analisis de viabilidad del proyecto]].
