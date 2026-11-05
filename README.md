# Nexo Security Suite

**Suite de higiene y monitoreo de seguridad para Windows 10/11.**
Complementa a Microsoft Defender; **no lo reemplaza y no debe usarse como única
protección.**

Proyecto personal de una sola persona, en desarrollo. No es un producto
comercial, no está certificado por ningún laboratorio (AV-TEST,
AV-Comparatives) y no publica tasas de detección.

---

## Qué es y qué no es

| Sí es | No es |
|---|---|
| Limpieza de disco con vista previa y confirmación | Un antivirus que bloquee en tiempo real (el análisis al vuelo solo detecta y avisa, después de escribirse el archivo) |
| Detección de duplicados por contenido | Un motor de firmas propio |
| Firewall por aplicación (planificado) | Un reemplazo de Windows Defender |
| Historial navegable de eventos en Obsidian | Software con detección de rootkits |

Todo funciona en **modo usuario**. Sin un driver de kernel firmado —fuera de
alcance para un proyecto individual— el sistema **detecta y reacciona**, pero no
puede **prevenir**. Esa limitación está documentada, no escondida.

---

## Estado

| Módulo | Estado |
|---|---|
| `Nexo.Reports` — notas markdown + vault de Obsidian | ✅ Implementado y verificado |
| `Nexo.Modules.Cleanup` — limpieza y duplicados | ✅ Implementado y verificado |
| `Nexo.Modules.Cleanup` — triturador, inicio, S.M.A.R.T. | ✅ Implementado; verificado en Windows salvo lo listado abajo |
| `Nexo.Modules.Threats` — firewall por aplicación y modo sigiloso | ✅ Implementado y verificado contra el Firewall de Windows real |
| `Nexo.Modules.Threats` — escaneo bajo demanda y cuarentena (clamd) | ✅ Implementado; verificado contra un clamd falso, **sin probar con ClamAV real** |
| `Nexo.Ipc` + `Nexo.Service` — servicio de Windows y canal por named pipe | ✅ Implementado y probado **en consola**; **sin instalar como servicio**. Aloja firewall, escaneo, cuarentena, tiempo real y limpieza (lo que cambia algo lleva vista previa y token) |
| `Nexo.Ui.Tray` — bandeja del sistema (icono, avisos, revisar detecciones, limpiar) | ✅ Implementada; **la parte visual (menú y diálogos) no la ha visto una persona**; aprobar con UAC sin probar |
| `Nexo.Ui.Desktop` — ventana principal (Avalonia + tema Classic, Windows y Linux) | 🚧 Empezada: funcionan «Estado» (tiempo real, motor, escaneo programado, firewall y cuarentena, solo lectura) «Escaneo» (escanear, ver el avance, cancelar, resultado; poner en cuarentena) y «Cuarentena» (lista, restaurar, eliminar vencidos); lo que cambia algo va con vista previa, token y la aprobación de la bandeja. Las otras 4 pestañas son marcadores. Probada en Linux (sin pantalla y en un escritorio real); **sin probar en Windows contra el servicio** |
| `Nexo.Modules.Threats` — tiempo real (FileSystemWatcher y diario USN) | ✅ Implementado; **apagado por omisión**; el diario USN probado **como administrador** en el equipo principal (2026-10-22): abre el volumen y entrega un archivo nuevo con su ruta |
| `Nexo.Modules.Threats` — heurística YARA, anti-ransomware | 📐 Diseñado |
| `Nexo.Modules.Identity` / `Nexo.Modules.Privacy` | 📐 Diseñado, pospuesto |
| `NexoFsMini` — driver minifiltro | ❌ Fuera de alcance |

**634 comprobaciones automatizadas** pasan en Windows 10: 13 de reportes, 96 de
la lógica portable de limpieza y 29 que solo tienen sentido en Windows
(registro, Papelera, archivos bloqueados, tipo de disco, discos reales), más 66
portables del firewall y 28 contra el Firewall de Windows real (como
administrador; 9 sin serlo) y 92 del escáner y la cuarentena, 43 del protocolo IPC, 170 del servicio, 57 del tiempo real y 40 de la bandeja. Como administrador se cubren además la escritura
en `HKLM` y los enlaces simbólicos de archivo. Aparte, 133 de la ventana principal
pasan en Linux (todavía no se han corrido en Windows).

**Todavía sin verificar:**

- Reglas del catálogo que piden administrador, contra un perfil real.
- El flujo completo con `BorradorPapelera` sobre un perfil limpio, y todo lo
  que implique borrado permanente: requiere una VM.
- Obsidian: el vault de demostración se abrió a mano y se vio correcto.

---

## Documentación

El repositorio es a la vez un vault de Obsidian. Ábrelo con Obsidian para
navegar los documentos con grafo y backlinks, o léelos como markdown normal.

| Documento | Qué contiene |
|---|---|
| `Salida 0 - Arquitectura general del sistema.md` | Módulos, IPC, tabla de las 20 funciones, fases |
| `Salida 6 - Analisis de viabilidad del proyecto.md` | **Léelo antes de programar nada**: horas reales, costos, 13 riesgos legales |
| `Salida 5 - Modulo de reportes y visualizacion.md` | Esquema de notas, formato YAML, seguridad del vault |
| `Salida 4 - Modulo de limpieza y optimizacion.md` | Los 6 submódulos, rutas de Windows, guardia de rutas |
| `Prompt *.md` | Los prompts que generaron cada salida |
| `CONTINUAR-EN-OTRO-EQUIPO.md` | **Traspaso vigente**: qué está hecho, qué falta y cómo montar la VM |
| `CONTINUAR-EN-WINDOWS.md` | Traspaso anterior (Linux → Windows), conservado como historia |

---

## Compilar y ejecutar

Requisitos: **.NET 8 SDK**. Para el trabajo con drivers y UI más adelante,
Visual Studio 2022 con el workload *.NET desktop development*.

```bash
dotnet build NexoAntivirus.sln
```

Arneses de aceptación — generan datos sintéticos y verifican el comportamiento:

```bash
# Genera un vault de ejemplo; ábrelo con Obsidian para ver el resultado
dotnet run --project tools/Nexo.Reports.Demo -- ./vault-demo

# Corpus sintético: guardia, limpieza, duplicados, triturador, inicio y
# S.M.A.R.T. Corre en cualquier sistema (96 comprobaciones)
dotnet run --project tools/Nexo.Cleanup.Demo

# Solo Windows: tipo de disco, registro de inicio (en una subclave temporal),
# Papelera, archivos bloqueados y lectura real de discos (29 comprobaciones)
dotnet run --project tools/Nexo.Cleanup.Windows.Demo

# Firewall por aplicación y modo sigiloso, contra un almacén en memoria
# (66 comprobaciones; no toca el Firewall de Windows)
dotnet run --project tools/Nexo.Firewall.Demo

# Solo Windows: el mismo flujo contra el Firewall de Windows REAL. Sin
# administrador solo lee; como administrador crea reglas temporales sobre un
# .exe sintético y las retira (28 comprobaciones)
dotnet run --project tools/Nexo.Firewall.Windows.Demo

# Escáner bajo demanda y cuarentena contra un clamd FALSO que habla el protocolo
# real por TCP (92 comprobaciones; no requiere ClamAV)
dotnet run --project tools/Nexo.Scan.Demo

# Protocolo IPC (named pipe) atacado con clientes buenos y malos: 43 comprobaciones.
# Y el servicio levantado en el mismo proceso, sin instalarlo (con firewall, motor y fuente de cambios falsos): 170 comprobaciones.
dotnet run --project tools/Nexo.Ipc.Demo
dotnet run --project tools/Nexo.Service.Demo

# Análisis en tiempo real: fuente de cambios y motor falsos, parser del diario USN con
# buffers malformados, y un FileSystemWatcher real sobre una carpeta temporal (57 comprobaciones)
dotnet run --project tools/Nexo.RealTime.Demo

# Bandeja del sistema: el modelo de estados sin pantalla, contra el servicio real y el ejecutable (40 comprobaciones)
dotnet run --project tools/Nexo.Tray.Demo

# Ventana principal: el resumen de estado, su modelo con fuentes falsas y la ventana cargada sin pantalla.
# Corre en Linux y en Windows (133 comprobaciones; --captura f.png guarda imágenes de la ventana)
dotnet run --project tools/Nexo.Desktop.Demo
```

### La ventana principal: `nexo-desktop`

```powershell
dotnet run --project src/Nexo.Ui.Desktop --framework net8.0-windows   # Windows: habla con el servicio por el pipe
dotnet run --project src/Nexo.Ui.Desktop --framework net8.0           # Linux: misma ventana, dice que no hay servicio
```

Usa Avalonia con el tema [Classic.Avalonia](https://github.com/BAndysc/Classic.Avalonia)
(aspecto Windows 9x, sin animaciones ni transparencias). Escanear solo lee. Lo que cambia
algo (poner en cuarentena, restaurar, eliminar los vencidos) va en dos pasos: el servicio
prepara el plan, la ventana lo muestra y solo si se acepta lo aplica con el token. Si hace falta aprobación de administrador, la
pide **`nexo-tray.exe`**, que tiene que estar en la misma carpeta que `nexo-desktop.exe`
(la ventana nunca se eleva a sí misma). En Linux el servicio todavía no existe, y la
ventana lo dice en vez de aparentar un estado.

Para compilar los proyectos de Windows desde Linux hace falta
`-p:EnableWindowsTargeting=true`.

Todos devuelven código de salida 0 solo si todas las comprobaciones pasan.
El arnés de Windows deja unos pocos archivos sintéticos `nexo-demo-*` en la
Papelera; son inofensivos y puedes vaciarla.

### El limpiador contra el equipo real: `nexo-cleanup`

```powershell
dotnet run --project tools/Nexo.Cleanup.Run                    # simulado: no toca nada
dotnet run --project tools/Nexo.Cleanup.Run -- --modo papelera # reversible; pide escribir BORRAR
dotnet run --project tools/Nexo.Cleanup.Run -- --ayuda
```

El modo `real` (borrado permanente) **se niega a ejecutarse fuera de una
máquina virtual**: lo hace cumplir el código, no una advertencia. Dentro de una
VM además exige `NEXO_PERMITIR_BORRADO_REAL=1`.

### El firewall contra el equipo real: `nexo-firewall`

```powershell
dotnet run --project tools/Nexo.Firewall.Run -- estado                    # perfiles, sigiloso, reglas de Nexo
dotnet run --project tools/Nexo.Firewall.Run -- bloquear C:\ruta\app.exe   # muestra el plan; pide escribir APLICAR
dotnet run --project tools/Nexo.Firewall.Run -- sigiloso on               # bloquea el ping entrante
dotnet run --project tools/Nexo.Firewall.Run -- quitar "Nexo: ..."        # solo reglas que creó Nexo
```

Ver el plan no requiere administrador; aplicarlo sí. Nexo **solo toca reglas de
su propio grupo** («Nexo Security Suite»), **nunca bloquea** procesos del
sistema (`svchost.exe`, `lsass.exe`…), Windows Defender ni a sí mismo, y no
activa un firewall que el usuario haya apagado: lo avisa. El modo sigiloso no
necesita driver: Windows ya descarta en silencio el tráfico entrante no
solicitado, y Nexo solo añade el bloqueo del ping (ICMPv4/ICMPv6).

### El escáner contra el equipo real: `nexo-scan`

Requiere **ClamAV** con `clamd` escuchando en `127.0.0.1:3310` (y `freshclam` para
las firmas). **Pruébalo primero en una VM**, no en el equipo principal.

```powershell
dotnet run --project tools/Nexo.Scan.Run -- estado                        # ¿hay un clamd?
dotnet run --project tools/Nexo.Scan.Run -- escanear C:\Users\yo\Descargas   # no modifica nada
dotnet run --project tools/Nexo.Scan.Run -- escanear C:\ruta --cuarentena   # plan + escribir CUARENTENA
dotnet run --project tools/Nexo.Scan.Run -- cuarentena restaurar <id>
```

Escanear **no modifica nada**; la cuarentena es una acción aparte con vista
previa y token. El contenido de los archivos **solo se envía a un clamd local**
(el cliente rechaza cualquier otra dirección). Un archivo que no se pudo
analizar (en uso, sin permisos, demasiado grande, o que el motor no supo
evaluar) **nunca** cuenta como limpio: el resultado y la nota del vault lo dicen.
Los códigos de salida distinguen «limpio» (0), «con detecciones» (10) y «sin
detecciones pero con archivos sin analizar» (11).

### ⚠ Antes de ejecutar el módulo de limpieza en un equipo real

1. Empieza siempre con el modo `simulado`: recorre el flujo completo y registra
   qué *habría* borrado, sin tocar un solo archivo.
2. Solo cuando la lista sea la esperada varias veces seguidas, usa `papelera`
   (reversible).
3. El borrado permanente, y cualquier prueba destructiva, va en una
   **máquina virtual con snapshot**.

---

## Estructura

```
src/
  Nexo.Reports/                 Librería de notas markdown. Cero dependencias NuGet.
  Nexo.Native/                  Todo el P/Invoke del proyecto vive aquí.
  Nexo.Modules.Cleanup/         Lógica portable: guardia, catálogo, duplicados,
                                triturador, inicio, S.M.A.R.T.
  Nexo.Modules.Cleanup.Windows/ Papelera, registro de inicio, WMI, detección de VM.
  Nexo.Modules.Threats/         Lógica portable: firewall (guardia de reglas, vista previa
                                con token, modo sigiloso), cliente de clamd, escáner y cuarentena.
  Nexo.Modules.Threats.Windows/ Firewall de Windows por COM (INetFwPolicy2).
tools/
  Nexo.Reports.Demo/            Arnés de aceptación de reportes.
  Nexo.Cleanup.Demo/            Arnés portable de limpieza.
  Nexo.Cleanup.Windows.Demo/    Arnés de lo que solo tiene sentido en Windows.
  Nexo.Cleanup.Run/             `nexo-cleanup`: el limpiador contra el equipo real.
  Nexo.Firewall.Demo/           Arnés portable del firewall.
  Nexo.Firewall.Windows.Demo/   Arnés contra el Firewall de Windows real.
  Nexo.Firewall.Run/            `nexo-firewall`: el firewall contra el equipo real.
  Nexo.Scan.Demo/               Arnés del escáner y la cuarentena (clamd falso).
  Nexo.Scan.Run/                `nexo-scan`: el escáner contra un clamd real.
```

---

## Privacidad y datos

Nexo **no envía nada a ningún servidor**. No hay telemetría.

El vault de reportes que genera contiene información sensible en texto plano:
nombres de archivos personales, dominios visitados, aplicaciones instaladas.
Se genera fuera del repositorio y está en `.gitignore`. El propio vault incluye
una nota `99 Sistema/ADVERTENCIA DE SEGURIDAD.md` con las medidas concretas
(BitLocker, ACL con `icacls`, no sincronizar con OneDrive).

La librería **rechaza con una excepción** cualquier intento de escribir un campo
cuyo nombre sugiera un secreto: contraseñas, tokens, cookies de sesión, hashes.

**Uso personal, sin tratamiento de datos de terceros.** Instalarlo en el equipo
de otra persona saca el proyecto del ámbito personal o doméstico; ver el riesgo
L8 del análisis de viabilidad antes de hacerlo.

---

## Fuera de alcance

Decidido en el análisis de viabilidad, con justificación en cada caso:

- **Driver minifiltro de kernel** y todo lo que depende de él: bloqueo
  preventivo, anti-ransomware propio, antivirus en tiempo real real.
- **Detección de rootkits** — requiere kernel por definición.
- **Entorno de rescate WinPE** — Microsoft Defender Offline ya lo hace, gratis.
- **Navegador seguro propio** — Windows Sandbox ya da aislamiento real.
- **Detección de deepfakes** — infactible para una persona.
- **Estafas por SMS** — Windows no expone API para leerlos.
- **Módulo de privacidad completo** — WireGuard, uBlock Origin y SmartScreen ya
  existen y son mejores que lo que este proyecto construiría.

---

## Licencia

MIT. Ver [LICENSE](LICENSE).

El software se entrega **sin garantía de ningún tipo**. Esto importa de verdad
aquí: el módulo de limpieza borra archivos.
