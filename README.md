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
| Limpieza de disco con vista previa y confirmación | Un antivirus en tiempo real |
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
| `Nexo.Modules.Threats` — firewall, escaneo bajo demanda | 📐 Diseñado |
| `Nexo.Modules.Identity` / `Nexo.Modules.Privacy` | 📐 Diseñado, pospuesto |
| `NexoFsMini` — driver minifiltro | ❌ Fuera de alcance |

**134 comprobaciones automatizadas** pasan en Windows 10: 13 de reportes, 92 de
la lógica portable de limpieza y 29 que solo tienen sentido en Windows
(registro, Papelera, archivos bloqueados, tipo de disco, discos reales).
Como administrador se cubren además la escritura en `HKLM` y los enlaces
simbólicos de archivo.

**Todavía sin verificar:**

- S.M.A.R.T. con atributos ATA reales (disco SATA): como administrador solo se
  probó un NVMe, que no los expone.
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
# S.M.A.R.T. Corre en cualquier sistema (92 comprobaciones)
dotnet run --project tools/Nexo.Cleanup.Demo

# Solo Windows: tipo de disco, registro de inicio (en una subclave temporal),
# Papelera, archivos bloqueados y lectura real de discos (29 comprobaciones)
dotnet run --project tools/Nexo.Cleanup.Windows.Demo
```

Los tres devuelven código de salida 0 solo si todas las comprobaciones pasan.
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
tools/
  Nexo.Reports.Demo/            Arnés de aceptación de reportes.
  Nexo.Cleanup.Demo/            Arnés portable de limpieza.
  Nexo.Cleanup.Windows.Demo/    Arnés de lo que solo tiene sentido en Windows.
  Nexo.Cleanup.Run/             `nexo-cleanup`: el limpiador contra el equipo real.
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
