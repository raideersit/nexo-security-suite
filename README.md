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
| `Nexo.Modules.Cleanup` — inicio, S.M.A.R.T., triturador | 📐 Diseñado |
| `Nexo.Modules.Threats` — firewall, escaneo bajo demanda | 📐 Diseñado |
| `Nexo.Modules.Identity` / `Nexo.Modules.Privacy` | 📐 Diseñado, pospuesto |
| `NexoFsMini` — driver minifiltro | ❌ Fuera de alcance |

**Verificado hasta ahora en Linux, no en Windows.** La lógica portable
—guardia de rutas, catálogo, token de confirmación, duplicados, reportes— pasa
41 comprobaciones automatizadas. Las rutas reales de Windows, la Papelera de
reciclaje y el comportamiento con archivos bloqueados **están sin probar**.

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

# Corpus sintético + guardia de rutas + duplicados (28 comprobaciones)
dotnet run --project tools/Nexo.Cleanup.Demo
```

Ambos devuelven código de salida 0 solo si todas las comprobaciones pasan.

### ⚠ Antes de ejecutar el módulo de limpieza en un equipo real

1. Usa una **máquina virtual con snapshot**, no tu equipo principal.
2. Empieza con `BorradorSimulado`: recorre el flujo completo y registra qué
   *habría* borrado, sin tocar un solo archivo.
3. Solo cuando la lista sea la esperada varias veces seguidas, cambia a
   `BorradorPapelera` (envía a la Papelera, reversible).
4. `BorradorReal` borra de forma permanente. Es una elección explícita.

---

## Estructura

```
src/
  Nexo.Reports/                 Librería de notas markdown. Cero dependencias NuGet.
  Nexo.Native/                  Todo el P/Invoke del proyecto vive aquí.
  Nexo.Modules.Cleanup/         Lógica portable: guardia, catálogo, duplicados.
  Nexo.Modules.Cleanup.Windows/ Papelera de reciclaje (SHFileOperation).
tools/
  Nexo.Reports.Demo/            Arnés de aceptación de reportes.
  Nexo.Cleanup.Demo/            Arnés de aceptación de limpieza.
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
