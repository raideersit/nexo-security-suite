# Continuar en Windows

> Documento de traspaso. El trabajo hasta aquí se hizo en Linux; **nada se ha
> ejecutado nunca en Windows.** Si abres una sesión nueva de Claude Code en este
> repositorio, empieza por leer este archivo.

---

## 1. Estado exacto

**Verificado (en Linux):** toda la lógica portable. 41 comprobaciones
automatizadas entre los dos arneses.

- `Nexo.Reports` — 59 notas generadas, 13 comprobaciones
- `Nexo.Modules.Cleanup` — 28 comprobaciones, incluidos archivos trampa

**Sin verificar (requiere Windows):**

- Las rutas del catálogo (`%LOCALAPPDATA%\Temp`, cachés de Chrome/Edge/Firefox,
  `%SystemRoot%\Temp`) contra un perfil real.
- `ShellFileOperations.EnviarAPapelera` — compila, nunca se ha ejecutado.
- El comportamiento con archivos **bloqueados por otro proceso**, que en Windows
  es la norma y en Linux no ocurre.
- Uniones NTFS (*junctions*): el guardia las trata igual que los enlaces
  simbólicos vía `ReparsePoint`, pero no está comprobado.
- Abrir el vault generado en **Obsidian** y confirmar que el grafo, los
  backlinks, las etiquetas y los callouts funcionan sin plugins.

---

## 2. Preparar el equipo

```powershell
winget install --id Git.Git
winget install --id Microsoft.DotNet.SDK.8
winget install --id GitHub.cli
winget install --id Obsidian.Obsidian
```

Para el trabajo posterior de UI: Visual Studio 2022 Community con el workload
*.NET desktop development*. **No instales el WDK** — son 15 GB y el driver está
fuera de alcance.

```powershell
gh auth login
git clone https://github.com/raideersit/nexo-security-suite
cd nexo-security-suite
```

Los finales de línea los normaliza `.gitattributes`; no deberías ver el clásico
"todos los archivos modificados" en el primer `git status`.

---

## 3. Comprobar que todo sigue en pie

```powershell
dotnet build NexoAntivirus.sln
dotnet run --project tools\Nexo.Reports.Demo -- .\vault-demo
dotnet run --project tools\Nexo.Cleanup.Demo
```

Ambos arneses deben terminar con `TODAS LAS VERIFICACIONES PASARON` y código de
salida 0. Si alguno falla en Windows y pasaba en Linux, **eso es un hallazgo
real**: probablemente una diferencia de rutas, de mayúsculas o de bloqueo de
archivos. Anótalo antes de arreglarlo.

Después, abre `.\vault-demo` como vault en Obsidian y comprueba a mano:
grafo, panel de backlinks, árbol de etiquetas `nexo/...`, callouts de colores y
la nota diaria con su tabla de resumen.

---

## 4. El siguiente paso real

Está en `Salida 6 - Analisis de viabilidad del proyecto.md`, paso 1, y **sigue
pendiente**: montar la VM.

1. Hyper-V o VirtualBox, Windows 11, 8 GB de RAM, snapshot llamado `limpia`.
2. Clonar el repo dentro de la VM.
3. Poblar `C:\TestCorpus` con archivos sintéticos.
4. Ejecutar el limpiador **con `BorradorSimulado`**, que recorre el flujo
   completo y registra qué *habría* borrado sin tocar nada.
5. Revisar la lista. Cuando sea la esperada dos o tres veces seguidas, cambiar a
   `BorradorPapelera`.

**No ejecutes el módulo de limpieza con `BorradorReal` en tu equipo principal.**
El guardia de rutas está probado, pero solo contra un corpus sintético en Linux.

---

## 5. Después de eso

Según el plan recortado:

- Cerrar `Nexo.Modules.Cleanup`: optimización de inicio, S.M.A.R.T. y triturador
  (~55–85 h). El diseño de los tres está en
  `Salida 4 - Modulo de limpieza y optimizacion.md`.
- O saltar al firewall por aplicación de
  `Prompt 1 Módulo de protección contra amenazas.md`, que necesita que antes se
  pegue la salida del Prompt 0 en su bloque `<arquitectura>`.

**Punto de decisión del mes 3** (§4 de la Salida 6): si para entonces no tienes
reportes + limpieza funcionando y usándolos al menos una vez por semana, la
conclusión no es esforzarte más — es recortar a esos dos módulos, publicarlos
como una utilidad honesta y terminada, y cerrar el resto como documentación.

---

## 6. Convenciones que no hay que romper

- **Ningún módulo escribe logs propios.** Publican un `NexoEvent` y
  `Nexo.Reports` decide cómo se persiste.
- **Ningún P/Invoke fuera de `Nexo.Native`.**
- **Nada que borre sin vista previa y token.** La API está diseñada para que no
  se pueda expresar lo contrario; si algún día parece que estorba, ese es el
  punto.
- **No se desactiva Windows Defender.** Nexo lo complementa.
- **Tres líneas rojas** (riesgo L9, ley 21.459): no dumpear la SAM, no hacer
  MITM de TLS, no capturar pulsaciones de teclado. Ni siquiera "para proteger".
