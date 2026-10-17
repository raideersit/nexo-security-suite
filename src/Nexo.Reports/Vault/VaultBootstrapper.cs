using System;
using System.Globalization;
using System.IO;
using System.Text;
using Nexo.Reports.Model;
using Nexo.Reports.Seguridad;

namespace Nexo.Reports.Vault
{
    /// <summary>
    /// Crea el esqueleto del vault: carpetas, nota de entrada, esquema y la
    /// advertencia de seguridad. Idempotente — no sobrescribe lo que ya existe.
    /// </summary>
    internal static class VaultBootstrapper
    {
        private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        public static void Inicializar(VaultLayout layout, VaultOptions opciones, Redactor redactor)
        {
            Directory.CreateDirectory(layout.Panel);
            Directory.CreateDirectory(layout.Diario);
            Directory.CreateDirectory(layout.Eventos);
            Directory.CreateDirectory(layout.Entidades);
            Directory.CreateDirectory(layout.Sistema);

            foreach (ModuloOrigen m in Enum.GetValues(typeof(ModuloOrigen)))
                Directory.CreateDirectory(Path.Combine(layout.Eventos, VaultLayout.CarpetaDeModulo(m)));

            foreach (TipoEntidad t in Enum.GetValues(typeof(TipoEntidad)))
                Directory.CreateDirectory(layout.CarpetaDeEntidad(t));

            if (!opciones.CrearArchivosDeSistema) return;

            EscribirSiFalta(Path.Combine(layout.Panel, "Panel.md"), Panel());
            EscribirSiFalta(Path.Combine(layout.Panel, "Como leer este vault.md"), ComoLeer());
            EscribirSiFalta(Path.Combine(layout.Sistema, "Esquema de notas.md"), Esquema());
            EscribirSiFalta(Path.Combine(layout.Sistema, "ADVERTENCIA DE SEGURIDAD.md"),
                Advertencia(layout, opciones, redactor));
            EscribirSiFalta(Path.Combine(layout.Raiz, ".gitignore"), GitIgnore());
        }

        private static void EscribirSiFalta(string ruta, string contenido)
        {
            if (File.Exists(ruta)) return;
            AtomicFile.EscribirTexto(ruta, contenido);
        }

        private static string Panel() =>
@"---
tipo: panel
tags:
  - nexo/panel
---

# Panel

Nota de entrada del vault de Nexo. Marcala como favorita en Obsidian.

## Por donde empezar

- [[Como leer este vault]]
- [[Esquema de notas]]
- [[ADVERTENCIA DE SEGURIDAD]]

## Busquedas utiles

Pega cualquiera de estas en la barra de busqueda de Obsidian (Ctrl+Shift+F).
No necesitan ningun plugin.

| Que quiero ver | Busqueda |
|---|---|
| Todo lo grave de esta semana | `tag:#nexo/severidad/alta OR tag:#nexo/severidad/critica` |
| Amenazas que quedaron sin accion | `tag:#nexo/amenazas tag:#nexo/accion/ninguna` |
| Todo lo que hizo el modulo de limpieza | `tag:#nexo/limpieza` |
| Eventos que esperan mi confirmacion | `tag:#nexo/accion/pendienteconfirmacion` |
| Un archivo concreto | `path:""03 Entidades/Archivos"" factura` |

## Vista de grafo

Abre el grafo global (Ctrl+G) y filtra por `tag:#nexo/amenazas`.
Los nodos mas conectados son los archivos y procesos que mas eventos acumulan:
suele ser el mejor punto de partida para investigar algo raro.
";

        private static string ComoLeer() =>
@"---
tipo: guia
tags:
  - nexo/guia
---

# Como leer este vault

## Estructura

| Carpeta | Que contiene |
|---|---|
| `00 Panel` | Nota de entrada y guias. Escrito una sola vez. |
| `01 Diario` | Una nota por dia, con el resumen y los enlaces a todo lo ocurrido. |
| `02 Eventos` | Una nota por evento, agrupada por modulo, ano y mes. |
| `03 Entidades` | Una nota por archivo, proceso, app, disco, dominio o cuenta. |
| `99 Sistema` | Esquema de datos y advertencias. |

## Las tres formas de navegar

1. **Por fecha** — abre la nota de hoy en `01 Diario`. Tiene el resumen del dia
   y enlaces a cada evento, ordenados por hora.
2. **Por entidad** — abre la nota de un archivo en `03 Entidades/Archivos` y mira
   el panel **Vinculos a esta nota** (backlinks). Ahi aparece todo lo que ese
   archivo provoco, de cualquier modulo y cualquier fecha.
3. **Por etiqueta** — el panel de etiquetas muestra el arbol `nexo/...`. Pliega y
   despliega por modulo, tipo o severidad.

## Que puedes escribir tu

Las notas de `03 Entidades` tienen una seccion **Notas** al final. Nexo crea esas
notas una sola vez y despues no las vuelve a tocar, asi que lo que escribas ahi
permanece.

**No escribas en las notas de `01 Diario`**: se regeneran cada vez que ocurre un
evento y perderias el texto.

## Plugins

Nada de esto necesita plugins. Si quieres tablas y consultas sobre los datos del
front matter, mira la seccion de Dataview en [[Esquema de notas]].
";

        private static string Esquema()
        {
            var sb = new StringBuilder();
            sb.Append(@"---
tipo: referencia
tags:
  - nexo/referencia
---

# Esquema de notas

Campos que Nexo.Reports escribe en el front matter de **toda** nota de evento.

| Campo | Tipo | Valores |
|---|---|---|
| `id` | texto | GUID del evento, para idempotencia |
| `fecha` | fecha y hora | `2026-09-28T14:32:07` (hora local, sin offset: es el formato que Obsidian reconoce) |
| `zona` | texto | Offset horario, por ejemplo `-03:00` |
| `modulo` | texto | ");
            bool primero = true;
            foreach (ModuloOrigen m in Enum.GetValues(typeof(ModuloOrigen)))
            {
                if (!primero) sb.Append(", ");
                sb.Append('`').Append(m.ToString().ToLowerInvariant()).Append('`');
                primero = false;
            }
            sb.Append(@" |
| `tipo` | texto | ver tabla de abajo |
| `severidad` | texto | `info`, `baja`, `media`, `alta`, `critica` |
| `accion` | texto | `ninguna`, `registrada`, `bloqueada`, `cuarentena`, `eliminada`, `restaurada`, `omitida`, `pendienteconfirmacion` |
| `equipo` | texto | nombre del equipo |
| `tags` | lista | `nexo/evento`, `nexo/{modulo}`, `nexo/tipo/{tipo}`, `nexo/severidad/{sev}`, `nexo/accion/{accion}` |

Cada tipo de evento anade sus propios campos; estan documentados en la salida del
Prompt 5 del proyecto.

## Tipos de evento

| Tipo | Modulo |
|---|---|
| `amenaza-detectada` | amenazas |
| `archivo-en-cuarentena` | amenazas |
| `archivo-restaurado` | amenazas |
| `bloqueo-firewall` | amenazas |
| `resultado-escaneo` | amenazas |
| `vulnerabilidad-detectada` | amenazas |
| `conexion-vpn` | privacidad |
| `acceso-dispositivo` | privacidad |
| `sitio-bloqueado` | privacidad |
| `alerta-identidad` | identidad |
| `brecha-detectada` | identidad |
| `sesion-limpieza` | limpieza |
| `duplicados-detectados` | limpieza |
| `salud-disco` | limpieza |
| `archivo-triturado` | limpieza |
| `resumen-diario` | sistema |
| `error-modulo` | sistema |

## Opcional: Dataview

Nada de lo anterior necesita plugins. Pero si instalas el plugin comunitario
**Dataview**, el front matter de arriba se vuelve consultable y puedes armar tus
propias tablas sin que Nexo tenga que construir un motor de reportes.

Ejemplo — amenazas graves del ultimo mes, en una tabla:

````
```dataview
TABLE severidad, accion, file.link AS Evento
FROM #nexo/amenazas
WHERE severidad = ""alta"" OR severidad = ""critica""
SORT fecha DESC
LIMIT 50
```
````

Ejemplo — espacio liberado por el modulo de limpieza:

````
```dataview
TABLE fecha, bytes_liberados / 1048576 AS ""MB liberados"", archivos_eliminados
FROM #nexo/tipo/sesion-limpieza
SORT fecha DESC
```
````

Esto es mejora opcional, no parte del MVP: si el plugin no esta instalado, el
bloque se muestra como codigo y no rompe nada.
");
            return sb.ToString();
        }

        private static string Advertencia(VaultLayout layout, VaultOptions opciones, Redactor redactor)
        {
            var sb = new StringBuilder();
            sb.Append(@"---
tipo: advertencia
tags:
  - nexo/seguridad
---

# ADVERTENCIA DE SEGURIDAD

> [!danger] Esta carpeta es informacion sensible en texto plano
> Contiene nombres de archivos personales, dominios visitados, aplicaciones
> instaladas y hallazgos de filtraciones de datos. Para alguien que acceda al
> equipo, este vault es un **mapa de tu vida digital** y probablemente sea mas
> valioso que buena parte de lo que Nexo protege.

## Lo que Nexo NUNCA escribe aqui

La libreria de reportes **rechaza con una excepcion** cualquier campo cuyo nombre
sugiera un secreto: contrasenas, claves, tokens, cookies de sesion, hashes NTLM,
PIN, CVV o codigos de recuperacion. No es una convencion que los modulos deban
recordar: la libreria se niega a escribirlos.

Cuando el modulo de identidad detecta que una credencial aparecio en una
filtracion, registra el dominio, la fecha y el tipo de dato expuesto — **nunca la
credencial, ni completa ni parcial, ni su hash**.

## Politica de redaccion activa

");
            sb.Append(redactor.DescribirPolitica());
            sb.Append(@"
## Como proteger esta carpeta

1. **Cifrado de disco.** Activa BitLocker en el volumen que contiene el vault.
   Es la unica medida que sirve si alguien se lleva el equipo o el disco.
2. **Permisos.** Quita la herencia de permisos y deja solo a tu usuario y a
   SYSTEM. Desde PowerShell como administrador:

   ```powershell
   $ruta = '");
            sb.Append(layout.Raiz.Replace("'", "''"));
            sb.Append(@"'
   icacls $ruta /inheritance:r
   icacls $ruta /grant:r ""$env:USERNAME:(OI)(CI)F"" ""SYSTEM:(OI)(CI)F""
   ```

3. **No sincronizar.** No pongas este vault en OneDrive, Dropbox, Google Drive ni
   Obsidian Sync. Si esta dentro de tu carpeta de usuario, excluyelo de OneDrive
   explicitamente.
4. **No versionar.** El `.gitignore` de la raiz esta para evitar un `git add .`
   accidental si algun dia el vault termina dentro de un repositorio.
5. **Retencion.** Las notas de evento se purgan automaticamente a los ");
            sb.Append(opciones.RetencionDias.ToString(Inv));
            sb.Append(@" dias.
   Cuanto menos historial guardes, menos hay que filtrar.

## Si vas a instalar Nexo en el equipo de otra persona

En ese momento dejas de estar en el ambito personal o domestico y pasas a tratar
datos personales de un tercero. Antes de hacerlo: consentimiento por escrito,
finalidad declarada y el minimo de datos necesario. Revisa la seccion de riesgos
legales del analisis de viabilidad del proyecto (riesgo L8).
");
            return sb.ToString();
        }

        private static string GitIgnore() =>
@"# El vault de Nexo contiene datos sensibles en texto plano.
# Ver ""99 Sistema/ADVERTENCIA DE SEGURIDAD.md"".
# Nada de esta carpeta debe llegar a un repositorio.
*
!.gitignore
";
    }
}
