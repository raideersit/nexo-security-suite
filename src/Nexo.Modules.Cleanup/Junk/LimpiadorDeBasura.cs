using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Cleanup.Abstractions;
using Nexo.Modules.Cleanup.Seguridad;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Modules.Cleanup.Junk
{
    /// <summary>
    /// Limpieza de archivos basura y cache.
    ///
    /// El flujo es de DOS fases y no hay forma de saltarse la primera:
    ///
    ///   1. PrepararVistaPreviaAsync  -> devuelve que se borraria y cuanto se libera,
    ///                                   junto con un token ligado a esa lista exacta.
    ///   2. EjecutarAsync             -> exige ese token. Revalida cada archivo contra
    ///                                   el guardia y contra la huella antes de borrar.
    ///
    /// No existe un metodo "limpiar y ya". Es deliberado: la regla del Prompt 4 es
    /// que ninguna operacion de borrado sea irreversible sin confirmacion previa, y
    /// la unica forma de garantizarlo es que la API no permita expresar lo contrario.
    /// </summary>
    public sealed class LimpiadorDeBasura
    {
        private readonly CatalogoDeRutas _catalogo;
        private readonly IReadOnlyDictionary<BaseDeRuta, string> _bases;
        private readonly IBorrador _borrador;
        private readonly IReportWriter _reportes;
        private readonly bool _esAdministrador;

        public LimpiadorDeBasura(
            CatalogoDeRutas catalogo,
            IReadOnlyDictionary<BaseDeRuta, string> bases,
            IBorrador borrador,
            IReportWriter reportes,
            bool esAdministrador)
        {
            _catalogo = catalogo;
            _bases = bases;
            _borrador = borrador;
            _reportes = reportes;
            _esAdministrador = esAdministrador;
        }

        // ============================================================
        //  FASE 1 — VISTA PREVIA
        // ============================================================

        /// <param name="reglasSeleccionadas">
        /// Ids de regla a evaluar. Si es null se usan solo las de riesgo bajo:
        /// las de riesgo medio y alto exigen que el usuario las marque a mano.
        /// </param>
        public async Task<VistaPreviaLimpieza> PrepararVistaPreviaAsync(
            IReadOnlyCollection<string>? reglasSeleccionadas = null,
            CancellationToken ct = default)
        {
            DateTimeOffset ahora = DateTimeOffset.Now;

            var elementos = new List<ElementoLimpiable>();
            var omitidas = new List<string>();
            var sinPermisos = new List<string>();

            foreach (ReglaDeLimpieza regla in _catalogo.Reglas)
            {
                ct.ThrowIfCancellationRequested();

                bool seleccionada = reglasSeleccionadas is null
                    ? regla.ActivaPorDefecto
                    : reglasSeleccionadas.Contains(regla.Id, StringComparer.OrdinalIgnoreCase);
                if (!seleccionada) continue;

                if (regla.RequiereAdmin && !_esAdministrador)
                {
                    sinPermisos.Add(regla.Nombre);
                    continue;
                }

                if (!_bases.TryGetValue(regla.Base, out string? rutaBase) || string.IsNullOrEmpty(rutaBase))
                    continue;

                // Guardia por regla, no global: cada regla solo puede borrar dentro
                // de SU carpeta. Asi un error en una regla no puede alcanzar la
                // carpeta de otra.
                foreach (string carpeta in ExpandirSubruta(rutaBase, regla.Subruta))
                {
                    ct.ThrowIfCancellationRequested();
                    if (!Directory.Exists(carpeta)) continue;

                    var guardia = new GuardiaDeRutas(regla.Antiguedad).PermitirRaiz(carpeta);
                    RecorrerCarpeta(carpeta, regla, guardia, ahora, elementos, omitidas, ct);
                }
            }

            var token = TokenConfirmacion.Emitir(elementos.Select(e => e.Huella), ahora);
            await Task.CompletedTask.ConfigureAwait(false);

            return new VistaPreviaLimpieza(elementos, omitidas, sinPermisos, token);
        }

        private static void RecorrerCarpeta(
            string carpeta,
            ReglaDeLimpieza regla,
            GuardiaDeRutas guardia,
            DateTimeOffset ahora,
            List<ElementoLimpiable> elementos,
            List<string> omitidas,
            CancellationToken ct)
        {
            // Recorrido propio, carpeta a carpeta, y no EnumerationOptions con
            // RecurseSubdirectories: ese enumerador lanza al tropezar con una
            // subcarpeta sin permisos y no puede reanudarse, asi que un solo
            // directorio inaccesible en %TEMP% dejaba la regla entera en 0
            // archivos. Aqui cada carpeta falla por separado, se anota como
            // omitida (no se presenta como "limpia") y el resto sigue.
            //
            // No se entra en uniones ni enlaces de carpeta (ReparsePoint): pueden
            // apuntar fuera de la raiz.
            var opcionesArchivos = new EnumerationOptions
            {
                RecurseSubdirectories = false,
                AttributesToSkip = FileAttributes.ReparsePoint,
                IgnoreInaccessible = false,
                MatchType = MatchType.Win32
            };
            var opcionesCarpetas = new EnumerationOptions
            {
                RecurseSubdirectories = false,
                AttributesToSkip = FileAttributes.ReparsePoint,
                IgnoreInaccessible = false
            };

            var pendientes = new Stack<string>();
            pendientes.Push(carpeta);

            while (pendientes.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                string actual = pendientes.Pop();

                if (regla.Recursivo)
                {
                    try
                    {
                        foreach (string sub in Directory.EnumerateDirectories(actual, "*", opcionesCarpetas))
                            pendientes.Push(sub);
                    }
                    catch (Exception ex) when (ex is UnauthorizedAccessException || ex is DirectoryNotFoundException || ex is IOException)
                    {
                        omitidas.Add(actual + " — subcarpetas no leidas: " + ex.GetType().Name);
                    }
                }

                // EnumerateFiles y no GetFiles: una carpeta Temp puede tener
                // cientos de miles de entradas y materializar el array entero
                // duplica la memoria sin ganar nada.
                IEnumerator<string> it;
                try
                {
                    it = Directory.EnumerateFiles(actual, regla.Patron, opcionesArchivos).GetEnumerator();
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException || ex is DirectoryNotFoundException || ex is IOException)
                {
                    omitidas.Add(actual + " — " + (actual == carpeta ? "" : "carpeta omitida: ") + ex.GetType().Name);
                    continue;
                }

                using IEnumerator<string> _ = it;
                while (true)
                {
                    ct.ThrowIfCancellationRequested();

                    string archivo;
                    try
                    {
                        if (!it.MoveNext()) break;
                        archivo = it.Current;
                    }
                    catch (Exception ex) when (ex is UnauthorizedAccessException || ex is DirectoryNotFoundException || ex is IOException)
                    {
                        omitidas.Add(actual + " — " + (actual == carpeta ? "" : "carpeta omitida: ") + ex.GetType().Name);
                        break;
                    }

                    if (Excluido(archivo, regla)) continue;

                    ResultadoValidacion v = guardia.Validar(archivo, ahora);
                    if (!v.Aceptada)
                    {
                        // Los rechazos rutinarios no ensucian el informe.
                        if (v.Motivo != MotivoRechazo.DemasiadoReciente && v.Motivo != MotivoRechazo.NoExiste)
                            omitidas.Add(v.RutaCanonica + " — " + v.Motivo);
                        continue;
                    }

                    try
                    {
                        var info = new FileInfo(v.RutaCanonica);
                        elementos.Add(new ElementoLimpiable(
                            v.RutaCanonica, info.Length,
                            new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero),
                            regla.Id, regla.Categoria));
                    }
                    catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                    {
                        omitidas.Add(archivo + " — " + ex.GetType().Name);
                    }
                }
            }
        }

        private static bool Excluido(string archivo, ReglaDeLimpieza regla)
        {
            if (regla.Excluir.Count == 0) return false;
            string nombre = Path.GetFileName(archivo);
            foreach (string patron in regla.Excluir)
            {
                if (CoincidePatron(nombre, patron)) return true;
            }
            return false;
        }

        /// <summary>Coincidencia glob simple: solo '*', suficiente para el catalogo.</summary>
        private static bool CoincidePatron(string texto, string patron)
        {
            if (patron == "*") return true;
            if (!patron.Contains('*', StringComparison.Ordinal))
                return string.Equals(texto, patron, StringComparison.OrdinalIgnoreCase);

            string[] partes = patron.Split('*');
            int pos = 0;
            for (int i = 0; i < partes.Length; i++)
            {
                if (partes[i].Length == 0) continue;
                int idx = texto.IndexOf(partes[i], pos, StringComparison.OrdinalIgnoreCase);
                if (idx < 0) return false;
                if (i == 0 && idx != 0) return false;
                pos = idx + partes[i].Length;
            }
            if (partes[^1].Length > 0 && !texto.EndsWith(partes[^1], StringComparison.OrdinalIgnoreCase))
                return false;
            return true;
        }

        /// <summary>
        /// Expande los comodines de la subruta: "Chrome\User Data\*\Cache" devuelve
        /// una carpeta por cada perfil existente. Necesario porque los navegadores
        /// numeran los perfiles (Default, Profile 1, Profile 2…) y Firefox les pone
        /// un sufijo aleatorio.
        /// </summary>
        private static IEnumerable<string> ExpandirSubruta(string rutaBase, string subruta)
        {
            var actuales = new List<string> { rutaBase };

            foreach (string segmento in subruta.Split(
                         new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var siguientes = new List<string>();
                foreach (string carpeta in actuales)
                {
                    if (!segmento.Contains('*', StringComparison.Ordinal))
                    {
                        siguientes.Add(Path.Combine(carpeta, segmento));
                        continue;
                    }

                    try
                    {
                        siguientes.AddRange(Directory.EnumerateDirectories(carpeta, segmento));
                    }
                    catch (Exception ex) when (ex is UnauthorizedAccessException || ex is DirectoryNotFoundException || ex is IOException)
                    {
                        // Una base inexistente no es un error: simplemente ese
                        // navegador no esta instalado en este equipo.
                    }
                }
                actuales = siguientes;
                if (actuales.Count == 0) break;
            }

            return actuales;
        }

        // ============================================================
        //  FASE 2 — EJECUCION
        // ============================================================

        /// <summary>
        /// Borra lo aprobado en la vista previa. Revalida todo: el token puede
        /// haber caducado, el disco pudo cambiar y un archivo pudo volverse un
        /// enlace simbolico entre ambas fases.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// Si el token no corresponde a la vista previa o ya caduco.
        /// </exception>
        public async Task<ResultadoBorrado> EjecutarAsync(
            VistaPreviaLimpieza vista,
            TokenConfirmacion token,
            CancellationToken ct = default)
        {
            if (vista is null) throw new ArgumentNullException(nameof(vista));
            if (token is null) throw new ArgumentNullException(nameof(token));

            DateTimeOffset ahora = DateTimeOffset.Now;

            if (!token.EsValidoPara(vista.Elementos.Select(e => e.Huella), ahora))
            {
                throw new InvalidOperationException(
                    "El token de confirmacion no corresponde a esta vista previa o ya caduco " +
                    "(vigencia " + TokenConfirmacion.Vigencia.TotalMinutes + " min). " +
                    "Vuelve a generar la vista previa y a confirmarla: el usuario debe aprobar " +
                    "exactamente la lista que se va a borrar.");
            }

            var reloj = Stopwatch.StartNew();
            var aBorrar = new List<(string Ruta, long Bytes)>();
            var descartados = new List<string>();

            // Segunda pasada del guardia, justo antes de borrar. El estado del
            // disco pudo cambiar desde la vista previa.
            foreach (ElementoLimpiable e in vista.Elementos)
            {
                ct.ThrowIfCancellationRequested();

                string? carpeta = Path.GetDirectoryName(e.Ruta);
                if (string.IsNullOrEmpty(carpeta)) { descartados.Add(e.Ruta + " — sin carpeta"); continue; }

                var guardia = new GuardiaDeRutas(TimeSpan.Zero).PermitirRaiz(carpeta);
                ResultadoValidacion v = guardia.Validar(e.Ruta, ahora);
                if (!v.Aceptada) { descartados.Add(e.Ruta + " — " + v.Motivo); continue; }

                try
                {
                    var info = new FileInfo(e.Ruta);
                    if (info.Length != e.Bytes)
                    {
                        descartados.Add(e.Ruta + " — cambio de tamano desde la vista previa");
                        continue;
                    }
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                {
                    descartados.Add(e.Ruta + " — " + ex.GetType().Name);
                    continue;
                }

                aBorrar.Add((e.Ruta, e.Bytes));
            }

            ResultadoBorrado resultado = _borrador.Borrar(aBorrar);
            reloj.Stop();

            var omitidos = new List<string>(descartados);
            omitidos.AddRange(resultado.Omitidos);

            var categorias = vista.Elementos
                .Select(e => e.Categoria)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(c => c, StringComparer.Ordinal)
                .ToArray();

            // Una sola llamada a la libreria de reportes. Sin logs propios.
            NexoEvent evento = Eventos.Limpieza.Sesion(
                categorias:           categorias,
                archivosEliminados:   resultado.Eliminados,
                bytesLiberados:       resultado.BytesLiberados,
                confirmadoPorUsuario: true,            // garantizado por el token
                enviadoAPapelera:     _borrador.EsReversible,
                duracion:             reloj.Elapsed);

            evento.Con("archivos_omitidos", omitidos.Count)
                  .Con("reversible", _borrador.EsReversible);

            if (omitidos.Count > 0)
            {
                evento = ConCuerpo(evento, ConstruirDetalleOmitidos(omitidos));
            }

            await _reportes.EscribirAsync(evento, ct).ConfigureAwait(false);

            return new ResultadoBorrado(resultado.Eliminados, resultado.BytesLiberados, omitidos);
        }

        private static string ConstruirDetalleOmitidos(List<string> omitidos)
        {
            const int max = 25;
            var sb = new System.Text.StringBuilder();
            sb.Append("### Archivos omitidos\n\n");
            sb.Append("Lo habitual es que estuvieran en uso: Windows bloquea el archivo y omitirlo ")
              .Append("es el comportamiento correcto.\n\n");
            foreach (string o in omitidos.Take(max)) sb.Append("- `").Append(o).Append("`\n");
            if (omitidos.Count > max)
                sb.Append("- … y ").Append(omitidos.Count - max).Append(" mas\n");
            return sb.ToString();
        }

        /// <summary>NexoEvent.Cuerpo es init-only; se reconstruye el evento con cuerpo.</summary>
        private static NexoEvent ConCuerpo(NexoEvent original, string cuerpo)
        {
            var copia = new NexoEvent(original.Modulo, original.Tipo, original.Titulo)
            {
                Id = original.Id,
                Fecha = original.Fecha,
                Severidad = original.Severidad,
                Accion = original.Accion,
                Cuerpo = string.IsNullOrEmpty(original.Cuerpo) ? cuerpo : original.Cuerpo + "\n\n" + cuerpo
            };
            foreach (var c in original.Campos) copia.Campos[c.Key] = c.Value;
            foreach (var e in original.Entidades) copia.Entidades.Add(e);
            return copia;
        }
    }
}
