using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.TiempoReal;
using Nexo.Native.Usn;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>
    /// Cambios de archivos a partir del diario USN de NTFS (Salida 0, §«Usn»). Necesita
    /// administrador (el servicio corre como SYSTEM). Ventajas sobre FileSystemWatcher: no tiene
    /// un buffer que se desborde y entrega el evento cuando el programa CIERRA el archivo.
    ///
    /// Reglas:
    ///   - Un volumen que no se pudo abrir (sin administrador, diario inactivo) se informa en
    ///     <see cref="NoVigiladas"/>; nunca se aparenta que se vigila.
    ///   - Si el diario sobrescribio lo que faltaba leer (error 1181) se avisa por <c>alPerder</c>
    ///     y se retoma desde el final: lo que paso en medio no se recupera, y se dice.
    ///   - Un registro cuya ruta no se pudo resolver (el archivo o su carpeta ya no existen) se
    ///     descarta: no hay nada que analizar.
    ///
    /// ESTADO: la decodificacion del buffer esta probada (ParserDeUsn); la lectura del volumen y
    /// la resolucion de rutas solo se pueden ejercitar elevado y estan SIN PROBAR en el equipo
    /// principal. Primera prueba: una VM, como administrador.
    /// </summary>
    public sealed class FuenteUsn : IFuenteDeCambios, IFuenteConCobertura
    {
        private const uint Motivos = RegistroUsn.RazonCreado | RegistroUsn.RazonDatosExtendidos | RegistroUsn.RazonDatosSobrescritos
                                     | RegistroUsn.RazonDatosTruncados | RegistroUsn.RazonRenombradoNuevoNombre | RegistroUsn.RazonCierre;
        private const int MaxPadresEnCache = 4096;

        private readonly IReadOnlyList<char> _unidades;
        private readonly IReadOnlyList<string> _prefijos;
        private readonly CancellationTokenSource _parar = new CancellationTokenSource();
        private readonly List<Task> _hilos = new List<Task>();
        private readonly List<string> _noVigiladas = new List<string>();

        /// <param name="unidades">Letras de unidad NTFS a leer.</param>
        /// <param name="prefijos">
        /// Si se indican, solo se emiten cambios dentro de esas carpetas (el diario es de TODO el volumen:
        /// sin esto Windows Update y compañia inundarian al vigilante). Vacio = todo el volumen.
        /// </param>
        public FuenteUsn(IEnumerable<char> unidades, IEnumerable<string>? prefijos = null)
        {
            _unidades = unidades.Select(char.ToUpperInvariant).Distinct().ToList();
            _prefijos = (prefijos ?? Array.Empty<string>()).Select(p => p.TrimEnd('\\', '/')).ToList();
        }

        public IReadOnlyList<string> NoVigiladas { get { lock (_noVigiladas) return _noVigiladas.ToList(); } }

        public void Iniciar(Action<CambioDeArchivo> alCambiar, Action<string> alPerder)
        {
            foreach (char u in _unidades)
            {
                VolumenUsn? v = VolumenUsn.Abrir(u, out int err);
                if (v is null) { Anotar(u + ": — " + VolumenUsn.DescribirError(err)); continue; }

                DatosDelDiario? d = v.Consultar(out err);
                if (d is null)
                {
                    Anotar(u + ": — " + VolumenUsn.DescribirError(err));
                    v.Dispose();
                    continue;
                }

                _hilos.Add(Task.Factory.StartNew(() => Leer(u, v, d.Value, alCambiar, alPerder),
                    CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default));
            }
        }

        private void Anotar(string s) { lock (_noVigiladas) _noVigiladas.Add(s); }

        private void Leer(char unidad, VolumenUsn volumen, DatosDelDiario diario, Action<CambioDeArchivo> alCambiar, Action<string> alPerder)
        {
            using (volumen)
            {
                CancellationToken ct = _parar.Token;
                byte[] buffer = new byte[64 * 1024];
                var padres = new Dictionary<ulong, string?>();
                long desde = diario.SiguienteUsn;           // solo lo NUEVO: no se analiza el historial del diario
                ulong id = diario.IdDelDiario;
                int esperaReintento = 1;

                while (!ct.IsCancellationRequested)
                {
                    int n = volumen.Leer(desde, id, Motivos, buffer, esperaSegundos: 1, out int err);

                    if (n < 0)
                    {
                        if (err == VolumenUsn.ErrorEntradaDelDiarioBorrada)
                        {
                            alPerder(unidad + ": el diario USN sobrescribio entradas que no se llegaron a leer");
                            DatosDelDiario? nuevo = volumen.Consultar(out _);
                            if (nuevo is not null) { desde = nuevo.Value.SiguienteUsn; id = nuevo.Value.IdDelDiario; }
                            continue;
                        }

                        alPerder(unidad + ": error leyendo el diario USN — " + VolumenUsn.DescribirError(err));
                        // Se reintenta con espera creciente (maximo 30 s) en vez de girar sin parar.
                        if (ct.WaitHandle.WaitOne(TimeSpan.FromSeconds(esperaReintento))) return;
                        esperaReintento = Math.Min(esperaReintento * 2, 30);
                        DatosDelDiario? d = volumen.Consultar(out _);
                        if (d is not null) { id = d.Value.IdDelDiario; desde = d.Value.SiguienteUsn; }
                        continue;
                    }

                    esperaReintento = 1;
                    ResultadoDeAnalisisUsn r = ParserDeUsn.Analizar(buffer.AsSpan(0, n));
                    if (r.Corrupto) alPerder(unidad + ": buffer del diario USN con registros que no cuadran; se descartaron");
                    if (r.Ignorados > 0) alPerder(unidad + ": " + r.Ignorados + " registros USN de otra version, no decodificados");

                    // Siempre se avanza: aunque el buffer venga corrupto, no se vuelve a pedir lo mismo.
                    if (r.Siguiente > desde) desde = r.Siguiente;

                    foreach (RegistroUsn reg in r.Registros)
                    {
                        if (reg.EsDirectorio)
                        {
                            if ((reg.Razon & RegistroUsn.RazonRenombradoNuevoNombre) != 0) padres.Clear();   // las rutas cacheadas dejaron de valer
                            continue;
                        }

                        string? ruta = Resolver(volumen, reg, padres);
                        if (ruta is null) continue;
                        if (_prefijos.Count > 0 && !_prefijos.Any(p => ruta.StartsWith(p + "\\", StringComparison.OrdinalIgnoreCase))) continue;

                        alCambiar(new CambioDeArchivo(ruta, reg.Motivo));
                    }
                }
            }
        }

        private static string? Resolver(VolumenUsn volumen, RegistroUsn reg, Dictionary<ulong, string?> padres)
        {
            if (!padres.TryGetValue(reg.FrnPadre, out string? carpeta))
            {
                carpeta = volumen.RutaDe(reg.FrnPadre);
                if (padres.Count >= MaxPadresEnCache) padres.Clear();
                padres[reg.FrnPadre] = carpeta;
            }
            return carpeta is null ? null : carpeta.TrimEnd('\\') + "\\" + reg.Nombre;
        }

        public void Dispose()
        {
            _parar.Cancel();
            try { Task.WaitAll(_hilos.ToArray(), TimeSpan.FromSeconds(4)); }
            catch (AggregateException) { }
            _parar.Dispose();
        }
    }
}
