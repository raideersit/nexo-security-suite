using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Media;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Ui.Desktop
{
    public sealed record FilaDeVersion(string Id, string Texto, string Detalle, bool Sospechosa, IBrush Color);

    /// <summary>
    /// La pestaña «Copias» (copia versionada, §2ap-§2ar). El servicio hace las copias (estado y «copiar ahora» por el pipe); la ventana lee la
    /// lista de versiones del destino, las verifica y las restaura con los permisos de la persona. Reglas (probadas en tools/Nexo.Desktop.Demo):
    ///  - Restaurar solo a una carpeta nueva o vacía; nunca pisa nada (lo garantiza <see cref="CopiaVersionada.Restaurar"/>).
    ///  - Una copia sospechosa (muchos archivos cambiaron de golpe) se muestra en ROJO y con el motivo: no es «todo bien».
    ///  - «Sin copias» y «disco desconectado» no son verde. Verde = hay una copia correcta, reciente y sin sospecha.
    /// </summary>
    public sealed class CopiaModelo : INotifyPropertyChanged
    {
        /// <summary>Pasados tantos días sin copia correcta, el indicador pasa a amarillo.</summary>
        public const int DiasAntesDeAvisar = 7;

        private readonly IServicioDeCopia _servicio;
        private readonly Func<string, string, string, CancellationToken, ResultadoDeRestauracion> _restaurar;
        private readonly Func<string, CancellationToken, ResultadoDeVerificacion> _verificar;
        private readonly Func<string, IReadOnlyList<Instantanea>> _listar;
        private readonly Func<string, string, (bool Correcto, string? Error)> _descartar;
        private readonly Func<DateTimeOffset> _reloj;
        private Consulta<EstadoDeCopiaVista>? _ultima;
        private IReadOnlyList<Instantanea> _versiones = Array.Empty<Instantanea>();
        private string _mensaje = "";
        private bool _ocupado;
        private string? _seleccionada;

        public CopiaModelo(IServicioDeCopia servicio,
                           Func<string, string, string, CancellationToken, ResultadoDeRestauracion>? restaurar = null,
                           Func<string, CancellationToken, ResultadoDeVerificacion>? verificar = null,
                           Func<string, IReadOnlyList<Instantanea>>? listar = null,
                           Func<string, string, (bool Correcto, string? Error)>? descartar = null,
                           Func<DateTimeOffset>? reloj = null)
        {
            _servicio = servicio;
            _restaurar = restaurar ?? ((d, id, c, ct) => CopiaVersionada.Restaurar(d, id, c, ct));
            _verificar = verificar ?? ((d, ct) => CopiaVersionada.Verificar(d, ct));
            _listar = listar ?? (d => CopiaVersionada.Listar(d, out _));
            // Por omisión lo hace el SERVICIO (la carpeta de copias es de solo lectura para la persona). El destino lo elige el servicio, no se manda.
            _descartar = descartar ?? ((_, id) =>
            {
                Consulta<ResultadoDeDescartar> c = _servicio.DescartarAsync(id, CancellationToken.None).GetAwaiter().GetResult();
                return c.Valor is ResultadoDeDescartar r ? (r.Exito, r.Error) : (false, c.Error);
            });
            _reloj = reloj ?? (() => DateTimeOffset.Now);
            Calcular();
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public EstadoDeCopiaVista? Estado => _ultima?.Valor;
        public string Titulo { get; private set; } = "";
        public string Explicacion { get; private set; } = "";
        public IBrush Color { get; private set; } = Colores.De(Indicador.SinDatos);
        public Indicador Indicador { get; private set; } = Indicador.SinDatos;
        public string Resumen { get; private set; } = "";
        public string Aviso { get; private set; } = "";
        public IReadOnlyList<FilaDeVersion> Versiones { get; private set; } = Array.Empty<FilaDeVersion>();
        public bool HayVersiones => Versiones.Count > 0;
        public string Nota { get; private set; } = "";
        public bool PuedeCopiar { get; private set; }
        public bool PuedeRestaurar { get; private set; }
        public bool PuedeVerificar { get; private set; }
        /// <summary>Solo con una versión SOSPECHOSA elegida: dar por buena una copia es una decisión de la persona, nunca automática.</summary>
        public bool PuedeDescartar { get; private set; }

        public string Mensaje { get => _mensaje; private set { if (_mensaje == value) return; _mensaje = value; Avisar(); } }

        /// <summary>El id de la versión elegida en la lista (null si no hay).</summary>
        public string? Seleccionada { get => _seleccionada; set { if (_seleccionada == value) return; _seleccionada = value; Calcular(); } }

        /// <summary>La fila elegida en la lista (enlazada en los dos sentidos). Reconstruir la lista no pasa por aquí: <see cref="Calcular"/> no toca <see cref="Versiones"/>.</summary>
        public FilaDeVersion? FilaSeleccionada
        {
            get => _seleccionada is null ? null : Versiones.FirstOrDefault(v => v.Id == _seleccionada);
            set => Seleccionada = value?.Id;
        }

        public async Task ActualizarAsync(CancellationToken ct = default)
        {
            if (_ocupado) return;
            _ocupado = true;
            Calcular();
            try
            {
                try { _ultima = await _servicio.EstadoAsync(ct).ConfigureAwait(true); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _ultima = Consulta<EstadoDeCopiaVista>.Mal("error inesperado al consultar (" + ex.GetType().Name + ")");
                }

                // La lista de versiones se lee del disco de destino, en este proceso. Solo con el destino conectado.
                _versiones = Array.Empty<Instantanea>();
                if (_ultima.Valor is { Activo: true, DestinoDisponible: true, Destino: { } d })
                {
                    try { _versiones = await Task.Run(() => _listar(d), ct).ConfigureAwait(true); }
                    catch (Exception ex) when (ex is not OperationCanceledException) { Mensaje = "No se pudo leer la lista de copias del disco (" + ex.GetType().Name + ")."; }
                }
                if (_seleccionada is not null && !_versiones.Any(v => v.Id == _seleccionada)) _seleccionada = null;
            }
            finally { _ocupado = false; ReconstruirVersiones(); Calcular(); }
        }

        /// <summary>Solo aquí se rehace la lista (al actualizar): hacerlo en cada cálculo deselecciona la fila y esa deselección vuelve a calcular.</summary>
        private void ReconstruirVersiones()
        {
            Versiones = _ultima?.Valor is { Activo: true }
                ? _versiones.OrderByDescending(v => v.Id, StringComparer.Ordinal).Select(v => new FilaDeVersion(v.Id,
                    v.Creada.ToLocalTime().ToString("dd/MM/yyyy HH:mm", System.Globalization.CultureInfo.InvariantCulture) + (v.Sospechosa ? "  ¡SOSPECHOSA!" : ""),
                    v.Entradas.Count + " archivos" + (v.Omitidos.Count > 0 ? ", " + v.Omitidos.Count + " omitidos" : ""),
                    v.Sospechosa, Colores.De(v.Sospechosa ? Indicador.Alerta : Indicador.Correcto))).ToList()
                : Array.Empty<FilaDeVersion>();
            Avisar(nameof(Versiones)); Avisar(nameof(HayVersiones)); Avisar(nameof(FilaSeleccionada));
        }

        /// <summary>Pide al servicio una copia ahora. Puede tardar minutos; mientras, el botón queda inactivo.</summary>
        public async Task HacerAhoraAsync(CancellationToken ct = default)
        {
            if (!PuedeCopiar) return;
            _ocupado = true;
            Mensaje = "Copiando... puede tardar unos minutos según cuántos archivos haya.";
            Calcular();
            Consulta<ResultadoDeHacerCopia> c;
            try { c = await _servicio.HacerAsync(ct).ConfigureAwait(true); }
            catch (Exception ex) when (ex is not OperationCanceledException) { c = Consulta<ResultadoDeHacerCopia>.Mal("error inesperado (" + ex.GetType().Name + ")"); }
            _ocupado = false;
            Mensaje = c.Valor is not ResultadoDeHacerCopia r ? "No se pudo pedir la copia: " + c.Error + "."
                    : !r.Exito ? "La copia no se hizo: " + r.Error
                    : r.Sospechosa ? "Copia hecha, pero SOSPECHOSA: " + r.MotivoSospecha + SufijoDeProteccion(r.AvisoDeProteccion)
                    : "Copia hecha: " + r.Archivos + " archivos (" + r.Nuevos + " nuevos)" + (r.Omitidos > 0 ? ", " + r.Omitidos + " omitidos" : "") + "." + SufijoDeProteccion(r.AvisoDeProteccion);
            await ActualizarAsync(ct).ConfigureAwait(true);
        }

        private static string SufijoDeProteccion(string? aviso) => string.IsNullOrEmpty(aviso) ? "" : " ATENCIÓN: las copias no quedaron protegidas contra cambios. " + aviso;

        /// <summary>Restaura la versión elegida a una carpeta nueva o vacía. Nunca pisa nada.</summary>
        public async Task RestaurarAsync(string carpetaNueva, CancellationToken ct = default)
        {
            if (!PuedeRestaurar || _seleccionada is null || Estado?.Destino is not { } destino) return;
            string id = _seleccionada;
            _ocupado = true;
            Mensaje = "Restaurando...";
            Calcular();
            ResultadoDeRestauracion r;
            try { r = await Task.Run(() => _restaurar(destino, id, carpetaNueva, ct), ct).ConfigureAwait(true); }
            catch (Exception ex) when (ex is not OperationCanceledException) { r = new ResultadoDeRestauracion(false, "error inesperado (" + ex.GetType().Name + ")", 0, Array.Empty<OmitidoEnCopia>()); }
            _ocupado = false;
            Mensaje = r.Correcto ? "Restaurados " + r.Restaurados + " archivos en " + carpetaNueva + ". Los originales no se tocaron."
                    : (r.Error ?? "No se pudo restaurar") + (r.NoRestaurados.Count > 0
                        ? " Primeros problemas: " + string.Join("; ", r.NoRestaurados.Take(3).Select(x => x.Ruta + " (" + x.Motivo + ")")) : "")
                      + (r.Restaurados > 0 ? " Sí se restauraron " + r.Restaurados + " archivos en " + carpetaNueva + "." : "");
            Calcular();
        }

        /// <summary>
        /// La persona revisó la versión sospechosa elegida y la da por buena. Desde ese momento la poda puede borrarla (y la última buena anterior).
        /// Solo reescribe la lista de esa copia, no su contenido.
        /// </summary>
        public async Task DescartarSospechaAsync(CancellationToken ct = default)
        {
            if (!PuedeDescartar || _seleccionada is null || Estado?.Destino is not { } destino) return;
            string id = _seleccionada;
            _ocupado = true;
            Calcular();
            (bool Correcto, string? Error) r;
            try { r = await Task.Run(() => _descartar(destino, id), ct).ConfigureAwait(true); }
            catch (Exception ex) when (ex is not OperationCanceledException) { r = (false, "error inesperado (" + ex.GetType().Name + ")"); }
            _ocupado = false;
            Mensaje = r.Correcto ? "Listo: esa copia ya no está marcada como sospechosa." : "No se pudo descartar la sospecha: " + r.Error;
            await ActualizarAsync(ct).ConfigureAwait(true);
        }

        /// <summary>Comprueba que todo el contenido guardado está y no cambió (lee todo el disco de copias: puede tardar).</summary>
        public async Task VerificarAsync(CancellationToken ct = default)
        {
            if (!PuedeVerificar || Estado?.Destino is not { } destino) return;
            _ocupado = true;
            Mensaje = "Comprobando las copias...";
            Calcular();
            ResultadoDeVerificacion v;
            try { v = await Task.Run(() => _verificar(destino, ct), ct).ConfigureAwait(true); }
            catch (Exception ex) when (ex is not OperationCanceledException) { v = new ResultadoDeVerificacion(false, 0, new[] { new OmitidoEnCopia(destino, "error inesperado (" + ex.GetType().Name + ")") }); }
            _ocupado = false;
            Mensaje = v.Correcto ? "Todo en orden: " + v.Comprobados + " contenidos comprobados."
                    : v.Problemas.Count + " problema(s) en las copias. Primeros: " + string.Join("; ", v.Problemas.Take(3).Select(x => x.Ruta + " (" + x.Motivo + ")"));
            Calcular();
        }

        // ------------------------------------------------------------
        private void Calcular()
        {
            EstadoDeCopiaVista? s = _ultima?.Valor;
            (Indicador ind, string titulo, string detalle) = Resumir(_ultima, _reloj());
            Titulo = titulo; Explicacion = detalle; Indicador = ind; Color = Colores.De(ind);
            Nota = s?.Nota ?? "";

            if (s is not { Activo: true })
            {
                Resumen = Aviso = "";
            }
            else
            {
                var partes = new List<string>();
                partes.Add("Destino: " + s.Destino + (s.DestinoDisponible ? "" : " (no conectado)"));
                if (s.UltimaCorrecta is DateTimeOffset u) partes.Add("última copia: " + Nexo.Ui.Desktop.Nucleo.Resumir.Fecha(u));
                partes.Add(s.VersionesEnDestino + " de " + s.VersionesAConservar + " versiones");
                if (s.AutomaticaCadaHoras is double h) partes.Add("automática cada " + h.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture) + " h");
                else partes.Add("solo a mano");
                if (s.EnCurso) partes.Add("copiando ahora...");
                Resumen = string.Join(" · ", partes);

                var avisos = new List<string>();
                if (s.Ultimo is { Sospechosa: true, MotivoSospecha: { } m }) avisos.Add(m);
                if (s.Ultimo is { PodaSuspendida: true, MotivoPoda: { } mp }) avisos.Add(mp);
                if (s.AvisoDeProteccion is { Length: > 0 } ap) avisos.Add("Las copias NO están protegidas contra cambios de otros programas: " + ap);
                if (s.ListasIlegibles > 0) avisos.Add(s.ListasIlegibles + " lista(s) de copias del disco no se pudieron leer.");
                if (s.Ultimo is { Omitidos: > 0 } o) avisos.Add(o.Omitidos + " archivo(s) no se copiaron en la última copia, por ejemplo: " + string.Join("; ", o.PrimerosOmitidos.Take(3).Select(x => x.Ruta + " (" + x.Motivo + ")")));
                if (s.SinCopia.Count > 0) avisos.Add("Carpetas sin copia: " + string.Join("; ", s.SinCopia));
                if (s.Aviso is { Length: > 0 } a) avisos.Add(a);
                Aviso = string.Join("\n", avisos);
            }

            bool conDestino = s is { Activo: true, DestinoDisponible: true };
            PuedeCopiar = conDestino && !_ocupado && s!.EnCurso == false;
            PuedeVerificar = conDestino && !_ocupado && s!.VersionesEnDestino > 0;
            PuedeRestaurar = conDestino && !_ocupado && _seleccionada is not null;
            PuedeDescartar = conDestino && !_ocupado && _seleccionada is not null && Versiones.Any(v => v.Id == _seleccionada && v.Sospechosa);
            foreach (string n in new[] { nameof(Titulo), nameof(Explicacion), nameof(Color), nameof(Indicador), nameof(Resumen), nameof(Aviso),
                                         nameof(Nota), nameof(PuedeCopiar), nameof(PuedeRestaurar), nameof(PuedeVerificar), nameof(PuedeDescartar), nameof(Estado) })
                Avisar(n);
        }

        /// <summary>Qué decir y de qué color. Solo es verde con una copia correcta, reciente y sin sospecha.</summary>
        public static (Indicador, string, string) Resumir(Consulta<EstadoDeCopiaVista>? c, DateTimeOffset ahora)
        {
            if (c is null) return (Indicador.SinDatos, "Sin consultar", "Abre esta pestaña con el servicio de Nexo en marcha para ver el estado de las copias.");
            if (c.Valor is not EstadoDeCopiaVista s) return (Indicador.SinDatos, "No se pudo consultar", (c.Error ?? "sin detalle") + ". No se sabe si hay copias.");
            if (!s.Activo) return (Indicador.SinDatos, "Copia de seguridad apagada", s.Nota);
            if (s.Ultimo is { Sospechosa: true }) return (Indicador.Alerta, "Muchos archivos cambiaron de golpe", "La última copia es sospechosa (podría ser un cifrado). Nexo conservó las versiones anteriores: no restaures ni borres nada hasta revisar.");
            // Una sospechosa guardada sigue siendo alarma aunque la copia siguiente haya salido «normal» (se compara con la ya cifrada): Nexo la protege de la poda.
            if (s.SospechosasGuardadas is > 0 and int g)
                return (Indicador.Alerta, g == 1 ? "Hay una copia sospechosa guardada" : "Hay " + g + " copias sospechosas guardadas",
                        "En algún momento cambiaron muchos archivos de golpe (podría ser un cifrado). Nexo no borra esas copias ni la última buena anterior. Revisa antes de restaurar o de borrar nada.");
            if (s.Ultimo is { Correcto: false } f) return (Indicador.Alerta, "La última copia falló", f.Error ?? "sin detalle");
            if (!s.DestinoDisponible) return (Indicador.Atencion, "El disco de copias no está conectado", "Conecta " + s.Destino + " para copiar o restaurar.");
            if (s.UltimaCorrecta is not DateTimeOffset u) return (Indicador.Atencion, "Todavía no hay copias", "Pulsa «Copiar ahora» para hacer la primera.");
            double dias = (ahora - u).TotalDays;
            if (dias > DiasAntesDeAvisar) return (Indicador.Atencion, "La última copia es antigua", "Es de hace " + (int)dias + " días. Conviene copiar de nuevo.");
            return (Indicador.Correcto, "Copias al día", "Hay " + s.VersionesEnDestino + " versiones guardadas en " + s.Destino + ".");
        }

        private void Avisar([CallerMemberName] string? nombre = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nombre));
    }
}
