using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Firewall
{
    /// <summary>Una conexion que el firewall bloqueo (evento 5157 del registro de Seguridad).</summary>
    public sealed record ConexionBloqueada(
        DateTimeOffset Cuando,
        string Aplicacion,
        DireccionDeRegla Direccion,
        string IpRemota,
        int PuertoRemoto,
        string Protocolo,
        long? Filtro);

    /// <summary>Resultado de pedirle los eventos en bruto a la fuente.</summary>
    public enum EstadoDeFuente
    {
        Ok,
        /// <summary>El registro de Seguridad exige administrador. NO significa "sin bloqueos".</summary>
        SinPermisos,
        /// <summary>El registro no existe o no se pudo abrir. NO significa "sin bloqueos".</summary>
        NoDisponible
    }

    /// <summary>Eventos 5157 en bruto (XML), tal como los entrega el sistema.</summary>
    public sealed record LecturaCruda(
        IReadOnlyList<string> Xml,
        EstadoDeFuente Estado,
        string? Motivo = null,
        bool Truncada = false);

    /// <summary>
    /// De donde salen los bloqueos. Se abstrae porque la real lee el registro de Seguridad de Windows
    /// (administrador) y las pruebas necesitan una que falle, se trunque o devuelva XML malicioso.
    /// </summary>
    public interface IFuenteDeBloqueos
    {
        /// <summary>Eventos 5157 desde <paramref name="desde"/>, los mas recientes primero, hasta <paramref name="maximo"/>.</summary>
        LecturaCruda Leer(DateTimeOffset desde, int maximo);

        /// <summary>
        /// True si la auditoria de fallos de "Filtering Platform Connection" esta activa (sin ella Windows NO
        /// escribe el 5157), false si esta apagada, null si no se pudo averiguar.
        /// </summary>
        bool? AuditoriaActiva();
    }

    /// <summary>Un mismo bloqueo repetido: misma aplicacion, direccion, destino, puerto y protocolo.</summary>
    public sealed record BloqueoAgrupado(
        string Aplicacion,
        DireccionDeRegla Direccion,
        string IpRemota,
        int PuertoRemoto,
        string Protocolo,
        long? Filtro,
        int Repeticiones,
        DateTimeOffset Primero,
        DateTimeOffset Ultimo);

    public sealed class ResultadoDeBloqueos
    {
        public ResultadoDeBloqueos(
            EstadoDeFuente estado, string? motivo, bool? auditoriaActiva, bool truncada,
            int eventosLeidos, int descartados, IReadOnlyList<BloqueoAgrupado> grupos)
        {
            Estado = estado; Motivo = motivo; AuditoriaActiva = auditoriaActiva; Truncada = truncada;
            EventosLeidos = eventosLeidos; Descartados = descartados; Grupos = grupos;
        }

        public EstadoDeFuente Estado { get; }
        public string? Motivo { get; }
        public bool? AuditoriaActiva { get; }

        /// <summary>Habia mas eventos de los que se leyeron: lo mostrado es lo mas reciente, no todo.</summary>
        public bool Truncada { get; }

        public int EventosLeidos { get; }

        /// <summary>Eventos que no se pudieron interpretar (XML roto o con valores invalidos). No se cuentan como bloqueos.</summary>
        public int Descartados { get; }

        public IReadOnlyList<BloqueoAgrupado> Grupos { get; }

        /// <summary>
        /// Solo es cierto si de verdad se sabe que no hubo bloqueos: se pudo leer el registro, la auditoria estaba
        /// activa, no se trunco nada y ningun evento quedo sin interpretar. "No pude leer" nunca es "esta bien".
        /// </summary>
        public bool PuedeAfirmarQueNoHuboBloqueos
            => Estado == EstadoDeFuente.Ok && AuditoriaActiva == true && !Truncada
               && Descartados == 0 && EventosLeidos == 0;

        /// <summary>Se pudo leer, pero con la auditoria apagada o desconocida un resultado vacio no prueba nada.</summary>
        public bool ResultadoNoConcluyente
            => Estado != EstadoDeFuente.Ok || (Grupos.Count == 0 && !PuedeAfirmarQueNoHuboBloqueos);
    }

    /// <summary>
    /// Lee los bloqueos del firewall, los interpreta con <see cref="ParserDeEvento5157"/> y los agrupa.
    /// Solo lee: no activa la auditoria ni cambia ninguna politica del equipo.
    /// </summary>
    public sealed class LectorDeBloqueos
    {
        public const int MaximoPorDefecto = 5000;

        private readonly IFuenteDeBloqueos _fuente;
        private readonly TraductorDeRutasNt _rutas;

        /// <param name="rutas">
        /// Convierte \device\harddiskvolumeN\... en C:\... antes de agrupar. Sin el solo se traducen las rutas de red;
        /// las demas quedan en forma de dispositivo, que es cierta aunque menos legible.
        /// </param>
        public LectorDeBloqueos(IFuenteDeBloqueos fuente, TraductorDeRutasNt? rutas = null)
        {
            _fuente = fuente;
            _rutas = rutas ?? TraductorDeRutasNt.Vacio;
        }

        public ResultadoDeBloqueos Leer(DateTimeOffset desde, int maximo = MaximoPorDefecto)
        {
            if (maximo < 1) maximo = 1;
            bool? auditoria = _fuente.AuditoriaActiva();
            LecturaCruda cruda = _fuente.Leer(desde, maximo);

            if (cruda.Estado != EstadoDeFuente.Ok)
                return new ResultadoDeBloqueos(cruda.Estado, cruda.Motivo, auditoria, cruda.Truncada, 0, 0, Array.Empty<BloqueoAgrupado>());

            var acumulado = new Dictionary<string, BloqueoAgrupado>(StringComparer.Ordinal);
            int descartados = 0;
            // Una fuente que ignora el maximo no debe poder inflar la memoria.
            bool truncada = cruda.Truncada || cruda.Xml.Count > maximo;

            foreach (string xml in cruda.Xml.Take(maximo))
            {
                if (!ParserDeEvento5157.TryParse(xml, out ConexionBloqueada? c, out _) || c is null || c.Cuando < desde)
                {
                    // Fuera de la ventana pedida no es un error: simplemente no se pidio.
                    if (c is null) descartados++;
                    continue;
                }

                // Se traduce antes de agrupar: la misma app vista como \device\... y como C:\... es un solo grupo.
                c = c with { Aplicacion = _rutas.Traducir(c.Aplicacion) };
                string clave = string.Join('\u001f', c.Aplicacion.ToLowerInvariant(), c.Direccion, c.IpRemota, c.PuertoRemoto, c.Protocolo);
                acumulado[clave] = acumulado.TryGetValue(clave, out BloqueoAgrupado? g)
                    ? g with
                    {
                        Repeticiones = g.Repeticiones + 1,
                        Primero = c.Cuando < g.Primero ? c.Cuando : g.Primero,
                        Ultimo = c.Cuando > g.Ultimo ? c.Cuando : g.Ultimo,
                        Filtro = g.Filtro ?? c.Filtro
                    }
                    : new BloqueoAgrupado(c.Aplicacion, c.Direccion, c.IpRemota, c.PuertoRemoto, c.Protocolo, c.Filtro, 1, c.Cuando, c.Cuando);
            }

            List<BloqueoAgrupado> grupos = acumulado.Values
                .OrderByDescending(g => g.Repeticiones).ThenByDescending(g => g.Ultimo).ToList();
            int leidos = Math.Min(cruda.Xml.Count, maximo);
            return new ResultadoDeBloqueos(EstadoDeFuente.Ok, cruda.Motivo, auditoria, truncada, leidos, descartados, grupos);
        }

        /// <summary>
        /// Anota los bloqueos como notas del vault (los mas repetidos primero). Un maximo de notas evita llenar el
        /// vault: un escaneo de puertos genera miles de eventos. Devuelve cuantos grupos quedaron sin anotar.
        /// </summary>
        public static async Task<int> RegistrarAsync(
            ResultadoDeBloqueos resultado, IReportWriter reportes, int maximoNotas = 50, CancellationToken ct = default)
        {
            int escritos = 0;
            foreach (BloqueoAgrupado g in resultado.Grupos.Take(Math.Max(0, maximoNotas)))
            {
                NexoEvent ev = Eventos.Amenazas.Firewall(
                    g.Aplicacion, g.Direccion == DireccionDeRegla.Entrante ? "entrante" : "saliente",
                    g.IpRemota, g.PuertoRemoto, g.Protocolo,
                    g.Filtro is { } f ? "filtro #" + f.ToString(System.Globalization.CultureInfo.InvariantCulture) : "desconocida")
                    .Con("repeticiones", g.Repeticiones)
                    .Con("primero", g.Primero.ToString("O", System.Globalization.CultureInfo.InvariantCulture))
                    .Con("ultimo", g.Ultimo.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
                await reportes.EscribirAsync(ev, ct).ConfigureAwait(false);
                escritos++;
            }
            return resultado.Grupos.Count - escritos;
        }
    }
}
