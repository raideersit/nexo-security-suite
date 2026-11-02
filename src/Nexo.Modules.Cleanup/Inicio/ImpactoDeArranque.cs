using System;
using System.Collections.Generic;
using System.Linq;

namespace Nexo.Modules.Cleanup.Inicio
{
    public enum EstadoDeLecturaDeArranque
    {
        Ok,
        /// <summary>El registro exige administrador. NO significa "arranque sin problemas".</summary>
        SinPermisos,
        /// <summary>El registro no existe o no se pudo abrir. NO significa "arranque sin problemas".</summary>
        NoDisponible
    }

    /// <summary>Eventos 100-103 en bruto (XML), tal como los entrega el sistema.</summary>
    public sealed record LecturaDeArranque(
        IReadOnlyList<string> Xml,
        EstadoDeLecturaDeArranque Estado,
        string? Motivo = null,
        bool Truncada = false);

    /// <summary>
    /// De donde salen los eventos de arranque. La real lee Diagnostics-Performance/Operational (administrador);
    /// las pruebas necesitan una que falle, se trunque o devuelva XML malicioso.
    /// </summary>
    public interface IFuenteDeArranque
    {
        /// <summary>Eventos 100-103 desde <paramref name="desde"/>, los mas recientes primero, hasta <paramref name="maximo"/>.</summary>
        LecturaDeArranque Leer(DateTimeOffset desde, int maximo);
    }

    /// <summary>Lo mismo (tipo y nombre) retrasando el arranque varias veces.</summary>
    public sealed record DegradacionAgrupada(
        TipoDeDegradacion Tipo,
        string Nombre,
        string? NombreAmigable,
        int Veces,
        long DegradacionMediaMs,
        long DegradacionMaximaMs,
        DateTimeOffset Ultima);

    public sealed class ResultadoDeArranque
    {
        public ResultadoDeArranque(
            EstadoDeLecturaDeArranque estado, string? motivo, bool truncada, int eventosLeidos, int descartados,
            IReadOnlyList<ArranqueMedido> arranques, IReadOnlyList<DegradacionAgrupada> degradaciones)
        {
            Estado = estado; Motivo = motivo; Truncada = truncada; EventosLeidos = eventosLeidos;
            Descartados = descartados; Arranques = arranques; Degradaciones = degradaciones;
        }

        public EstadoDeLecturaDeArranque Estado { get; }
        public string? Motivo { get; }

        /// <summary>Habia mas eventos de los leidos: lo mostrado es lo mas reciente, no todo.</summary>
        public bool Truncada { get; }

        public int EventosLeidos { get; }

        /// <summary>Eventos que no se pudieron interpretar. No cuentan ni como arranque ni como degradacion.</summary>
        public int Descartados { get; }

        /// <summary>Arranques medidos (evento 100), el mas reciente primero.</summary>
        public IReadOnlyList<ArranqueMedido> Arranques { get; }

        /// <summary>Lo que retraso el arranque, lo que mas veces lo hizo primero.</summary>
        public IReadOnlyList<DegradacionAgrupada> Degradaciones { get; }

        /// <summary>Mediana del tiempo total de arranque, o null sin arranques medidos.</summary>
        public long? MedianaMs
        {
            get
            {
                if (Arranques.Count == 0) return null;
                long[] t = Arranques.Select(a => a.TotalMs).OrderBy(x => x).ToArray();
                int m = t.Length / 2;
                return t.Length % 2 == 1 ? t[m] : (t[m - 1] + t[m]) / 2;
            }
        }

        /// <summary>
        /// Solo es cierto si de verdad se sabe que nada retraso el arranque: se leyo el registro, hay al menos un
        /// arranque medido (prueba que Windows esta midiendo; sin el servicio de diagnostico no escribe nada), no
        /// se trunco y nada quedo sin interpretar. Aun asi, el 101 se escribe cuando algo tarda MAS DE LO HABITUAL:
        /// "sin degradaciones" no es "nada pesa en el arranque".
        /// </summary>
        public bool PuedeAfirmarQueNadaLoRetraso
            => Estado == EstadoDeLecturaDeArranque.Ok && Arranques.Count > 0 && !Truncada
               && Descartados == 0 && Degradaciones.Count == 0;

        /// <summary>
        /// Lo que se sabe de una entrada de inicio, buscando su ejecutable entre las aplicaciones (evento 101).
        /// null = no hay datos (no se pudo sacar el ejecutable, es un acceso directo o no aparecio): NO "no pesa".
        /// </summary>
        public DegradacionAgrupada? ImpactoDe(EntradaDeInicio entrada)
        {
            string? exe = NombreDeEjecutable(entrada.Comando);
            if (exe is null) return null;
            return Degradaciones.FirstOrDefault(d => d.Tipo == TipoDeDegradacion.Aplicacion
                                                     && string.Equals(NombreDeArchivo(d.Nombre), exe, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// El nombre del ejecutable de una linea de comando de Run: <c>"C:\Program Files\X\x.exe" --min</c> -> x.exe.
        /// null si no termina en .exe (accesos directos .lnk, scripts) o no se entiende: no se adivina.
        /// </summary>
        public static string? NombreDeEjecutable(string? comando)
        {
            if (string.IsNullOrWhiteSpace(comando)) return null;
            string c = comando.Trim();
            string ruta;
            if (c[0] == '"')
            {
                int cierre = c.IndexOf('"', 1);
                if (cierre < 0) return null;
                ruta = c[1..cierre];
            }
            else
            {
                // Sin comillas una ruta puede tener espacios (C:\Program Files\...): se corta en el primer ".exe".
                int exe = c.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                ruta = exe >= 0 ? c[..(exe + 4)] : c.Split(' ', 2)[0];
            }

            string nombre = NombreDeArchivo(ruta);
            return nombre.Length > 4 && nombre.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? nombre : null;
        }

        // Path.GetFileName no separa por '\' fuera de Windows, y esto debe funcionar igual en las pruebas portables.
        private static string NombreDeArchivo(string ruta)
            => ruta[(ruta.LastIndexOfAny(new[] { '\\', '/' }) + 1)..].Trim();
    }

    /// <summary>
    /// Lee el impacto de arranque que mide Windows (Diagnostics-Performance): cuanto tardo cada arranque (100) y
    /// que lo retraso (101 aplicacion, 102 controlador, 103 servicio). Solo lee.
    /// </summary>
    public sealed class AnalizadorDeArranque
    {
        public const int MaximoPorDefecto = 2000;

        private readonly IFuenteDeArranque _fuente;

        public AnalizadorDeArranque(IFuenteDeArranque fuente)
        {
            _fuente = fuente;
        }

        public ResultadoDeArranque Leer(DateTimeOffset desde, int maximo = MaximoPorDefecto)
        {
            if (maximo < 1) maximo = 1;
            LecturaDeArranque cruda = _fuente.Leer(desde, maximo);
            if (cruda.Estado != EstadoDeLecturaDeArranque.Ok)
                return new ResultadoDeArranque(cruda.Estado, cruda.Motivo, cruda.Truncada, 0, 0,
                    Array.Empty<ArranqueMedido>(), Array.Empty<DegradacionAgrupada>());

            // Una fuente que ignora el maximo no debe poder inflar la memoria.
            bool truncada = cruda.Truncada || cruda.Xml.Count > maximo;
            var arranques = new List<ArranqueMedido>();
            var degradaciones = new List<DegradacionDeArranque>();
            int descartados = 0;

            foreach (string xml in cruda.Xml.Take(maximo))
            {
                if (!ParserDeEventoDeArranque.TryParse(xml, out ArranqueMedido? a, out DegradacionDeArranque? d, out _))
                {
                    descartados++;
                    continue;
                }
                // Fuera de la ventana pedida no es un error: simplemente no se pidio.
                if (a is not null && a.Cuando >= desde) arranques.Add(a);
                if (d is not null && d.Cuando >= desde) degradaciones.Add(d);
            }

            List<DegradacionAgrupada> grupos = degradaciones
                .GroupBy(d => (d.Tipo, Nombre: d.Nombre.ToLowerInvariant()))
                .Select(g =>
                {
                    DegradacionDeArranque ultima = g.MaxBy(d => d.Cuando)!;
                    return new DegradacionAgrupada(g.Key.Tipo, ultima.Nombre,
                        g.Select(d => d.NombreAmigable).FirstOrDefault(n => n is not null),
                        g.Count(), (long)g.Average(d => d.DegradacionMs), g.Max(d => d.DegradacionMs), ultima.Cuando);
                })
                .OrderByDescending(g => g.Veces).ThenByDescending(g => g.DegradacionMaximaMs)
                .ToList();

            return new ResultadoDeArranque(EstadoDeLecturaDeArranque.Ok, cruda.Motivo, truncada,
                Math.Min(cruda.Xml.Count, maximo), descartados,
                arranques.OrderByDescending(a => a.Cuando).ToList(), grupos);
        }
    }
}
