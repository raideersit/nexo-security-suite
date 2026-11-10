using System;
using System.Collections.Generic;

namespace Nexo.Ui.Tray.Nucleo
{
    // Sin dependencias de Windows ni del pipe: Nexo.Ui.Desktop compila este archivo (y ModeloDeBandeja.cs)
    // tambien para Linux. Lo que habla con el servicio esta en Instantanea.cs.

    public sealed record DeteccionVista(string Ruta, string Firma, long Bytes, string? Sha256)
    {
        /// <summary>Identifica una deteccion entre consultas: la misma ruta con otro contenido es otra deteccion.</summary>
        public string Clave => Ruta + "|" + Sha256;
    }

    /// <summary>
    /// Un señuelo contra ransomware que alguien tocó (§2am). <see cref="Severidad"/> es el nombre que da el servicio («Alta», o «Media» si
    /// se envió a la papelera). Se identifica por ruta y momento: si se repone y se vuelve a tocar, es otro aviso.
    /// </summary>
    public sealed record SenueloTocadoVista(string Ruta, string Tipo, string Detalle, string Severidad, DateTimeOffset Cuando)
    {
        public string Clave => Ruta + "|" + Cuando.UtcTicks;
    }

    /// <summary>Lo que se sabe del servicio en un momento dado. Si no se pudo hablar con el, <see cref="Conectado"/> es false.</summary>
    public sealed record InstantaneaDelServicio(
        bool Conectado,
        string? Version,
        bool TiempoRealActivo,
        bool CoberturaCompleta,
        bool MotorCaido,
        long Perdidos,
        long NoAnalizados,
        IReadOnlyList<DeteccionVista> Detecciones,
        string? UltimoAviso,
        string? Error,
        IReadOnlyList<string>? PorRevisar = null,
        long DesbordesDeFuente = 0,
        IReadOnlyList<SenueloTocadoVista>? SenuelosTocados = null,
        bool SenuelosEnRafaga = false,
        string? SenuelosError = null)
    {
        /// <summary>Señuelos tocados según el servicio (vacío si están apagados o si no se pudo saber: ver <see cref="SenuelosError"/>).</summary>
        public IReadOnlyList<SenueloTocadoVista> Tocados => SenuelosTocados ?? Array.Empty<SenueloTocadoVista>();

        /// <summary>Carpetas donde el tiempo real perdio o no pudo analizar algo; se revisan con un escaneo bajo demanda.</summary>
        public IReadOnlyList<string> CarpetasPorRevisar => PorRevisar ?? Array.Empty<string>();

        public static InstantaneaDelServicio SinConexion(string motivo)
            => new InstantaneaDelServicio(false, null, false, false, false, 0, 0, Array.Empty<DeteccionVista>(), null, motivo);
    }
}
