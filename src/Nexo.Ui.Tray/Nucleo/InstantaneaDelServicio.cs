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

    /// <summary>
    /// Un hallazgo de posible criptominería (§2aw) que merece un globo: solo gravedad «Alta» o «Crítica» (la CPU alta sola es «Baja» o «Media»:
    /// se ve en la ventana, no se avisa con un globo). Se identifica por tipo y programa: no se repite mientras siga siendo el mismo.
    /// </summary>
    public sealed record AvisoDeMineriaVista(string Id, string? Sujeto, string Titulo, string Severidad)
    {
        public string Clave => Id + "|" + Sujeto;
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
        string? SenuelosError = null,
        int CopiaSospechosas = 0,
        bool CopiaFallida = false,
        IReadOnlyList<AvisoDeMineriaVista>? MineriaAvisos = null,
        bool WifiSinCifrado = false)
    {
        /// <summary>Hallazgos graves de criptominería según el servicio (vacío si está apagada o si no se pudo saber).</summary>
        public IReadOnlyList<AvisoDeMineriaVista> Mineria => MineriaAvisos ?? Array.Empty<AvisoDeMineriaVista>();

        /// <summary>Señuelos tocados según el servicio (vacío si están apagados o si no se pudo saber: ver <see cref="SenuelosError"/>).</summary>
        public IReadOnlyList<SenueloTocadoVista> Tocados => SenuelosTocados ?? Array.Empty<SenueloTocadoVista>();

        /// <summary>Carpetas donde el tiempo real perdio o no pudo analizar algo; se revisan con un escaneo bajo demanda.</summary>
        public IReadOnlyList<string> CarpetasPorRevisar => PorRevisar ?? Array.Empty<string>();

        public static InstantaneaDelServicio SinConexion(string motivo)
            => new InstantaneaDelServicio(false, null, false, false, false, 0, 0, Array.Empty<DeteccionVista>(), null, motivo);
    }
}
