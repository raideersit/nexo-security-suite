namespace Nexo.Modules.Cleanup.Seguridad
{
    /// <summary>Motivo por el que una ruta fue aceptada o rechazada para borrado.</summary>
    public enum MotivoRechazo
    {
        Aceptada,
        RutaVacia,
        RutaInvalida,
        FueraDeRaicesPermitidas,
        EnListaNegra,
        EsEnlaceSimbolico,
        EsDirectorio,
        NoExiste,
        EsArchivoDeSistema,
        DemasiadoReciente
    }

    public sealed class ResultadoValidacion
    {
        private ResultadoValidacion(bool aceptada, MotivoRechazo motivo, string rutaCanonica, string? detalle)
        {
            Aceptada = aceptada;
            Motivo = motivo;
            RutaCanonica = rutaCanonica;
            Detalle = detalle;
        }

        public bool Aceptada { get; }
        public MotivoRechazo Motivo { get; }
        public string RutaCanonica { get; }
        public string? Detalle { get; }

        public static ResultadoValidacion Ok(string rutaCanonica)
            => new ResultadoValidacion(true, MotivoRechazo.Aceptada, rutaCanonica, null);

        public static ResultadoValidacion Rechazo(MotivoRechazo motivo, string ruta, string? detalle = null)
            => new ResultadoValidacion(false, motivo, ruta, detalle);
    }
}
