namespace Nexo.Reports.Seguridad
{
    /// <summary>Cuanta ruta se escribe en el vault.</summary>
    public enum NivelRuta
    {
        /// <summary>C:\Users\alvaro\Descargas\factura.pdf — maxima utilidad, maxima exposicion.</summary>
        Completa,

        /// <summary>%USERPROFILE%\Descargas\factura.pdf — se puede actuar sobre ella sin revelar el usuario.</summary>
        RelativaAlPerfil,

        /// <summary>factura.pdf — solo el nombre. Util para el grafo, inutil para restaurar.</summary>
        SoloNombre
    }

    /// <summary>
    /// Politica de redaccion del vault. Existe por el riesgo L7 del analisis de
    /// viabilidad: la carpeta de reportes acumula nombres de archivos personales,
    /// dominios visitados y hallazgos de brechas, y es un objetivo de mas valor
    /// que buena parte de lo que el antivirus protege.
    /// </summary>
    public sealed class RedactionOptions
    {
        public NivelRuta Rutas { get; set; } = NivelRuta.RelativaAlPerfil;

        /// <summary>usu***plo@correo.cl en vez del correo completo.</summary>
        public bool EnmascararCorreos { get; set; } = true;

        /// <summary>
        /// Si es true (recomendado y por defecto), el writer LANZA una excepcion
        /// cuando un modulo intenta escribir un campo con nombre de secreto.
        /// Es un cortafuegos de diseno: no basta con que los modulos "recuerden"
        /// no escribir contrasenas, la libreria se niega a hacerlo.
        /// </summary>
        public bool RechazarCamposSecretos { get; set; } = true;

        public static RedactionOptions PorDefecto() => new RedactionOptions();

        /// <summary>
        /// Para el equipo de desarrollo, donde ver la ruta completa ahorra horas.
        /// No usar en un equipo con datos reales.
        /// </summary>
        public static RedactionOptions Desarrollo() => new RedactionOptions
        {
            Rutas = NivelRuta.Completa,
            EnmascararCorreos = false,
            RechazarCamposSecretos = true // esto no se relaja nunca
        };
    }
}
