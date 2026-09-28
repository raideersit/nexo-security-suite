using System;
using Nexo.Reports.Seguridad;

namespace Nexo.Reports.Vault
{
    /// <summary>Configuracion de la libreria. La inyecta Nexo.Service desde appsettings.json.</summary>
    public sealed class VaultOptions
    {
        /// <summary>Raiz del vault. Por defecto %ProgramData%\Nexo\Vault.</summary>
        public string RutaVault { get; set; } = "";

        /// <summary>Nombre del equipo que se estampa en cada nota.</summary>
        public string Equipo { get; set; } = Environment.MachineName;

        /// <summary>
        /// Politica de redaccion. Ver Redactor. Por defecto es la mas estricta que
        /// sigue siendo util: rutas relativas al perfil y correos enmascarados.
        /// </summary>
        public RedactionOptions Redaccion { get; set; } = RedactionOptions.PorDefecto();

        /// <summary>Dias que se conservan las notas de evento. 0 = sin purga. Ver riesgo L7.</summary>
        public int RetencionDias { get; set; } = 90;

        /// <summary>
        /// Si es true, crea el archivo .gitignore y la nota de advertencia de
        /// seguridad al inicializar el vault.
        /// </summary>
        public bool CrearArchivosDeSistema { get; set; } = true;

        /// <summary>Longitud maxima del nombre de archivo, con extension. Margen para MAX_PATH.</summary>
        public int MaxLargoNombreArchivo { get; set; } = 120;
    }
}
