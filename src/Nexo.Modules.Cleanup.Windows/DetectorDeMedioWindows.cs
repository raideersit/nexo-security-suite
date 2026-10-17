using System.IO;
using System.Runtime.Versioning;
using Nexo.Modules.Cleanup.Abstractions;
using Nexo.Native.Storage;

namespace Nexo.Modules.Cleanup.Windows
{
    /// <summary>
    /// Decide si una ruta esta en un SSD o en un disco magnetico preguntandole a
    /// Windows. Si no hay forma de saberlo, responde Desconocido y el triturador
    /// actua como si fuera SSD: la advertencia se muestra de mas, nunca de menos.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class DetectorDeMedioWindows : IDetectorDeMedio
    {
        public MedioDeAlmacenamiento Detectar(string ruta)
        {
            string? raiz = Path.GetPathRoot(ruta);

            // Solo unidades con letra. Una ruta UNC (\\servidor\share) es red:
            // no hay disco local que consultar.
            if (string.IsNullOrEmpty(raiz) || raiz.Length < 2 || raiz[1] != ':')
                return MedioDeAlmacenamiento.Desconocido;

            bool? magnetico = StorageQuery.IncurreEnPenalizacionDeBusqueda(raiz[0]);
            if (magnetico is null) return MedioDeAlmacenamiento.Desconocido;
            return magnetico.Value ? MedioDeAlmacenamiento.Hdd : MedioDeAlmacenamiento.Ssd;
        }
    }
}
