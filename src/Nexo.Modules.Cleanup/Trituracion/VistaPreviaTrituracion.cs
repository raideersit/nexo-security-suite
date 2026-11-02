using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using Nexo.Modules.Cleanup.Abstractions;
using Nexo.Modules.Cleanup.Junk;
using Nexo.Modules.Cleanup.Seguridad;
using Nexo.Reports.Model;

namespace Nexo.Modules.Cleanup.Trituracion
{
    /// <summary>Un archivo que el usuario eligio triturar, ya validado por el guardia.</summary>
    public sealed class ElementoATriturar
    {
        public ElementoATriturar(string ruta, long bytes, DateTimeOffset modificado)
        {
            Ruta = ruta;
            Bytes = bytes;
            Modificado = modificado;
        }

        public string Ruta { get; }
        public long Bytes { get; }
        public DateTimeOffset Modificado { get; }

        public (string Ruta, long Bytes, DateTimeOffset Modificado) Huella => (Ruta, Bytes, Modificado);
    }

    /// <summary>
    /// Lo que el usuario ve ANTES de triturar. El triturado es irreversible por
    /// definicion (ni siquiera la Papelera lo rescata), asi que esta vista previa y
    /// su token son aun mas importantes que en la limpieza de basura.
    /// </summary>
    public sealed class VistaPreviaTrituracion
    {
        internal VistaPreviaTrituracion(
            IReadOnlyList<ElementoATriturar> elementos,
            IReadOnlyList<string> rutasOmitidas,
            IReadOnlyList<string> advertencias,
            MedioDeAlmacenamiento medio,
            TokenConfirmacion token)
        {
            Elementos = elementos;
            RutasOmitidas = rutasOmitidas;
            Advertencias = advertencias;
            Medio = medio;
            Token = token;
        }

        public IReadOnlyList<ElementoATriturar> Elementos { get; }
        public IReadOnlyList<string> RutasOmitidas { get; }

        /// <summary>
        /// Limites reales del triturado, que se muestran SIEMPRE junto a la lista.
        /// No son opcionales: esconderlos seria prometer mas de lo que se cumple.
        /// </summary>
        public IReadOnlyList<string> Advertencias { get; }

        /// <summary>Medio del primer archivo; si hay varios volumenes, se usa el peor caso.</summary>
        public MedioDeAlmacenamiento Medio { get; }

        public TokenConfirmacion Token { get; }

        public int TotalArchivos => Elementos.Count;
        public long TotalBytes => Elementos.Sum(e => e.Bytes);

        public string Describir()
        {
            var sb = new StringBuilder();
            sb.Append("Se van a triturar ").Append(TotalArchivos.ToString(CultureInfo.InvariantCulture))
              .Append(" archivos (").Append(Formato.Bytes(TotalBytes))
              .Append("). Esto NO se puede deshacer, ni siquiera desde la Papelera.\n\n");

            foreach (ElementoATriturar e in Elementos)
                sb.Append("  ").Append(TextoVisible.UnaLinea(e.Ruta)).Append("  (").Append(Formato.Bytes(e.Bytes)).Append(")\n");

            if (Advertencias.Count > 0)
            {
                sb.Append("\nLimites de esta operacion:\n");
                foreach (string a in Advertencias) sb.Append("  - ").Append(a).Append('\n');
            }

            if (RutasOmitidas.Count > 0)
            {
                sb.Append("\nOmitido por el guardia de rutas:\n");
                foreach (string o in RutasOmitidas) sb.Append("  - ").Append(TextoVisible.UnaLinea(o)).Append('\n');
            }
            return sb.ToString();
        }
    }
}
