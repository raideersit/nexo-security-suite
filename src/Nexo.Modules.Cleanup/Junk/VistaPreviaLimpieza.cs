using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using Nexo.Modules.Cleanup.Seguridad;

namespace Nexo.Modules.Cleanup.Junk
{
    /// <summary>
    /// Lo que el usuario ve ANTES de que se borre nada. Es obligatoria: el
    /// limpiador no expone ningun camino que borre sin haber producido una de
    /// estas y haber recibido de vuelta su token.
    /// </summary>
    public sealed class VistaPreviaLimpieza
    {
        internal VistaPreviaLimpieza(
            IReadOnlyList<ElementoLimpiable> elementos,
            IReadOnlyList<string> rutasOmitidas,
            IReadOnlyList<string> reglasSaltadasPorPermisos,
            TokenConfirmacion token)
        {
            Elementos = elementos;
            RutasOmitidas = rutasOmitidas;
            ReglasSaltadasPorPermisos = reglasSaltadasPorPermisos;
            Token = token;
        }

        public IReadOnlyList<ElementoLimpiable> Elementos { get; }

        /// <summary>Rutas que el guardia rechazo, con el motivo. Se muestran para que nada sea invisible.</summary>
        public IReadOnlyList<string> RutasOmitidas { get; }

        /// <summary>Reglas que necesitaban administrador y no se pudieron evaluar.</summary>
        public IReadOnlyList<string> ReglasSaltadasPorPermisos { get; }

        /// <summary>
        /// El token que hay que devolver a EjecutarAsync. Va aqui dentro a
        /// proposito: es imposible llamar a ejecutar sin haber pasado por la
        /// vista previa.
        /// </summary>
        public TokenConfirmacion Token { get; }

        public int TotalArchivos => Elementos.Count;
        public long TotalBytes => Elementos.Sum(e => e.Bytes);

        public IEnumerable<(string Categoria, int Archivos, long Bytes)> PorCategoria()
            => Elementos
                .GroupBy(e => e.Categoria, StringComparer.Ordinal)
                .Select(g => (Categoria: g.Key, Archivos: g.Count(), Bytes: g.Sum(e => e.Bytes)))
                .OrderByDescending(x => x.Bytes);

        /// <summary>Resumen en texto para la consola o el dialogo de confirmacion.</summary>
        public string Describir(int maxEjemplos = 5)
        {
            var sb = new StringBuilder();
            sb.Append("Se van a borrar ").Append(TotalArchivos.ToString(CultureInfo.InvariantCulture))
              .Append(" archivos y liberar ").Append(Formato.Bytes(TotalBytes)).Append(".\n\n");

            foreach (var (categoria, archivos, bytes) in PorCategoria())
            {
                sb.Append("  ").Append(categoria.PadRight(20))
                  .Append(archivos.ToString(CultureInfo.InvariantCulture).PadLeft(6)).Append(" archivos   ")
                  .Append(Formato.Bytes(bytes).PadLeft(10)).Append('\n');

                foreach (ElementoLimpiable e in Elementos
                             .Where(x => x.Categoria == categoria)
                             .OrderByDescending(x => x.Bytes)
                             .Take(maxEjemplos))
                {
                    sb.Append("      ").Append(e.Ruta).Append("  (").Append(Formato.Bytes(e.Bytes)).Append(")\n");
                }

                int resto = archivos - Math.Min(archivos, maxEjemplos);
                if (resto > 0)
                    sb.Append("      … y ").Append(resto.ToString(CultureInfo.InvariantCulture)).Append(" mas\n");
            }

            if (ReglasSaltadasPorPermisos.Count > 0)
            {
                sb.Append("\nNo evaluado por falta de permisos de administrador:\n");
                foreach (string r in ReglasSaltadasPorPermisos) sb.Append("  - ").Append(r).Append('\n');
            }

            if (RutasOmitidas.Count > 0)
            {
                sb.Append("\nOmitido por el guardia de rutas: ")
                  .Append(RutasOmitidas.Count.ToString(CultureInfo.InvariantCulture)).Append(" rutas\n");
            }

            return sb.ToString();
        }
    }

    internal static class Formato
    {
        public static string Bytes(long bytes)
        {
            string[] u = { "B", "KB", "MB", "GB", "TB" };
            double v = bytes;
            int i = 0;
            while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
            return v.ToString(i == 0 ? "0" : "0.##", CultureInfo.InvariantCulture) + " " + u[i];
        }
    }
}
