using System;
using System.Globalization;
using System.IO;
using System.Text;
using Nexo.Reports.Model;
using Nexo.Reports.Seguridad;

namespace Nexo.Reports.Vault
{
    /// <summary>
    /// Crea, una sola vez, la nota de cada entidad (archivo, proceso, disco...).
    ///
    /// Por que existen estas notas: Obsidian dibuja en el grafo incluso los
    /// enlaces sin destino, pero un nodo sin nota no se puede abrir ni anotar.
    /// Al materializarlas, abrir "Archivo - factura.pdf" muestra en el panel de
    /// vinculos entrantes TODOS los eventos que tocaron ese archivo, de cualquier
    /// modulo y de cualquier fecha. Ese es el valor real del vault frente a un log.
    /// </summary>
    internal sealed class EntityNoteWriter
    {
        private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        private readonly VaultLayout _layout;
        private readonly Redactor _redactor;
        private readonly int _maxNombre;

        public EntityNoteWriter(VaultLayout layout, Redactor redactor, int maxNombre)
        {
            _layout = layout;
            _redactor = redactor;
            _maxNombre = maxNombre;
        }

        /// <summary>Devuelve el nombre de nota (lo que va dentro de [[ ]]) y la crea si falta.</summary>
        public string AsegurarNota(EntidadRef entidad, DateTimeOffset primeraVez)
        {
            string prefijo = VaultLayout.PrefijoDeEntidad(entidad.Tipo);
            string nombreSaneado = NoteNaming.Sanear(entidad.Nombre, _maxNombre - prefijo.Length - 8);
            string nombreNota = prefijo + " - " + nombreSaneado;

            string carpeta = _layout.CarpetaDeEntidad(entidad.Tipo);
            string ruta = Path.Combine(carpeta, nombreNota + ".md");

            // Si ya existe no se toca: puede tener anotaciones escritas a mano por
            // el usuario, y sobrescribirlas seria destruir trabajo suyo.
            if (File.Exists(ruta)) return nombreNota;

            var sb = new StringBuilder();
            sb.Append("---\n");
            YamlWriter.EscribirCampo(sb, "tipo", "entidad");
            YamlWriter.EscribirCampo(sb, "entidad", entidad.Tipo.ToString().ToLowerInvariant());
            YamlWriter.EscribirCampo(sb, "nombre", entidad.Nombre);
            if (!string.IsNullOrWhiteSpace(entidad.Detalle))
            {
                object detalle = entidad.Tipo == TipoEntidad.Archivo
                    ? _redactor.Ruta(entidad.Detalle)
                    : _redactor.TextoLibre(entidad.Detalle, 200);
                YamlWriter.EscribirCampo(sb, "detalle", detalle);
            }
            YamlWriter.EscribirCampo(sb, "primera_vez", primeraVez);
            YamlWriter.EscribirCampo(sb, "tags", new[]
            {
                "nexo/entidad",
                "nexo/entidad/" + Etiqueta(entidad.Tipo)
            });
            sb.Append("---\n\n");

            sb.Append("# ").Append(nombreNota).Append("\n\n");
            sb.Append("> [!info] Nota de entidad\n");
            sb.Append("> Generada automaticamente por Nexo el ")
              .Append(primeraVez.ToString("yyyy-MM-dd HH:mm", Inv)).Append(".\n");
            sb.Append("> Todos los eventos que mencionan esta entidad aparecen en **Vinculos a esta nota**,\n");
            sb.Append("> en el panel derecho de Obsidian. Puedes escribir aqui abajo con confianza:\n");
            sb.Append("> Nexo no vuelve a tocar este archivo.\n\n");
            sb.Append("## Notas\n\n");

            AtomicFile.EscribirTexto(ruta, sb.ToString());
            return nombreNota;
        }

        private static string Etiqueta(TipoEntidad tipo) => tipo switch
        {
            TipoEntidad.Archivo => "archivo",
            TipoEntidad.Proceso => "proceso",
            TipoEntidad.Aplicacion => "aplicacion",
            TipoEntidad.Dispositivo => "dispositivo",
            TipoEntidad.Dominio => "dominio",
            TipoEntidad.Cuenta => "cuenta",
            _ => "otra"
        };
    }
}
