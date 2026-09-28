using System;

namespace Nexo.Reports.Model
{
    /// <summary>
    /// Resultado de escribir una nota. Lo devuelve el writer para que el modulo
    /// pueda, por ejemplo, mostrar la ruta en un toast o enlazar desde otra nota.
    /// </summary>
    public sealed class NoteRef
    {
        public NoteRef(Guid id, string rutaAbsoluta, string nombreNota, bool yaExistia)
        {
            Id = id;
            RutaAbsoluta = rutaAbsoluta;
            NombreNota = nombreNota;
            YaExistia = yaExistia;
        }

        public Guid Id { get; }

        public string RutaAbsoluta { get; }

        /// <summary>Nombre sin extension: es exactamente lo que va dentro de [[ ]].</summary>
        public string NombreNota { get; }

        /// <summary>True si el evento ya estaba escrito (reintento idempotente).</summary>
        public bool YaExistia { get; }

        public string Wikilink => "[[" + NombreNota + "]]";
    }
}
