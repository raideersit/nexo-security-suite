using System;

namespace Nexo.Modules.Cleanup.Junk
{
    /// <summary>Un archivo concreto candidato a borrarse, ya validado por el guardia.</summary>
    public sealed class ElementoLimpiable
    {
        public ElementoLimpiable(string ruta, long bytes, DateTimeOffset modificado, string reglaId, string categoria)
        {
            Ruta = ruta;
            Bytes = bytes;
            Modificado = modificado;
            ReglaId = reglaId;
            Categoria = categoria;
        }

        public string Ruta { get; }
        public long Bytes { get; }
        public DateTimeOffset Modificado { get; }
        public string ReglaId { get; }
        public string Categoria { get; }

        public (string Ruta, long Bytes, DateTimeOffset Modificado) Huella => (Ruta, Bytes, Modificado);
    }
}
