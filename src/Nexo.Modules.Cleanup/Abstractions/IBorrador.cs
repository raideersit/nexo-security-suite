using System.Collections.Generic;

namespace Nexo.Modules.Cleanup.Abstractions
{
    /// <summary>Que le paso a cada archivo al intentar borrarlo.</summary>
    public sealed class ResultadoBorrado
    {
        public ResultadoBorrado(int eliminados, long bytesLiberados, IReadOnlyList<string> omitidos)
        {
            Eliminados = eliminados;
            BytesLiberados = bytesLiberados;
            Omitidos = omitidos;
        }

        public int Eliminados { get; }
        public long BytesLiberados { get; }

        /// <summary>
        /// Rutas que no se pudieron borrar, con el motivo. En un limpiador de
        /// Windows esto NO es excepcional: los archivos en uso quedan bloqueados
        /// y omitirlos silenciosamente es el comportamiento correcto.
        /// </summary>
        public IReadOnlyList<string> Omitidos { get; }
    }

    /// <summary>
    /// Abstrae el acto de borrar para poder (a) probar sin destruir nada y
    /// (b) elegir entre Papelera y borrado permanente sin tocar el limpiador.
    /// </summary>
    public interface IBorrador
    {
        /// <summary>True si lo borrado se puede recuperar desde la Papelera.</summary>
        bool EsReversible { get; }

        ResultadoBorrado Borrar(IReadOnlyList<(string Ruta, long Bytes)> elementos);
    }
}
