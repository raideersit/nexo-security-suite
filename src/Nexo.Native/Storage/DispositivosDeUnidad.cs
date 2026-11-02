using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace Nexo.Native.Storage
{
    /// <summary>
    /// A que dispositivo del kernel apunta cada letra de unidad ("C:" -> "\Device\HarddiskVolume3"). Es lo que
    /// hace falta para leer las rutas que escribe el registro de Seguridad (evento 5157). No necesita
    /// administrador.
    /// </summary>
    public static class DispositivosDeUnidad
    {
        private const int Capacidad = 1024;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint QueryDosDeviceW(string lpDeviceName, char[] lpTargetPath, uint ucchMax);

        /// <summary>
        /// Letra -> dispositivo de las unidades presentes ahora mismo. Una letra que no se pudo consultar no
        /// aparece (no se inventa su dispositivo).
        /// </summary>
        public static IReadOnlyDictionary<string, string> Leer()
        {
            var tabla = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string[] raices;
            try { raices = Directory.GetLogicalDrives(); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return tabla; }

            foreach (string raiz in raices)
            {
                if (raiz.Length < 2 || raiz[1] != ':') continue;
                string letra = raiz[..2];
                if (Consultar(letra) is { } dispositivo) tabla[letra] = dispositivo;
            }
            return tabla;
        }

        /// <summary>El dispositivo actual de "C:", o null si no se pudo averiguar.</summary>
        public static string? Consultar(string letra)
        {
            var buffer = new char[Capacidad];
            uint n;
            try { n = QueryDosDeviceW(letra, buffer, (uint)buffer.Length); }
            catch (Exception e) when (e is EntryPointNotFoundException or DllNotFoundException) { return null; }
            if (n == 0) return null;

            // Devuelve una lista de cadenas terminadas en NUL; la primera es la asignacion vigente.
            int fin = Array.IndexOf(buffer, '\0', 0, (int)Math.Min(n, (uint)buffer.Length));
            string destino = fin < 0 ? new string(buffer, 0, (int)Math.Min(n, (uint)buffer.Length)) : new string(buffer, 0, fin);
            return destino.Length == 0 ? null : destino;
        }
    }
}
