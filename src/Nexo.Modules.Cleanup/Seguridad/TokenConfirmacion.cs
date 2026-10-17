using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Nexo.Modules.Cleanup.Seguridad
{
    /// <summary>
    /// Prueba de que el usuario vio una vista previa concreta y la aprobo.
    ///
    /// No es un simple booleano. El token lleva la huella del contenido EXACTO de
    /// la vista previa: rutas, tamanos y fechas de modificacion. Al ejecutar, el
    /// limpiador recalcula la huella sobre el estado actual del disco y solo borra
    /// lo que coincide.
    ///
    /// Cierra dos agujeros a la vez:
    ///   1. TOCTOU — entre que el usuario mira la lista y pulsa "Limpiar" pueden
    ///      pasar minutos; un archivo pudo cambiar de tamano o reaparecer.
    ///   2. Escalada desde la UI — el servicio corre como LocalSystem y no confia
    ///      en la interfaz (regla de Salida 0). Un proceso que intente pedir el
    ///      borrado de otra lista distinta no tiene un token valido para ella.
    /// </summary>
    public sealed class TokenConfirmacion
    {
        private TokenConfirmacion(string huella, DateTimeOffset emitido, DateTimeOffset expira)
        {
            Huella = huella;
            Emitido = emitido;
            Expira = expira;
        }

        public string Huella { get; }
        public DateTimeOffset Emitido { get; }
        public DateTimeOffset Expira { get; }

        /// <summary>Ventana de validez. Pasado este tiempo hay que volver a previsualizar.</summary>
        public static readonly TimeSpan Vigencia = TimeSpan.FromMinutes(10);

        public static TokenConfirmacion Emitir(IEnumerable<(string Ruta, long Bytes, DateTimeOffset Modificado)> elementos,
                                               DateTimeOffset ahora)
            => new TokenConfirmacion(CalcularHuella(elementos), ahora, ahora + Vigencia);

        public bool EsValidoPara(IEnumerable<(string Ruta, long Bytes, DateTimeOffset Modificado)> elementos,
                                 DateTimeOffset ahora)
            => ahora <= Expira
               && CryptographicOperations.FixedTimeEquals(
                      Encoding.ASCII.GetBytes(Huella),
                      Encoding.ASCII.GetBytes(CalcularHuella(elementos)));

        /// <summary>
        /// La huella incluye tamano y fecha porque una ruta sola no basta: si el
        /// archivo cambio despues de la vista previa, ya no es lo que el usuario
        /// aprobo. El orden se normaliza para que la huella no dependa del orden
        /// en que el escaner recorrio el disco.
        /// </summary>
        private static string CalcularHuella(IEnumerable<(string Ruta, long Bytes, DateTimeOffset Modificado)> elementos)
        {
            var lineas = new List<string>();
            foreach (var e in elementos)
            {
                lineas.Add(string.Create(CultureInfo.InvariantCulture,
                    $"{e.Ruta}|{e.Bytes}|{e.Modificado.UtcTicks}"));
            }
            lineas.Sort(StringComparer.Ordinal);

            using var sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(string.Join("\n", lineas)));
            return Convert.ToHexString(hash);
        }
    }
}
