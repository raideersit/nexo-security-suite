using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Modules.Identity.Filtraciones
{
    public enum EstadoDeComprobacion
    {
        /// <summary>La contrasena aparece en filtraciones publicas conocidas.</summary>
        Filtrada,

        /// <summary>
        /// El servicio respondio con un listado bien formado y la contrasena no esta. Significa «no aparece en las filtraciones
        /// conocidas», NO «es una buena contrasena».
        /// </summary>
        NoEncontrada,

        /// <summary>No se pudo comprobar (sin red, respuesta rara, vacia, demasiado grande...). NUNCA equivale a NoEncontrada.</summary>
        NoSePudoComprobar
    }

    public sealed record ResultadoDeComprobacion(EstadoDeComprobacion Estado, long Apariciones = 0, string? Motivo = null)
    {
        public static ResultadoDeComprobacion NoSePudo(string motivo) => new(EstadoDeComprobacion.NoSePudoComprobar, 0, motivo);
    }

    /// <summary>Lo que devuelve el servicio de rangos para un prefijo. <see cref="Exito"/> false = no hay respuesta fiable.</summary>
    public sealed record RespuestaDeRango(bool Exito, string? Cuerpo, string? Motivo)
    {
        public static RespuestaDeRango Ok(string cuerpo) => new(true, cuerpo, null);
        public static RespuestaDeRango Fallo(string motivo) => new(false, null, motivo);
    }

    /// <summary>Quien contesta «que sufijos de hash hay con este prefijo». En produccion es HTTP; en las pruebas, un falso.</summary>
    public interface IConsultaDeRangos
    {
        /// <summary>Recibe SOLO los 5 primeros caracteres hexadecimales (mayusculas) del SHA-1. No debe lanzar por fallos de red.</summary>
        Task<RespuestaDeRango> ObtenerAsync(string prefijo, CancellationToken ct);
    }

    /// <summary>
    /// Comprueba si una contrasena aparece en filtraciones publicas con la API de rangos de Pwned Passwords (gratuita, sin
    /// clave ni cuenta), con k-anonimato: se calcula el SHA-1 en el equipo y al servicio solo salen los 5 primeros caracteres
    /// del hash. Ni la contrasena ni el hash completo salen jamas; el servicio devuelve todos los sufijos que comparten ese
    /// prefijo y la comparacion se hace aqui.
    ///
    /// Regla del proyecto: «no pude comprobar» nunca se presenta como «esta bien». Cualquier fallo, respuesta vacia, mal
    /// formada o demasiado grande es <see cref="EstadoDeComprobacion.NoSePudoComprobar"/>.
    /// </summary>
    public sealed class ComprobadorDeContrasenas
    {
        private readonly IConsultaDeRangos _consulta;

        public ComprobadorDeContrasenas(IConsultaDeRangos consulta)
        {
            _consulta = consulta ?? throw new ArgumentNullException(nameof(consulta));
        }

        public async Task<ResultadoDeComprobacion> ComprobarAsync(string contrasena, CancellationToken ct = default)
        {
            if (contrasena is null) throw new ArgumentNullException(nameof(contrasena));
            if (contrasena.Length == 0) return ResultadoDeComprobacion.NoSePudo("la contraseña está vacía");

            string hash = Sha1Hex(contrasena);
            string prefijo = hash.Substring(0, 5), sufijo = hash.Substring(5);

            RespuestaDeRango r;
            try { r = await _consulta.ObtenerAsync(prefijo, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                return ResultadoDeComprobacion.NoSePudo("la consulta falló (" + ex.GetType().Name + ")");
            }

            if (!r.Exito || r.Cuerpo is null) return ResultadoDeComprobacion.NoSePudo(r.Motivo ?? "sin respuesta");
            return Interpretar(r.Cuerpo, sufijo);
        }

        /// <summary>
        /// Lee el listado «SUFIJO:CANTIDAD» por lineas. Las lineas con cantidad 0 son relleno que el servicio anade a proposito
        /// (cabecera Add-Padding) para ocultar cuantos resultados reales hay: no cuentan como aparicion.
        /// </summary>
        internal static ResultadoDeComprobacion Interpretar(string cuerpo, string sufijo)
        {
            long encontrado = -1;
            int validas = 0;
            foreach (string cruda in cuerpo.Split('\n'))
            {
                string linea = cruda.TrimEnd('\r');
                if (linea.Length == 0) continue;
                if (!TryLeerLinea(linea, out string suf, out long cantidad))
                    return encontrado > 0
                        ? new ResultadoDeComprobacion(EstadoDeComprobacion.Filtrada, encontrado)
                        : ResultadoDeComprobacion.NoSePudo("la respuesta no tiene el formato esperado (¿un portal de acceso a Internet?)");
                validas++;
                if (cantidad > 0 && string.Equals(suf, sufijo, StringComparison.OrdinalIgnoreCase)) encontrado = cantidad;
            }

            if (encontrado > 0) return new ResultadoDeComprobacion(EstadoDeComprobacion.Filtrada, encontrado);
            if (validas == 0) return ResultadoDeComprobacion.NoSePudo("la respuesta llegó vacía");
            return new ResultadoDeComprobacion(EstadoDeComprobacion.NoEncontrada);
        }

        private static bool TryLeerLinea(string linea, out string sufijo, out long cantidad)
        {
            sufijo = "";
            cantidad = 0;
            int dos = linea.IndexOf(':');
            if (dos != 35) return false; // el sufijo de un SHA-1 son exactamente 35 caracteres hexadecimales
            for (int i = 0; i < 35; i++)
                if (!Uri.IsHexDigit(linea[i])) return false;
            string num = linea.Substring(36);
            if (num.Length is 0 or > 12) return false;
            foreach (char c in num) if (c is < '0' or > '9') return false;
            sufijo = linea.Substring(0, 35);
            cantidad = long.Parse(num, System.Globalization.CultureInfo.InvariantCulture);
            return true;
        }

        /// <summary>SHA-1 en hexadecimal mayuscula de los bytes UTF-8 de la contrasena tal como se escribio (asi lo calcula Pwned Passwords).</summary>
        internal static string Sha1Hex(string contrasena)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(contrasena);
            try { return Convert.ToHexString(SHA1.HashData(bytes)); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }
}
