using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Native.Accounts;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>
    /// Lee de Windows lo que necesita <see cref="AnalizadorDeCuentas"/>: cuentas locales y politica de contrasenas por la API
    /// de red (sin administrador, solo metadatos) e inicio automatico por el registro. Cada parte que no se pueda leer queda
    /// null: «no evaluado», nunca un valor inventado. NO toca la SAM ni lee contrasenas: del inicio automatico solo mira si
    /// existe el valor <c>DefaultPassword</c>, jamas su contenido.
    /// </summary>
    public static class LectorDeCuentasWindows
    {
        private const string Winlogon = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

        public static InstantaneaDeCuentas Leer()
        {
            IReadOnlyList<CuentaLocalNativa>? nativas = CuentasLocales.Enumerar(out _);
            IReadOnlyList<CuentaLocal>? cuentas = nativas?.Select(n => new CuentaLocal(
                n.Nombre, (int)n.Rid,
                Habilitada: !n.Tiene(CuentaLocalNativa.CuentaDeshabilitada),
                ContrasenaNoRequerida: n.Tiene(CuentaLocalNativa.ContrasenaNoRequerida),
                ContrasenaNoExpira: n.Tiene(CuentaLocalNativa.ContrasenaNoExpira),
                Bloqueada: n.Tiene(CuentaLocalNativa.Bloqueada))).ToList();

            PoliticaNativa? p = CuentasLocales.LeerPolitica(out _);
            PoliticaDeContrasenas? politica = p is null ? null : new PoliticaDeContrasenas(
                (int)Math.Min(p.Value.LongitudMinima, int.MaxValue),
                p.Value.EdadMaximaSegundos == PoliticaNativa.ParaSiempre ? null : TimeSpan.FromSeconds(p.Value.EdadMaximaSegundos),
                (int)Math.Min(p.Value.HistorialDeContrasenas, int.MaxValue),
                (int)Math.Min(p.Value.UmbralDeBloqueo, int.MaxValue));

            return new InstantaneaDeCuentas(cuentas, politica, LeerAutologon());
        }

        /// <summary>null si no se pudo leer el registro. Nunca lee el valor de DefaultPassword: solo si existe.</summary>
        public static EstadoDeAutologon? LeerAutologon()
        {
            try
            {
                using RegistryKey? k = Registry.LocalMachine.OpenSubKey(Winlogon, writable: false);
                if (k is null) return null;

                bool activo = string.Equals(Convert.ToString(k.GetValue("AutoAdminLogon")), "1", StringComparison.Ordinal);
                string? usuario = k.GetValue("DefaultUserName") as string;
                bool conClave = k.GetValueNames().Contains("DefaultPassword", StringComparer.OrdinalIgnoreCase);
                return new EstadoDeAutologon(activo, string.IsNullOrWhiteSpace(usuario) ? null : usuario, conClave);
            }
            catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or System.IO.IOException)
            {
                return null;
            }
        }
    }
}
