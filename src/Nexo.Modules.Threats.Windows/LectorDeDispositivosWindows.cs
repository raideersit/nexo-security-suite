using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using Microsoft.Win32;
using Nexo.Modules.Threats.Vulnerabilidades;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>
    /// Lee, SOLO LECTURA, el registro de uso de la camara y el microfono que Windows lleva en
    /// <c>HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore</c>. Es por usuario: debe correr con el usuario
    /// (la ventana), no como SYSTEM (que veria su propio perfil). No cambia ningun permiso. Una clave o valor que no se puede leer se
    /// cuenta como «ilegible»; un almacen que no existe es «sin almacen», nunca «nadie lo uso».
    /// </summary>
    public static class LectorDeDispositivosWindows
    {
        private const string Almacen = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";
        private static readonly string[] Dispositivos = { "webcam", "microphone" };

        public static InstantaneaDeDispositivos Leer()
        {
            try
            {
                using RegistryKey? raiz = Registry.CurrentUser.OpenSubKey(Almacen);
                if (raiz is null) return new InstantaneaDeDispositivos(EstadoDeLecturaDispositivos.SinAlmacen, null, null, Array.Empty<RegistroDeDispositivo>(), 0);

                var registros = new List<RegistroDeDispositivo>();
                int ilegibles = 0;
                string? camara = null, microfono = null;

                foreach (string disp in Dispositivos)
                {
                    using RegistryKey? k = raiz.OpenSubKey(disp);
                    if (k is null) continue;
                    string? global = Combinar(Texto(k), TextoDeMaquina(disp));
                    if (disp == "webcam") camara = global; else microfono = global;

                    foreach (string nombre in k.GetSubKeyNames())
                    {
                        if (string.Equals(nombre, "NonPackaged", StringComparison.OrdinalIgnoreCase))
                        {
                            using RegistryKey? np = k.OpenSubKey(nombre);
                            if (np is null) { ilegibles++; continue; }
                            foreach (string programa in np.GetSubKeyNames()) LeerFila(np, programa, disp, empaquetada: false, registros, ref ilegibles);
                        }
                        else LeerFila(k, nombre, disp, empaquetada: true, registros, ref ilegibles);
                    }
                }
                return new InstantaneaDeDispositivos(EstadoDeLecturaDispositivos.Correcta, camara, microfono, registros, ilegibles);
            }
            catch (Exception e) when (e is SecurityException or UnauthorizedAccessException or IOException or ObjectDisposedException)
            {
                return new InstantaneaDeDispositivos(EstadoDeLecturaDispositivos.Error, null, null, Array.Empty<RegistroDeDispositivo>(), 0);
            }
        }

        private static void LeerFila(RegistryKey padre, string nombre, string disp, bool empaquetada, List<RegistroDeDispositivo> registros, ref int ilegibles)
        {
            try
            {
                using RegistryKey? f = padre.OpenSubKey(nombre);
                if (f is null) { ilegibles++; return; }
                registros.Add(new RegistroDeDispositivo(disp, nombre, empaquetada, Texto(f), Numero(f, "LastUsedTimeStart"), Numero(f, "LastUsedTimeStop")));
            }
            catch (Exception e) when (e is SecurityException or UnauthorizedAccessException or IOException)
            {
                ilegibles++;
            }
        }

        private static string? Texto(RegistryKey k) => k.GetValue("Value") as string;

        /// <summary>QWORD (long). Si no es un numero, es «sin dato»: no se inventa una fecha.</summary>
        private static long? Numero(RegistryKey k, string nombre) => k.GetValue(nombre) is long n ? n : null;

        private static string? TextoDeMaquina(string disp)
        {
            try
            {
                using RegistryKey? m = Registry.LocalMachine.OpenSubKey(Almacen + "\\" + disp);
                return m?.GetValue("Value") as string;
            }
            catch (Exception e) when (e is SecurityException or UnauthorizedAccessException or IOException) { return null; }
        }

        /// <summary>El permiso global: si el equipo (HKLM) o el usuario (HKCU) lo tiene en «Deny», esta apagado; si no, lo del usuario.</summary>
        private static string? Combinar(string? usuario, string? maquina)
            => string.Equals(maquina, "Deny", StringComparison.OrdinalIgnoreCase) ? "Deny" : usuario ?? maquina;
    }
}
