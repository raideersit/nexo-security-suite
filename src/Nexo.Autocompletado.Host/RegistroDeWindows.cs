using System;
using Microsoft.Win32;
using Nexo.Modules.Identity.Autocompletado;

namespace Nexo.Autocompletado.Host
{
    /// <summary>
    /// HKCU de verdad (API administrada de .NET, sin P/Invoke). Con <c>raizDePruebas</c>, todo va bajo esa subclave en lugar de las claves que
    /// leen los navegadores: así las pruebas usan el registro real sin tocar Brave ni Edge.
    /// </summary>
    public sealed class RegistroDeWindows : IRegistroDeUsuario
    {
        private readonly string? _raiz;

        public RegistroDeWindows(string? raizDePruebas = null)
        {
            if (raizDePruebas is not null && (raizDePruebas.Length == 0 || !raizDePruebas.StartsWith(@"Software\", StringComparison.OrdinalIgnoreCase)))
                throw new ArgumentException(@"la raíz de pruebas debe estar bajo Software\", nameof(raizDePruebas));
            _raiz = raizDePruebas?.TrimEnd('\\');
        }

        private string Ruta(string subclave) => _raiz is null ? subclave : _raiz + "\\" + subclave;

        public string? LeerValor(string subclave)
        {
            using RegistryKey? k = Registry.CurrentUser.OpenSubKey(Ruta(subclave), writable: false);
            return k?.GetValue("") as string;
        }

        public void EscribirValor(string subclave, string valor)
        {
            using RegistryKey k = Registry.CurrentUser.CreateSubKey(Ruta(subclave), writable: true);
            k.SetValue("", valor, RegistryValueKind.String);
        }

        public bool BorrarClave(string subclave)
        {
            string r = Ruta(subclave);
            using (RegistryKey? k = Registry.CurrentUser.OpenSubKey(r, writable: false))
                if (k is null) return false;
            Registry.CurrentUser.DeleteSubKey(r, throwOnMissingSubKey: false);
            return true;
        }
    }
}
