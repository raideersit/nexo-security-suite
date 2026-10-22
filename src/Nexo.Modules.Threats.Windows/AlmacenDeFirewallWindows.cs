using System;
using System.Collections;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using Nexo.Modules.Threats.Firewall;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>
    /// Firewall de Windows a traves de INetFwPolicy2 (COM, enlace tardio).
    ///
    /// Es codigo administrado, no P/Invoke: por eso vive aqui y no en Nexo.Native
    /// (misma razon que WMI y el registro en Nexo.Modules.Cleanup.Windows). El
    /// enlace tardio (ProgID + dynamic) evita generar y mantener un ensamblado de
    /// interoperabilidad para unas pocas propiedades.
    ///
    /// Leer las reglas no necesita administrador; escribir si. Cuando Windows
    /// niega el acceso (E_ACCESSDENIED) se traduce a UnauthorizedAccessException,
    /// que es lo que espera AdministradorDeFirewall.
    /// </summary>
    public sealed class AlmacenDeFirewallWindows : IAlmacenDeFirewall
    {
        private const string ProgIdPolitica = "HNetCfg.FwPolicy2";
        private const string ProgIdRegla = "HNetCfg.FWRule";

        // NET_FW_RULE_DIRECTION_
        private const int DirEntrante = 1;
        private const int DirSaliente = 2;

        // NET_FW_ACTION_
        private const int AccionBloquear = 0;
        private const int AccionPermitir = 1;

        // NET_FW_PROFILE_TYPE2_ (Todos = 0x7FFFFFFF, se normaliza)
        private const int PerfilDominio = 1;
        private const int PerfilPrivado = 2;
        private const int PerfilPublico = 4;

        private const int ProtocoloCualquiera = 256;

        private const int E_ACCESSDENIED = unchecked((int)0x80070005);

        public IReadOnlyList<ReglaDeFirewall> Enumerar()
        {
            var resultado = new List<ReglaDeFirewall>();
            dynamic politica = Crear(ProgIdPolitica);
            try
            {
                foreach (object o in (IEnumerable)politica.Rules)
                {
                    dynamic r = o;
                    try { resultado.Add(Convertir(r)); }
                    finally { Liberar(o); }
                }
            }
            finally { Liberar(politica); }
            return resultado;
        }

        public void Agregar(ReglaDeFirewall regla)
        {
            dynamic politica = Crear(ProgIdPolitica);
            dynamic nueva = Crear(ProgIdRegla);
            try
            {
                nueva.Name = regla.Nombre;
                nueva.Description = regla.Descripcion ?? "";
                nueva.Grouping = regla.Grupo ?? "";
                if (regla.RutaApp is not null) nueva.ApplicationName = regla.RutaApp;

                // El protocolo va antes que los tipos ICMP: Windows rechaza
                // IcmpTypesAndCodes si el protocolo todavia no es ICMP.
                if (regla.Protocolo is int p) nueva.Protocol = p;
                if (regla.TiposIcmp is not null) nueva.IcmpTypesAndCodes = regla.TiposIcmp;

                nueva.Direction = regla.Direccion == DireccionDeRegla.Entrante ? DirEntrante : DirSaliente;
                nueva.Action = regla.Accion == AccionDeRegla.Bloquear ? AccionBloquear : AccionPermitir;
                nueva.Profiles = (int)regla.Perfiles;
                nueva.Enabled = regla.Habilitada;

                politica.Rules.Add(nueva);
            }
            catch (COMException ex) when (ex.HResult == E_ACCESSDENIED)
            {
                throw new UnauthorizedAccessException("El Firewall de Windows requiere administrador.", ex);
            }
            catch (Exception ex) when (ex is COMException || ex is Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
            {
                throw new InvalidOperationException("No se pudo crear la regla: " + ex.Message, ex);
            }
            finally { Liberar(nueva); Liberar(politica); }
        }

        public void Eliminar(string nombre)
        {
            dynamic politica = Crear(ProgIdPolitica);
            try { politica.Rules.Remove(nombre); }
            catch (COMException ex) when (ex.HResult == E_ACCESSDENIED)
            {
                throw new UnauthorizedAccessException("El Firewall de Windows requiere administrador.", ex);
            }
            catch (COMException ex)
            {
                throw new InvalidOperationException("No se pudo eliminar la regla: " + ex.Message, ex);
            }
            finally { Liberar(politica); }
        }

        public void Habilitar(string nombre, bool habilitada)
        {
            dynamic politica = Crear(ProgIdPolitica);
            try
            {
                dynamic regla = politica.Rules.Item(nombre);
                try { regla.Enabled = habilitada; }
                finally { Liberar(regla); }
            }
            catch (COMException ex) when (ex.HResult == E_ACCESSDENIED)
            {
                throw new UnauthorizedAccessException("El Firewall de Windows requiere administrador.", ex);
            }
            catch (COMException ex)
            {
                throw new InvalidOperationException("No se pudo cambiar la regla: " + ex.Message, ex);
            }
            finally { Liberar(politica); }
        }

        public IReadOnlyList<PoliticaDePerfil> LeerPoliticas()
        {
            var lista = new List<PoliticaDePerfil>();
            object politica = Crear(ProgIdPolitica);
            try
            {
                foreach ((int codigo, PerfilesDeRed perfil) in new[]
                {
                    (PerfilDominio, PerfilesDeRed.Dominio),
                    (PerfilPrivado, PerfilesDeRed.Privado),
                    (PerfilPublico, PerfilesDeRed.Publico)
                })
                {
                    // Propiedades con indice: InvokeMember es mas fiable sobre IDispatch
                    // que la sintaxis dynamic de indexador.
                    bool activo = (bool)Leer(politica, "FirewallEnabled", codigo);
                    int entrada = Convert.ToInt32(Leer(politica, "DefaultInboundAction", codigo));
                    int salida = Convert.ToInt32(Leer(politica, "DefaultOutboundAction", codigo));
                    lista.Add(new PoliticaDePerfil(perfil, activo,
                        entrada == AccionBloquear ? AccionDeRegla.Bloquear : AccionDeRegla.Permitir,
                        salida == AccionBloquear ? AccionDeRegla.Bloquear : AccionDeRegla.Permitir));
                }
            }
            finally { Liberar(politica); }
            return lista;
        }

        // ---------------------------------------------------------------

        private static ReglaDeFirewall Convertir(dynamic r)
        {
            string? ruta = r.ApplicationName as string;
            string? grupo = r.Grouping as string;
            string? desc = r.Description as string;
            int protocolo = (int)r.Protocol;
            string? icmp = r.IcmpTypesAndCodes as string;
            int perfiles = (int)r.Profiles;

            return new ReglaDeFirewall(
                Nombre: (string)r.Name,
                RutaApp: string.IsNullOrEmpty(ruta) ? null : ruta,
                Direccion: (int)r.Direction == DirEntrante ? DireccionDeRegla.Entrante : DireccionDeRegla.Saliente,
                Accion: (int)r.Action == AccionBloquear ? AccionDeRegla.Bloquear : AccionDeRegla.Permitir,
                Perfiles: Normalizar(perfiles),
                Habilitada: (bool)r.Enabled,
                Grupo: string.IsNullOrEmpty(grupo) ? null : grupo,
                Descripcion: string.IsNullOrEmpty(desc) ? null : desc,
                Protocolo: protocolo == ProtocoloCualquiera ? null : protocolo,
                TiposIcmp: string.IsNullOrEmpty(icmp) ? null : icmp);
        }

        /// <summary>0x7FFFFFFF ("todos") y combinaciones se llevan a las tres banderas.</summary>
        private static PerfilesDeRed Normalizar(int perfiles)
        {
            if (perfiles < 0 || perfiles > PerfilDominio + PerfilPrivado + PerfilPublico)
                return PerfilesDeRed.Todos;

            var p = PerfilesDeRed.Ninguno;
            if ((perfiles & PerfilDominio) != 0) p |= PerfilesDeRed.Dominio;
            if ((perfiles & PerfilPrivado) != 0) p |= PerfilesDeRed.Privado;
            if ((perfiles & PerfilPublico) != 0) p |= PerfilesDeRed.Publico;
            return p;
        }

        private static object Leer(object com, string propiedad, int indice)
            => com.GetType().InvokeMember(propiedad, BindingFlags.GetProperty, null, com, new object[] { indice })!;

        private static dynamic Crear(string progId)
        {
            Type tipo = Type.GetTypeFromProgID(progId)
                        ?? throw new PlatformNotSupportedException("No se encontro " + progId + " (¿no es Windows?).");
            return Activator.CreateInstance(tipo)!;
        }

        private static void Liberar(object? com)
        {
            if (com is not null && Marshal.IsComObject(com)) Marshal.ReleaseComObject(com);
        }
    }
}
