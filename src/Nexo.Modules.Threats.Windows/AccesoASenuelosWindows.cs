using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using Microsoft.Win32;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Native.Files;

namespace Nexo.Modules.Threats.Windows
{
    /// <summary>
    /// Los señuelos sobre el disco real. Crea con <see cref="FileMode.CreateNew"/> (nunca sobrescribe), los deja ocultos (si
    /// se pide) y guarda su número de archivo de NTFS para encontrarlos si alguien los renombra. No necesita administrador.
    ///
    /// Ocultos o no (hallazgo real, §2am): Windows NIEGA reescribir un archivo oculto con CREATE_ALWAYS (lo que hace
    /// File.WriteAllBytes) si no se piden los mismos atributos. Un programa de cifrado que reescriba así fallaría con el
    /// señuelo oculto y no lo tocaría: no saltaría. Abrir y escribir encima, renombrar o borrar sí funcionan. Por omisión
    /// se ocultan igualmente (un archivo raro visible en el Escritorio estorba y acaba borrado: falsas alarmas).
    /// </summary>
    public sealed class AccesoASenuelosWindows : IAccesoASenuelos
    {
        private readonly bool _ocultos;

        public AccesoASenuelosWindows(bool ocultos = true) => _ocultos = ocultos;

        /// <summary>Un señuelo es pequeño: algo mucho mayor ya es «otro contenido» sin necesidad de leerlo entero.</summary>
        private const long MaxBytesALeer = 16L * 1024 * 1024;
        private const int ErrorArchivoExiste = 80, ErrorYaExiste = 183;

        public bool CarpetaExiste(string carpeta) => Directory.Exists(carpeta);

        public bool Existe(string ruta) => File.Exists(ruta) || Directory.Exists(ruta);

        public CreacionDeSenuelo Crear(string ruta, byte[] contenido)
        {
            ulong? id;
            int error;
            try
            {
                using (var fs = new FileStream(ruta, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    fs.Write(contenido, 0, contenido.Length);
                    fs.Flush(flushToDisk: true);
                    id = NumeroDeArchivo.De(fs.SafeFileHandle, out error);
                }
            }
            catch (IOException ex) when ((ex.HResult & 0xFFFF) is ErrorArchivoExiste or ErrorYaExiste)
            {
                return new CreacionDeSenuelo(EstadoDeCreacion.Ocupado);
            }
            catch (UnauthorizedAccessException)
            {
                return new CreacionDeSenuelo(EstadoDeCreacion.Fallo, Motivo:
                    "Windows no deja escribir en esa carpeta (si las carpetas protegidas de Defender están activadas, hay que permitir a Nexo)");
            }
            catch (Exception ex) when (ex is IOException || ex is NotSupportedException || ex is ArgumentException)
            {
                return new CreacionDeSenuelo(EstadoDeCreacion.Fallo, Motivo: ex.GetType().Name + ": " + ex.Message);
            }

            // Oculto para no estorbar. Si no se puede, el señuelo vale igual (solo se ve).
            if (_ocultos)
            {
                try { File.SetAttributes(ruta, File.GetAttributes(ruta) | FileAttributes.Hidden); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
            }

            return new CreacionDeSenuelo(EstadoDeCreacion.Creado, id,
                id is null ? "no se pudo leer su número de archivo (" + NumeroDeArchivo.Describir(error) + "): si se renombra, no se sabrá a dónde" : null);
        }

        public LecturaDeSenuelo Leer(string ruta)
        {
            try
            {
                using var fs = new FileStream(ruta, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                ulong? id = NumeroDeArchivo.De(fs.SafeFileHandle, out _);
                long largo = fs.Length;
                if (largo > MaxBytesALeer) return new LecturaDeSenuelo(EstadoDeLectura.Leido, largo, null, id);
                string sha = Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
                return new LecturaDeSenuelo(EstadoDeLectura.Leido, largo, sha, id);
            }
            catch (FileNotFoundException) { return LecturaDeSenuelo.NoExiste; }
            catch (DirectoryNotFoundException) { return LecturaDeSenuelo.NoExiste; }
            catch (UnauthorizedAccessException ex)
            {
                // También es lo que da una CARPETA con ese nombre: no es el señuelo, pero tampoco se puede decir que esté intacto.
                return LecturaDeSenuelo.NoLeido("sin permiso para leerlo (" + ex.GetType().Name + ")");
            }
            catch (IOException ex)
            {
                return LecturaDeSenuelo.NoLeido("otro programa lo tiene abierto o bloqueado (" + ex.GetType().Name + ")");
            }
        }

        public BusquedaPorId BuscarPorId(string carpeta, ulong id)
        {
            string? raiz = Path.GetPathRoot(carpeta);
            if (string.IsNullOrEmpty(raiz)) return new BusquedaPorId(EstadoDeBusqueda.NoSePudo, Motivo: "ruta sin unidad");
            string? ruta = NumeroDeArchivo.RutaPorNumero(raiz, id, out int error);
            if (ruta is not null) return new BusquedaPorId(EstadoDeBusqueda.Encontrado, ruta);
            return error == 0
                ? new BusquedaPorId(EstadoDeBusqueda.NoExiste)
                : new BusquedaPorId(EstadoDeBusqueda.NoSePudo, Motivo: NumeroDeArchivo.Describir(error));
        }
    }

    /// <summary>
    /// Los perfiles de usuario reales del equipo (ProfileList, SID S-1-5-21-…) y, si están abiertos, sus carpetas del shell
    /// (Documentos, Escritorio, Imágenes pueden estar movidas). Solo lectura del registro.
    /// </summary>
    public static class LectorDePerfilesWindows
    {
        private const string ListaDePerfiles = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
        private const string CarpetasDelShell = @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";

        public static IReadOnlyList<PerfilParaSenuelos> Leer(out IReadOnlyList<string> problemas)
        {
            var perfiles = new List<PerfilParaSenuelos>();
            var mal = new List<string>();
            try
            {
                using RegistryKey? lista = Registry.LocalMachine.OpenSubKey(ListaDePerfiles, writable: false);
                if (lista is null) { problemas = new[] { "no se encontró la lista de perfiles del equipo" }; return perfiles; }

                foreach (string sid in lista.GetSubKeyNames().Where(s => s.StartsWith("S-1-5-21-", StringComparison.Ordinal) && !s.EndsWith(".bak", StringComparison.OrdinalIgnoreCase)))
                {
                    using RegistryKey? k = lista.OpenSubKey(sid, writable: false);
                    if (k?.GetValue("ProfileImagePath") is not string carpeta || carpeta.Length == 0) { mal.Add("perfil " + sid + " sin carpeta"); continue; }
                    carpeta = Environment.ExpandEnvironmentVariables(carpeta);
                    perfiles.Add(new PerfilParaSenuelos(sid, carpeta, LeerShell(sid)));
                }
            }
            catch (Exception ex) when (ex is SecurityException || ex is UnauthorizedAccessException || ex is IOException)
            {
                mal.Add("no se pudo leer la lista de perfiles (" + ex.GetType().Name + ")");
            }
            problemas = mal;
            return perfiles;
        }

        /// <summary>null si el perfil no está abierto (o no se puede leer: otro usuario sin ser SYSTEM).</summary>
        private static IReadOnlyDictionary<string, string>? LeerShell(string sid)
        {
            try
            {
                using RegistryKey? k = Registry.Users.OpenSubKey(sid + "\\" + CarpetasDelShell, writable: false);
                if (k is null) return null;
                var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach ((string clave, _) in CarpetasParaSenuelos.Carpetas)
                    if (k.GetValue(clave, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string v) d[clave] = v;
                return d;
            }
            catch (Exception ex) when (ex is SecurityException || ex is UnauthorizedAccessException || ex is IOException)
            {
                return null;
            }
        }
    }
}
