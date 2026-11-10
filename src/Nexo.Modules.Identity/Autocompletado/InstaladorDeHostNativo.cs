using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Nexo.Modules.Identity.Autocompletado
{
    /// <summary>El registro de Windows del usuario (HKCU), reducido a lo que hace falta. Rutas relativas a HKCU.</summary>
    public interface IRegistroDeUsuario
    {
        /// <summary>El valor por omisión de la clave, o null si la clave no existe o no tiene texto.</summary>
        string? LeerValor(string subclave);
        void EscribirValor(string subclave, string valor);
        /// <returns>false si no existía.</returns>
        bool BorrarClave(string subclave);
    }

    /// <summary>Dónde busca cada navegador el host. <c>Subclave</c> es relativa a HKCU.</summary>
    public sealed record NavegadorDeHost(string Nombre, string Subclave);

    public enum SituacionDelHost { Listo, NoRegistrado, ManifiestoNoExiste, ManifiestoIlegible, ProgramaNoExiste, NoAutorizaLaExtension }

    public sealed record EstadoDelHost(NavegadorDeHost Navegador, SituacionDelHost Situacion, string Detalle);

    /// <summary>
    /// Registra el host nativo para los navegadores del usuario, sin administrador (todo en HKCU y en %LOCALAPPDATA%):
    ///  - Brave y Chrome leen <c>HKCU\Software\Google\Chrome\NativeMessagingHosts\…</c> (Brave usa la clave de Chrome en Windows).
    ///  - Edge lee primero <c>HKCU\Software\Microsoft\Edge\NativeMessagingHosts\…</c> (y si no está, la de Chrome).
    /// El valor por omisión de la clave es la ruta del manifiesto JSON, y el manifiesto dice qué programa lanzar y qué extensiones pueden
    /// hablarle (<c>allowed_origins</c>, sin comodines). Desinstalar solo borra claves que apuntan a NUESTRO manifiesto.
    /// </summary>
    public static class InstaladorDeHostNativo
    {
        public const string NombreDelHost = "com.nexo.autocompletado";

        /// <summary>
        /// La clave PÚBLICA de la extensión (va en el <c>"key"</c> de su manifest.json). Fija el ID aunque se cargue «sin empaquetar» desde
        /// cualquier carpeta. La clave privada no se guardó: no hace falta para cargarla ni para publicarla en Edge (la tienda firma).
        /// </summary>
        public const string ClavePublicaDeLaExtension =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv/kt+/gQsfEe4iBoM0D3qEqbkmzS6z3U6gN7IsCdDkaOJ8HbnZdPs1yMTuYXlH7flHhi+P7q3A92dkHzKoJ/wVSOrLTiJQ1Be27hcTUnmihg9QRAiLyYNY6bceRnRAXOHD3kLVwfWIyAKCOjeTnV7bpVH1jPPmQaDEDItBTf3U4y+8TREDDEV1M84TiyMRYdJoI0hr/0oCyCBh84PM1KF0toyibqwFB5BBRaZA7SxIqOcH6e+CZExlQ5k5Rh8fQF7lE6g2lLrqPLseP7WyzSjjZLai8WZ/L4i2x5a6SIh/mj7Y4r+/A2nQbpH29uKeETB7MvAIHiHKOnjiEOIi2uxQIDAQAB";

        /// <summary>El ID que sale de esa clave (se comprueba en las pruebas: si alguien cambia la clave, cambia el ID y lo dice).</summary>
        public const string IdDeLaExtension = "kffjcngenealkjoecfdcliemblgbihpc";

        public static readonly IReadOnlyList<NavegadorDeHost> Navegadores = new[]
        {
            new NavegadorDeHost("Brave y Chrome", @"Software\Google\Chrome\NativeMessagingHosts\" + NombreDelHost),
            new NavegadorDeHost("Edge", @"Software\Microsoft\Edge\NativeMessagingHosts\" + NombreDelHost),
        };

        private static readonly Regex IdValido = new Regex("^[a-p]{32}$", RegexOptions.CultureInvariant);

        /// <summary>El ID de Chromium de una clave pública: SHA-256 del DER, primeros 16 bytes, cada medio byte como una letra a–p.</summary>
        public static string IdDesdeClave(string clavePublicaBase64)
        {
            byte[] h = SHA256.HashData(Convert.FromBase64String(clavePublicaBase64));
            var sb = new StringBuilder(32);
            for (int i = 0; i < 16; i++) { sb.Append((char)('a' + (h[i] >> 4))); sb.Append((char)('a' + (h[i] & 0xF))); }
            return sb.ToString();
        }

        public static string OrigenDe(string id) => "chrome-extension://" + id + "/";

        /// <summary>¿Es <paramref name="origen"/> el de una extensión con un ID bien formado? (El primer argumento con que el navegador lanza el host.)</summary>
        public static bool EsOrigenDeExtension(string? origen)
            => origen is not null && origen.StartsWith("chrome-extension://", StringComparison.Ordinal) && origen.EndsWith('/')
               && IdValido.IsMatch(origen["chrome-extension://".Length..^1]);

        /// <summary>El manifiesto del host. Ruta absoluta obligatoria (más claro que una relativa) e IDs con la forma de Chromium.</summary>
        public static byte[] Manifiesto(string rutaPrograma, IEnumerable<string> idsDeExtension)
        {
            if (!Path.IsPathFullyQualified(rutaPrograma)) throw new ArgumentException("la ruta del programa debe ser absoluta", nameof(rutaPrograma));
            List<string> ids = idsDeExtension.Distinct(StringComparer.Ordinal).ToList();
            if (ids.Count == 0 || ids.Any(i => !IdValido.IsMatch(i))) throw new ArgumentException("ID de extensión no válido", nameof(idsDeExtension));
            var m = new Dictionary<string, object>
            {
                ["name"] = NombreDelHost,
                ["description"] = "Nexo: autocompletado de la bóveda de contraseñas",
                ["path"] = rutaPrograma,
                ["type"] = "stdio",
                ["allowed_origins"] = ids.Select(OrigenDe).ToArray()
            };
            return JsonSerializer.SerializeToUtf8Bytes(m, new JsonSerializerOptions { WriteIndented = true });
        }

        /// <summary>Escribe el manifiesto (de forma atómica) y registra el host en cada navegador. Devuelve los problemas (vacío = todo bien).</summary>
        public static IReadOnlyList<string> Instalar(IRegistroDeUsuario registro, string rutaManifiesto, string rutaPrograma, IEnumerable<string> idsDeExtension)
        {
            if (!Path.IsPathFullyQualified(rutaManifiesto)) throw new ArgumentException("la ruta del manifiesto debe ser absoluta", nameof(rutaManifiesto));
            byte[] json = Manifiesto(rutaPrograma, idsDeExtension);
            var problemas = new List<string>();
            try
            {
                string carpeta = Path.GetDirectoryName(rutaManifiesto)!;
                Directory.CreateDirectory(carpeta);
                string tmp = rutaManifiesto + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp";
                File.WriteAllBytes(tmp, json);
                File.Move(tmp, rutaManifiesto, overwrite: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Sin manifiesto no se registra nada: una clave que apunta a un archivo que no existe solo confunde.
                return new[] { "no se pudo escribir el manifiesto (" + ex.GetType().Name + ")" };
            }
            foreach (NavegadorDeHost n in Navegadores)
            {
                try { registro.EscribirValor(n.Subclave, rutaManifiesto); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
                {
                    problemas.Add(n.Nombre + ": no se pudo registrar (" + ex.GetType().Name + ")");
                }
            }
            return problemas;
        }

        /// <summary>Quita el registro. Una clave que apunta a OTRO manifiesto no se toca (y se dice). Devuelve lo que se hizo y lo que no.</summary>
        public static IReadOnlyList<string> Desinstalar(IRegistroDeUsuario registro, string rutaManifiesto)
        {
            var lineas = new List<string>();
            foreach (NavegadorDeHost n in Navegadores)
            {
                string? valor = registro.LeerValor(n.Subclave);
                if (valor is null) { lineas.Add(n.Nombre + ": no estaba registrado"); continue; }
                if (!MismaRuta(valor, rutaManifiesto)) { lineas.Add(n.Nombre + ": apunta a otro archivo («" + valor + "»), no se toca"); continue; }
                try { registro.BorrarClave(n.Subclave); lineas.Add(n.Nombre + ": quitado"); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
                {
                    lineas.Add(n.Nombre + ": no se pudo quitar (" + ex.GetType().Name + ")");
                }
            }
            try
            {
                if (File.Exists(rutaManifiesto)) { File.Delete(rutaManifiesto); lineas.Add("manifiesto borrado"); }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { lineas.Add("no se pudo borrar el manifiesto (" + ex.GetType().Name + ")"); }
            return lineas;
        }

        /// <summary>Qué ve cada navegador. «Listo» solo si la clave lleva a un manifiesto legible, cuyo programa existe y que autoriza la extensión de Nexo.</summary>
        public static IReadOnlyList<EstadoDelHost> Revisar(IRegistroDeUsuario registro, string idDeExtension = IdDeLaExtension)
        {
            var r = new List<EstadoDelHost>();
            foreach (NavegadorDeHost n in Navegadores)
            {
                string? ruta = registro.LeerValor(n.Subclave);
                if (ruta is null) { r.Add(new(n, SituacionDelHost.NoRegistrado, "no registrado")); continue; }
                if (!File.Exists(ruta)) { r.Add(new(n, SituacionDelHost.ManifiestoNoExiste, "el registro apunta a «" + ruta + "», que no existe")); continue; }
                string? programa;
                string[] origenes;
                try
                {
                    using JsonDocument d = JsonDocument.Parse(File.ReadAllBytes(ruta));
                    JsonElement e = d.RootElement;
                    if (e.ValueKind != JsonValueKind.Object || e.GetProperty("name").GetString() != NombreDelHost || e.GetProperty("type").GetString() != "stdio")
                        throw new InvalidDataException();
                    programa = e.GetProperty("path").GetString();
                    origenes = e.GetProperty("allowed_origins").EnumerateArray().Select(x => x.GetString() ?? "").ToArray();
                }
                catch (Exception ex) when (ex is JsonException or InvalidDataException or KeyNotFoundException or InvalidOperationException or IOException or UnauthorizedAccessException)
                {
                    r.Add(new(n, SituacionDelHost.ManifiestoIlegible, "el manifiesto «" + ruta + "» no se pudo leer o no es de Nexo"));
                    continue;
                }
                if (programa is null || !Path.IsPathFullyQualified(programa) || !File.Exists(programa))
                    r.Add(new(n, SituacionDelHost.ProgramaNoExiste, "el manifiesto apunta a «" + programa + "», que no existe"));
                else if (!origenes.Contains(OrigenDe(idDeExtension), StringComparer.Ordinal))
                    r.Add(new(n, SituacionDelHost.NoAutorizaLaExtension, "el manifiesto no autoriza la extensión de Nexo (" + idDeExtension + ")"));
                else
                    r.Add(new(n, SituacionDelHost.Listo, "listo (" + programa + ")"));
            }
            return r;
        }

        private static bool MismaRuta(string a, string b)
        {
            try { return string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
        }
    }
}
