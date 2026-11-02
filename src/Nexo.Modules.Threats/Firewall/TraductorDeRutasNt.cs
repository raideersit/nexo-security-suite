using System;
using System.Collections.Generic;
using System.Linq;

namespace Nexo.Modules.Threats.Firewall
{
    /// <summary>
    /// Convierte rutas de dispositivo del kernel (<c>\device\harddiskvolume3\apps\x.exe</c>, como las escribe el
    /// evento 5157) en rutas de Win32 (<c>C:\apps\x.exe</c>). Es portable: recibe la tabla letra -> dispositivo
    /// (en Windows sale de QueryDosDevice) y solo transforma texto, no toca el disco.
    ///
    /// Si una ruta no corresponde a ninguna unidad conocida se devuelve TAL CUAL: una ruta de dispositivo es fea
    /// pero cierta; adivinar la letra seria inventar. La tabla es la del momento de leer: un USB que ya no esta
    /// conectado no se traduce.
    /// </summary>
    public sealed class TraductorDeRutasNt
    {
        private const string PrefijoDispositivo = @"\Device\";

        // Los recursos de red (UNC) llegan por el redirector multiple: \device\mup\servidor\recurso\...
        private const string PrefijoRed = @"\Device\Mup\";

        // Dispositivo -> letra ("C:"), ordenado de mayor a menor longitud para que gane el prefijo mas largo.
        private readonly List<KeyValuePair<string, string>> _unidades;

        /// <param name="unidades">
        /// Letra de unidad ("C:") -> dispositivo ("\Device\HarddiskVolume3"). Se ignoran las entradas que no tienen
        /// esa forma: una unidad de red mapeada o un <c>subst</c> no apuntan a un \Device\ de un solo componente.
        /// Si dos letras apuntan al mismo dispositivo gana la primera en orden alfabetico.
        /// </param>
        public TraductorDeRutasNt(IEnumerable<KeyValuePair<string, string>> unidades)
        {
            var porDispositivo = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (letra, dispositivo) in unidades.OrderBy(u => u.Key, StringComparer.OrdinalIgnoreCase))
            {
                if (!EsLetraDeUnidad(letra) || !EsDispositivoSimple(dispositivo)) continue;
                porDispositivo.TryAdd(dispositivo, char.ToUpperInvariant(letra[0]) + ":");
            }
            _unidades = porDispositivo.OrderByDescending(u => u.Key.Length).ToList();
        }

        /// <summary>Sin unidades: solo traduce las rutas de red.</summary>
        public static TraductorDeRutasNt Vacio { get; } = new(Array.Empty<KeyValuePair<string, string>>());

        public int Unidades => _unidades.Count;

        /// <summary>La ruta en forma Win32, o la original si no se sabe traducir.</summary>
        public string Traducir(string ruta) => TryTraducir(ruta, out string t) ? t : ruta;

        public bool TryTraducir(string ruta, out string traducida)
        {
            traducida = ruta;
            if (string.IsNullOrEmpty(ruta) || !ruta.StartsWith(PrefijoDispositivo, StringComparison.OrdinalIgnoreCase))
                return false;

            if (ruta.StartsWith(PrefijoRed, StringComparison.OrdinalIgnoreCase))
            {
                // Hace falta al menos un servidor y un recurso, o el resultado no seria una ruta UNC valida.
                string resto = ruta[PrefijoRed.Length..];
                int barra = resto.IndexOf('\\');
                if (barra <= 0 || barra == resto.Length - 1) return false;
                traducida = @"\\" + resto;
                return true;
            }

            foreach (var (dispositivo, letra) in _unidades)
            {
                if (!ruta.StartsWith(dispositivo, StringComparison.OrdinalIgnoreCase)) continue;
                // El limite debe ser una barra o el final: \device\harddiskvolume3 NO es prefijo de ...volume30.
                if (ruta.Length == dispositivo.Length) { traducida = letra + @"\"; return true; }
                if (ruta[dispositivo.Length] != '\\') continue;
                traducida = letra + ruta[dispositivo.Length..];
                return true;
            }
            return false;
        }

        private static bool EsLetraDeUnidad(string? s)
            => s is { Length: 2 } && s[1] == ':' && char.IsAsciiLetter(s[0]);

        /// <summary>"\Device\Nombre", un solo componente, sin barra final ni caracteres de control.</summary>
        private static bool EsDispositivoSimple(string? s)
        {
            if (s is null || s.Length <= PrefijoDispositivo.Length
                || !s.StartsWith(PrefijoDispositivo, StringComparison.OrdinalIgnoreCase))
                return false;
            foreach (char c in s.AsSpan(PrefijoDispositivo.Length))
                if (c == '\\' || char.IsControl(c)) return false;
            return true;
        }
    }
}
