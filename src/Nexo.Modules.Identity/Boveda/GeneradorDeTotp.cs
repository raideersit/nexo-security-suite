using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Nexo.Modules.Identity.Boveda
{
    /// <summary>La configuracion de un codigo de dos factores: la clave secreta y como se calcula el codigo.</summary>
    public sealed record ConfiguracionTotp(byte[] Secreto, string Algoritmo, int Digitos, int Periodo);

    /// <summary>
    /// Codigos de dos factores por tiempo (TOTP, RFC 6238 sobre HOTP, RFC 4226), todo local: sin red y sin servicios. Acepta la clave
    /// en base32 («JBSWY3DPEHPK3PXP») o el enlace <c>otpauth://totp/...</c> que dan los sitios. Reglas de honestidad: lo que no se
    /// entiende (algoritmo raro, digitos raros, HOTP por contador, clave demasiado corta o no base32) se RECHAZA con su motivo; nunca
    /// se adivina, porque un codigo calculado con otros parametros seria un codigo que no funciona y nadie sabria por que.
    /// </summary>
    public static class GeneradorDeTotp
    {
        public const int MinimoDeBytesDeClave = 10, MaximoDeBytesDeClave = 128, MaximoDeCaracteres = 1000;
        public static readonly string[] Algoritmos = { "SHA1", "SHA256", "SHA512" };

        public static bool TryParsear(string? texto, out ConfiguracionTotp? configuracion, out string? error)
        {
            configuracion = null;
            error = null;
            string t = (texto ?? "").Trim();
            if (t.Length == 0) { error = "Escribe la clave 2FA."; return false; }
            if (t.Length > MaximoDeCaracteres) { error = "La clave 2FA es demasiado larga."; return false; }

            string algoritmo = "SHA1", secreto = t;
            int digitos = 6, periodo = 30;

            if (t.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
            {
                if (!Uri.TryCreate(t, UriKind.Absolute, out Uri? uri) || !string.Equals(uri.Scheme, "otpauth", StringComparison.OrdinalIgnoreCase))
                { error = "El enlace otpauth no es válido."; return false; }
                if (!string.Equals(uri.Host, "totp", StringComparison.OrdinalIgnoreCase))
                { error = "Solo se admiten códigos por tiempo (totp); los de contador (hotp) no."; return false; }

                var q = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (string par in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
                {
                    int i = par.IndexOf('=');
                    if (i <= 0) continue;
                    string k = Uri.UnescapeDataString(par.Substring(0, i)), v = Uri.UnescapeDataString(par.Substring(i + 1).Replace('+', ' '));
                    if (q.ContainsKey(k)) { error = "El enlace repite el parámetro «" + k + "»."; return false; }
                    q[k] = v;
                }
                if (!q.TryGetValue("secret", out string? s) || string.IsNullOrWhiteSpace(s)) { error = "El enlace no trae la clave («secret»)."; return false; }
                secreto = s;
                if (q.TryGetValue("algorithm", out string? a))
                {
                    algoritmo = a.Trim().ToUpperInvariant();
                    if (Array.IndexOf(Algoritmos, algoritmo) < 0) { error = "Algoritmo no admitido («" + a + "»): solo SHA1, SHA256 o SHA512."; return false; }
                }
                if (q.TryGetValue("digits", out string? d))
                {
                    if (!int.TryParse(d, NumberStyles.None, CultureInfo.InvariantCulture, out digitos) || digitos < 6 || digitos > 8) { error = "Número de dígitos no admitido («" + d + "»): de 6 a 8."; return false; }
                }
                if (q.TryGetValue("period", out string? p))
                {
                    if (!int.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out periodo) || periodo < 15 || periodo > 120) { error = "Periodo no admitido («" + p + "»): de 15 a 120 segundos."; return false; }
                }
            }

            byte[]? clave = DecodificarBase32(secreto);
            if (clave is null) { error = "La clave no es base32 válida (solo letras A–Z y dígitos 2–7)."; return false; }
            if (clave.Length < MinimoDeBytesDeClave) { error = "La clave es demasiado corta."; return false; }
            if (clave.Length > MaximoDeBytesDeClave) { error = "La clave es demasiado larga."; return false; }

            configuracion = new ConfiguracionTotp(clave, algoritmo, digitos, periodo);
            return true;
        }

        /// <summary>El codigo de ese instante (TOTP: HOTP con contador = segundos desde 1970 / periodo).</summary>
        public static string Codigo(ConfiguracionTotp c, DateTimeOffset ahora)
        {
            if (c is null) throw new ArgumentNullException(nameof(c));
            long segundos = ahora.ToUnixTimeSeconds();
            if (segundos < 0) throw new ArgumentOutOfRangeException(nameof(ahora), "La fecha es anterior a 1970.");
            return Hotp(c.Secreto, c.Algoritmo, segundos / c.Periodo, c.Digitos);
        }

        /// <summary>Cuantos segundos le quedan al codigo actual (de 1 a periodo).</summary>
        public static int SegundosRestantes(ConfiguracionTotp c, DateTimeOffset ahora)
            => c.Periodo - (int)(ahora.ToUnixTimeSeconds() % c.Periodo);

        /// <summary>HOTP de RFC 4226 con truncado dinamico.</summary>
        public static string Hotp(byte[] secreto, string algoritmo, long contador, int digitos)
        {
            if (secreto is null || secreto.Length == 0) throw new ArgumentException("Falta la clave.", nameof(secreto));
            if (digitos < 6 || digitos > 8) throw new ArgumentOutOfRangeException(nameof(digitos));
            if (contador < 0) throw new ArgumentOutOfRangeException(nameof(contador));

            byte[] mensaje = new byte[8];
            for (int i = 7, c = 0; i >= 0; i--, c += 8) mensaje[i] = (byte)(contador >> c);

            byte[] mac;
            switch (algoritmo)
            {
                case "SHA1": using (var h = new HMACSHA1(secreto)) mac = h.ComputeHash(mensaje); break;
                case "SHA256": using (var h = new HMACSHA256(secreto)) mac = h.ComputeHash(mensaje); break;
                case "SHA512": using (var h = new HMACSHA512(secreto)) mac = h.ComputeHash(mensaje); break;
                default: throw new ArgumentException("Algoritmo no admitido.", nameof(algoritmo));
            }

            int desplazamiento = mac[mac.Length - 1] & 0x0F;
            int binario = ((mac[desplazamiento] & 0x7F) << 24) | (mac[desplazamiento + 1] << 16) | (mac[desplazamiento + 2] << 8) | mac[desplazamiento + 3];
            int modulo = 1;
            for (int i = 0; i < digitos; i++) modulo *= 10;
            CryptographicOperations.ZeroMemory(mac);
            return (binario % modulo).ToString(CultureInfo.InvariantCulture).PadLeft(digitos, '0');
        }

        /// <summary>Base32 de RFC 4648: sin distinguir mayusculas, ignora espacios y guiones, y el relleno «=» solo al final. null si no es valida.</summary>
        public static byte[]? DecodificarBase32(string? texto)
        {
            if (string.IsNullOrWhiteSpace(texto)) return null;
            var limpio = new StringBuilder(texto.Length);
            foreach (char ch in texto)
            {
                if (ch is ' ' or '-' or '\t') continue;
                limpio.Append(char.ToUpperInvariant(ch));
            }
            string s = limpio.ToString().TrimEnd('=');
            if (s.Length == 0 || s.Contains('=')) return null;
            // Un resto de 1, 3 o 6 caracteres no corresponde a ningun numero entero de bytes.
            if (s.Length % 8 is 1 or 3 or 6) return null;

            var salida = new List<byte>(s.Length * 5 / 8);
            int buffer = 0, bits = 0;
            foreach (char ch in s)
            {
                int v = ch >= 'A' && ch <= 'Z' ? ch - 'A' : ch >= '2' && ch <= '7' ? ch - '2' + 26 : -1;
                if (v < 0) return null;
                buffer = (buffer << 5) | v;
                bits += 5;
                if (bits >= 8) { bits -= 8; salida.Add((byte)((buffer >> bits) & 0xFF)); }
            }
            return salida.ToArray();
        }
    }
}
