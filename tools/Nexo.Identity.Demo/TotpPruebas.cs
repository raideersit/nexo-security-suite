using System;
using System.Linq;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Nexo.Modules.Identity.Boveda;

namespace Nexo.Identity.Demo
{
    internal static partial class Program
    {
        private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

        public static void ProbarTotp()
        {
            Console.WriteLine("Códigos 2FA (TOTP): vectores oficiales de los RFC");

            // RFC 4226, apendice D: HOTP con la clave «12345678901234567890», 6 digitos, contadores 0 a 9.
            string[] hotp = { "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489" };
            for (int i = 0; i < hotp.Length; i++)
                Check(GeneradorDeTotp.Hotp(Ascii("12345678901234567890"), "SHA1", i, 6) == hotp[i], "RFC 4226: HOTP con contador " + i + " = " + hotp[i]);

            // RFC 6238, apendice B (8 digitos, periodo 30). Cada algoritmo con su clave de la longitud del hash.
            string k1 = "12345678901234567890", k256 = "12345678901234567890123456789012", k512 = "1234567890123456789012345678901234567890123456789012345678901234";
            (long T, string Sha1, string Sha256, string Sha512)[] vectores =
            {
                (59, "94287082", "46119246", "90693936"),
                (1111111109, "07081804", "68084774", "25091201"),
                (1111111111, "14050471", "67062674", "99943326"),
                (1234567890, "89005924", "91819424", "93441116"),
                (2000000000, "69279037", "90698825", "38618901"),
                (20000000000, "65353130", "77737706", "47863826")
            };
            foreach (var v in vectores)
            {
                var d = DateTimeOffset.FromUnixTimeSeconds(v.T);
                Check(GeneradorDeTotp.Codigo(new ConfiguracionTotp(Ascii(k1), "SHA1", 8, 30), d) == v.Sha1, "RFC 6238 SHA1 en t=" + v.T + ": " + v.Sha1);
                Check(GeneradorDeTotp.Codigo(new ConfiguracionTotp(Ascii(k256), "SHA256", 8, 30), d) == v.Sha256, "RFC 6238 SHA256 en t=" + v.T + ": " + v.Sha256);
                Check(GeneradorDeTotp.Codigo(new ConfiguracionTotp(Ascii(k512), "SHA512", 8, 30), d) == v.Sha512, "RFC 6238 SHA512 en t=" + v.T + ": " + v.Sha512);
            }

            // Ventanas: el codigo cambia justo en el limite del periodo.
            var cfg = new ConfiguracionTotp(Ascii(k1), "SHA1", 6, 30);
            var t0 = DateTimeOffset.FromUnixTimeSeconds(1_700_000_010); // 1_700_000_010 % 30 == 0
            Check(GeneradorDeTotp.Codigo(cfg, t0) == GeneradorDeTotp.Codigo(cfg, t0.AddSeconds(29)), "el mismo codigo dura los 30 s del periodo");
            Check(GeneradorDeTotp.Codigo(cfg, t0) != GeneradorDeTotp.Codigo(cfg, t0.AddSeconds(30)), "y cambia al empezar el siguiente");
            Check(GeneradorDeTotp.SegundosRestantes(cfg, t0) == 30 && GeneradorDeTotp.SegundosRestantes(cfg, t0.AddSeconds(29)) == 1 && GeneradorDeTotp.SegundosRestantes(cfg, t0.AddSeconds(10)) == 20, "los segundos restantes van de 30 a 1");
            Check(GeneradorDeTotp.Codigo(cfg, t0).Length == 6 && GeneradorDeTotp.Codigo(new ConfiguracionTotp(Ascii(k1), "SHA1", 7, 30), t0).Length == 7, "el codigo tiene los digitos pedidos (con ceros a la izquierda)");
            var c60 = new ConfiguracionTotp(Ascii(k1), "SHA1", 6, 60);
            var t60 = DateTimeOffset.FromUnixTimeSeconds(1_700_000_040); // 1_700_000_040 % 60 == 0
            Check(GeneradorDeTotp.Codigo(c60, t60) == GeneradorDeTotp.Codigo(c60, t60.AddSeconds(59)) && GeneradorDeTotp.Codigo(c60, t60) != GeneradorDeTotp.Codigo(c60, t60.AddSeconds(60)), "con periodo de 60 s el codigo dura 60 s y cambia en el 61");

            Console.WriteLine("Códigos 2FA (TOTP): leer la clave");
            // Base32 de RFC 4648 (vectores del apendice 10).
            Check(Encoding.ASCII.GetString(GeneradorDeTotp.DecodificarBase32("MZXW6YTBOI======")!) == "foobar", "base32 «MZXW6YTBOI======» = «foobar» (RFC 4648)");
            Check(Encoding.ASCII.GetString(GeneradorDeTotp.DecodificarBase32("mzxw6ytboi")!) == "foobar", "sin relleno y en minusculas tambien");
            Check(Encoding.ASCII.GetString(GeneradorDeTotp.DecodificarBase32("MZXW 6YTB-OI")!) == "foobar", "ignora espacios y guiones (como los muestran los sitios)");
            Check(Encoding.ASCII.GetString(GeneradorDeTotp.DecodificarBase32("MZXQ====")!) == "fo", "«MZXQ====» = «fo»");
            foreach (string mala in new[] { "", "  ", "MZXW6YT1", "MZXW6YT!", "M", "MZX", "MZXW6Y", "MZ=XW6YTBOI", "====", "añadido" })
                Check(GeneradorDeTotp.DecodificarBase32(mala) is null, "base32 no valida, se rechaza: «" + mala + "»");

            bool Ok(string? t, out ConfiguracionTotp? c, out string? e) => GeneradorDeTotp.TryParsear(t, out c, out e);
            Check(Ok("JBSWY3DPEHPK3PXP", out ConfiguracionTotp? c1, out _) && c1!.Algoritmo == "SHA1" && c1.Digitos == 6 && c1.Periodo == 30 && c1.Secreto.Length == 10, "una clave base32 sola: SHA1, 6 digitos, 30 s");
            Check(Ok("jbsw y3dp ehpk 3pxp", out ConfiguracionTotp? c2, out _) && c2!.Secreto.SequenceEqual(c1.Secreto), "con espacios y minusculas da la misma clave");
            Check(Ok("otpauth://totp/Banco:ana@ejemplo.cl?secret=JBSWY3DPEHPK3PXP&issuer=Banco", out ConfiguracionTotp? c3, out _) && c3!.Secreto.SequenceEqual(c1.Secreto) && c3.Digitos == 6, "un enlace otpauth: toma la clave (el nombre y el emisor no importan)");
            Check(Ok("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60", out ConfiguracionTotp? c4, out _) && c4!.Algoritmo == "SHA256" && c4.Digitos == 8 && c4.Periodo == 60, "con algoritmo, digitos y periodo propios");
            Check(Ok("otpauth://totp/x?SECRET=JBSWY3DPEHPK3PXP&ALGORITHM=sha512", out ConfiguracionTotp? c5, out _) && c5!.Algoritmo == "SHA512", "los parametros no distinguen mayusculas");
            Check(Ok("OTPAUTH://TOTP/x?secret=JBSWY3DPEHPK3PXP", out _, out _), "el esquema y el tipo tampoco");

            void Rechaza(string? t, string contiene)
            {
                bool ok = Ok(t, out ConfiguracionTotp? c, out string? e);
                Check(!ok && c is null && e is not null && e.Contains(contiene), "se rechaza «" + (t is null ? "null" : t.Length > 50 ? t.Substring(0, 50) + "…" : t) + "»: " + contiene, e);
            }
            Rechaza(null, "Escribe");
            Rechaza("   ", "Escribe");
            Rechaza("JBSWY3DP", "demasiado corta");               // 5 bytes
            Rechaza("JBSWY3DPEHPK3PX1", "base32");
            Rechaza("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1", "hotp");
            Rechaza("otpauth://totp/x?issuer=Banco", "no trae la clave");
            Rechaza("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", "Algoritmo no admitido");
            Rechaza("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA3", "Algoritmo no admitido");
            Rechaza("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=5", "dígitos");
            Rechaza("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=9", "dígitos");
            Rechaza("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=abc", "dígitos");
            Rechaza("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=-6", "dígitos");
            Rechaza("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=5", "Periodo");
            Rechaza("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0", "Periodo");
            Rechaza("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=3600", "Periodo");
            Rechaza("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&secret=KRSXG5CTMVRXEZLU", "repite");
            Rechaza("otpauth://totp/x?secret=" + new string('A', 300), "demasiado larga");
            Rechaza(new string('A', 1001), "demasiado larga");
            Rechaza("otpauth://", "Solo se admiten");

            // Los parametros de un enlace no pueden contagiar a otro: el algoritmo es el del enlace, no uno adivinado.
            Check(Ok("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", out ConfiguracionTotp? c6, out _) && c6!.Algoritmo == "SHA1" && c6.Digitos == 6 && c6.Periodo == 30, "sin parametros, los valores por omision del estandar (SHA1, 6, 30)");

            // Un limite de seguridad: la fecha no puede ser anterior a 1970.
            bool lanzo = false;
            try { GeneradorDeTotp.Codigo(cfg, DateTimeOffset.FromUnixTimeSeconds(-5)); } catch (ArgumentOutOfRangeException) { lanzo = true; }
            Check(lanzo, "una fecha anterior a 1970 no genera codigo");
        }

        public static async Task ProbarTotpEnLaBoveda(string dir)
        {
            Console.WriteLine("Códigos 2FA (TOTP): en la bóveda");
            string d = Path.Combine(dir, "totp");
            Directory.CreateDirectory(d);
            const string secreto = "JBSWY3DPEHPK3PXP";
            using Boveda b = await NuevaAsync(d, "t").ConfigureAwait(false);

            EntradaDeBoveda sin = await b.AgregarAsync("sin2fa.ejemplo.cl", "ana", "clave-larga-uno-1").ConfigureAwait(false);
            Check(sin.Totp == "", "una entrada sin 2FA tiene el campo vacio");
            EntradaDeBoveda con = await b.AgregarAsync("con2fa.ejemplo.cl", "ana", "clave-larga-dos-2", "", "  " + secreto + "  ").ConfigureAwait(false);
            Check(con.Totp == secreto, "una entrada con clave 2FA la guarda (sin los espacios de los bordes)");

            foreach (string mala in new[] { "no-es-base32!", "JBSWY3DP", "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5" })
            {
                bool lanzo = false;
                try { await b.AgregarAsync("mala.ejemplo.cl", "x", "y", "", mala).ConfigureAwait(false); } catch (ArgumentException) { lanzo = true; }
                Check(lanzo, "una clave 2FA que no daria codigos que funcionen se rechaza al guardar: «" + mala + "»");
            }
            Check(b.Entradas.Count == 2, "y las rechazadas no entran en la boveda");

            // Actualizar: null conserva, «» quita, otra la cambia.
            EntradaDeBoveda a1 = await b.ActualizarAsync(con.Id, "con2fa.ejemplo.cl", "ana", "clave-larga-dos-2", "nota nueva").ConfigureAwait(false);
            Check(a1.Totp == secreto && a1.Notas == "nota nueva", "actualizar sin tocar el 2FA (null) lo CONSERVA");
            EntradaDeBoveda a2 = await b.ActualizarAsync(con.Id, "con2fa.ejemplo.cl", "ana", "clave-larga-dos-2", "nota nueva", "KRSXG5CTMVRXEZLU").ConfigureAwait(false);
            Check(a2.Totp == "KRSXG5CTMVRXEZLU", "actualizar con otra clave 2FA la cambia");
            EntradaDeBoveda a3 = await b.ActualizarAsync(con.Id, "con2fa.ejemplo.cl", "ana", "clave-larga-dos-2", "nota nueva", "").ConfigureAwait(false);
            Check(a3.Totp == "", "actualizar con «» la quita");
            bool malaAct = false;
            try { await b.ActualizarAsync(con.Id, "con2fa.ejemplo.cl", "ana", "clave-larga-dos-2", "nota nueva", "basura!").ConfigureAwait(false); } catch (ArgumentException) { malaAct = true; }
            Check(malaAct && b.Entradas.First(e => e.Id == con.Id).Totp == "", "actualizar con una clave invalida se rechaza y no cambia nada");

            await b.ActualizarAsync(con.Id, "con2fa.ejemplo.cl", "ana", "clave-larga-dos-2", "nota nueva", secreto).ConfigureAwait(false);
            string ruta = Ruta(d, "t");
            byte[] bytes = File.ReadAllBytes(ruta);
            Check(bytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes(secreto)) < 0, "en el archivo de la boveda NO se ve la clave 2FA (va cifrada como todo lo demas)");

            // Persistencia al reabrir.
            b.Bloquear();
            ResultadoDeApertura r = await Boveda.AbrirAsync(ruta, Maestra).ConfigureAwait(false);
            Check(r.Abierta && r.Boveda!.Entradas.Single(e => e.Sitio == "con2fa.ejemplo.cl").Totp == secreto && r.Boveda.Entradas.Single(e => e.Sitio == "sin2fa.ejemplo.cl").Totp == "", "al reabrir la boveda, cada entrada conserva su 2FA (o su ausencia)");
            r.Boveda?.Dispose();

            // Compatibilidad: una entrada guardada ANTES de existir el campo se lee con el 2FA vacio.
            string viejo = "{\"Id\":\"" + Guid.NewGuid() + "\",\"Sitio\":\"viejo.ejemplo.cl\",\"Usuario\":\"a\",\"Contrasena\":\"b\",\"Notas\":\"\",\"Creada\":\"2026-01-01T00:00:00+00:00\",\"Modificada\":\"2026-01-01T00:00:00+00:00\"}";
            EntradaDeBoveda? leida = JsonSerializer.Deserialize<EntradaDeBoveda>(viejo);
            Check(leida is not null && leida.Totp == "" && leida.Sitio == "viejo.ejemplo.cl", "una entrada de una boveda anterior (sin el campo) se lee con el 2FA vacio");
        }
    }
}
