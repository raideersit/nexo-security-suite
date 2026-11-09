using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Nexo.Modules.Threats.Enlaces
{
    /// <summary>
    /// Utilidades sobre nombres de sitio en ASCII y minusculas. No es la Public Suffix List completa (miles de entradas que cambian):
    /// solo las terminaciones de dos niveles mas habituales en Chile y Latinoamerica, que bastan para no confundir «santander.com.ar»
    /// con un sitio llamado «com».
    /// </summary>
    public static class Dominios
    {
        private static readonly HashSet<string> DosNiveles = new(StringComparer.Ordinal)
        {
            "co.uk", "org.uk", "gov.uk", "ac.uk", "com.ar", "gob.ar", "com.br", "gov.br", "net.br", "com.mx", "gob.mx", "com.pe", "gob.pe",
            "com.co", "gov.co", "com.uy", "com.ve", "com.ec", "com.bo", "com.py", "gob.cl", "com.au", "co.jp", "co.za", "com.es", "com.tr", "co.nz"
        };

        public static bool EsTerminacionDeDosNiveles(string s) => DosNiveles.Contains(s);

        /// <summary>«login.banco.com.ar» → «com.ar»; «banco.cl» → «cl».</summary>
        public static string Terminacion(string sitio)
        {
            string[] e = sitio.Split('.');
            if (e.Length >= 3 && DosNiveles.Contains(e[^2] + "." + e[^1])) return e[^2] + "." + e[^1];
            return e[^1];
        }

        /// <summary>Las etiquetas que NO son la terminacion: «a.b.banco.com.ar» → [a, b, banco].</summary>
        public static string[] EtiquetasPropias(string sitio)
        {
            string term = Terminacion(sitio);
            if (sitio.Length <= term.Length) return Array.Empty<string>();
            return sitio.Substring(0, sitio.Length - term.Length - 1).Split('.', StringSplitOptions.RemoveEmptyEntries);
        }

        /// <summary>La etiqueta justo antes de la terminacion: «a.b.banco.com.ar» → «banco». Null si no hay.</summary>
        public static string? EtiquetaPrincipal(string sitio)
        {
            string[] e = EtiquetasPropias(sitio);
            return e.Length == 0 ? null : e[^1];
        }

        /// <summary>El sitio es <paramref name="dominio"/> o esta dentro de el («www.bancoestado.cl» dentro de «bancoestado.cl»).</summary>
        public static bool EsODentroDe(string sitio, string dominio)
            => sitio == dominio || sitio.EndsWith("." + dominio, StringComparison.Ordinal);
    }

    /// <param name="Menciones">
    /// Como se nombra en un mensaje que DICE venir de ella (sin tildes, minusculas, palabra entera). Vacio para las plataformas que se
    /// nombran a diario en mensajes normales («escríbeme al WhatsApp», «búscalo en Google»): nombrarlas no es decir ser ellas.
    /// </param>
    public sealed record Marca(string Nombre, IReadOnlyList<string> Fichas, IReadOnlyList<string> Oficiales, IReadOnlyList<string>? Menciones = null)
    {
        public IReadOnlyList<string> Menciones { get; init; } = Menciones ?? Array.Empty<string>();
    }

    public enum TipoDeImitacion
    {
        /// <summary>El nombre de la marca aparece tal cual en un sitio que no es suyo («bancoestado.cl.verificar.top»).</summary>
        Nombre,
        /// <summary>Aparece al cambiar numeros por letras parecidas («paypa1», «bancoestad0»).</summary>
        Numeros,
        /// <summary>Aparece al cambiar letras de otro alfabeto que se ven iguales (la «а» cirilica en vez de la «a» latina).</summary>
        OtroAlfabeto,
        /// <summary>Se diferencia de la marca en una sola letra («steamcomunity», «santandr»).</summary>
        UnaLetra,
        /// <summary>Es exactamente la marca con otra terminacion de pais («santander.co.uk»): puede ser la misma empresa en otro pais.</summary>
        OtroPais
    }

    public sealed record Imitacion(Marca Marca, TipoDeImitacion Tipo, string Parte);

    /// <summary>
    /// Las marcas que mas se suplantan en mensajes de estafa en Chile, y sus dominios oficiales. NO es exhaustiva: un dominio que no
    /// esta aqui no es por eso falso, y uno que si esta no garantiza que el mensaje sea legitimo (un mensaje puede mentir sobre quien
    /// lo envia). Se puede revisar en cualquier momento: cada dominio oficial es el que la propia empresa usa en su sitio.
    /// </summary>
    public static class CatalogoDeMarcas
    {
        public static readonly IReadOnlyList<Marca> Todas = new Marca[]
        {
            new("BancoEstado", new[] { "bancoestado" }, new[] { "bancoestado.cl" }, new[] { "bancoestado", "banco estado", "cuentarut", "cuenta rut" }),
            new("Banco de Chile", new[] { "bancochile", "bancodechile", "bancoedwards" }, new[] { "bancochile.cl", "bancoedwards.cl" }, new[] { "banco de chile", "bancochile", "banco chile", "banco edwards" }),
            new("Santander", new[] { "santander" }, new[] { "santander.cl", "santander.com", "santanderconsumer.cl", "santander.es", "santander.com.mx", "santander.com.br", "santander.com.ar", "santander.co.uk" }, new[] { "santander", "banco santander" }),
            new("BCI", new[] { "bci" }, new[] { "bci.cl" }, new[] { "bci", "banco bci", "mach" }),
            new("Scotiabank", new[] { "scotiabank" }, new[] { "scotiabank.cl", "scotiabank.com", "scotiabankchile.cl" }, new[] { "scotiabank" }),
            new("Itaú", new[] { "itau" }, new[] { "itau.cl", "itau.com.br" }, new[] { "itau", "banco itau" }),
            new("Falabella", new[] { "falabella" }, new[] { "falabella.com", "falabella.cl", "bancofalabella.cl" }, new[] { "falabella", "banco falabella", "cmr" }),
            new("Mercado Libre / Mercado Pago", new[] { "mercadolibre", "mercadopago", "mercadolivre" },
                new[] { "mercadolibre.cl", "mercadolibre.com", "mercadolibre.com.ar", "mercadolibre.com.mx", "mercadopago.cl", "mercadopago.com", "mercadopago.com.ar", "mercadopago.com.mx", "mercadolivre.com.br", "mlstatic.com" }, new[] { "mercado libre", "mercadolibre", "mercado pago", "mercadopago" }),
            new("Correos de Chile", new[] { "correoschile", "correos" }, new[] { "correos.cl" }, new[] { "correos de chile", "correoschile", "correos chile" }),
            new("Chilexpress", new[] { "chilexpress" }, new[] { "chilexpress.cl" }, new[] { "chilexpress" }),
            new("Starken", new[] { "starken" }, new[] { "starken.cl" }, new[] { "starken" }),
            new("Servicio de Impuestos Internos (SII)", new[] { "sii" }, new[] { "sii.cl" }, new[] { "sii", "impuestos internos" }),
            new("Registro Civil", new[] { "registrocivil" }, new[] { "registrocivil.cl" }, new[] { "registro civil", "registrocivil" }),
            new("ClaveÚnica", new[] { "claveunica" }, new[] { "claveunica.gob.cl" }, new[] { "clave unica", "claveunica" }),
            new("Tesorería General (TGR)", new[] { "tgr" }, new[] { "tgr.cl" }, new[] { "tgr", "tesoreria general" }),
            new("PayPal", new[] { "paypal" }, new[] { "paypal.com", "paypal.me", "paypalobjects.com" }, new[] { "paypal" }),
            new("Microsoft", new[] { "microsoft", "office365", "outlook", "hotmail", "onedrive", "sharepoint" },
                new[] { "microsoft.com", "live.com", "office.com", "office365.com", "microsoftonline.com", "outlook.com", "hotmail.com", "msn.com", "microsoft365.com",
                        "sharepoint.com", "onedrive.com", "onedrive.live.com", "bing.com", "xbox.com", "skype.com", "windows.net", "azure.com" }, new[] { "microsoft", "office 365", "cuenta microsoft" }),
            new("Apple", new[] { "apple", "icloud", "appleid" }, new[] { "apple.com", "icloud.com", "me.com" }, new[] { "apple id", "icloud", "cuenta de apple" }),
            new("Google", new[] { "google", "gmail" },
                new[] { "google.com", "google.cl", "gmail.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "youtube.com", "goo.gl", "googlevideo.com", "withgoogle.com", "g.co", "google.com.ar", "google.com.mx", "google.es" }),
            new("WhatsApp", new[] { "whatsapp" }, new[] { "whatsapp.com", "whatsapp.net", "wa.me" }),
            new("Instagram", new[] { "instagram" }, new[] { "instagram.com", "cdninstagram.com" }),
            new("Facebook", new[] { "facebook" }, new[] { "facebook.com", "fb.com", "fb.me", "facebook.net", "fbcdn.net", "messenger.com", "meta.com" }),
            new("Netflix", new[] { "netflix" }, new[] { "netflix.com", "netflix.net" }, new[] { "netflix" }),
            new("Steam", new[] { "steampowered", "steamcommunity" }, new[] { "steampowered.com", "steamcommunity.com", "steamstatic.com" }, new[] { "steam" }),
            new("Discord", new[] { "discord" }, new[] { "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media" }),
            new("Riot Games", new[] { "riotgames", "leagueoflegends" }, new[] { "riotgames.com", "leagueoflegends.com" }),
            new("Roblox", new[] { "roblox" }, new[] { "roblox.com", "rbxcdn.com" }),
            new("Amazon", new[] { "amazon" }, new[] { "amazon.com", "amazon.es", "amazon.com.mx", "amazon.com.br", "amazonaws.com", "media-amazon.com" }, new[] { "amazon" }),
        };

        /// <summary>
        /// Fichas que solo cuentan como palabra entera (separada por «.» o «-»), aunque sean largas: «outlook» y «correos» son palabras
        /// normales («economicoutlook.org», «correos.es» del correo de España).
        /// </summary>
        private static readonly HashSet<string> SoloPalabraEntera = new(StringComparer.Ordinal) { "outlook", "correos" };

        /// <summary>Largo minimo para buscar la ficha DENTRO de una palabra («bancoestadoseguro»); las mas cortas solo cuentan enteras («bci», «sii»).</summary>
        public const int LargoParaBuscarDentro = 7;

        /// <summary>Terminaciones muy usadas en estafas: baratas o gratuitas. Muchas webs normales tambien las usan.</summary>
        public static readonly IReadOnlySet<string> TerminacionesAbusadas = new HashSet<string>(StringComparer.Ordinal)
        {
            "top", "xyz", "icu", "buzz", "cyou", "sbs", "cfd", "bond", "click", "rest", "monster", "lol", "quest", "mom", "cam", "tk", "ml", "ga", "cf", "gq"
        };

        /// <summary>Las marcas que el texto dice ser (por sus menciones, sin tildes, palabra entera). Las plataformas sin menciones no cuentan.</summary>
        public static IReadOnlyList<Marca> Mencionadas(string? texto)
        {
            if (string.IsNullOrWhiteSpace(texto)) return Array.Empty<Marca>();
            string t = " " + Regex.Replace(AnalizadorDeMensajes.SinTildes(texto), "[^a-z0-9]+", " ") + " ";
            return Todas.Where(m => m.Menciones.Any(f => t.Contains(" " + f + " ", StringComparison.Ordinal))).ToList();
        }

        /// <summary>Como se parece una palabra suelta (el nombre de un remitente de SMS) a una marca: igual, con numeros por letras o a una letra.</summary>
        public static Imitacion? PalabraParecida(string palabra)
        {
            string p = Regex.Replace(AnalizadorDeMensajes.SinTildes(palabra ?? ""), "[^a-z0-9]", "");
            if (p.Length < 3) return null;
            foreach (Marca m in Todas)
                foreach (string f in m.Fichas.Concat(m.Menciones.Select(x => x.Replace(" ", ""))))
                    if (p == f) return new Imitacion(m, TipoDeImitacion.Nombre, p);
            foreach (string v in VariantesSinNumeros(new[] { p }))
                foreach (Marca m in Todas)
                    foreach (string f in m.Fichas.Concat(m.Menciones.Select(x => x.Replace(" ", ""))))
                        if (v == f) return new Imitacion(m, TipoDeImitacion.Numeros, p);
            foreach (Marca m in Todas)
                foreach (string f in m.Fichas.Concat(m.Menciones.Select(x => x.Replace(" ", ""))))
                    if (f.Length >= LargoParaBuscarDentro && DistanciaDeUnaLetra(p, f)) return new Imitacion(m, TipoDeImitacion.UnaLetra, p);
            return null;
        }

        public static Marca? OficialDe(string sitio)
            => Todas.FirstOrDefault(m => m.Oficiales.Any(o => Dominios.EsODentroDe(sitio, o)));

        /// <summary>
        /// Si el sitio parece hacerse pasar por una marca del catalogo. <paramref name="sitio"/> en ASCII; <paramref name="legible"/>
        /// con sus letras reales (para ver las de otro alfabeto). Un sitio oficial de cualquier marca nunca se marca.
        /// </summary>
        public static Imitacion? Imitada(string sitio, string legible)
        {
            if (OficialDe(sitio) is not null) return null;
            string[] etiquetas = Dominios.EtiquetasPropias(sitio);
            if (etiquetas.Length == 0) return null;
            string? principal = etiquetas[^1];
            string terminacion = Dominios.Terminacion(sitio);

            // 1. El nombre tal cual.
            foreach (Marca m in Todas)
                foreach (string f in m.Fichas)
                {
                    string? parte = Contiene(etiquetas, f);
                    if (parte is null) continue;
                    // Exactamente la marca con otra terminacion de pais (dos letras, no de las abusadas) y en ninguna otra parte del nombre.
                    bool soloPrincipal = principal == f && etiquetas.Take(etiquetas.Length - 1).All(e => Contiene(new[] { e }, f) is null);
                    string ultima = terminacion.Split('.')[^1];
                    if (soloPrincipal && ultima.Length == 2 && !TerminacionesAbusadas.Contains(ultima))
                        return new Imitacion(m, TipoDeImitacion.OtroPais, parte);
                    return new Imitacion(m, TipoDeImitacion.Nombre, parte);
                }

            // 2. Numeros en vez de letras («paypa1», «bancoestad0», «rn» por «m»).
            foreach (string variante in VariantesSinNumeros(etiquetas))
            {
                string[] ev = variante.Split('.');
                foreach (Marca m in Todas)
                    foreach (string f in m.Fichas)
                        if (Contiene(ev, f) is string p) return new Imitacion(m, TipoDeImitacion.Numeros, p);
            }

            // 3. Letras de otro alfabeto que se ven iguales.
            if (legible != sitio)
            {
                string[] propiasLegibles = EtiquetasLegibles(legible, etiquetas.Length);
                string esqueleto = string.Join(".", propiasLegibles.Select(Esqueleto));
                string[] ee = esqueleto.Split('.');
                foreach (Marca m in Todas)
                    foreach (string f in m.Fichas)
                        if (Contiene(ee, f) is string p) return new Imitacion(m, TipoDeImitacion.OtroAlfabeto, p);
            }

            // 4. A una letra de distancia (solo marcas largas: en las cortas una letra cambia demasiadas palabras normales).
            foreach (string etiqueta in etiquetas)
                foreach (string parte in Partes(etiqueta))
                    foreach (Marca m in Todas)
                        foreach (string f in m.Fichas)
                            if (f.Length >= LargoParaBuscarDentro && parte != f && Math.Abs(parte.Length - f.Length) <= 1 && DistanciaDeUnaLetra(parte, f))
                                return new Imitacion(m, TipoDeImitacion.UnaLetra, parte);
            return null;
        }

        /// <summary>Busca la ficha en las etiquetas: dentro de la palabra si es larga, como palabra entera (entre «.» o «-») si es corta.</summary>
        private static string? Contiene(string[] etiquetas, string ficha)
        {
            bool dentro = ficha.Length >= LargoParaBuscarDentro && !SoloPalabraEntera.Contains(ficha);
            foreach (string e in etiquetas)
            {
                if (dentro && e.Contains(ficha, StringComparison.Ordinal)) return e;
                if (Partes(e).Contains(ficha)) return e;
            }
            return null;
        }

        private static string[] Partes(string etiqueta) => etiqueta.Split('-', StringSplitOptions.RemoveEmptyEntries);

        /// <summary>Las etiquetas propias en su forma legible (Unicode), alineadas con las ASCII.</summary>
        private static string[] EtiquetasLegibles(string legible, int cuantas)
        {
            string[] todas = legible.ToLowerInvariant().Split('.');
            return todas.Take(Math.Min(cuantas, todas.Length)).ToArray();
        }

        private static IEnumerable<string> VariantesSinNumeros(string[] etiquetas)
        {
            string unidas = string.Join(".", etiquetas);
            if (!unidas.Any(char.IsDigit) && !unidas.Contains("rn") && !unidas.Contains("vv")) yield break;
            string baseComun = unidas.Replace('0', 'o').Replace('3', 'e').Replace('4', 'a').Replace('5', 's').Replace('7', 't');
            foreach (string v in new[] { baseComun.Replace('1', 'l'), baseComun.Replace('1', 'i') })
            {
                if (v != unidas) yield return v;
                string mv = v.Replace("rn", "m").Replace("vv", "w");
                if (mv != v) yield return mv;
            }
        }

        /// <summary>Letras cirilicas y griegas que se ven como latinas, llevadas a su gemela latina.</summary>
        private static readonly Dictionary<char, char> Gemelas = new()
        {
            ['а'] = 'a', ['е'] = 'e', ['о'] = 'o', ['р'] = 'p', ['с'] = 'c', ['у'] = 'y', ['х'] = 'x', ['і'] = 'i', ['ј'] = 'j', ['ѕ'] = 's',
            ['ԁ'] = 'd', ['һ'] = 'h', ['ӏ'] = 'l', ['ԛ'] = 'q', ['ԝ'] = 'w', ['ь'] = 'b', ['к'] = 'k', ['м'] = 'm', ['т'] = 't', ['п'] = 'n',
            ['ο'] = 'o', ['α'] = 'a', ['ν'] = 'v', ['ρ'] = 'p', ['ι'] = 'i', ['κ'] = 'k', ['τ'] = 't', ['υ'] = 'u', ['χ'] = 'x', ['ε'] = 'e',
            ['ɡ'] = 'g', ['ı'] = 'i'
        };

        public static string Esqueleto(string etiqueta)
        {
            var sb = new StringBuilder(etiqueta.Length);
            foreach (char c in etiqueta) sb.Append(Gemelas.TryGetValue(c, out char l) ? l : c);
            return sb.ToString();
        }

        public enum Alfabeto { Latino, Cirilico, Griego, Otro, Neutro }

        public static Alfabeto AlfabetoDe(char c)
        {
            if (c < 128) return char.IsLetter(c) ? Alfabeto.Latino : Alfabeto.Neutro;
            if (c >= 'À' && c <= 'ɏ') return Alfabeto.Latino;
            if (c >= 'Ѐ' && c <= 'ԯ') return Alfabeto.Cirilico;
            if (c >= 'Ͱ' && c <= 'Ͽ') return Alfabeto.Griego;
            if (c == 'ɡ' || c == 'ı') return Alfabeto.Latino;
            return char.IsLetter(c) ? Alfabeto.Otro : Alfabeto.Neutro;
        }

        /// <summary>Una etiqueta que mezcla letras latinas con cirilicas o griegas: el truco clasico para imitar un nombre.</summary>
        public static bool MezclaAlfabetos(string etiqueta)
        {
            var vistos = new HashSet<Alfabeto>();
            foreach (char c in etiqueta)
            {
                Alfabeto a = AlfabetoDe(c);
                if (a != Alfabeto.Neutro) vistos.Add(a);
            }
            return vistos.Contains(Alfabeto.Latino) && (vistos.Contains(Alfabeto.Cirilico) || vistos.Contains(Alfabeto.Griego));
        }

        /// <summary>true si a y b se diferencian en exactamente una letra: cambiada, sobrante, faltante o dos vecinas intercambiadas.</summary>
        public static bool DistanciaDeUnaLetra(string a, string b)
        {
            if (a == b) return false;
            if (a.Length == b.Length)
            {
                int[] dif = Enumerable.Range(0, a.Length).Where(i => a[i] != b[i]).ToArray();
                if (dif.Length == 1) return true;
                return dif.Length == 2 && dif[1] == dif[0] + 1 && a[dif[0]] == b[dif[1]] && a[dif[1]] == b[dif[0]];
            }
            string corta = a.Length < b.Length ? a : b, larga = a.Length < b.Length ? b : a;
            if (larga.Length - corta.Length != 1) return false;
            for (int i = 0; i < larga.Length; i++)
                if (larga.Remove(i, 1) == corta) return true;
            return false;
        }
    }
}
