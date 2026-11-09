using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Enlaces
{
    public enum TipoDeRemitente
    {
        Correo,
        /// <summary>Un celular chileno comun (+56 9 ...).</summary>
        CelularChileno,
        /// <summary>Un numero con codigo de otro pais.</summary>
        Extranjero,
        /// <summary>Un numero corto (3 a 6 cifras), como los que usan las empresas para SMS masivos.</summary>
        NumeroCorto,
        /// <summary>Otro numero (fijo, o sin codigo de pais y de largo poco habitual).</summary>
        OtroNumero,
        /// <summary>Un nombre en vez de numero («BancoEstado»): en SMS se puede falsificar.</summary>
        Nombre
    }

    public sealed record Remitente(string Original, TipoDeRemitente Tipo, string? NombreVisible, string? Dominio, string? Numero);

    /// <summary>
    /// Revisa quien envia el mensaje (lo escribe el usuario: un numero o un correo). Reglas de honestidad:
    ///  - El «De:» de un correo y el nombre de un SMS se pueden FALSIFICAR, y Nexo no puede comprobarlo desde un texto pegado (no ve las
    ///    cabeceras SPF/DKIM ni la red del operador). Por eso un remitente oficial nunca hace que el mensaje sea «de fiar»: solo es una nota.
    ///  - Un celular comun o un correo gratuito no son delito: solo pesan si el mensaje DICE ser una empresa.
    ///  - Lo que no se reconoce como numero ni correo se dice («no evaluado»).
    /// </summary>
    public static class AnalizadorDeRemitente
    {
        public static readonly IReadOnlySet<string> CorreosGratuitos = new HashSet<string>(StringComparer.Ordinal)
        {
            "gmail.com", "googlemail.com", "hotmail.com", "hotmail.cl", "hotmail.es", "outlook.com", "outlook.cl", "outlook.es", "live.com", "live.cl",
            "yahoo.com", "yahoo.es", "ymail.com", "icloud.com", "me.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net", "aol.com",
            "yandex.com", "yandex.ru", "mail.ru", "zoho.com", "tutanota.com"
        };

        private static readonly Regex Correo = new(@"^(?:(?<nombre>[^<>]*?)\s*<)?\s*(?<local>[^@\s<>]+)@(?<dominio>[^@\s<>]+?)\s*>?\z", RegexOptions.CultureInvariant);
        private static readonly Regex Numero = new(@"^\+?[0-9]{3,15}\z", RegexOptions.CultureInvariant);
        private static readonly Regex NombreDeSms = new(@"^(?=.*\p{L})[\p{L}0-9 ._&-]{2,20}\z", RegexOptions.CultureInvariant);

        /// <summary>Interpreta lo que escribio el usuario. Null (con el motivo) si no es un numero, un correo ni un nombre de remitente.</summary>
        public static Remitente? Interpretar(string? texto, out string? motivo)
        {
            motivo = null;
            string t = (texto ?? "").Trim();
            if (t.Length == 0) { motivo = "está vacío"; return null; }
            if (t.Length > 200) { motivo = "es demasiado largo"; return null; }

            Match c = Correo.Match(t);
            if (c.Success)
            {
                string dominio;
                try { dominio = new IdnMapping().GetAscii(c.Groups["dominio"].Value.Trim().TrimEnd('.')).ToLowerInvariant(); }
                catch (ArgumentException) { motivo = "el dominio del correo no es válido"; return null; }
                if (!dominio.Contains('.') || !Regex.IsMatch(dominio, @"^[a-z0-9.-]+\z")) { motivo = "el dominio del correo no es válido"; return null; }
                string? nombre = c.Groups["nombre"].Success && c.Groups["nombre"].Value.Trim().Trim('"').Length > 0 ? c.Groups["nombre"].Value.Trim().Trim('"') : null;
                return new Remitente(t, TipoDeRemitente.Correo, nombre, dominio, null);
            }

            string cifras = Regex.Replace(t, @"[\s\-.()]", "");
            if (Numero.IsMatch(cifras))
            {
                bool mas = cifras.StartsWith('+');
                string d = mas ? cifras.Substring(1) : cifras;
                TipoDeRemitente tipo;
                if (mas && !d.StartsWith("56", StringComparison.Ordinal)) tipo = TipoDeRemitente.Extranjero;
                else if (d.StartsWith("56", StringComparison.Ordinal) && d.Length == 11) tipo = d[2] == '9' ? TipoDeRemitente.CelularChileno : TipoDeRemitente.OtroNumero;
                else if (!mas && d.Length == 9 && d[0] == '9') tipo = TipoDeRemitente.CelularChileno;
                else if (!mas && d.Length >= 3 && d.Length <= 6) tipo = TipoDeRemitente.NumeroCorto;
                else tipo = TipoDeRemitente.OtroNumero;
                return new Remitente(t, tipo, null, null, cifras);
            }

            if (NombreDeSms.IsMatch(t)) return new Remitente(t, TipoDeRemitente.Nombre, t, null, null);
            motivo = "no parece un número de teléfono, un correo ni el nombre de un remitente";
            return null;
        }

        /// <param name="dice">Las marcas que el mensaje dice ser (por su texto).</param>
        public static List<HallazgoDeSistema> Analizar(Remitente r, IReadOnlyList<Marca> dice, ListasDePhishing listas)
        {
            var hs = new List<HallazgoDeSistema>();
            string sujeto = r.Original;
            void Add(string id, Severidad s, string titulo, string detalle, string recomendacion) => hs.Add(new HallazgoDeSistema(id, s, titulo, detalle, recomendacion, sujeto));
            string Marcas(IEnumerable<Marca> ms) => string.Join(" o ", ms.Select(m => m.Nombre).Distinct());
            const string Falsificable = "Ojo: el remitente de un correo se puede falsificar, y Nexo no puede comprobarlo desde un texto pegado.";

            switch (r.Tipo)
            {
                case TipoDeRemitente.Correo:
                {
                    string dom = r.Dominio!;
                    // El nombre visible tambien «dice» ser alguien: «BancoEstado <x@y.com>».
                    List<Marca> todas = dice.Concat(CatalogoDeMarcas.Mencionadas(r.NombreVisible)).Distinct().ToList();
                    if (listas.CoincidenciaEnPhishingArmy(dom) is string enLista)
                        Add("REM-CORREO-EN-LISTA", Severidad.Alta, "El correo viene de un sitio de phishing",
                            "El dominio del remitente («" + enLista + "») figura en la lista de Phishing Army.", "No respondas ni abras sus enlaces o adjuntos.");

                    if (CorreosGratuitos.Contains(dom))
                    {
                        if (todas.Count > 0)
                            Add("REM-CORREO-GRATUITO", Severidad.Alta, "Dice ser " + Marcas(todas) + ", pero escribe desde un correo gratuito",
                                "El remitente es una cuenta de «" + dom + "», que cualquiera puede crear. Las empresas escriben desde su propio dominio.",
                                "No respondas ni abras sus enlaces. Si te preocupa, entra tú mismo a la aplicación o web oficial.");
                        break;
                    }

                    Imitacion? im = CatalogoDeMarcas.Imitada(dom, dom);
                    if (im is { Tipo: not TipoDeImitacion.OtroPais and not TipoDeImitacion.UnaLetra })
                        Add("REM-CORREO-IMITA", Severidad.Alta, "El correo parece hacerse pasar por " + im.Marca.Nombre,
                            "El dominio del remitente («" + dom + "») usa el nombre de " + im.Marca.Nombre + ", pero no es uno de sus dominios que Nexo conoce (" + string.Join(", ", im.Marca.Oficiales.Take(3)) + ").",
                            "No respondas ni abras sus enlaces o adjuntos.");
                    else if (im is { Tipo: TipoDeImitacion.UnaLetra })
                        Add("REM-CORREO-PARECIDO", Severidad.Media, "El dominio del correo se parece mucho a " + im.Marca.Nombre,
                            "«" + im.Parte + "» se diferencia en una sola letra de «" + im.Marca.Fichas[0] + "».", "Fíjate letra por letra antes de confiar.");

                    Marca? oficial = CatalogoDeMarcas.OficialDe(dom);
                    List<Marca> ajenas = todas.Where(m => !m.Oficiales.Any(o => Dominios.EsODentroDe(dom, o))).ToList();
                    if (im is null && ajenas.Count > 0 && (oficial is null || !todas.Contains(oficial)))
                        Add("REM-CORREO-NO-OFICIAL", Severidad.Media, "Dice ser " + Marcas(ajenas) + ", pero el correo viene de otro dominio",
                            "El remitente es de «" + dom + "», que no es un dominio de " + Marcas(ajenas) + " que Nexo conozca. Algunas empresas usan servicios de envío externos, pero también es lo típico de una estafa.",
                            "No abras sus enlaces: entra tú mismo a la web oficial.");
                    else if (oficial is not null && todas.Contains(oficial))
                        Add("REM-CORREO-OFICIAL", Severidad.Info, "El correo dice venir de un dominio oficial de " + oficial.Nombre,
                            "«" + dom + "» es de " + oficial.Nombre + ". " + Falsificable, "Fíjate igual en los enlaces: son más difíciles de disfrazar.");
                    break;
                }

                case TipoDeRemitente.CelularChileno:
                    if (dice.Count > 0)
                        Add("REM-CELULAR", Severidad.Media, "Dice ser " + Marcas(dice) + ", pero escribe desde un celular común",
                            "Las empresas suelen enviar SMS desde números cortos o con su nombre. Algunas atienden por WhatsApp desde un número normal, pero es justo lo que imitan los estafadores.",
                            "Comprueba el número en la web oficial de la empresa antes de responder.");
                    break;

                case TipoDeRemitente.Extranjero:
                    Add("REM-EXTRANJERO", dice.Count > 0 ? Severidad.Media : Severidad.Baja,
                        dice.Count > 0 ? "Dice ser " + Marcas(dice) + ", pero el número es extranjero" : "El número es extranjero",
                        "No empieza por +56. " + (dice.Count > 0 ? "Una empresa chilena no te escribiría desde otro país." : "Muchas estafas por WhatsApp (ofertas de trabajo, inversiones) llegan desde números de otros países."),
                        "Si no conoces a quien escribe, no respondas ni abras enlaces.");
                    break;

                case TipoDeRemitente.Nombre:
                {
                    Imitacion? im = CatalogoDeMarcas.PalabraParecida(r.Original);
                    if (im is { Tipo: TipoDeImitacion.Numeros or TipoDeImitacion.UnaLetra })
                        Add("REM-NOMBRE-IMITA", Severidad.Alta, "El nombre del remitente imita a " + im.Marca.Nombre,
                            "«" + r.Original + "» no es «" + im.Marca.Fichas[0] + "»: " + (im.Tipo == TipoDeImitacion.Numeros ? "cambia letras por números." : "se diferencia en una letra."),
                            "No respondas ni abras sus enlaces.");
                    else
                        Add("REM-NOMBRE-FALSIFICABLE", Severidad.Info, "El remitente es un nombre, no un número",
                            "En los SMS el nombre del remitente se puede falsificar: hay estafas cuyo mensaje aparece en la misma conversación que los reales del banco. Que diga «" + r.Original + "» no prueba nada.",
                            "Juzga el mensaje por su enlace y por lo que pide, no por el remitente.");
                    break;
                }
            }
            return hs;
        }
    }
}
