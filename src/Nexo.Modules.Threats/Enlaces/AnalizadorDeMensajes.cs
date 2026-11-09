using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Enlaces
{
    public enum Veredicto
    {
        /// <summary>Ninguna señal conocida. NO significa «seguro»: un sitio de phishing nuevo no esta en ninguna lista.</summary>
        SinSenales,
        Sospechoso,
        Peligroso
    }

    public sealed record EnlaceRevisado(string Original, string Sitio, string SitioLegible, Veredicto Veredicto, IReadOnlyList<HallazgoDeSistema> Hallazgos, string? MarcaOficial);

    public sealed record RevisionDeMensaje(IReadOnlyList<EnlaceRevisado> Enlaces, ResultadoDeAnalisis Analisis, Veredicto Veredicto, int EnlacesIlegibles);

    /// <summary>
    /// Revisa un mensaje pegado (SMS, correo, WhatsApp) y sus enlaces. Todo es LOCAL: Nexo nunca abre el enlace, no pregunta a ningun
    /// servidor por el (ni siquiera resuelve el nombre) y no lo guarda. Reglas de honestidad:
    ///  - «Sin señales» nunca es «seguro»: las listas llegan tarde a los sitios nuevos y las reglas no ven todo.
    ///  - Sin listas, o con listas viejas, la revision queda incompleta y se dice.
    ///  - Las frases de estafa solo se reconocen en español; que no haya ninguna no prueba nada.
    ///  - Lo que no se pudo interpretar se nombra.
    /// No analiza audio ni video (deepfakes): esta fuera del alcance de una persona y la ventana lo dice.
    /// </summary>
    public static class AnalizadorDeMensajes
    {
        public static readonly TimeSpan ListaVieja = TimeSpan.FromDays(7);

        public static readonly IReadOnlySet<string> Acortadores = new HashSet<string>(StringComparer.Ordinal)
        {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "v.gd", "cutt.ly", "rebrand.ly", "shorturl.at", "t.ly", "rb.gy", "s.id",
            "tiny.cc", "buff.ly", "bit.do", "acortar.link", "n9.cl", "qrco.de", "short.gy", "lnkd.in", "tr.ee", "u.to", "clck.ru"
        };

        /// <param name="remitente">Opcional: quien lo envia (numero o correo), tal como lo escribio el usuario.</param>
        public static RevisionDeMensaje Analizar(string? texto, ListasDePhishing listas, DateTimeOffset ahora, string? remitente = null)
        {
            if (listas is null) throw new ArgumentNullException(nameof(listas));
            var noEvaluado = new List<string>();
            ExtraccionDeEnlaces ex = ExtractorDeEnlaces.Extraer(texto);

            // Quien dice ser el mensaje: por su texto y, si el remitente es un nombre de SMS que coincide con una marca, tambien por el.
            string recortado = texto is null ? "" : texto.Length > ExtractorDeEnlaces.MaximoDeCaracteres ? texto.Substring(0, ExtractorDeEnlaces.MaximoDeCaracteres) : texto;
            // Sin los enlaces: que un enlace lleve a «bancoestado.cl» no es que el mensaje DIGA ser BancoEstado.
            string sinEnlaces = recortado;
            foreach (EnlaceEncontrado e in ex.Enlaces) sinEnlaces = sinEnlaces.Replace(e.Texto, " ", StringComparison.Ordinal);
            var dice = CatalogoDeMarcas.Mencionadas(sinEnlaces).ToList();
            Remitente? rem = null;
            if (!string.IsNullOrWhiteSpace(remitente))
            {
                rem = AnalizadorDeRemitente.Interpretar(remitente, out string? porQue);
                if (rem is null) noEvaluado.Add("No se reconoce el remitente «" + Recortar(remitente.Trim(), 60) + "»: " + porQue + ".");
                else if (rem.Tipo == TipoDeRemitente.Nombre && CatalogoDeMarcas.PalabraParecida(rem.Original) is { Tipo: TipoDeImitacion.Nombre } exacta && !dice.Contains(exacta.Marca))
                    dice.Add(exacta.Marca);
            }
            if (ex.TextoRecortado)
                noEvaluado.Add("El texto es muy largo: solo se revisaron los primeros " + ExtractorDeEnlaces.MaximoDeCaracteres.ToString("N0", CultureInfo.GetCultureInfo("es-CL")) + " caracteres.");
            if (ex.DemasiadosEnlaces)
                noEvaluado.Add("Hay más de " + ExtractorDeEnlaces.MaximoDeEnlaces + " enlaces: solo se revisaron los primeros " + ExtractorDeEnlaces.MaximoDeEnlaces + ".");

            var enlaces = new List<EnlaceRevisado>();
            int ilegibles = 0;
            foreach (EnlaceEncontrado e in ex.Enlaces)
            {
                EnlaceNormalizado? n = NormalizadorDeEnlaces.Normalizar(e, out string? motivo);
                if (n is null)
                {
                    ilegibles++;
                    noEvaluado.Add("No se pudo interpretar «" + Recortar(e.Texto, 80) + "»: " + motivo + ".");
                    continue;
                }
                enlaces.Add(RevisarEnlace(n, listas, dice));
            }

            if (enlaces.Count > 0)
            {
                foreach (FuenteDeLista f in new[] { FuenteDeLista.PhishingArmy, FuenteDeLista.OpenPhish })
                {
                    ListaCargada? l = listas.De(f);
                    if (l is null)
                        noEvaluado.Add("No hay lista de " + NombreDe(f) + " descargada: los enlaces no se cruzaron con ella (pulsa «Actualizar listas»).");
                    else if (l.Antiguedad(ahora) > ListaVieja)
                        noEvaluado.Add("La lista de " + NombreDe(f) + " tiene " + (int)l.Antiguedad(ahora).TotalDays + " días: no tiene los sitios de phishing más nuevos (pulsa «Actualizar listas»).");
                }
            }

            var hallazgos = new List<HallazgoDeSistema>();
            foreach (EnlaceRevisado e in enlaces) hallazgos.AddRange(e.Hallazgos);
            if (rem is not null) hallazgos.AddRange(AnalizadorDeRemitente.Analizar(rem, dice, listas));
            hallazgos.AddRange(RevisarAcciones(recortado));
            hallazgos.AddRange(RevisarFrases(texto is null ? "" : texto.Length > ExtractorDeEnlaces.MaximoDeCaracteres ? texto.Substring(0, ExtractorDeEnlaces.MaximoDeCaracteres) : texto,
                                             enlaces.Count + ilegibles > 0, ilegibles == 0 && enlaces.Count > 0 && enlaces.All(e => e.MarcaOficial is not null)));

            var r = new ResultadoDeAnalisis(
                hallazgos.OrderByDescending(h => h.Severidad).ThenBy(h => h.Id, StringComparer.Ordinal).ThenBy(h => h.Sujeto, StringComparer.Ordinal).ToList(),
                noEvaluado);
            return new RevisionDeMensaje(enlaces, r, VeredictoDe(r.Hallazgos), ilegibles);
        }

        // Lo que un QR (o un mensaje) puede hacer ademas de abrir un enlace: unirse a una red, enviar un SMS, llamar, pagar.
        private static readonly Regex Wifi = R(@"(?i)\bWIFI:((?:[^;\\]|\\.)*;)+;?");
        private static readonly Regex CampoWifi = R(@"(?i)(?<=[:;])(?<k>[STPH]):(?<v>(?:[^;\\]|\\.)*)");
        private static readonly Regex Sms = R(@"(?i)\b(?:SMSTO|SMS):\+?(?<n>[0-9][0-9 ]{1,19})(?:[:?](?:body=)?(?<t>[^\r\n]{0,160}))?");
        private static readonly Regex Llamada = R(@"(?i)\btel:(?<n>\+?[0-9][0-9 \-]{1,19})");
        private static readonly Regex Cripto = R(@"(?i)\b(?<m>bitcoin|ethereum|litecoin|monero|dogecoin|tron|usdt|solana|bitcoincash):[A-Za-z0-9]{10,}");

        private static IEnumerable<HallazgoDeSistema> RevisarAcciones(string texto)
        {
            if (string.IsNullOrWhiteSpace(texto)) yield break;
            foreach (Match w in Wifi.Matches(texto).Cast<Match>().Take(3))
            {
                string? red = null, tipo = null;
                foreach (Match c in CampoWifi.Matches(w.Value))
                {
                    string v = Regex.Replace(c.Groups["v"].Value, @"\\(.)", "$1");
                    if (c.Groups["k"].Value.Equals("S", StringComparison.OrdinalIgnoreCase)) red = v;
                    else if (c.Groups["k"].Value.Equals("T", StringComparison.OrdinalIgnoreCase)) tipo = v.ToUpperInvariant();
                }
                // La contraseña (P:) jamas se muestra ni se guarda.
                string nombre = "«" + Recortar(red ?? "(sin nombre)", 40) + "»";
                bool abierta = string.IsNullOrEmpty(tipo) || tipo == "NOPASS";
                if (abierta || tipo == "WEP")
                    yield return new HallazgoDeSistema("MSJ-WIFI", Severidad.Media, "Conecta a una red Wi-Fi " + (abierta ? "abierta" : "con cifrado WEP (roto)") + " " + nombre,
                        "Al escanearlo, el teléfono se une a esa red. En una red " + (abierta ? "sin contraseña" : "WEP") + " quien la controle puede ver o desviar lo que haces. Hay QR falsos pegados en cafés y aeropuertos para eso.",
                        "Conéctate solo si es la red del lugar donde estás, y no entres a tu banco desde ella.", nombre);
                else
                    yield return new HallazgoDeSistema("MSJ-WIFI", Severidad.Info, "Conecta a la red Wi-Fi " + nombre,
                        "Al escanearlo, el teléfono se une a esa red (" + (tipo ?? "") + ", con contraseña). Nexo no muestra la contraseña.",
                        "Conéctate solo si es la red del lugar donde estás.", nombre);
            }
            foreach (Match m in Sms.Matches(texto).Cast<Match>().Take(3))
            {
                string n = m.Groups["n"].Value.Replace(" ", "");
                yield return new HallazgoDeSistema("MSJ-SMS", Severidad.Media, "Envía un SMS al " + n,
                    "Prepara un SMS al número " + n + (m.Groups["t"].Value.Trim().Length > 0 ? " con el texto «" + Recortar(m.Groups["t"].Value.Trim(), 60) + "»" : "") +
                    ". Los SMS a números cortos o especiales pueden cobrarse o suscribirte a servicios de pago.",
                    "No lo envíes si no sabes a quién va ni cuánto cuesta.", n);
            }
            foreach (Match m in Llamada.Matches(texto).Cast<Match>().Take(3))
            {
                string n = Regex.Replace(m.Groups["n"].Value, @"[ \-]", "");
                yield return new HallazgoDeSistema("MSJ-LLAMADA", Severidad.Baja, "Llama al " + n,
                    "Marca el número " + n + ". Hay estafas que dan un número falso del «banco» para que entregues tus datos por teléfono.",
                    "Antes de llamar, comprueba el número en la web oficial de la empresa.", n);
            }
            foreach (Match m in Cripto.Matches(texto).Cast<Match>().Take(3))
                yield return new HallazgoDeSistema("MSJ-CRIPTO", Severidad.Media, "Pide un pago en criptomonedas (" + m.Groups["m"].Value.ToLowerInvariant() + ")",
                    "Contiene una dirección para pagar con criptomonedas. Un pago así no se puede anular ni reclamar: es el medio favorito de las estafas.",
                    "No pagues si no tienes absoluta certeza de a quién le pagas.", m.Groups["m"].Value.ToLowerInvariant());
        }

        public static string NombreDe(FuenteDeLista f) => f == FuenteDeLista.PhishingArmy ? "Phishing Army" : "OpenPhish";

        public static Veredicto VeredictoDe(IEnumerable<HallazgoDeSistema> hs)
        {
            Severidad max = hs.Select(h => h.Severidad).DefaultIfEmpty(Severidad.Info).Max();
            return max >= Severidad.Alta ? Veredicto.Peligroso : max == Severidad.Media ? Veredicto.Sospechoso : Veredicto.SinSenales;
        }

        /// <param name="dice">Las marcas que el mensaje dice ser: un enlace que no es de ninguna de ellas se marca.</param>
        public static EnlaceRevisado RevisarEnlace(EnlaceNormalizado n, ListasDePhishing listas, IReadOnlyList<Marca>? dice = null)
        {
            var hs = new List<HallazgoDeSistema>();
            string sujeto = n.SitioLegible == n.Sitio ? n.Sitio : n.SitioLegible + " (" + n.Sitio + ")";
            void Add(string id, Severidad s, string titulo, string detalle, string recomendacion) => hs.Add(new HallazgoDeSistema(id, s, titulo, detalle, recomendacion, sujeto));
            const string NoLoAbras = "No lo abras. Si crees que puede ser real, entra escribiendo tú mismo la dirección oficial o llama al número que conoces.";

            // Listas.
            if (listas.CoincidenciaEnPhishingArmy(n.Sitio) is string dominio)
                Add("ENL-LISTA-PHISHING", Severidad.Alta, "El sitio está en una lista de phishing",
                    "«" + dominio + "» figura en la lista de Phishing Army (sitios de phishing denunciados).", NoLoAbras);
            if (listas.DireccionEnOpenPhish(n.Clave))
                Add("ENL-LISTA-OPENPHISH", Severidad.Alta, "La dirección exacta está en una lista de phishing",
                    "Esta dirección figura en la lista de OpenPhish (páginas de phishing comprobadas).", NoLoAbras);
            else if (listas.SitioEnOpenPhish(n.Sitio))
                Add("ENL-SITIO-OPENPHISH", Severidad.Media, "Otra página de este sitio está en una lista de phishing",
                    "OpenPhish tiene otra dirección de «" + n.Sitio + "» como phishing. Puede ser un servicio compartido por muchas personas, pero alguien ya lo usó para estafar.",
                    "Desconfía: no escribas claves ni datos de tarjetas ahí.");

            // La parte antes de «@» no es el sitio.
            if (n.Usuario is not null)
                Add("ENL-USUARIO-EN-ENLACE", Severidad.Alta, "El enlace esconde el sitio real detrás de una «@»",
                    "Lo que va antes de la «@» («" + Recortar(n.Usuario, 60) + "») es decoración: el navegador abre «" + n.Sitio + "». Es un truco para que parezca otro sitio.", NoLoAbras);

            // Marcas.
            Marca? oficial = n.EsIp ? null : CatalogoDeMarcas.OficialDe(n.Sitio);
            if (!n.EsIp && CatalogoDeMarcas.Imitada(n.Sitio, n.SitioLegible) is Imitacion im)
            {
                string oficiales = string.Join(", ", im.Marca.Oficiales.Take(3));
                switch (im.Tipo)
                {
                    case TipoDeImitacion.OtroPais:
                        Add("ENL-MARCA-OTRO-PAIS", Severidad.Info, "Lleva el nombre de " + im.Marca.Nombre + " con otra terminación",
                            "«" + n.Sitio + "» no es uno de los dominios de " + im.Marca.Nombre + " que Nexo conoce (" + oficiales + "). Puede ser la misma empresa en otro país, o no.",
                            "Si el mensaje dice venir de " + im.Marca.Nombre + " en Chile, entra por " + im.Marca.Oficiales[0] + ".");
                        break;
                    case TipoDeImitacion.UnaLetra:
                        Add("ENL-PARECIDO-A-MARCA", Severidad.Media, "El nombre se parece mucho a " + im.Marca.Nombre,
                            "«" + im.Parte + "» se diferencia en una sola letra de «" + im.Marca.Fichas[0] + "». Así se fabrican sitios que pasan por el original a simple vista.",
                            "Fíjate letra por letra. Los dominios oficiales que Nexo conoce son: " + oficiales + ".");
                        break;
                    default:
                        string como = im.Tipo switch
                        {
                            TipoDeImitacion.Numeros => " cambiando letras por números o letras parecidas",
                            TipoDeImitacion.OtroAlfabeto => " con letras de otro alfabeto que se ven iguales",
                            _ => ""
                        };
                        Add("ENL-IMITA-MARCA", Severidad.Alta, "Parece hacerse pasar por " + im.Marca.Nombre,
                            "El nombre del sitio usa «" + im.Marca.Fichas[0] + "»" + como + ", pero el sitio real es «" + n.Sitio + "», que no es uno de los dominios de " + im.Marca.Nombre +
                            " que Nexo conoce (" + oficiales + ").", NoLoAbras);
                        break;
                }
            }
            else if (oficial is not null)
            {
                Add("ENL-DOMINIO-OFICIAL", Severidad.Info, "Es un dominio oficial de " + oficial.Nombre,
                    "«" + n.Sitio + "» es de " + oficial.Nombre + " según la lista de Nexo. Aun así, un mensaje puede mentir sobre quién lo envía.",
                    "Lo más seguro sigue siendo entrar escribiendo tú la dirección, no desde el mensaje.");
            }

            // El mensaje dice ser una marca y el enlace no es suyo (ni de ninguna marca conocida): lo mas comun en los SMS de estafa,
            // y lo unico que delata a un sitio nuevo que aun no esta en ninguna lista. No se repite si ya se dijo que la imita.
            if (dice is { Count: > 0 } && oficial is null && !hs.Any(h => h.Id is "ENL-IMITA-MARCA" or "ENL-PARECIDO-A-MARCA"))
            {
                string nombres = string.Join(" o ", dice.Select(m => m.Nombre).Distinct());
                Add("ENL-NO-ES-DE-LA-MARCA", Severidad.Media, "El mensaje dice ser " + nombres + ", pero el enlace lleva a otro sitio",
                    "El enlace lleva a «" + n.Sitio + "», que no es un dominio de " + nombres + " que Nexo conozca. Así son la mayoría de los SMS de estafa: el nombre de la empresa en el texto y un sitio ajeno en el enlace.",
                    "No lo abras. Entra tú mismo a la aplicación o web oficial de " + nombres + ".");
            }

            // Letras de alfabetos distintos en una misma parte del nombre.
            if (!n.EsIp)
            {
                if (n.NombreMalCodificado)
                    Add("ENL-NOMBRE-MAL-CODIFICADO", Severidad.Media, "El nombre del sitio está mal codificado",
                        "«" + n.Sitio + "» usa la forma «xn--» de los nombres con letras especiales, pero no corresponde a ningún nombre válido.", "Desconfía de este enlace.");
                else if (n.SitioLegible.Split('.').Any(CatalogoDeMarcas.MezclaAlfabetos))
                    Add("ENL-MEZCLA-ALFABETOS", Severidad.Alta, "El nombre mezcla letras de alfabetos distintos",
                        "«" + n.SitioLegible + "» (en realidad «" + n.Sitio + "») mezcla letras latinas con cirílicas o griegas que se ven iguales. Es el truco clásico para imitar un nombre conocido.", NoLoAbras);
                else if (n.SitioLegible != n.Sitio)
                    Add("ENL-LETRAS-ESPECIALES", Severidad.Baja, "El nombre usa letras especiales",
                        "Se ve como «" + n.SitioLegible + "», pero su nombre real es «" + n.Sitio + "». Es normal en nombres con ñ o tildes; también se usa para imitar otros.",
                        "Comprueba que sea el sitio que esperas.");
            }

            if (n.EsIp)
                Add("ENL-IP", Severidad.Media, "El enlace usa un número (IP) en vez de un nombre",
                    "Lleva a «" + n.Sitio + "» sin nombre de sitio. Los bancos y servicios serios no envían enlaces así.", "No escribas claves ni datos ahí.");

            if (Acortadores.Contains(n.Sitio))
                Add("ENL-ACORTADOR", Severidad.Media, "Es un enlace acortado: no se ve adónde lleva",
                    "«" + n.Sitio + "» es un acortador de enlaces: esconde el destino real. Nexo no lo abre para averiguarlo (abrirlo avisaría al que lo envió).",
                    "Si no esperabas este mensaje, no lo abras.");

            if (!n.Cifrado && n.Origen == OrigenDelEnlace.ConEsquema)
                Add("ENL-SIN-CIFRADO", Severidad.Baja, "El enlace no está cifrado (http)",
                    "Empieza por «http://», sin la «s»: lo que escribas viaja sin cifrar. Ningún banco usa eso para entrar a tu cuenta.", "No escribas claves ni datos ahí.");

            if (n.PuertoRaro)
                Add("ENL-PUERTO", Severidad.Baja, "El enlace usa un puerto poco habitual",
                    "Lleva el número «:" + n.Puerto.ToString(CultureInfo.InvariantCulture) + "» después del nombre. Las webs normales casi nunca lo necesitan.", "Desconfía si no lo esperabas.");

            if (!n.EsIp && CatalogoDeMarcas.TerminacionesAbusadas.Contains(Dominios.Terminacion(n.Sitio)))
                Add("ENL-TERMINACION", Severidad.Baja, "Termina en «." + Dominios.Terminacion(n.Sitio) + "», muy usada en estafas",
                    "Es una terminación barata o gratuita que se usa mucho para sitios de estafa. Muchas webs normales también la usan: por sí sola no prueba nada.",
                    "Tómalo como una señal más, no como prueba.");

            return new EnlaceRevisado(n.Original, n.Sitio, n.SitioLegible, VeredictoDe(hs), hs, oficial?.Nombre);
        }

        // Las frases se buscan sin tildes y en minusculas. Solo español (decision del proyecto): en otro idioma no se reconoce nada.
        private static readonly (string Grupo, Regex Patron)[] Frases =
        {
            ("credenciales", R(@"\bclaves?\b|\bcontrasenas?\b|\bcoordenadas\b|\bcodigo (de )?(verificacion|seguridad|sms|confirmacion)\b|\bcodigo que (te |le )?(llego|enviamos|llegara)\b|\bpin\b|\bsuperclave\b|\bdigipass\b|\bdatos bancarios\b|\bnumero de (tu |su )?tarjeta\b|\bcvv\b|\b(actualiza|actualizar|actualice|verifica|verificar|verifique|confirma|confirmar|confirme|valida|validar|valide|regulariza|regularizar|regularice) (tus|sus|los) (datos|cuenta|informacion)\b")),
            ("urgencia", R(@"\burgente\b|\binmediat\w*|\bultimo aviso\b|\b(24|48|72) ?(h|hrs|horas)\b|\bhoy mismo\b|\bde lo contrario\b|\b(sera|seran|ha sido|han sido|fue|esta|se encuentra) (bloquead|suspendid|desactivad|cancelad|eliminad|restringid)\w*|\bcaduca\w*|\bvence hoy\b|\bexpira\w*")),
            ("pago", R(@"\bpago pendiente\b|\bdeuda\b|\bmulta\b|\btag\b|\bpeajes?\b|\baduana\b|\b(paquete|envio|pedido|encomienda) (esta |se encuentra |fue )?(retenid\w*|pendiente|detenid\w*|en espera)|\b(costo|cargo|tasa|tarifa) de (envio|aduana|entrega|reenvio)\b|\breembolso\b|\bdevolucion de impuestos\b")),
            ("premio", R(@"\bganaste\b|\bganador(a)?\b|\bpremio\b|\bsorteo\b|\bfelicidades\b|\bfelicitaciones\b|\bregalo\b|\bbeneficio exclusivo\b|\bhas sido seleccionad\w*"))
        };

        private static Regex R(string p) => new(p, RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

        public static string SinTildes(string s)
        {
            string d = s.Normalize(NormalizationForm.FormD);
            var sb = new StringBuilder(d.Length);
            foreach (char c in d)
                if (CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark) sb.Append(c);
            return sb.ToString().Normalize(NormalizationForm.FormC).ToLowerInvariant();
        }

        /// <summary>«Nunca te pediremos tu clave», «no compartas tu código»: el mensaje advierte en vez de pedir (los reales del banco lo dicen).</summary>
        private static readonly Regex Advertencia = R(@"\bnunca (te |le |les )?(pediremos|pedimos|solicitaremos|solicitamos|vamos a pedir|llamaremos)\b|\bno (compartas|comparta|entregues|entregue|des|de a nadie|reveles|revele) (tu|su|tus|sus|nunca)\b");

        private static IEnumerable<HallazgoDeSistema> RevisarFrases(string texto, bool hayEnlaces, bool todosOficiales)
        {
            if (string.IsNullOrWhiteSpace(texto)) yield break;
            string t = Regex.Replace(SinTildes(texto), @"\s+", " ");
            var porGrupo = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            foreach ((string grupo, Regex patron) in Frases)
            {
                List<string> vistas;
                try { vistas = patron.Matches(t).Select(m => m.Value.Trim()).Distinct(StringComparer.Ordinal).Take(4).ToList(); }
                catch (RegexMatchTimeoutException) { continue; }
                if (vistas.Count > 0) porGrupo[grupo] = vistas;
            }

            if (porGrupo.TryGetValue("credenciales", out List<string>? cred))
            {
                bool advierte = Advertencia.IsMatch(t);
                if (hayEnlaces && (advierte || todosOficiales))
                    // Bajado a Media y no quitado: un estafador tambien puede copiar «nunca te pediremos tu clave» o poner un enlace oficial de adorno.
                    yield return new HallazgoDeSistema("MSJ-PIDE-CLAVES", advierte && todosOficiales ? Severidad.Baja : Severidad.Media, "El mensaje habla de claves o datos y trae un enlace",
                        "Menciona " + Citas(cred) + (advierte ? ", aunque parece advertir en vez de pedir" : "") + (todosOficiales ? ", y los enlaces son de dominios oficiales que Nexo conoce" : "") +
                        ". Aun así, los bancos y servicios serios no piden claves, códigos ni datos de tarjetas por mensaje.",
                        "No entregues ninguna clave ni código. Si te preocupa tu cuenta, entra tú mismo por la aplicación o la web oficial.");
                else if (hayEnlaces)
                    yield return new HallazgoDeSistema("MSJ-PIDE-CLAVES", Severidad.Alta, "El mensaje pide claves o datos y trae un enlace",
                        "Menciona " + Citas(cred) + " y trae un enlace. Los bancos, el SII, Correos y las tiendas serias no piden claves, códigos ni datos de tarjetas por mensaje.",
                        "No abras el enlace ni respondas. Si te preocupa tu cuenta, entra tú mismo por la aplicación o la web oficial.");
                else
                    yield return new HallazgoDeSistema("MSJ-PIDE-CLAVES", Severidad.Media, "El mensaje habla de claves o datos",
                        "Menciona " + Citas(cred) + ". Nadie serio te pedirá claves, códigos ni datos de tarjetas por mensaje o por teléfono.",
                        "No entregues ninguna clave ni código, aunque digan ser del banco.");
            }

            string[] presion = new[] { "urgencia", "pago", "premio" }.Where(porGrupo.ContainsKey).ToArray();
            if (presion.Length > 0)
            {
                string todas = string.Join("; ", presion.Select(g => Citas(porGrupo[g])));
                if (presion.Length >= 2)
                    yield return new HallazgoDeSistema("MSJ-PRESION", Severidad.Media, "El mensaje usa varias tácticas típicas de estafa",
                        "Combina " + string.Join(" y ", presion.Select(NombreDeGrupo)) + ": " + todas + ". Las estafas meten prisa para que no lo pienses.",
                        "Tómate tu tiempo y comprueba por otra vía (la app oficial, un número que ya conoces).");
                else
                    yield return new HallazgoDeSistema("MSJ-PRESION", Severidad.Baja, "El mensaje usa una táctica típica de estafa",
                        "Habla de " + NombreDeGrupo(presion[0]) + ": " + todas + ". Los mensajes reales también pueden hacerlo: por sí solo no prueba nada.",
                        "Si no lo esperabas, comprueba por otra vía antes de hacer nada.");
            }
        }

        private static string NombreDeGrupo(string g) => g switch
        {
            "urgencia" => "urgencia o amenaza de bloqueo",
            "pago" => "pagos, deudas o envíos retenidos",
            _ => "premios o regalos"
        };

        private static string Citas(IEnumerable<string> frases) => string.Join(", ", frases.Select(f => "«" + f + "»"));

        private static string Recortar(string s, int max) => s.Length <= max ? s : s.Substring(0, max) + "…";
    }
}
