using System;
using System.Collections.Generic;
using System.Globalization;
using Nexo.Modules.Threats.Enlaces;
using Nexo.Reports.Model;

namespace Nexo.Ui.Movil.Revisar;

/// <summary>
/// Textos del resultado de una revision. COPIA de ResumirEnlaces (src/Nexo.Ui.Desktop/EnlacesModelo.cs), adaptada a «tocar» en vez de «pulsar».
/// Se copia y no se mueve porque el escritorio se desarrolla en otro equipo: moverla provocaria conflictos. Si cambian alla, revisar aqui.
/// </summary>
public static class TextosDeEnlaces
{
    public static string Veredicto(Veredicto v) => v switch
    {
        Modules.Threats.Enlaces.Veredicto.Peligroso => "PELIGROSO",
        Modules.Threats.Enlaces.Veredicto.Sospechoso => "SOSPECHOSO",
        _ => "SIN SEÑALES CONOCIDAS",
    };

    public static (string Titulo, string Explicacion) General(RevisionDeMensaje r)
    {
        string incompleta = r.Analisis.Completo ? "" : " Revisión incompleta: mira abajo lo que no se pudo comprobar.";
        switch (r.Veredicto)
        {
            case Modules.Threats.Enlaces.Veredicto.Peligroso:
                return ("Peligroso: no abras el enlace ni respondas",
                    "Hay señales claras de estafa o phishing. Si crees que el mensaje puede ser real, entra escribiendo tú la dirección oficial o llama a un número que ya conoces." + incompleta);
            case Modules.Threats.Enlaces.Veredicto.Sospechoso:
                return ("Sospechoso: ten cuidado",
                    "Hay señales de que puede ser una estafa. No escribas claves ni datos de tarjetas desde este mensaje." + incompleta);
            default:
                if (r.Enlaces.Count == 0 && r.EnlacesIlegibles == 0)
                    return ("No se encontró ningún enlace",
                        (r.Analisis.Hallazgos.Count == 0 ? "Tampoco frases típicas de estafa (solo se reconocen en español). " : "") +
                        "Nexo reconoce enlaces con «http», con «www.» o con un nombre que termina en «.cl», «.com» y similares." + incompleta);
                return ("Sin señales conocidas (esto NO prueba que sea seguro)",
                    "No está en las listas de phishing y no tiene los trucos que Nexo reconoce. Los sitios de phishing nuevos tardan horas o días en entrar en las listas: si no esperabas el mensaje, desconfía igual." + incompleta);
        }
    }

    public static string Gravedad(Severidad s) => s switch
    {
        Severidad.Critica => "CRÍTICO",
        Severidad.Alta => "ALTO",
        Severidad.Media => "MEDIO",
        Severidad.Baja => "BAJO",
        _ => "INFORMATIVO",
    };

    public static string EstadoDeListas(ListasDePhishing l, IReadOnlyList<string> avisos, DateTimeOffset ahora)
    {
        var lineas = new List<string>();
        foreach (FuenteDeLista f in new[] { FuenteDeLista.PhishingArmy, FuenteDeLista.OpenPhish })
        {
            ListaCargada? x = l.De(f);
            string nombre = AnalizadorDeMensajes.NombreDe(f);
            if (x is null) { lineas.Add(nombre + ": no descargada."); continue; }
            TimeSpan a = x.Antiguedad(ahora);
            string edad = a.TotalHours < 1 ? "hace menos de una hora" : a.TotalDays < 2 ? "hace " + (int)a.TotalHours + " h" : "hace " + (int)a.TotalDays + " días";
            lineas.Add(nombre + ": " + x.Entradas.ToString("N0", CultureInfo.GetCultureInfo("es-CL")) + (f == FuenteDeLista.PhishingArmy ? " sitios" : " direcciones") + ", de " + edad +
                       (a > AnalizadorDeMensajes.ListaVieja ? " (vieja: conviene actualizarla)." : "."));
        }
        lineas.AddRange(avisos);
        return string.Join("\n", lineas);
    }
}
