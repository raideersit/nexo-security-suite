using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Nexo.Modules.Threats.Apps
{
    // =====================================================================================================
    //  CHEQUEO DEL EQUIPO (Salida 7, 3.4). Portable: recibe DATOS ya leidos y devuelve una lista de comprobacion.
    //  Todo es SOLO LECTURA. Un dato que no se pudo leer es «sin evaluar» (Info), nunca «todo bien».
    //  Sobre el Wi-Fi: solo se recibe el TIPO de seguridad. No hay campo para el nombre de la red, y por eso el chequeo no puede
    //  filtrarlo ni pedir el permiso de ubicacion que ese nombre exigiria.
    // =====================================================================================================

    public enum NivelDeComprobacion { Bien, Aviso, Info }

    /// <param name="DetalleParaReporte">
    /// Texto para el vault de Obsidian cuando el detalle de pantalla lleva datos personales (nombres de apps). null = se usa <paramref name="Detalle"/>.
    /// </param>
    public sealed record Comprobacion(string Nombre, NivelDeComprobacion Nivel, string Detalle, string? DetalleParaReporte = null);

    /// <summary>Seguridad de la red Wi-Fi actual, ya reducida a lo que importa (la traduccion desde los codigos de Android vive en el lector).</summary>
    public enum SeguridadDeWifi { NoConectado, NoEvaluable, Abierta, Wep, Cifrada, Desconocida }

    /// <summary>Una app que puede instalar otras apps, con su nivel de riesgo de §3.1.</summary>
    public sealed record AppQueInstala(string Nombre, string Paquete, NivelDeRiesgo Riesgo);

    public sealed record DatosDelEquipo
    {
        public bool? BloqueoDePantalla { get; init; }
        /// <summary>Fecha del parche de seguridad, o null si no se pudo leer.</summary>
        public DateTime? ParcheDeSeguridad { get; init; }
        public int Api { get; init; }
        public string Release { get; init; } = "";
        public bool? OpcionesDeDesarrollo { get; init; }
        public bool? DepuracionUsb { get; init; }
        public IReadOnlyList<string> PistasDeRoot { get; init; } = Array.Empty<string>();
        public SeguridadDeWifi Wifi { get; init; } = SeguridadDeWifi.NoEvaluable;
        /// <summary>null = todavia no se calcula (necesita leer todas las apps).</summary>
        public IReadOnlyList<AppQueInstala>? AppsQueInstalan { get; init; }
    }

    public static class ChequeoDelEquipo
    {
        private const int MaximoDeNombres = 5;

        public static IReadOnlyList<Comprobacion> Evaluar(DatosDelEquipo d, DateTime hoy, CatalogoDeSenales catalogo)
        {
            var r = new List<Comprobacion>();

            r.Add(d.BloqueoDePantalla switch
            {
                true => new("Bloqueo de pantalla", NivelDeComprobacion.Bien, "Hay PIN, patrón o clave."),
                false => new("Bloqueo de pantalla", NivelDeComprobacion.Aviso, "Sin bloqueo: cualquiera con el teléfono entra a todo."),
                null => new("Bloqueo de pantalla", NivelDeComprobacion.Info, "No se pudo leer."),
            });

            r.Add(Parche(d.ParcheDeSeguridad, hoy, catalogo.ParcheMaximoDias));

            r.Add(d.Api >= catalogo.ApiMinimaConSoporte
                ? new("Versión de Android", NivelDeComprobacion.Bien, $"Android {d.Release} (API {d.Api}).")
                : new("Versión de Android", NivelDeComprobacion.Aviso, $"Android {d.Release} (API {d.Api}) puede haber dejado de recibir parches. (Tabla provisional: se revisa a mano.)"));

            r.Add(Ajuste("Opciones de desarrollador", d.OpcionesDeDesarrollo, "apagadas.", "encendidas: normal si programas, riesgoso si no."));
            r.Add(Ajuste("Depuración USB", d.DepuracionUsb, "apagada.", "encendida: un cable con un PC autorizado controla el teléfono."));

            r.Add(d.PistasDeRoot.Count == 0
                ? new("Indicios de root", NivelDeComprobacion.Bien, "Ninguno (solo informativo).")
                : new("Indicios de root", NivelDeComprobacion.Info, string.Join(", ", d.PistasDeRoot)));

            r.Add(Wifi(d.Wifi));
            r.Add(Instaladoras(d.AppsQueInstalan));
            r.Add(new("Play Protect", NivelDeComprobacion.Info, "Android no permite leerlo: se revisa a mano en Play Store (Perfil > Play Protect)."));
            return r;
        }

        public static int Avisos(IEnumerable<Comprobacion> c) => c.Count(x => x.Nivel == NivelDeComprobacion.Aviso);

        private static Comprobacion Parche(DateTime? parche, DateTime hoy, int maxDias)
        {
            if (parche is null) return new("Parche de seguridad", NivelDeComprobacion.Info, "No se pudo leer la fecha.");
            var texto = parche.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            int dias = (int)(hoy.Date - parche.Value.Date).TotalDays;
            if (dias < 0) return new("Parche de seguridad", NivelDeComprobacion.Info, $"{texto}: es una fecha futura (¿el reloj del teléfono está mal?).");
            return dias > maxDias
                ? new("Parche de seguridad", NivelDeComprobacion.Aviso, $"{texto}: hace {dias} días (más de {maxDias}).")
                : new("Parche de seguridad", NivelDeComprobacion.Bien, $"{texto}: hace {dias} días.");
        }

        private static Comprobacion Ajuste(string nombre, bool? valor, string bien, string aviso) => valor switch
        {
            false => new(nombre, NivelDeComprobacion.Bien, nombre + " " + bien),
            true => new(nombre, NivelDeComprobacion.Aviso, aviso),
            null => new(nombre, NivelDeComprobacion.Info, "No se pudo leer."),
        };

        private static Comprobacion Wifi(SeguridadDeWifi w) => w switch
        {
            SeguridadDeWifi.Cifrada => new("Wi-Fi actual", NivelDeComprobacion.Bien, "La red tiene cifrado."),
            SeguridadDeWifi.Abierta => new("Wi-Fi actual", NivelDeComprobacion.Aviso, "La red NO tiene cifrado: cualquiera cerca puede ver el tráfico que no vaya cifrado por su cuenta. Evita usar cuentas o claves en ella."),
            SeguridadDeWifi.Wep => new("Wi-Fi actual", NivelDeComprobacion.Aviso, "La red usa WEP, un cifrado roto desde hace años. Equivale a no tener cifrado."),
            SeguridadDeWifi.NoConectado => new("Wi-Fi actual", NivelDeComprobacion.Info, "No estás conectado a una red Wi-Fi."),
            SeguridadDeWifi.Desconocida => new("Wi-Fi actual", NivelDeComprobacion.Info, "La red usa un tipo de seguridad que Nexo no reconoce: no se evaluó."),
            _ => new("Wi-Fi actual", NivelDeComprobacion.Info, "No se pudo evaluar (necesita Android 12 o superior)."),
        };

        private static Comprobacion Instaladoras(IReadOnlyList<AppQueInstala>? apps)
        {
            if (apps is null) return new("Apps que pueden instalar otras apps", NivelDeComprobacion.Info, "Calculando...");
            if (apps.Count == 0) return new("Apps que pueden instalar otras apps", NivelDeComprobacion.Bien, "Ninguna app de usuario tiene ese permiso concedido.");
            var nombres = string.Join(", ", apps.Take(MaximoDeNombres).Select(a => string.IsNullOrEmpty(a.Nombre) ? a.Paquete : a.Nombre))
                          + (apps.Count > MaximoDeNombres ? $" y {apps.Count - MaximoDeNombres} más" : "");
            var dudosas = apps.Where(a => a.Riesgo is NivelDeRiesgo.ARevisar or NivelDeRiesgo.Prioritaria).ToList();
            // Para el vault solo la cantidad: los nombres de las apps instaladas son informacion personal.
            var paraReporte = $"{apps.Count} con el permiso concedido" + (dudosas.Count > 0 ? $", {dudosas.Count} con señales de riesgo (los nombres no se guardan en el vault)." : " (los nombres no se guardan en el vault).");
            return dudosas.Count > 0
                ? new("Apps que pueden instalar otras apps", NivelDeComprobacion.Aviso, $"{apps.Count} con el permiso concedido: {nombres}. {dudosas.Count} de ellas además tiene(n) señales de riesgo (ver «Apps instaladas»).", paraReporte)
                : new("Apps que pueden instalar otras apps", NivelDeComprobacion.Info, $"{apps.Count} con el permiso concedido: {nombres}. Es normal en navegadores y gestores de archivos.", paraReporte);
        }
    }
}
