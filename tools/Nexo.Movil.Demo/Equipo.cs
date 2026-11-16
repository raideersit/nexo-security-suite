using System;
using System.Collections.Generic;
using System.Linq;
using Nexo.Modules.Threats.Apps;

namespace Nexo.Movil.Demo
{
    internal static partial class Program
    {
        private static readonly DateTime Hoy = new(2026, 11, 16);

        private static Comprobacion Fila(IReadOnlyList<Comprobacion> l, string nombre) => l.Single(c => c.Nombre == nombre);

        private static DatosDelEquipo Sano() => new()
        {
            BloqueoDePantalla = true, ParcheDeSeguridad = Hoy.AddDays(-30), Api = 34, Release = "14",
            OpcionesDeDesarrollo = false, DepuracionUsb = false, Wifi = SeguridadDeWifi.Cifrada,
            AppsQueInstalan = Array.Empty<AppQueInstala>(),
        };

        private static void ProbarChequeoDelEquipo()
        {
            var cat = CatalogoDeSenales.Embebido();
            Titulo("Equipo: un telefono sano");
            var sano = ChequeoDelEquipo.Evaluar(Sano(), Hoy, cat);
            Check(ChequeoDelEquipo.Avisos(sano) == 0, "sin avisos", string.Join(";", sano.Where(c => c.Nivel == NivelDeComprobacion.Aviso).Select(c => c.Nombre)));
            Check(sano.Select(c => c.Nombre).Distinct().Count() == sano.Count, "cada comprobacion aparece una sola vez");

            Titulo("Equipo: bloqueo, desarrollador y depuracion");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { BloqueoDePantalla = false }, Hoy, cat), "Bloqueo de pantalla").Nivel == NivelDeComprobacion.Aviso, "sin bloqueo: aviso");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { BloqueoDePantalla = null }, Hoy, cat), "Bloqueo de pantalla").Nivel == NivelDeComprobacion.Info, "bloqueo ilegible: sin evaluar (no «bien»)");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { DepuracionUsb = true }, Hoy, cat), "Depuración USB").Nivel == NivelDeComprobacion.Aviso, "depuracion USB encendida: aviso");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { OpcionesDeDesarrollo = true }, Hoy, cat), "Opciones de desarrollador").Nivel == NivelDeComprobacion.Aviso, "opciones de desarrollador encendidas: aviso");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { DepuracionUsb = null }, Hoy, cat), "Depuración USB").Nivel == NivelDeComprobacion.Info, "depuracion ilegible: sin evaluar");

            Titulo("Equipo: parche de seguridad");
            Check(cat.ParcheMaximoDias == 90, "el umbral sale del catalogo (90 dias)");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { ParcheDeSeguridad = Hoy.AddDays(-90) }, Hoy, cat), "Parche de seguridad").Nivel == NivelDeComprobacion.Bien, "exactamente 90 dias: todavia bien");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { ParcheDeSeguridad = Hoy.AddDays(-91) }, Hoy, cat), "Parche de seguridad").Nivel == NivelDeComprobacion.Aviso, "91 dias: aviso");
            var futuro = Fila(ChequeoDelEquipo.Evaluar(Sano() with { ParcheDeSeguridad = Hoy.AddDays(10) }, Hoy, cat), "Parche de seguridad");
            Check(futuro.Nivel == NivelDeComprobacion.Info && futuro.Detalle.Contains("futura"), "fecha futura (reloj mal): sin evaluar, no «al dia»");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { ParcheDeSeguridad = null }, Hoy, cat), "Parche de seguridad").Nivel == NivelDeComprobacion.Info, "parche ilegible: sin evaluar");

            Titulo("Equipo: version de Android");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { Api = cat.ApiMinimaConSoporte }, Hoy, cat), "Versión de Android").Nivel == NivelDeComprobacion.Bien, "la version minima con soporte: bien");
            var vieja = Fila(ChequeoDelEquipo.Evaluar(Sano() with { Api = cat.ApiMinimaConSoporte - 1 }, Hoy, cat), "Versión de Android");
            Check(vieja.Nivel == NivelDeComprobacion.Aviso && vieja.Detalle.Contains("provisional"), "una version mas vieja: aviso, y dice que la tabla es provisional");

            Titulo("Equipo: Wi-Fi (solo el tipo de seguridad)");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { Wifi = SeguridadDeWifi.Abierta }, Hoy, cat), "Wi-Fi actual").Nivel == NivelDeComprobacion.Aviso, "red abierta: aviso");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { Wifi = SeguridadDeWifi.Wep }, Hoy, cat), "Wi-Fi actual").Nivel == NivelDeComprobacion.Aviso, "WEP: aviso");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { Wifi = SeguridadDeWifi.NoConectado }, Hoy, cat), "Wi-Fi actual").Nivel == NivelDeComprobacion.Info, "sin Wi-Fi: es un hecho, no un aviso");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { Wifi = SeguridadDeWifi.NoEvaluable }, Hoy, cat), "Wi-Fi actual").Nivel == NivelDeComprobacion.Info, "no evaluable (Android 11): sin evaluar");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { Wifi = SeguridadDeWifi.Desconocida }, Hoy, cat), "Wi-Fi actual").Nivel == NivelDeComprobacion.Info, "tipo desconocido: no se da por bueno");
            Check(typeof(DatosDelEquipo).GetProperties().All(p => !p.Name.Contains("Ssid", StringComparison.OrdinalIgnoreCase) && !p.Name.Contains("Bssid", StringComparison.OrdinalIgnoreCase) && !p.Name.Contains("NombreDeRed", StringComparison.OrdinalIgnoreCase)),
                "el modelo no tiene campo para el nombre de la red: no puede filtrarlo ni pedir ubicacion");

            Titulo("Equipo: apps que pueden instalar otras apps");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { AppsQueInstalan = null }, Hoy, cat), "Apps que pueden instalar otras apps").Detalle == "Calculando...", "mientras se calcula lo dice");
            var una = new[] { new AppQueInstala("Chrome", "com.android.chrome", NivelDeRiesgo.Normal) };
            var fu = Fila(ChequeoDelEquipo.Evaluar(Sano() with { AppsQueInstalan = una }, Hoy, cat), "Apps que pueden instalar otras apps");
            Check(fu.Nivel == NivelDeComprobacion.Info && fu.Detalle.Contains("Chrome"), "una app normal con el permiso: informativo, con su nombre");
            var mala = new[] { new AppQueInstala("Chrome", "com.android.chrome", NivelDeRiesgo.Normal), new AppQueInstala("Rara", "com.rara", NivelDeRiesgo.Prioritaria) };
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { AppsQueInstalan = mala }, Hoy, cat), "Apps que pueden instalar otras apps").Nivel == NivelDeComprobacion.Aviso, "si una de ellas ademas tiene riesgo: aviso (se cruza con §3.1)");
            var muchas = Enumerable.Range(0, 9).Select(i => new AppQueInstala("App" + i, "com.a" + i, NivelDeRiesgo.Normal)).ToList();
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { AppsQueInstalan = muchas }, Hoy, cat), "Apps que pueden instalar otras apps").Detalle.Contains("y 4 más"), "con muchas, lista 5 y resume el resto");

            Titulo("Equipo: root y Play Protect");
            Check(Fila(ChequeoDelEquipo.Evaluar(Sano() with { PistasDeRoot = new[] { "compilacion test-keys" } }, Hoy, cat), "Indicios de root").Nivel == NivelDeComprobacion.Info, "indicios de root: solo informativo, nunca aviso");
            Check(Fila(sano, "Play Protect").Nivel == NivelDeComprobacion.Info && Fila(sano, "Play Protect").Detalle.Contains("no permite leerlo"), "Play Protect: dice que Android no deja leerlo");

            Titulo("Equipo: el catalogo valida la seccion «equipo»");
            const string Base = """{"umbrales":{"aRevisar":4,"prioritaria":7},"equipo":{"parcheMaximoDias":90,"apiMinimaConSoporte":34},"senales":[{"id":"a","peso":1,"motivo":"motivo de prueba largo"}],"combinaciones":[],"origenes":{},"appsConocidas":[]}""";
            Check(Lanza(Base) is null, "una seccion «equipo» valida carga");
            Check(Lanza(Base.Replace("\"parcheMaximoDias\":90", "\"parcheMaximoDias\":0")) is not null, "parche de 0 dias es invalido");
            Check(Lanza(Base.Replace("\"apiMinimaConSoporte\":34", "\"apiMinimaConSoporte\":5")) is not null, "API minima absurda es invalida");
            Check(Lanza(Base.Replace("\"equipo\":{\"parcheMaximoDias\":90,\"apiMinimaConSoporte\":34},", "")) is not null, "sin seccion «equipo» tambien falla (no se usan valores a ciegas)");
        }
    }
}
