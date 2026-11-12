using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Comportamiento;
using Nexo.Service;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Tray.Demo
{
    internal static partial class Program
    {
        private sealed class FuenteDeComportamientoFalsa : IFuenteDeComportamiento
        {
            public string? Iniciar() => null;
            public bool Activa => true;
            public long Recibidos => 10;
            public long Descartados => 0;
            public void Dispose() { }
        }

        /// <summary>El comportamiento sospechoso en la bandeja, con el JSON REAL de ModuloComportamiento: globo solo para Alta, una vez por hallazgo.</summary>
        private static async Task ProbarComportamientoEnLaBandeja()
        {
            Console.WriteLine("Comportamiento sospechoso en la bandeja (con el JSON real del servicio)");
            static JsonElement J(object? o) => JsonSerializer.SerializeToElement(o);

            Check(ConsultorDelServicio.LeerComportamiento(J(await new ModuloComportamientoApagado().ManejarAsync("comportamiento.estado", null, CancellationToken.None)))!.Count == 0, "apagado: ningún aviso (lista vacía, no «desconocido»)");

            // Media (sin firma + Inicio = 5): se ve en la ventana, pero NO merece un globo.
            var pMedia = new PuntuadorDeComportamiento();
            pMedia.Registrar(new EventoDeComportamiento(TipoDeSenal.ArchivoEnInicio, 10, "x.exe", @"C:\Program Files\X\x.exe", EstadoDeFirma.Ausente, @"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\a.lnk"));
            var mMedia = new ModuloComportamiento(new FuenteDeComportamientoFalsa(), pMedia); mMedia.Iniciar();
            var estadoMedia = J(await mMedia.ManejarAsync("comportamiento.estado", null, CancellationToken.None));
            Check(estadoMedia.GetProperty("hallazgos").GetArrayLength() == 1 && ConsultorDelServicio.LeerComportamiento(estadoMedia)!.Count == 0, "Media: hay hallazgo en el servicio pero la bandeja no abre un globo");

            // Alta (sin firma + Descargas + Inicio = 6): globo.
            var pAlta = new PuntuadorDeComportamiento();
            pAlta.Registrar(new EventoDeComportamiento(TipoDeSenal.ArchivoEnInicio, 11, "malo.exe", @"C:\Users\a\Downloads\malo.exe", EstadoDeFirma.Ausente, @"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\a.lnk"));
            var mAlta = new ModuloComportamiento(new FuenteDeComportamientoFalsa(), pAlta); mAlta.Iniciar();
            var estadoAlta = J(await mAlta.ManejarAsync("comportamiento.estado", null, CancellationToken.None));
            var graves = ConsultorDelServicio.LeerComportamiento(estadoAlta);
            Check(graves is { Count: 1 } && graves[0].Severidad == "Alta" && graves[0].Sujeto == "malo.exe", "Alta: un aviso, con el programa", estadoAlta.GetRawText());

            var m = new ModeloDeBandeja();
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { ComportamientoAvisos = graves });
            Check(m.ComportamientoNuevo.Count == 1 && m.MineriaNueva.Count == 0, "el modelo lo da como nuevo la primera vez (y no se mezcla con la criptominería)");
            (string titulo, string texto) = AccionesDelServicio.AvisoDeComportamiento(m.ComportamientoNuevo);
            Check(titulo.Contains("comportamiento sospechoso") && texto.Contains("no detiene nada") && texto.Contains("analízalo"), "el aviso dice qué hacer y que Nexo no detiene nada");
            Check(AccionesDelServicio.TextoDeComportamiento(graves!).Contains("solo observa") && AccionesDelServicio.TextoDeComportamiento(graves!).Contains("malo.exe"), "el diálogo explica qué hacer, nombra el programa y dice que solo observa");

            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { ComportamientoAvisos = graves });
            Check(m.ComportamientoNuevo.Count == 0, "en la siguiente consulta NO se vuelve a avisar");
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { ComportamientoAvisos = null });
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { ComportamientoAvisos = graves });
            Check(m.ComportamientoNuevo.Count == 0, "sin poder leerlo y al volver, el mismo hallazgo no se avisa dos veces");
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { ComportamientoAvisos = Array.Empty<AvisoDeMineriaVista>() });
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { ComportamientoAvisos = graves });
            Check(m.ComportamientoNuevo.Count == 1, "si desaparece y vuelve a aparecer, se avisa de nuevo");

            Check(ConsultorDelServicio.LeerComportamiento(JsonDocument.Parse("{\"activo\":true,\"hallazgos\":[{\"id\":\"X\",\"severidad\":\"Grave\",\"titulo\":\"t\",\"sujeto\":null}]}").RootElement) is null, "una gravedad desconocida: null");
        }
    }
}
