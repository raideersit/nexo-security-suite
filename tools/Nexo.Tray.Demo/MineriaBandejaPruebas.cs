using System;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Criptojacking;
using Nexo.Service;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Tray.Demo
{
    internal static partial class Program
    {
        private static MuestraDeMineria MuestraB(double cpu, string? ipRemota = null)
            => new(DateTimeOffset.Now, new[] { new ProcesoMuestreado(100, "minero", @"C:\Users\x\AppData\Local\Temp\m.exe", cpu, false) }, true,
                   ipRemota is null ? Array.Empty<ConexionDeProceso>() : new[] { new ConexionDeProceso(100, ipRemota, 443) }, true);

        /// <summary>La criptominería en la bandeja, con el JSON REAL de ModuloMineria: globo solo para Alta o Crítica, una vez por hallazgo.</summary>
        private static async Task ProbarMineriaEnLaBandeja()
        {
            Console.WriteLine("Criptominería en la bandeja (con el JSON real del servicio)");
            static JsonElement J(object? o) => JsonSerializer.SerializeToElement(o);

            Check(ConsultorDelServicio.LeerMineria(J(await new ModuloMineriaApagado().ManejarAsync("mineria.estado", null, CancellationToken.None)))!.Count == 0, "apagada: ningún aviso (lista vacía, no «desconocido»)");

            // CPU alta sola en Temp = «Media»: se ve en la ventana, pero NO merece un globo.
            var soloCpu = new ModuloMineria(() => MuestraB(90));
            soloCpu.PrepararParaPruebas(new ListaDePools(new[] { "203.0.113.9" }, Array.Empty<string>()));
            for (int i = 0; i < VigilanteDeMineria.MuestrasSostenidas; i++) await soloCpu.UnaVueltaAsync(CancellationToken.None);
            var estadoCpu = J(await soloCpu.ManejarAsync("mineria.estado", null, CancellationToken.None));
            Check(estadoCpu.GetProperty("hallazgos").GetArrayLength() == 1 && ConsultorDelServicio.LeerMineria(estadoCpu)!.Count == 0, "CPU sostenida sola (Media): hay hallazgo en el servicio pero la bandeja no abre un globo");

            // CPU sostenida + pool conocido = Crítica: globo.
            var pool = new ModuloMineria(() => MuestraB(90, "203.0.113.9"));
            pool.PrepararParaPruebas(new ListaDePools(new[] { "203.0.113.9" }, Array.Empty<string>()));
            for (int i = 0; i < VigilanteDeMineria.MuestrasSostenidas; i++) await pool.UnaVueltaAsync(CancellationToken.None);
            var estadoPool = J(await pool.ManejarAsync("mineria.estado", null, CancellationToken.None));
            var graves = ConsultorDelServicio.LeerMineria(estadoPool);
            Check(graves is { Count: 1 } && graves[0].Severidad == "Critica" && graves[0].Sujeto is not null, "CPU + pool de la lista (Crítica): un aviso, con el programa", estadoPool.GetRawText());

            var m = new ModeloDeBandeja();
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { MineriaAvisos = graves });
            Check(m.MineriaNueva.Count == 1, "el modelo lo da como nuevo la primera vez");
            (string titulo, string texto) = AccionesDelServicio.AvisoDeMineria(m.MineriaNueva);
            Check(titulo.Contains("grave") && texto.Contains("no detiene nada") && texto.Contains("Administrador de tareas") && texto.Contains("minero") && !texto.Contains("(minero)"), "el aviso dice qué mirar y que Nexo no detiene nada (sin repetir el nombre)", texto);
            Check(AccionesDelServicio.TextoDeMineria(graves!).Contains("solo observa"), "el diálogo explica qué hacer y que solo observa");

            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { MineriaAvisos = graves });
            Check(m.MineriaNueva.Count == 0, "en la siguiente consulta NO se vuelve a avisar");

            // Sin poder leerlo (null) no se afirma nada ni se repite el aviso al volver.
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { MineriaAvisos = null });
            Check(m.MineriaNueva.Count == 0, "sin poder leer la criptominería: nada nuevo");
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { MineriaAvisos = graves });
            Check(m.MineriaNueva.Count == 0, "y cuando vuelve a leerse, el mismo hallazgo no se avisa dos veces");

            // Desaparece y reaparece: es nuevo otra vez.
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { MineriaAvisos = Array.Empty<AvisoDeMineriaVista>() });
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { MineriaAvisos = graves });
            Check(m.MineriaNueva.Count == 1, "si desaparece y vuelve a aparecer, se avisa de nuevo");

            // Formas raras: nunca «ninguno» por no entender.
            Check(ConsultorDelServicio.LeerMineria(JsonDocument.Parse("{\"activo\":true,\"hallazgos\":[{\"id\":\"X\",\"severidad\":\"Grave\",\"titulo\":\"t\",\"sujeto\":null}]}").RootElement) is null, "una gravedad desconocida: null (no se interpreta a medias)");
            Check(ConsultorDelServicio.LeerMineria(JsonDocument.Parse("{\"activo\":true}").RootElement) is null, "sin «hallazgos»: null");
        }
    }
}
