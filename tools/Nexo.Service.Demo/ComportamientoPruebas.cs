using System;
using System.Linq;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Comportamiento;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        private sealed class FuenteFalsa : IFuenteDeComportamiento
        {
            public string? Motivo; public bool Lanza; public bool Viva; public long Perdidos; public long Vistos; public bool Cerrada; public int Aperturas;
            public string? Iniciar() { Aperturas++; if (Lanza) throw new InvalidOperationException("x"); Viva = Motivo is null; return Motivo; }
            public bool Activa => Viva; public long Recibidos => Vistos; public long Descartados => Perdidos;
            public void Dispose() => Cerrada = true;
        }

        public static async Task ProbarComportamientoDelServicio()
        {
            Console.WriteLine("Análisis de comportamiento del servicio (§2bc): sesión, hallazgos y lo que no se pudo");

            // Sin permiso: no arranca, lo dice y NUNCA «sin sospechas».
            var sin = new FuenteFalsa { Motivo = "hace falta ejecutar como administrador" };
            var m0 = new ModuloComportamiento(sin, new PuntuadorDeComportamiento());
            m0.Iniciar();
            var e0 = (await PedirSenuelos(m0, "comportamiento.estado", null)).R!.Value;
            Check(e0.GetProperty("activo").GetBoolean() && !e0.GetProperty("sesion_activa").GetBoolean() && !e0.GetProperty("sin_sospechas").GetBoolean() && !e0.GetProperty("completo").GetBoolean()
                  && e0.GetProperty("aviso").GetString()!.Contains("administrador") && e0.GetProperty("no_evaluado")[0].GetString()!.Contains("no está en marcha"),
                  "sin administrador: sesión inactiva, aviso con el motivo y NO «sin sospechas»", e0.GetRawText());

            // Una fuente que lanza al abrir no tumba el servicio.
            var lanza = new ModuloComportamiento(new FuenteFalsa { Lanza = true }, new PuntuadorDeComportamiento());
            lanza.Iniciar();
            var el = (await PedirSenuelos(lanza, "comportamiento.estado", null)).R!.Value;
            Check(!el.GetProperty("sesion_activa").GetBoolean() && el.GetProperty("aviso").GetString()!.Contains("InvalidOperationException"), "si abrir la sesión lanza, el servicio sigue y el estado lo dice");

            // Sesión viva y sin nada: «sin sospechas».
            var pun = new PuntuadorDeComportamiento();
            var viva = new FuenteFalsa { Vistos = 42 };
            var m = new ModuloComportamiento(viva, pun);
            m.Iniciar(); m.Iniciar(); // dos veces: abre una sola
            Check(viva.Aperturas == 1, "iniciar dos veces abre la sesión una sola vez");
            var e1 = (await PedirSenuelos(m, "comportamiento.estado", null)).R!.Value;
            Check(e1.GetProperty("sesion_activa").GetBoolean() && e1.GetProperty("sin_sospechas").GetBoolean() && e1.GetProperty("eventos_recibidos").GetInt64() == 42 && e1.GetProperty("aviso").ValueKind == System.Text.Json.JsonValueKind.Null,
                  "sesión viva y sin hallazgos: «sin sospechas»", e1.GetRawText());

            // Un hallazgo real del puntuador aparece y quita el «sin sospechas».
            pun.Registrar(new EventoDeComportamiento(TipoDeSenal.ServicioCreado, 10, "x.exe", @"C:\Users\ana\Downloads\x.exe", EstadoDeFirma.Ausente));
            var e2 = (await PedirSenuelos(m, "comportamiento.estado", null)).R!.Value;
            Check(e2.GetProperty("hallazgos").GetArrayLength() == 1 && !e2.GetProperty("sin_sospechas").GetBoolean() && e2.GetProperty("severidad_maxima").GetString() == "Alta"
                  && e2.GetProperty("hallazgos")[0].GetProperty("sujeto").GetString() == "x.exe", "un hallazgo del puntuador sale con severidad y sujeto, y quita el «sin sospechas»", e2.GetRawText());

            // Eventos perdidos: no se puede decir «sin sospechas».
            var perdida = new FuenteFalsa { Perdidos = 7 };
            var m3 = new ModuloComportamiento(perdida, new PuntuadorDeComportamiento());
            m3.Iniciar();
            var e3 = (await PedirSenuelos(m3, "comportamiento.estado", null)).R!.Value;
            Check(!e3.GetProperty("sin_sospechas").GetBoolean() && e3.GetProperty("no_evaluado").EnumerateArray().Any(x => x.GetString()!.Contains("se perdieron 7")), "con eventos perdidos: no es «sin sospechas» y lo dice");

            // Firma desconocida: se dice, pero no impide «sin sospechas» (no acusa).
            var pd = new PuntuadorDeComportamiento();
            pd.Registrar(new EventoDeComportamiento(TipoDeSenal.ProcesoIniciado, 5, "a.exe"));
            var m4 = new ModuloComportamiento(new FuenteFalsa(), pd);
            m4.Iniciar();
            var e4 = (await PedirSenuelos(m4, "comportamiento.estado", null)).R!.Value;
            Check(e4.GetProperty("sin_sospechas").GetBoolean() && !e4.GetProperty("completo").GetBoolean() && e4.GetProperty("no_evaluado")[0].GetString()!.Contains("firma digital"), "firma desconocida: «sin sospechas» pero NO completo");

            // Contrato: el JSON REAL del servicio lo lee la ventana igual que el servicio lo dice.
            static Nexo.Ui.Desktop.Nucleo.RespuestaCruda Cruda(System.Text.Json.JsonElement x) => new(true, null, x);
            var lc = Nexo.Ui.Desktop.Nucleo.LectorDeComportamientoDelServicio.Leer(Cruda(e2));
            Check(lc.Valor is { Eventos: 42 } && lc.Valor.Analisis.Hallazgos.Single().Severidad == Nexo.Reports.Model.Severidad.Alta, "la ventana lee el estado real con un hallazgo", lc.Error ?? e2.GetRawText());
            var lc0 = Nexo.Ui.Desktop.Nucleo.LectorDeComportamientoDelServicio.Leer(Cruda(e0));
            Check(lc0.Valor is { } v0 && !v0.Analisis.Completo && v0.Analisis.NoEvaluado.Any(x => x.Contains("administrador")), "sin sesión: la ventana lo lee como «no evaluado» con el motivo", lc0.Error);
            var lc3 = Nexo.Ui.Desktop.Nucleo.LectorDeComportamientoDelServicio.Leer(Cruda(e3));
            Check(lc3.Valor is { } v3 && v3.Analisis.NoEvaluado.Any(x => x.Contains("se perdieron 7")), "con eventos perdidos: la ventana lo lee como «no evaluado»", lc3.Error);
            var lap = Nexo.Ui.Desktop.Nucleo.LectorDeComportamientoDelServicio.Leer(Cruda((await PedirSenuelos(new ModuloComportamientoApagado(), "comportamiento.estado", null)).R!.Value));
            Check(lap.Valor is { Nota: not null } && lap.Valor.Nota.Contains("Nexo:Comportamiento:Activo"), "apagado: la ventana lo lee como apagado, con la nota");

            // Método desconocido, apagado y cierre.
            var malo = await PedirSenuelos(m, "comportamiento.otra", null);
            Check(!malo.Ok, "un método desconocido se rechaza");
            var ap = (await PedirSenuelos(new ModuloComportamientoApagado(), "comportamiento.estado", null)).R!.Value;
            Check(!ap.GetProperty("activo").GetBoolean() && !ap.GetProperty("sin_sospechas").GetBoolean() && ap.GetProperty("nota").GetString()!.Contains("Nexo:Comportamiento:Activo"), "apagado: lo dice y dónde se activa");
            await m.DisposeAsync();
            Check(viva.Cerrada, "al cerrar el servicio se cierra la sesión");
        }
    }
}
