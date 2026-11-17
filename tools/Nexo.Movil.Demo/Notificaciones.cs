using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Nexo.Modules.Threats.Apps;

namespace Nexo.Movil.Demo
{
    internal static partial class Program
    {
        private const long Dia = 24 * Hora;

        private static Comprobacion Fila(string nombre, NivelDeComprobacion nivel) => new(nombre, nivel, nombre + " detalle " + nivel);

        private static IReadOnlyList<Comprobacion> Chequeo(NivelDeComprobacion usb, NivelDeComprobacion wifi, NivelDeComprobacion bloqueo = NivelDeComprobacion.Bien) => new[]
        {
            Fila("Bloqueo de pantalla", bloqueo),
            Fila("Depuración USB", usb),
            Fila("Wi-Fi actual", wifi),
        };

        private static void ProbarNotificacionesDelEquipo()
        {
            const NivelDeComprobacion B = NivelDeComprobacion.Bien, A = NivelDeComprobacion.Aviso, I = NivelDeComprobacion.Info;

            Titulo("Equipo: la primera vez solo anota (linea base)");
            var e = new EstadoDelEquipo();
            var r0 = VigilanteDelEquipo.Revisar(Chequeo(usb: A, wifi: I), e, 1 * Hora);
            Check(r0.Count == 0, "lo que ya estaba mal no llega como aviso", $"{r0.Count}");
            Check(e.EnAviso.SetEquals(new[] { "Depuración USB" }) && e.UltimaRevisionMs == 1 * Hora, "pero queda anotado como ya avisado");
            Check(VigilanteDelEquipo.Revisar(Chequeo(usb: A, wifi: I), e, 2 * Hora).Count == 0, "sin cambios: nada que avisar");

            Titulo("Equipo: una fila que empeora avisa una vez");
            var r1 = VigilanteDelEquipo.Revisar(Chequeo(usb: A, wifi: I, bloqueo: A), e, 3 * Hora);
            Check(r1.Count == 1 && r1[0].Fila == "Bloqueo de pantalla", "quitar el bloqueo de pantalla avisa", string.Join(",", r1.Select(x => x.Fila)));
            Check(r1[0].Titulo.Contains("Bloqueo de pantalla") && r1[0].Texto == "Bloqueo de pantalla detalle Aviso", "el aviso nombra la fila y usa el detalle del chequeo");
            Check(VigilanteDelEquipo.Revisar(Chequeo(usb: A, wifi: I, bloqueo: A), e, 4 * Hora).Count == 0, "no se repite mientras siga mal");

            Titulo("Equipo: «Bien» rearma, «Info» no");
            VigilanteDelEquipo.Revisar(Chequeo(usb: B, wifi: I), e, 5 * Hora);
            Check(!e.EnAviso.Contains("Depuración USB"), "apagar la depuracion USB la rearma");
            var r2 = VigilanteDelEquipo.Revisar(Chequeo(usb: A, wifi: I), e, 6 * Hora);
            Check(r2.Count == 1 && r2[0].Fila == "Depuración USB", "volver a encenderla avisa de nuevo");

            var r3 = VigilanteDelEquipo.Revisar(Chequeo(usb: A, wifi: A), e, 7 * Hora);
            Check(r3.Count == 1 && r3[0].Fila == "Wi-Fi actual", "conectarse a una Wi-Fi abierta avisa");
            VigilanteDelEquipo.Revisar(Chequeo(usb: A, wifi: I), e, 8 * Hora);
            var r4 = VigilanteDelEquipo.Revisar(Chequeo(usb: A, wifi: A), e, 9 * Hora);
            Check(r4.Count == 0, "desconectarse (Info) y volver a la misma red abierta NO repite el aviso");
            VigilanteDelEquipo.Revisar(Chequeo(usb: A, wifi: B), e, 10 * Hora);
            Check(VigilanteDelEquipo.Revisar(Chequeo(usb: A, wifi: A), e, 11 * Hora).Count == 1, "pasar por una red cifrada (Bien) si la rearma");

            Titulo("Equipo: varias filas a la vez y filas desconocidas");
            var e2 = new EstadoDelEquipo();
            VigilanteDelEquipo.Revisar(Chequeo(usb: B, wifi: B), e2, 1 * Hora);
            var r5 = VigilanteDelEquipo.Revisar(Chequeo(usb: A, wifi: A, bloqueo: A), e2, 2 * Hora);
            Check(r5.Count == 3, "tres filas que empeoran: tres avisos", $"{r5.Count}");
            var conNueva = Chequeo(usb: A, wifi: A, bloqueo: A).Append(Fila("Fila nueva de una version futura", A)).ToList();
            var r6 = VigilanteDelEquipo.Revisar(conNueva, e2, 3 * Hora);
            Check(r6.Count == 1 && r6[0].Fila == "Fila nueva de una version futura", "una fila que no existia y sale en «Aviso» avisa (no es linea base)");

            Titulo("Equipo: con el chequeo real (ChequeoDelEquipo)");
            var catalogo = CatalogoDeSenales.Embebido();
            var hoy = new DateTime(2026, 11, 17);
            var bien = new DatosDelEquipo { BloqueoDePantalla = true, ParcheDeSeguridad = hoy.AddDays(-10), Api = 35, Release = "15", OpcionesDeDesarrollo = false, DepuracionUsb = false, Wifi = SeguridadDeWifi.Cifrada, AppsQueInstalan = Array.Empty<AppQueInstala>() };
            var e3 = new EstadoDelEquipo();
            Check(VigilanteDelEquipo.Revisar(ChequeoDelEquipo.Evaluar(bien, hoy, catalogo), e3, 1 * Hora).Count == 0 && e3.EnAviso.Count == 0, "un equipo en orden: linea base vacia");
            var r7 = VigilanteDelEquipo.Revisar(ChequeoDelEquipo.Evaluar(bien with { DepuracionUsb = true }, hoy, catalogo), e3, 2 * Hora);
            Check(r7.Count == 1 && r7[0].Fila == "Depuración USB" && r7[0].Texto.Contains("cable"), "encender la depuracion USB avisa con el texto del chequeo");
            var r8 = VigilanteDelEquipo.Revisar(ChequeoDelEquipo.Evaluar(bien with { DepuracionUsb = true }, hoy.AddDays(81), catalogo), e3, 3 * Hora);
            Check(r8.Count == 1 && r8[0].Fila == "Parche de seguridad", "el parche que cumple mas de 90 dias avisa solo", string.Join(",", r8.Select(x => x.Fila)));
            var r9 = VigilanteDelEquipo.Revisar(ChequeoDelEquipo.Evaluar(bien with { DepuracionUsb = null }, hoy, catalogo), e3, 4 * Hora);
            Check(r9.Count == 0 && e3.EnAviso.Contains("Depuración USB"), "si la depuracion pasa a «no se pudo leer», no se da por arreglada");
            Check(r7.Concat(r8).All(a => !a.Titulo.Contains("malware", StringComparison.OrdinalIgnoreCase)), "ningun aviso dice «malware»");

            Titulo("Equipo: persistencia");
            var ruta = Path.Combine(Path.GetTempPath(), "nexo-equipo-" + Guid.NewGuid().ToString("N") + ".json");
            try
            {
                e3.UltimoResumenMs = 42;
                e3.Guardar(ruta);
                var leido = EstadoDelEquipo.Cargar(ruta, out var aviso);
                Check(aviso == null && leido.EnAviso.SetEquals(e3.EnAviso) && leido.UltimaRevisionMs == e3.UltimaRevisionMs && leido.UltimoResumenMs == 42, "guarda y carga lo mismo");
                File.WriteAllText(ruta, "{ esto no es json");
                var danado = EstadoDelEquipo.Cargar(ruta, out var aviso2);
                Check(aviso2 != null && danado.UltimaRevisionMs is null, "un archivo dañado empieza de nuevo (linea base) y lo dice");
                File.WriteAllText(ruta, "{\"Version\":99}");
                Check(EstadoDelEquipo.Cargar(ruta, out var aviso3).UltimaRevisionMs is null && aviso3 != null, "una version desconocida empieza de nuevo");
                Check(EstadoDelEquipo.Cargar(ruta + ".no-existe", out var aviso4).UltimaRevisionMs is null && aviso4 == null, "sin archivo: estado nuevo, sin aviso");
            }
            finally { File.Delete(ruta); }
        }

        private static void ProbarResumenSemanal()
        {
            Titulo("Resumen semanal: cuando toca");
            var e = new EstadoDelEquipo();
            Check(!VigilanteDelEquipo.TocaResumen(e, 10 * Dia) && e.UltimoResumenMs == 10 * Dia, "la primera vez solo anota la fecha (activarlo no muestra uno al instante)");
            Check(!VigilanteDelEquipo.TocaResumen(e, 16 * Dia), "a los 6 dias, todavia no");
            Check(VigilanteDelEquipo.TocaResumen(e, 17 * Dia), "a los 7 dias, si");
            Check(VigilanteDelEquipo.TocaResumen(e, 17 * Dia + Hora), "si no se mostro, sigue tocando en la revision siguiente");
            VigilanteDelEquipo.ResumenMostrado(e, 17 * Dia + Hora);
            Check(!VigilanteDelEquipo.TocaResumen(e, 18 * Dia), "una vez mostrado, espera otra semana");
            var atras = new EstadoDelEquipo { UltimoResumenMs = 30 * Dia };
            Check(!VigilanteDelEquipo.TocaResumen(atras, 20 * Dia) && atras.UltimoResumenMs == 20 * Dia, "si el reloj retrocede, se reanota en vez de mostrar uno cada 15 min");

            Titulo("Resumen semanal: el texto");
            var bien = new[] { Fila("Bloqueo de pantalla", NivelDeComprobacion.Bien), Fila("Wi-Fi actual", NivelDeComprobacion.Info) };
            var (t1, x1) = VigilanteDelEquipo.ComponerResumen(106, 0, 2, bien);
            Check(t1.Contains("todo en orden") && x1 == "106 apps instaladas por ti (2 de confianza). Ninguna app a revisar. El equipo, sin avisos.", "todo bien", x1);
            var mal = new[] { Fila("Bloqueo de pantalla", NivelDeComprobacion.Aviso), Fila("Depuración USB", NivelDeComprobacion.Aviso) };
            var (t2, x2) = VigilanteDelEquipo.ComponerResumen(50, 1, 0, mal);
            Check(t2.Contains("cosas que mirar") && x2 == "50 apps instaladas por ti. 1 app a revisar. 2 avisos en el equipo.", "con cosas que mirar, singular y plural bien puestos", x2);
            var (_, x3) = VigilanteDelEquipo.ComponerResumen(50, 3, 0, new[] { mal[0] });
            Check(x3.Contains("3 apps a revisar") && x3.Contains("1 aviso en el equipo"), "plural de apps y singular de avisos", x3);
        }
    }
}
