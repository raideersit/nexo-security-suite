using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Headless;
using Avalonia.Threading;
using Nexo.Modules.Threats.Enlaces;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Ui.Desktop;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        private sealed class DescargaDeListasFalsa : IDescargaDeListas
        {
            public int Llamadas;
            public bool Falla;

            public Task<RespuestaHttp> DescargarAsync(FuenteDeLista fuente, CancellationToken ct)
            {
                Llamadas++;
                if (Falla) return Task.FromResult(new RespuestaHttp(503, ""));
                return Task.FromResult(new RespuestaHttp(200, fuente == FuenteDeLista.PhishingArmy ? ArmyDePrueba() : OpenPhishDePrueba()));
            }
        }

        /// <summary>Cabecera con el formato REAL de Phishing Army (2026-11-09) y 1200 dominios de relleno + el de prueba que publica la propia lista.</summary>
        private static string ArmyDePrueba()
        {
            var sb = new StringBuilder("#\n# Title: Phishing Army | Community phishing domain blocklist\n# Generated: 2026-11-09T14:00:33Z\n# Entries: 1201\n# Format: domains; version=1\n#\n");
            for (int i = 0; i < 1200; i++) sb.Append("sitio-falso-").Append(i.ToString("D5")).Append(".example\n");
            sb.Append("amiprotected.it\n");
            return sb.ToString();
        }

        /// <summary>Direcciones con la forma de las del feed real de OpenPhish (dos son copias literales del del 2026-11-09).</summary>
        private static string OpenPhishDePrueba()
            => string.Join("\n", Enumerable.Range(0, 30).Select(i => "https://pagina-" + i + ".example/login")
                .Concat(new[] { "https://www.roblox.com.ml/users/364354365772/profile", "https://hkdiscord.antsoon.com/category/engineering" })) + "\n";

        private static readonly DateTimeOffset AhoraEnlaces = new(2026, 11, 9, 15, 0, 0, TimeSpan.Zero);

        private static EnlacesModelo ModeloDeEnlaces(string carpeta, DescargaDeListasFalsa d, RastroFalso? r = null)
            => new(new AlmacenDeListas(carpeta), () => d, () => AhoraEnlaces) { Rastro = r ?? (IRastroDeVentana)RastroNulo.Instancia };

        public static void ProbarEnlaces()
        {
            Console.WriteLine("Pestaña Enlaces (anti-phishing)");
            string carpeta = Path.Combine(Path.GetTempPath(), "nexo-ventana-enlaces-" + Guid.NewGuid().ToString("N"));
            try
            {
                var d = new DescargaDeListasFalsa();
                var r = new RastroFalso();
                EnlacesModelo m = ModeloDeEnlaces(carpeta, d, r);
                Check(m.Titulo == "Sin revisar" && m.Indicador == Indicador.SinDatos && !m.PuedeRevisar && m.EstadoDeListas.Contains("sin leer"),
                    "al empezar: sin revisar, gris, «Revisar» apagado (no hay texto) y listas sin leer", m.Titulo + " / " + m.EstadoDeListas);

                Esperar(m.CargarSiHaceFaltaAsync());
                Check(m.EstadoDeListas == "Phishing Army: no descargada.\nOpenPhish: no descargada." && d.Llamadas == 0,
                    "cargar solo lee el disco: sin listas guardadas lo dice, y NO descarga nada", m.EstadoDeListas);

                const string estafa = "Correos de Chile: su paquete esta retenido. Pague el costo de envio en correoschile-pagos.top hoy mismo o sera devuelto.";
                m.Texto = estafa;
                Check(m.PuedeRevisar && m.Titulo == "Sin revisar", "con texto se puede revisar; escribir no revisa solo");
                Esperar(m.RevisarAsync());
                Check(m.Titulo.StartsWith("Peligroso") && m.Indicador == Indicador.Alerta && m.Enlaces.Count == 1 && m.Enlaces[0].Veredicto == "Peligroso",
                    "un SMS falso de Correos: Peligroso, en rojo, con su enlace", m.Titulo);
                Check(m.HallazgosDelMensaje.Any(h => h.Titulo.Contains("tácticas")) && m.Enlaces[0].Hallazgos.Any(h => h.Titulo.Contains("Correos de Chile")),
                    "los hallazgos del mensaje van aparte de los del enlace");
                Check(m.HayNoEvaluado && m.NoEvaluado.Count == 2 && m.Explicacion.Contains("incompleta"), "sin listas la revisión se marca incompleta, aunque salga Peligroso", string.Join(" | ", m.NoEvaluado));
                Check(d.Llamadas == 0, "revisar NO descarga nada (solo el botón de las listas sale a Internet)");

                // El rastro: solo conteos, ni texto, ni enlaces, ni sitios.
                Check(r.Avisos.Count == 1 && r.Avisos[0].Tipo == "enlaces.revision" && (string)r.Avisos[0].Campos["maxima"]! == "Alta" && (bool)r.Avisos[0].Campos["completa"]! == false,
                    "avisa al vault: tipo «enlaces.revision», gravedad Alta, incompleta", Todo(r));
                Check(r.Avisos[0].Campos.Keys.OrderBy(k => k).SequenceEqual(new[] { "completa", "hallazgos", "maxima" }) && !Todo(r).Contains("correos") && !Todo(r).Contains(".top"),
                    "el aviso no lleva el texto, el enlace ni el sitio", Todo(r));

                m.Texto = estafa + " ";
                Check(m.Titulo == "Sin revisar" && m.Enlaces.Count == 0 && !m.HayNoEvaluado, "si el texto cambia, el resultado anterior desaparece (era de otro texto)");

                // Descargar las listas (el aviso previo lo pone la ventana).
                Esperar(m.ActualizarListasAsync());
                Check(d.Llamadas == 2 && m.EstadoDeListas.Contains("Phishing Army: 1.201 sitios, de hace menos de una hora.") && m.EstadoDeListas.Contains("OpenPhish: 32 direcciones"),
                    "«Actualizar listas» baja las dos y el estado dice cuántas entradas tienen", m.EstadoDeListas);
                Check(m.MensajeDeActualizacion!.Contains("Phishing Army: actualizada") && m.MensajeDeActualizacion.Contains("OpenPhish: actualizada"), "y dice qué se actualizó", m.MensajeDeActualizacion);
                Check(File.Exists(Path.Combine(carpeta, "phishing-army.txt")) && File.Exists(Path.Combine(carpeta, "openphish.txt")), "quedan guardadas en la carpeta de listas");

                m.Texto = "Mira esto https://www.amiprotected.it/ y https://www.bancoestado.cl/";
                Esperar(m.RevisarAsync());
                Check(m.Titulo.StartsWith("Peligroso") && !m.HayNoEvaluado && m.Enlaces.Count == 2 && m.Enlaces[0].Veredicto == "Peligroso" && m.Enlaces[1].Veredicto == "Sin señales conocidas",
                    "con listas: el sitio de la lista es Peligroso, el oficial no tiene señales, y la revisión está completa", m.Titulo + " / " + string.Join(",", m.Enlaces.Select(e => e.Veredicto)));
                Check(ReferenceEquals(m.Enlaces[1].Color, Colores.De(Indicador.SinDatos)) && ReferenceEquals(m.Enlaces[0].Color, Colores.De(Indicador.Alerta)),
                    "cada enlace con su color: el peligroso en rojo, el «sin señales» en gris (NUNCA verde)");

                Esperar(m.ActualizarListasAsync());
                Check(m.Titulo == "Sin revisar" && m.MensajeDeActualizacion!.Contains("ya está al día") && m.MensajeDeActualizacion.Contains("Vuelve a pulsar «Revisar»"),
                    "actualizar después de revisar borra el veredicto (era con las listas de antes) y lo dice", m.MensajeDeActualizacion);

                m.Texto = "Te dejo el enlace oficial: https://www.bancoestado.cl/";
                Esperar(m.RevisarAsync());
                Check(m.Titulo == "Sin señales conocidas (esto NO prueba que sea seguro)" && m.Indicador == Indicador.SinDatos,
                    "sin señales: gris (NUNCA verde) y dice que no prueba que sea seguro", m.Titulo + " / " + m.Indicador);

                m.Texto = "Nos vemos mañana a las 5";
                Esperar(m.RevisarAsync());
                Check(m.Titulo == "No se encontró ningún enlace" && m.Explicacion.Contains("Tampoco frases") && m.Indicador == Indicador.SinDatos, "sin enlaces ni frases: lo dice, en gris", m.Explicacion);

                // El remitente (opcional).
                m.Texto = "BancoEstado: su clave vence hoy.";
                m.Remitente = "soporte.bancoestado@gmail.com";
                Esperar(m.RevisarAsync());
                Check(m.Titulo.StartsWith("Peligroso") && m.HallazgosDelMensaje.Any(h => h.Titulo.Contains("correo gratuito")),
                    "con remitente: «dice ser BancoEstado desde un gmail» sale entre los hallazgos del mensaje", m.Titulo + " / " + string.Join(" | ", m.HallazgosDelMensaje.Select(h => h.Titulo)));
                m.Remitente = "soporte.bancoestado@gmail.co";
                Check(m.Titulo == "Sin revisar" && !m.HayHallazgosDelMensaje, "cambiar el remitente también borra el resultado anterior");
                m.Remitente = "<<<>>>";
                Esperar(m.RevisarAsync());
                Check(m.NoEvaluado.Any(n => n.Contains("No se reconoce el remitente")), "un remitente que no se entiende se dice abajo, en «no se pudo comprobar»");

                m.Borrar();
                Check(m.Texto == "" && m.Remitente == "" && m.Titulo == "Sin revisar" && !m.PuedeRevisar, "«Borrar» vacía el texto, el remitente y el resultado");

                // Una nueva ventana (otro modelo sobre la misma carpeta) lee las listas guardadas.
                var d2 = new DescargaDeListasFalsa();
                EnlacesModelo m2 = ModeloDeEnlaces(carpeta, d2);
                Esperar(m2.CargarSiHaceFaltaAsync());
                Check(m2.EstadoDeListas.Contains("1.201 sitios") && d2.Llamadas == 0, "al volver a abrir Nexo las listas se leen del disco, sin descargar", m2.EstadoDeListas);

                // Una descarga que falla deja las listas anteriores.
                d2.Falla = true;
                var m3 = new EnlacesModelo(new AlmacenDeListas(carpeta), () => d2, () => AhoraEnlaces.AddHours(5));
                Esperar(m3.ActualizarListasAsync());
                Check(m3.MensajeDeActualizacion!.Contains("503") && m3.MensajeDeActualizacion.Contains("Se sigue usando la anterior") && m3.EstadoDeListas.Contains("1.201 sitios"),
                    "si la descarga falla, se dice y se siguen usando las listas anteriores", m3.MensajeDeActualizacion);

                Check(EnlacesModelo.TextoDeAvisoDeDescarga.Contains("no se envía ningún enlace") && EnlacesModelo.TextoDeAvisoDeDescarga.EndsWith("¿Descargar ahora?"),
                    "el aviso previo a la descarga dice qué sale y qué no");
            }
            finally
            {
                try { Directory.Delete(carpeta, true); } catch (IOException) { }
            }
        }

        private static void ProbarVentanaDeEnlaces(MainWindow w, EnlacesModelo m, DescargaDeListasFalsa d, string? captura)
        {
            w.Pestanas.SelectedIndex = 9;
            Dispatcher.UIThread.RunJobs();
            Esperar(m.CargarSiHaceFaltaAsync());
            Dispatcher.UIThread.RunJobs();
            Check(w.Pestanas.ItemCount == 12 && d.Llamadas == 0 && w.EstadoDeListas.Text!.Contains("1.201 sitios"),
                "pestaña Enlaces: al entrar lee las listas guardadas y no descarga nada", w.EstadoDeListas.Text);
            Check(!w.BotonRevisarEnlaces.IsEnabled && w.TituloDeEnlaces.Text == "Sin revisar", "sin texto, «Revisar» está apagado");

            w.CajaDeMensaje.Text = "BancoEstado: su cuenta sera bloqueada. Ingrese a bаncoestado.cl/clave para validar sus datos.";
            Dispatcher.UIThread.RunJobs();
            w.CajaDeRemitente.Text = "+56 9 8765 4321";
            Dispatcher.UIThread.RunJobs();
            Check(m.Texto.StartsWith("BancoEstado") && m.Remitente == "+56 9 8765 4321" && w.BotonRevisarEnlaces.IsEnabled, "lo escrito en las dos cajas llega al modelo y habilita «Revisar»");
            Pulsar(w.BotonRevisarEnlaces);
            for (int i = 0; i < 500 && w.TituloDeEnlaces.Text is "Revisando..." or "Sin revisar"; i++) { Dispatcher.UIThread.RunJobs(); Thread.Sleep(5); }
            Check(w.TituloDeEnlaces.Text!.StartsWith("Peligroso") && w.ListaDeEnlaces.ItemCount == 1,
                "pulsar «Revisar» con una «а» cirílica en el nombre: Peligroso, con el enlace en la lista", w.TituloDeEnlaces.Text);

            if (captura is not null)
            {
                AvaloniaHeadlessPlatform.ForceRenderTimerTick();
                string ruta = Path.ChangeExtension(captura, null) + "-enlaces.png";
                w.CaptureRenderedFrame()?.Save(ruta);
                Console.WriteLine("           captura: " + ruta);
            }

            Pulsar(w.BotonBorrarMensaje);
            Check(string.IsNullOrEmpty(w.CajaDeMensaje.Text) && string.IsNullOrEmpty(w.CajaDeRemitente.Text) && w.TituloDeEnlaces.Text == "Sin revisar", "«Borrar» vacía las dos cajas y el resultado", w.CajaDeMensaje.Text);
        }
    }
}
