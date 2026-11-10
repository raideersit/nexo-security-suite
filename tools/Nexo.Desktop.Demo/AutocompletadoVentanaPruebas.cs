using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Threading;
using Nexo.Modules.Identity.Autocompletado;
using Nexo.Modules.Identity.Boveda;
using Nexo.Ui.Desktop;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        private sealed class EmparejadosDePrueba : INavegadoresEmparejados
        {
            public readonly Dictionary<string, byte[]> Claves = new();
            public bool Autorizado(string n, byte[] c) { lock (Claves) return Claves.TryGetValue(n, out byte[]? k) && k.SequenceEqual(c); }
            public string? Guardar(string n, byte[] c) { lock (Claves) Claves[n] = c.ToArray(); return null; }
            public IReadOnlyList<string> Lista() { lock (Claves) return Claves.Keys.OrderBy(x => x).ToList(); }
            public bool Olvidar(string n) { lock (Claves) return Claves.Remove(n); }
        }

        private sealed class RelojDePrueba
        {
            public DateTimeOffset Ahora = new(2026, 11, 10, 15, 0, 0, TimeSpan.FromHours(-3));
        }

        private static string PipeDePrueba() => "nexo-prueba-ventana-auto-" + Guid.NewGuid().ToString("N")[..12];

        private static JsonElement PedirPorPipe(string pipe, object mensaje)
        {
            byte[] r = new RelevoNativo(pipe, conectar: TimeSpan.FromSeconds(2)).ReenviarAsync(JsonSerializer.SerializeToUtf8Bytes(mensaje)).GetAwaiter().GetResult();
            return JsonDocument.Parse(r).RootElement.Clone();
        }

        private static string Est(JsonElement e) => e.GetProperty("estado").GetString()!;

        /// <summary>El modelo sin ventana: avisos inmediatos (sin despachador), reloj de prueba y el pipe de verdad.</summary>
        public static void ProbarAutocompletadoDelModelo()
        {
            Console.WriteLine("Autocompletado en la ventana: el modelo (pipe real, sin pantalla)");
            var reloj = new RelojDePrueba();
            var emp = new EmparejadosDePrueba();
            var gh = new EntradaDeBoveda(Guid.NewGuid(), "github.com", "ana", "clave-gh", "", DateTimeOffset.Now, DateTimeOffset.Now);
            IReadOnlyList<EntradaDeBoveda>? abiertas = new[] { gh };
            string pipe = PipeDePrueba();
            var rastro = new RastroFalso();
            var m = new AutocompletadoModelo(() => abiertas, emp, pipe, a => a(), () => reloj.Ahora) { Rastro = rastro };
            var preguntas = new List<(string nav, string codigo)>();
            bool responder = true;
            m.Preguntar = (n, c, ct) => { preguntas.Add((n, c)); return Task.FromResult(responder); };

            Check(!m.Escuchando && !m.PuedeArmar, "antes de iniciar: no escucha y no se puede pedir emparejar");
            m.ArmarEmparejamiento();
            Check(!m.Armado, "armar sin escuchar no hace nada");
            Esperar(m.IniciarAsync());
            Check(m.Escuchando && m.Estado.StartsWith("Atendiendo") && m.PuedeArmar, "iniciado: escucha y lo dice", m.Estado);

            var otra = new AutocompletadoModelo(() => null, new EmparejadosDePrueba(), pipe, a => a(), () => reloj.Ahora);
            Esperar(otra.IniciarAsync());
            Check(!otra.Escuchando && otra.Estado.Contains("otra ventana de Nexo") && otra.Estado.Contains("revisar el equipo"),
                "una segunda ventana con el canal ocupado NO se suma (y avisa de que podría ser otro programa)", otra.Estado);

            byte[] clave = RandomNumberGenerator.GetBytes(32);
            string k = Convert.ToBase64String(clave);
            JsonElement r = PedirPorPipe(pipe, new { tipo = "emparejar", navegador = "brave-3f9a", clave = k });
            Check(Est(r) == "rechazado" && r.GetProperty("motivo").GetString() == AutocompletadoModelo.NoSolicitado && preguntas.Count == 0,
                "emparejar SIN haber pulsado «Emparejar un navegador…»: rechazado, y NO se pregunta nada", r.ToString());
            Check(m.Aviso.Contains("brave-3f9a") && m.Aviso.Contains("sin que pulsaras") && rastro.Avisos.Any(a => a.Tipo == "autocompletado.no_solicitado"),
                "y la ventana avisa de que alguien lo intentó (y queda en el rastro)", m.Aviso);

            m.ArmarEmparejamiento();
            Check(m.Armado && !m.PuedeArmar && m.TextoDeEmparejamiento.Contains("quedan 2:00") && m.Aviso.Length == 0,
                "pulsar «Emparejar un navegador…»: abre el plazo de 2 minutos (y borra el aviso anterior)", m.TextoDeEmparejamiento);
            reloj.Ahora += TimeSpan.FromSeconds(30);
            m.Tic();
            Check(m.TextoDeEmparejamiento.Contains("quedan 1:30"), "la cuenta atrás avanza", m.TextoDeEmparejamiento);

            r = PedirPorPipe(pipe, new { tipo = "emparejar", navegador = "brave-3f9a", clave = k });
            Check(Est(r) == "ok" && preguntas.Count == 1 && preguntas[0] == ("brave-3f9a", PuenteDeAutocompletado.CodigoDe(clave)),
                "con el plazo abierto: se pregunta con el navegador y el código, y «Sí» empareja", r.ToString());
            Check(!m.Armado && m.Navegadores.SequenceEqual(new[] { "brave-3f9a" }) && m.UltimaActividad.Contains("Emparejado «brave-3f9a»"),
                "tras emparejar: el plazo se cierra y el navegador aparece en la lista");

            m.ArmarEmparejamiento();
            responder = false;
            byte[] clave2 = RandomNumberGenerator.GetBytes(32);
            r = PedirPorPipe(pipe, new { tipo = "emparejar", navegador = "edge-0001", clave = Convert.ToBase64String(clave2) });
            Check(Est(r) == "rechazado" && !m.Armado && m.Navegadores.Count == 1 && rastro.Avisos.Any(a => a.Tipo == "autocompletado.rechazado"),
                "«No»: rechazado, el plazo se cierra y no se añade nada");

            m.ArmarEmparejamiento();
            reloj.Ahora += TimeSpan.FromMinutes(2);
            m.Tic();
            Check(!m.Armado && m.UltimaActividad.Contains("Se acabó el plazo"), "pasados 2 minutos sin navegador: el plazo se cierra solo");
            int antes = preguntas.Count;
            reloj.Ahora += TimeSpan.FromMinutes(1); // más allá de la espera tras un rechazo
            r = PedirPorPipe(pipe, new { tipo = "emparejar", navegador = "edge-0001", clave = Convert.ToBase64String(clave2) });
            Check(Est(r) == "rechazado" && preguntas.Count == antes, "y después ya no se pregunta");

            m.ArmarEmparejamiento();
            m.Preguntar = (n, c, ct) => throw new InvalidOperationException("la ventana se cerró");
            reloj.Ahora += TimeSpan.FromMinutes(1);
            r = PedirPorPipe(pipe, new { tipo = "emparejar", navegador = "edge-0001", clave = Convert.ToBase64String(clave2) });
            Check(Est(r) == "rechazado" && !m.Armado && m.Navegadores.Count == 1, "si la pregunta falla, cuenta como «No»");

            // El navegador deja de esperar con la pregunta abierta (no hay «Sí» ni «No», así que tampoco hay aviso del puente): el plazo se cierra igual.
            m.ArmarEmparejamiento();
            m.Preguntar = async (n, c, ct) => { await Task.Delay(Timeout.Infinite, ct); return true; };
            reloj.Ahora += TimeSpan.FromMinutes(1);
            using (var corta = new CancellationTokenSource(TimeSpan.FromMilliseconds(300)))
            {
                bool cancelada = false;
                try { Esperar(m.Puente.AtenderAsync(JsonSerializer.SerializeToUtf8Bytes(new { tipo = "emparejar", navegador = "edge-0002", clave = Convert.ToBase64String(clave2) }), corta.Token)); }
                catch (OperationCanceledException) { cancelada = true; }
                Check(cancelada && !m.Armado && m.Navegadores.Count == 1, "si el navegador deja de esperar a mitad de la pregunta, el plazo también se cierra");
            }

            r = PedirPorPipe(pipe, new { tipo = "rellenar", navegador = "brave-3f9a", clave = k, url = "https://github.com/login", id = gh.Id });
            Check(Est(r) == "ok" && r.GetProperty("contrasena").GetString() == "clave-gh" && m.UltimaActividad.Contains("github.com"),
                "emparejado y con la bóveda abierta: rellena, y la ventana dice dónde", m.UltimaActividad);
            Check(rastro.Avisos.Where(a => a.Tipo.StartsWith("autocompletado.")).All(a => a.Campos.Count == 0),
                "al rastro del servicio no va ni el navegador ni el sitio (sin campos)");
            abiertas = null;
            r = PedirPorPipe(pipe, new { tipo = "rellenar", navegador = "brave-3f9a", clave = k, url = "https://github.com/login", id = gh.Id });
            Check(Est(r) == "bloqueada" && !r.ToString().Contains("clave-gh"), "bóveda bloqueada: «bloqueada» y nada más");

            m.Seleccionado = "brave-3f9a";
            Check(m.HaySeleccionado, "se puede elegir un navegador de la lista");
            m.OlvidarSeleccionado();
            Check(m.Navegadores.Count == 0 && !m.HaySeleccionado && m.SinNavegadores.Length > 0 && rastro.Avisos.Any(a => a.Tipo == "autocompletado.olvidado"),
                "quitarlo: desaparece de la lista");
            abiertas = new[] { gh };
            r = PedirPorPipe(pipe, new { tipo = "buscar", navegador = "brave-3f9a", clave = k, url = "https://github.com/" });
            Check(Est(r) == "no_emparejado", "y ese navegador ya no recibe nada");

            string t = AutocompletadoModelo.TextoDePregunta("brave-3f9a", "915 824");
            Check(t.Contains("«brave-3f9a»") && t.Contains("915 824") && t.Contains("pulsa «No»"), "la pregunta nombra el navegador, enseña el código y dice qué hacer si no coincide");

            Esperar(m.DisposeAsync().AsTask());
            byte[] tras = new RelevoNativo(pipe, conectar: TimeSpan.FromMilliseconds(300)).ReenviarAsync(Encoding.UTF8.GetBytes("{}")).GetAwaiter().GetResult();
            Check(Encoding.UTF8.GetString(tras).Contains("sin_nexo") && !m.Escuchando, "al cerrar la ventana el canal se cierra («sin_nexo» para el navegador)");
            Esperar(otra.DisposeAsync().AsTask());

            // Con la bóveda de verdad: la lista solo con la bóveda abierta, y lo que pide el navegador NO la mantiene abierta.
            string dir = Path.Combine(Path.GetTempPath(), "nexo-auto-boveda-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var c = new Controles();
                var b = Modelo(Path.Combine(dir, "b.nxv"), c, new PortapapelesFalso());
                Check(b.EntradasParaAutocompletar() is null, "bóveda real sin crear: nada para el navegador");
                Esperar(b.CrearAsync(Maestra, Maestra));
                Check(b.EsAbierta && b.EntradasParaAutocompletar() is { Count: 0 }, "abierta: la lista (vacía) para el navegador");
                var m2 = new AutocompletadoModelo(b.EntradasParaAutocompletar, new EmparejadosDePrueba(), PipeDePrueba(), a => a());
                c.Ahora += TimeSpan.FromMinutes(4);
                for (int i = 0; i < 5; i++) Esperar(m2.Puente.AtenderAsync(Encoding.UTF8.GetBytes("{\"tipo\":\"estado\",\"navegador\":\"brave-1\"}")));
                c.Ahora += TimeSpan.FromMinutes(2);
                Check(b.ComprobarInactividad() && b.EsBloqueada, "las peticiones del navegador NO cuentan como actividad: se bloquea sola a los 5 minutos");
                Check(b.EntradasParaAutocompletar() is null, "y bloqueada ya no da nada");
                Esperar(b.DesbloquearAsync(Maestra));
                b.Bloquear();
                Check(b.EntradasParaAutocompletar() is null, "bloquear a mano: nada");
            }
            finally { try { Directory.Delete(dir, true); } catch (IOException) { } }
        }

        /// <summary>La ventana de verdad (sin pantalla): el panel, el botón, la pregunta con el código y lo que recibe el navegador.</summary>
        private static void ProbarVentanaDeAutocompletado(MainWindow w, AutocompletadoModelo m, string pipe)
        {
            Console.WriteLine("  -- pestaña Contraseñas: autocompletar en el navegador");
            var fin = DateTime.UtcNow + TimeSpan.FromSeconds(10);
            while (!m.Escuchando && DateTime.UtcNow < fin) { Dispatcher.UIThread.RunJobs(); Thread.Sleep(20); }
            Check(w.PanelDeAutocompletado.IsVisible && m.Escuchando && (w.EstadoDeAutocompletado.Text ?? "").StartsWith("Atendiendo"),
                "el panel se ve y, al abrirse la ventana, empezó a atender al navegador", w.EstadoDeAutocompletado.Text);
            Check(w.BotonEmparejarNavegador.IsEnabled && !w.BotonCancelarEmparejamiento.IsVisible && !w.BotonOlvidarNavegador.IsEnabled,
                "«Emparejar un navegador...» activo; «Cancelar» oculto; «Quitar» sin nada elegido");

            Pulsar(w.BotonEmparejarNavegador);
            Check(m.Armado && !w.BotonEmparejarNavegador.IsEnabled && w.BotonCancelarEmparejamiento.IsVisible && w.TextoDeEmparejamiento.IsVisible
                  && (w.TextoDeEmparejamiento.Text ?? "").Contains("quedan 2:00"), "pulsarlo abre el plazo y enseña la cuenta atrás", w.TextoDeEmparejamiento.Text);
            Pulsar(w.BotonCancelarEmparejamiento);
            Check(!m.Armado && w.BotonEmparejarNavegador.IsEnabled, "«Cancelar» lo cierra");

            byte[] clave = RandomNumberGenerator.GetBytes(32);
            JsonElement Emparejar(Action<DialogoEnEspanol.VentanaDeDialogo?> contestar)
            {
                Task<byte[]> t = Task.Run(() => new RelevoNativo(pipe).ReenviarAsync(JsonSerializer.SerializeToUtf8Bytes(
                    new { tipo = "emparejar", navegador = "brave-3f9a", clave = Convert.ToBase64String(clave) })));
                DialogoEnEspanol.VentanaDeDialogo? d = null;
                var hasta = DateTime.UtcNow + TimeSpan.FromSeconds(5);
                while (d is null && !t.IsCompleted && DateTime.UtcNow < hasta) { d = DialogoAbierto(w); Thread.Sleep(20); }
                contestar(d);
                hasta = DateTime.UtcNow + TimeSpan.FromSeconds(10);
                while (!t.IsCompleted && DateTime.UtcNow < hasta) { Dispatcher.UIThread.RunJobs(); Thread.Sleep(20); }
                Dispatcher.UIThread.RunJobs();
                return t.IsCompleted ? JsonDocument.Parse(t.Result).RootElement.Clone() : JsonDocument.Parse("{\"estado\":\"colgado\"}").RootElement.Clone();
            }

            JsonElement r = Emparejar(d => Check(d is null, "sin pulsar el botón, el navegador NO hace saltar ninguna pregunta"));
            Check(Est(r) == "rechazado" && w.AvisoDeAutocompletado.IsVisible && (w.AvisoDeAutocompletado.Text ?? "").Contains("sin que pulsaras"),
                "y la ventana enseña el aviso de que alguien lo intentó", w.AvisoDeAutocompletado.Text);

            // «Sí» ANTES que «No»: tras un «No» el puente (con reloj real aquí) espera 30 s antes de volver a preguntar.
            ProbarVentanaEmparejaDeVerdad(w, m, pipe);

            w.Pestanas.SelectedIndex = 0;
            Pulsar(w.BotonEmparejarNavegador);
            r = Emparejar(d =>
            {
                Check(d is not null && (d.Texto.Text ?? "").Contains(PuenteDeAutocompletado.CodigoDe(clave)) && (d.Texto.Text ?? "").Contains("brave-3f9a")
                      && d.BotonNo!.IsDefault, "con el plazo abierto se pregunta EN la ventana, con el código y «No» por omisión", d?.Texto.Text);
                Check(w.Pestanas.SelectedIndex == 8, "y la ventana se va a «Contraseñas» para que se vea");
                if (d is not null) Pulsar(d.BotonNo!);
            });
            Check(Est(r) == "rechazado" && !m.Armado && w.ListaDeNavegadores.ItemCount == 0 && !w.ListaDeNavegadores.IsVisible, "«No»: el navegador recibe «rechazado» y no se añade");

            m.CancelarEmparejamiento();
            Pulsar(w.BotonEmparejarNavegador);
            // Tras un «No» el puente espera 30 s antes de volver a preguntar (con reloj real): esto se comprueba en Identity.Demo; aquí basta con ver que no pregunta.
            r = Emparejar(d => Check(d is null, "justo después de un «No», no se vuelve a preguntar (espera de 30 s)"));
            Check(Est(r) == "rechazado", "y el navegador recibe «rechazado»");
            m.CancelarEmparejamiento();

            // Una pregunta que ya no sirve se cierra sola como «No».
            using (var cts = new CancellationTokenSource())
            {
                Task<bool> p = DialogoEnEspanol.PreguntarAsync(w, "¿Seguro?", "Pregunta", IconoDeDialogo.Pregunta, cts.Token);
                Check(DialogoAbierto(w) is not null, "(la pregunta con plazo se abre)");
                cts.Cancel();
                var hasta = DateTime.UtcNow + TimeSpan.FromSeconds(5);
                while (!p.IsCompleted && DateTime.UtcNow < hasta) { Dispatcher.UIThread.RunJobs(); Thread.Sleep(10); }
                Check(p.IsCompleted && !p.Result && DialogoAbierto(w) is null, "si el navegador deja de esperar, la pregunta se cierra sola como «No»");
            }
        }

        /// <summary>Lo que prueba Identity.Demo con reloj de prueba (la espera tras un «No») aquí se hace con un modelo nuevo para emparejar de verdad.</summary>
        private static void ProbarVentanaEmparejaDeVerdad(MainWindow w, AutocompletadoModelo m, string pipe)
        {
            byte[] clave = RandomNumberGenerator.GetBytes(32);
            Pulsar(w.BotonEmparejarNavegador);
            Task<byte[]> t = Task.Run(() => new RelevoNativo(pipe).ReenviarAsync(JsonSerializer.SerializeToUtf8Bytes(
                new { tipo = "emparejar", navegador = "edge-77aa", clave = Convert.ToBase64String(clave) })));
            DialogoEnEspanol.VentanaDeDialogo? d = null;
            var hasta = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            while (d is null && DateTime.UtcNow < hasta) { d = DialogoAbierto(w); Thread.Sleep(20); }
            if (d is not null) Pulsar(d.BotonSi!);
            hasta = DateTime.UtcNow + TimeSpan.FromSeconds(10);
            while (!t.IsCompleted && DateTime.UtcNow < hasta) { Dispatcher.UIThread.RunJobs(); Thread.Sleep(20); }
            Dispatcher.UIThread.RunJobs();
            JsonElement r = t.IsCompleted ? JsonDocument.Parse(t.Result).RootElement.Clone() : JsonDocument.Parse("{\"estado\":\"colgado\"}").RootElement.Clone();
            Check(d is not null && Est(r) == "ok" && w.ListaDeNavegadores.IsVisible && w.ListaDeNavegadores.ItemCount == 1 && w.BotonEmparejarNavegador.IsEnabled,
                "«Sí»: el navegador queda emparejado, aparece en la lista y el botón vuelve a estar disponible", r.ToString());
            Check((w.UltimaActividadDeAutocompletado.Text ?? "").Contains("edge-77aa"), "y se dice qué se emparejó", w.UltimaActividadDeAutocompletado.Text);
            w.ListaDeNavegadores.SelectedIndex = 0;
            Dispatcher.UIThread.RunJobs();
            Check(w.BotonOlvidarNavegador.IsEnabled, "al elegirlo se puede quitar");
            Pulsar(w.BotonOlvidarNavegador);
            Check(w.ListaDeNavegadores.ItemCount == 0 && m.Navegadores.Count == 0, "«Quitar el seleccionado» lo saca de la lista");
        }
    }
}
