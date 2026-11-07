using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Reports;
using Nexo.Reports.Model;
using Nexo.Reports.Vault;
using Nexo.Service;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        private sealed class EscritorFalso : IReportWriter
        {
            public readonly List<NexoEvent> Eventos = new();
            public Task<NoteRef> EscribirAsync(NexoEvent evento, CancellationToken ct = default) { Eventos.Add(evento); return Task.FromResult<NoteRef>(null!); }
            public Task InicializarVaultAsync(CancellationToken ct = default) => Task.CompletedTask;
        }

        private static JsonElement J(string json) => JsonDocument.Parse(json).RootElement.Clone();

        private static async Task<(bool Ok, int Codigo, string Mensaje)> Pedir(ModuloRastroDeVentana m, string json)
        {
            try { await m.ManejarAsync(ModuloRastroDeVentana.Registrar, J(json), CancellationToken.None).ConfigureAwait(false); return (true, 0, ""); }
            catch (ErrorDeComando e) { return (false, e.Codigo, e.Message); }
        }

        public static async Task ProbarRastroDeVentana(string raiz)
        {
            Console.WriteLine("Rastro de la ventana: «ventana.registrar»");
            var ahora = new DateTimeOffset(2026, 11, 7, 12, 0, 0, TimeSpan.Zero);
            var w = new EscritorFalso();
            var m = new ModuloRastroDeVentana(w, () => ahora);
            void Avanza(double s) => ahora += TimeSpan.FromSeconds(s);

            Check(m.Metodos.SequenceEqual(new[] { "ventana.registrar" }), "el modulo atiende solo «ventana.registrar»");
            bool desconocido = false;
            try { await m.ManejarAsync("ventana.otra", J("{}"), CancellationToken.None); } catch (ErrorDeComando e) { desconocido = e.Codigo == CodigoDeError.MetodoDesconocido; }
            Check(desconocido, "otro metodo: «desconocido»");

            // Una revision con hallazgos graves.
            Check((await Pedir(m, "{\"tipo\":\"seguridad.aplicaciones\",\"hallazgos\":3,\"maxima\":\"Alta\",\"completa\":true}")).Ok && w.Eventos.Count == 1, "una revision con hallazgos se registra");
            NexoEvent e1 = w.Eventos[0];
            Check(e1.Severidad == Severidad.Alta && e1.Modulo == ModuloOrigen.Amenazas && e1.Tipo == TipoEvento.VulnerabilidadDetectada, "con la gravedad maxima, en Amenazas", e1.Severidad + " " + e1.Modulo);
            Check((int)e1.Campos["hallazgos"]! == 3 && (bool)e1.Campos["completa"]! && (string)e1.Campos["origen"]! == "ventana" && (string)e1.Campos["gravedad_maxima"]! == "Alta", "con sus conteos y el origen «ventana»");
            Check(e1.Titulo.Contains("desde la ventana") && e1.Cuerpo!.Contains("el servicio no lo comprobó"), "el titulo y el cuerpo dicen que lo informo la ventana y que el servicio no lo comprobo");

            // Sin hallazgos: completa = Info; incompleta = Media (lo desconocido no es «bien»).
            Avanza(5);
            await Pedir(m, "{\"tipo\":\"seguridad.wifi\",\"hallazgos\":0,\"completa\":true}");
            Check(w.Eventos[^1].Severidad == Severidad.Info && w.Eventos[^1].Cuerpo!.StartsWith("Sin hallazgos."), "sin hallazgos y completa: Info");
            Avanza(5);
            await Pedir(m, "{\"tipo\":\"seguridad.cuentas\",\"hallazgos\":0,\"completa\":false}");
            Check(w.Eventos[^1].Severidad == Severidad.Media && w.Eventos[^1].Cuerpo!.Contains("incompleta") && w.Eventos[^1].Cuerpo!.Contains("NO significa que esté bien"), "sin hallazgos pero incompleta: Media, y dice que NO significa que este bien");

            // Boveda.
            Avanza(5);
            await Pedir(m, "{\"tipo\":\"boveda.bloqueada\",\"motivo\":\"minimizar\"}");
            Check(w.Eventos[^1].Modulo == ModuloOrigen.Identidad && w.Eventos[^1].Tipo == TipoEvento.BovedaBloqueada && (string)w.Eventos[^1].Campos["motivo"]! == "minimizar", "bloqueo de la boveda con su motivo, en Identidad");
            Avanza(5);
            await Pedir(m, "{\"tipo\":\"boveda.desbloqueada\",\"entradas\":12}");
            Check((int)w.Eventos[^1].Campos["entradas"]! == 12 && w.Eventos[^1].Tipo == TipoEvento.BovedaDesbloqueada, "desbloqueo con el numero de entradas (solo el numero)");
            Avanza(5);
            await Pedir(m, "{\"tipo\":\"boveda.auditoria\",\"comprobadas\":10,\"comprometidas\":2}");
            Check(w.Eventos[^1].Severidad == Severidad.Alta && (int)w.Eventos[^1].Campos["comprometidas"]! == 2, "auditoria con 2 comprometidas: Alta");

            // Rechazos: nada de texto libre, tipos desconocidos, campos ajenos, rangos.
            async Task Rechaza(string json, string porque)
            {
                int antes = w.Eventos.Count;
                (bool ok, int codigo, _) = await Pedir(m, json);
                Check(!ok && codigo == CodigoDeError.ParametrosInvalidos && w.Eventos.Count == antes, "se rechaza: " + porque);
            }
            Avanza(5);
            await Rechaza("{\"tipo\":\"inventado\"}", "un tipo que no esta en el catalogo");
            await Rechaza("{}", "sin tipo");
            await Rechaza("{\"tipo\":5}", "tipo que no es texto");
            await Rechaza("{\"tipo\":\"seguridad.wifi\",\"hallazgos\":1,\"maxima\":\"Alta\",\"completa\":true,\"texto\":\"hola\"}", "un campo de texto libre que no admite («texto»)");
            await Rechaza("{\"tipo\":\"seguridad.wifi\",\"hallazgos\":1,\"maxima\":\"Alta\",\"completa\":true,\"red\":\"MiCasa\"}", "el nombre de una red");
            await Rechaza("{\"tipo\":\"boveda.creada\",\"sitio\":\"banco.cl\"}", "un sitio en un evento de la boveda");
            await Rechaza("{\"tipo\":\"boveda.desbloqueada\",\"entradas\":-1}", "entradas negativas");
            await Rechaza("{\"tipo\":\"boveda.desbloqueada\",\"entradas\":1000000}", "entradas fuera de rango");
            await Rechaza("{\"tipo\":\"boveda.desbloqueada\",\"entradas\":\"3\"}", "entradas como texto");
            await Rechaza("{\"tipo\":\"boveda.bloqueada\",\"motivo\":\"porque si\"}", "un motivo que no esta en la lista");
            await Rechaza("{\"tipo\":\"boveda.bloqueada\",\"entradas\":3}", "un campo de otro tipo");
            await Rechaza("{\"tipo\":\"seguridad.wifi\",\"hallazgos\":2,\"maxima\":\"Gravisima\",\"completa\":true}", "una gravedad inventada");
            await Rechaza("{\"tipo\":\"seguridad.wifi\",\"hallazgos\":0,\"maxima\":\"Alta\",\"completa\":true}", "gravedad sin hallazgos");
            await Rechaza("{\"tipo\":\"seguridad.wifi\",\"hallazgos\":2000,\"maxima\":\"Alta\",\"completa\":true}", "hallazgos fuera de rango");
            await Rechaza("{\"tipo\":\"seguridad.wifi\",\"hallazgos\":1,\"maxima\":\"Alta\"}", "sin decir si la revision quedo completa");
            await Rechaza("{\"tipo\":\"seguridad.wifi\",\"hallazgos\":1,\"maxima\":\"Alta\",\"completa\":\"si\"}", "«completa» como texto");
            await Rechaza("{\"tipo\":\"boveda.auditoria\",\"comprobadas\":1,\"comprometidas\":5}", "mas comprometidas que comprobadas");
            bool sinParametros = false;
            try { await m.ManejarAsync(ModuloRastroDeVentana.Registrar, null, CancellationToken.None); } catch (ErrorDeComando e) { sinParametros = e.Codigo == CodigoDeError.ParametrosInvalidos; }
            Check(sinParametros, "sin parametros: se rechaza");

            // El catalogo: cada clave produce un evento valido, y el texto lo pone siempre el servicio.
            var w2 = new EscritorFalso();
            var m2 = new ModuloRastroDeVentana(w2, () => ahora);
            foreach (string clave in ModuloRastroDeVentana.Claves)
            {
                Avanza(5);
                string json = clave.StartsWith("seguridad.") ? "{\"tipo\":\"" + clave + "\",\"hallazgos\":0,\"completa\":true}" : "{\"tipo\":\"" + clave + "\"}";
                Check((await Pedir(m2, json)).Ok, "«" + clave + "» se registra");
            }
            Check(w2.Eventos.Count == ModuloRastroDeVentana.Claves.Count && w2.Eventos.All(e => e.Titulo.EndsWith("(desde la ventana)") && e.Cuerpo!.Contains("nunca nombres")), "todos los eventos llevan el texto del servicio y el aviso de privacidad");

            // Topes de frecuencia.
            var w3 = new EscritorFalso();
            var m3 = new ModuloRastroDeVentana(w3, () => ahora);
            string uno = "{\"tipo\":\"boveda.creada\"}";
            Check((await Pedir(m3, uno)).Ok && w3.Eventos.Count == 1, "(preparacion) primer aviso");
            Avanza(1);
            await m3.ManejarAsync(ModuloRastroDeVentana.Registrar, J(uno), CancellationToken.None);
            Check(w3.Eventos.Count == 1, "el mismo tipo a 1 s del anterior NO se registra (minimo 2 s)");
            Avanza(1.1);
            await m3.ManejarAsync(ModuloRastroDeVentana.Registrar, J(uno), CancellationToken.None);
            Check(w3.Eventos.Count == 2, "pasados los 2 s se registra");
            object? resp = await m3.ManejarAsync(ModuloRastroDeVentana.Registrar, J("{\"tipo\":\"boveda.desbloqueada\"}"), CancellationToken.None);
            Check(w3.Eventos.Count == 3, "otro tipo no espera al anterior");
            string r = JsonSerializer.Serialize(await m3.ManejarAsync(ModuloRastroDeVentana.Registrar, J(uno), CancellationToken.None));
            Check(r.Contains("\"registrado\":false") && r.Contains("demasiados avisos"), "lo que no se registra por el tope se dice («registrado»:false), no se finge", r);

            var w4 = new EscritorFalso();
            var m4 = new ModuloRastroDeVentana(w4, () => ahora);
            string[] claves = ModuloRastroDeVentana.Claves.Where(c => c.StartsWith("boveda.") && c != "boveda.bloqueada" && c != "boveda.desbloqueada" && c != "boveda.auditoria").ToArray();
            int pedidos = 0;
            for (int i = 0; i < ModuloRastroDeVentana.MaximoPorHora + 40; i++)
            {
                ahora += TimeSpan.FromSeconds(2.5 / claves.Length + 0.0); // varios tipos a la vez para no chocar con el minimo entre iguales
                await m4.ManejarAsync(ModuloRastroDeVentana.Registrar, J("{\"tipo\":\"" + claves[i % claves.Length] + "\"}"), CancellationToken.None);
                pedidos++;
            }
            Check(w4.Eventos.Count == ModuloRastroDeVentana.MaximoPorHora, "un maximo de " + ModuloRastroDeVentana.MaximoPorHora + " avisos por hora: un programa no puede inundar el vault", w4.Eventos.Count + " de " + pedidos);
            ahora += TimeSpan.FromHours(1.1);
            await m4.ManejarAsync(ModuloRastroDeVentana.Registrar, J("{\"tipo\":\"" + claves[0] + "\"}"), CancellationToken.None);
            Check(w4.Eventos.Count == ModuloRastroDeVentana.MaximoPorHora + 1, "pasada una hora vuelve a registrar");

            // Escritura REAL en un vault de prueba: la nota existe, no lleva nada que no sea del catalogo.
            string vault = Path.Combine(raiz, "vault-rastro");
            using (var real = new ReportWriter(new VaultOptions { RutaVault = vault }))
            {
                await real.InicializarVaultAsync();
                var mr = new ModuloRastroDeVentana(real, () => DateTimeOffset.UtcNow);
                await mr.ManejarAsync(ModuloRastroDeVentana.Registrar, J("{\"tipo\":\"seguridad.fallos_conocidos\",\"hallazgos\":2,\"maxima\":\"Critica\",\"completa\":false}"), CancellationToken.None);
                await mr.ManejarAsync(ModuloRastroDeVentana.Registrar, J("{\"tipo\":\"boveda.bloqueada\",\"motivo\":\"sesion\"}"), CancellationToken.None);
            }
            string[] notas = Directory.GetFiles(vault, "*.md", SearchOption.AllDirectories);
            string todo = string.Join("\n", notas.Select(File.ReadAllText));
            Check(todo.Contains("desde la ventana") && todo.Contains("gravedad_maxima: Critica") && todo.Contains("motivo: sesion"), "en un vault REAL quedan las notas con sus campos", notas.Length + " notas");
            Check(todo.Contains("el servicio no lo comprobó"), "y con el aviso de que el servicio no lo comprobo");
        }
    }
}
