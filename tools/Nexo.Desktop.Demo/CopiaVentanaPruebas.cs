using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Ui.Desktop;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        private sealed class CopiaFalsa : IServicioDeCopia
        {
            public Consulta<EstadoDeCopiaVista> Estado = Consulta<EstadoDeCopiaVista>.Mal("sin datos de prueba");
            public Consulta<ResultadoDeHacerCopia> AlHacer = Consulta<ResultadoDeHacerCopia>.Bien(new ResultadoDeHacerCopia(true, null, 3, 3, 0, false, null));
            public int Consultas, Pedidos;
            public Task<Consulta<EstadoDeCopiaVista>> EstadoAsync(CancellationToken ct) { Consultas++; return Task.FromResult(Estado); }
            public Task<Consulta<ResultadoDeHacerCopia>> HacerAsync(CancellationToken ct) { Pedidos++; return Task.FromResult(AlHacer); }
        }

        private static EstadoDeCopiaVista EstadoCopia(string destino, bool disponible = true, int versiones = 1, DateTimeOffset? ultima = null, UltimaCopiaVista? ultimo = null, bool enCurso = false)
            => new(true, destino, disponible, 7, versiones, 0, null, enCurso, ultima, ultimo, new[] { @"C:\Users\ana\Documents" }, Array.Empty<string>(), null, "nota");

        private static UltimaCopiaVista UltimoBueno() => new(true, null, 3, 3, 0, Array.Empty<OmitidoVista>(), false, null, 0, false, null);

        private static void ProbarCopiaEnLaVentana()
        {
            Console.WriteLine("== Copias: resumen, modelo de la pestaña, restaurar y verificar");
            DateTimeOffset ahora = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);

            // ---- qué se dice y de qué color
            Check(CopiaModelo.Resumir(null, ahora).Item1 == Indicador.SinDatos, "sin consultar: gris");
            Check(CopiaModelo.Resumir(Consulta<EstadoDeCopiaVista>.Mal("el servicio no está en marcha"), ahora).Item1 == Indicador.SinDatos, "sin servicio: gris, nunca verde");
            Check(CopiaModelo.Resumir(Consulta<EstadoDeCopiaVista>.Bien(new EstadoDeCopiaVista(false, null, false, 0, 0, 0, null, false, null, null, Array.Empty<string>(), Array.Empty<string>(), null, "apagada")), ahora).Item1 == Indicador.SinDatos,
                  "apagada: gris, no «todo bien»");
            Check(CopiaModelo.Resumir(Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia("E:\\", ultima: ahora.AddHours(-1), ultimo: UltimoBueno() with { Sospechosa = true, MotivoSospecha = "25 de 25" })), ahora).Item1 == Indicador.Alerta,
                  "copia sospechosa: ROJO aunque sea reciente");
            Check(CopiaModelo.Resumir(Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia("E:\\", ultima: ahora.AddHours(-1), ultimo: UltimoBueno()) with { SospechosasGuardadas = 1 }), ahora) is (Indicador.Alerta, "Hay una copia sospechosa guardada", _),
                  "una sospechosa GUARDADA mantiene el rojo aunque la última copia salió normal");
            Check(CopiaModelo.Resumir(Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia("E:\\", ultima: ahora.AddHours(-1), ultimo: UltimoBueno()) with { SospechosasGuardadas = 0 }), ahora).Item1 == Indicador.Correcto, "con 0 sospechosas guardadas, verde");
            Check(CopiaModelo.Resumir(Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia("E:\\", ultima: ahora.AddHours(-1), ultimo: UltimoBueno() with { Correcto = false, Error = "disco lleno" })), ahora).Item1 == Indicador.Alerta, "última copia fallida: rojo");
            Check(CopiaModelo.Resumir(Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia("E:\\", disponible: false, ultima: ahora.AddHours(-1), ultimo: UltimoBueno())), ahora).Item1 == Indicador.Atencion, "disco desconectado: amarillo");
            Check(CopiaModelo.Resumir(Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia("E:\\", versiones: 0)), ahora) is (Indicador.Atencion, "Todavía no hay copias", _), "sin ninguna copia: amarillo, no verde");
            Check(CopiaModelo.Resumir(Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia("E:\\", ultima: ahora.AddDays(-8), ultimo: UltimoBueno())), ahora).Item1 == Indicador.Atencion, "copia de hace 8 días: amarillo");
            Check(CopiaModelo.Resumir(Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia("E:\\", ultima: ahora.AddDays(-6), ultimo: UltimoBueno())), ahora).Item1 == Indicador.Correcto, "copia de hace 6 días: verde");

            // ---- el modelo, con disco real
            string raiz = Path.Combine(Path.GetTempPath(), "nexo-copia-ven-" + Guid.NewGuid().ToString("N"));
            try
            {
                string docs = Path.Combine(raiz, "docs"), copia = Path.Combine(raiz, "copia");
                Directory.CreateDirectory(docs);
                File.WriteAllText(Path.Combine(docs, "a.txt"), "uno"); File.WriteAllText(Path.Combine(docs, "b.txt"), "dos");
                var cfg = new ConfiguracionDeCopia(new[] { docs }, copia, 5);
                CopiaVersionada.Copiar(cfg, ahora);
                File.WriteAllText(Path.Combine(docs, "a.txt"), "uno cambiado");
                CopiaVersionada.Copiar(cfg, ahora.AddMinutes(5));

                var srv = new CopiaFalsa { Estado = Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia(copia, versiones: 2, ultima: ahora.AddMinutes(5), ultimo: UltimoBueno())) };
                var m = new CopiaModelo(srv, reloj: () => ahora.AddMinutes(10));
                Check(!m.PuedeCopiar && !m.PuedeRestaurar && !m.PuedeVerificar && m.Titulo == "Sin consultar", "antes de consultar: nada habilitado");
                Esperar(m.ActualizarAsync());
                Check(m.Indicador == Indicador.Correcto && m.Versiones.Count == 2 && m.PuedeCopiar && m.PuedeVerificar && !m.PuedeRestaurar,
                      "tras consultar: verde, 2 versiones leídas del disco, sin versión elegida no se puede restaurar");
                Check(m.Versiones[0].Id.CompareTo(m.Versiones[1].Id) > 0, "la más reciente primero");

                // Elegir y deseleccionar muchas veces no recursa ni pierde el estado
                for (int i = 0; i < 50; i++) { m.FilaSeleccionada = m.Versiones[i % 2]; m.FilaSeleccionada = null; }
                m.FilaSeleccionada = m.Versiones[1];
                Check(m.PuedeRestaurar && m.Seleccionada == m.Versiones[1].Id, "elegir una versión habilita «Restaurar»");
                Esperar(m.ActualizarAsync());
                Check(m.Seleccionada == m.Versiones[1].Id && m.FilaSeleccionada?.Id == m.Seleccionada, "actualizar conserva la versión elegida");

                // Restaurar la vieja: trae «uno», no «uno cambiado»
                string rest = Path.Combine(raiz, "rest");
                Esperar(m.RestaurarAsync(rest));
                Check(m.Mensaje.StartsWith("Restaurados 2 archivos") && File.ReadAllText(Path.Combine(rest, "docs", "a.txt")) == "uno", "restaurar la versión vieja devuelve el contenido de entonces", m.Mensaje);
                Check(File.ReadAllText(Path.Combine(docs, "a.txt")) == "uno cambiado", "y no toca los originales");
                Esperar(m.RestaurarAsync(rest));
                Check(m.Mensaje.Contains("no pisa") && !m.Mensaje.StartsWith("Restaurados"), "restaurar sobre una carpeta con cosas: se niega y lo dice", m.Mensaje);

                Esperar(m.VerificarAsync());
                Check(m.Mensaje.StartsWith("Todo en orden"), "verificar: todo en orden", m.Mensaje);
                string blob = Directory.GetFiles(Path.Combine(copia, CopiaVersionada.CarpetaDeCopias, "contenido"), "*", SearchOption.AllDirectories).First(f => Path.GetFileName(f).Length == 64);
                File.WriteAllText(blob, "alterado");
                Esperar(m.VerificarAsync());
                Check(m.Mensaje.Contains("problema") && m.Mensaje.Contains("cambió"), "verificar caza el contenido alterado", m.Mensaje);

                // Copiar ahora
                Esperar(m.HacerAhoraAsync());
                Check(srv.Pedidos == 1 && m.Mensaje.StartsWith("Copia hecha: 3 archivos"), "«Copiar ahora» pide una copia al servicio", m.Mensaje);
                srv.AlHacer = Consulta<ResultadoDeHacerCopia>.Bien(new ResultadoDeHacerCopia(false, "El destino no está disponible.", 0, 0, 0, false, null));
                Esperar(m.HacerAhoraAsync());
                Check(m.Mensaje.StartsWith("La copia no se hizo: El destino no está disponible"), "si no se hizo, lo dice");
                srv.AlHacer = Consulta<ResultadoDeHacerCopia>.Bien(new ResultadoDeHacerCopia(true, null, 25, 25, 0, true, "25 de 25 cambiaron"));
                Esperar(m.HacerAhoraAsync());
                Check(m.Mensaje.Contains("SOSPECHOSA") && m.Mensaje.Contains("25 de 25"), "una copia sospechosa se dice con letras grandes");
                srv.AlHacer = Consulta<ResultadoDeHacerCopia>.Mal("el servicio no está en marcha");
                Esperar(m.HacerAhoraAsync());
                Check(m.Mensaje.StartsWith("No se pudo pedir la copia: el servicio no está en marcha"), "sin servicio: lo dice");

                // Disco desconectado: no se puede copiar ni restaurar y no se lee la lista
                srv.Estado = Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia(copia, disponible: false, versiones: 0, ultima: ahora, ultimo: UltimoBueno()));
                Esperar(m.ActualizarAsync());
                Check(!m.PuedeCopiar && !m.PuedeRestaurar && !m.PuedeVerificar && m.Versiones.Count == 0 && m.Indicador == Indicador.Atencion, "disco desconectado: todo inactivo y sin lista");
                int antesDePedir = srv.Pedidos;
                Esperar(m.HacerAhoraAsync());
                Check(srv.Pedidos == antesDePedir, "y «Copiar ahora» no llama al servicio");

                // En curso
                srv.Estado = Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia(copia, enCurso: true, ultima: ahora, ultimo: UltimoBueno()));
                Esperar(m.ActualizarAsync());
                Check(!m.PuedeCopiar && m.Resumen.Contains("copiando ahora"), "con una copia en marcha no se pide otra");

                // Aviso: omitidos y poda suspendida
                srv.Estado = Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia(copia, ultima: ahora, ultimo: UltimoBueno() with { Omitidos = 2, PrimerosOmitidos = new[] { new OmitidoVista(@"C:\x\a.docx", "Está en uso") }, PodaSuspendida = true, MotivoPoda = "No se borró ninguna versión vieja" }));
                Esperar(m.ActualizarAsync());
                Check(m.Aviso.Contains("a.docx (Está en uso)") && m.Aviso.Contains("No se borró ninguna versión vieja"), "lo omitido y la poda suspendida se ven, con motivo");

                // Servicio roto
                var rota = new CopiaModelo(new CopiaFalsa());
                Esperar(rota.ActualizarAsync());
                Check(rota.Indicador == Indicador.SinDatos && !rota.PuedeCopiar && rota.Explicacion.Contains("No se sabe si hay copias"), "servicio sin respuesta: gris y sin botones");
                Check(new CopiaModelo(new ServicioDeCopiaNoDisponible("sin servicio")).Indicador == Indicador.SinDatos, "sin fuente: gris");
            }
            finally { try { Directory.Delete(raiz, true); } catch { } }

            // ---- descartar la sospecha (disco real)
            string r2 = Path.Combine(Path.GetTempPath(), "nexo-copia-ven2-" + Guid.NewGuid().ToString("N"));
            try
            {
                string d = Path.Combine(r2, "d"), c = Path.Combine(r2, "c");
                Directory.CreateDirectory(d);
                for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(d, "f" + i), "bueno " + i);
                var cfg = new ConfiguracionDeCopia(new[] { d }, c, 5);
                CopiaVersionada.Copiar(cfg, ahora);
                for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(d, "f" + i), "CIFRADO " + i);
                CopiaVersionada.Copiar(cfg, ahora.AddMinutes(5));
                var srv = new CopiaFalsa { Estado = Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia(c, versiones: 2, ultima: ahora.AddMinutes(5), ultimo: UltimoBueno()) with { SospechosasGuardadas = 1 }) };
                var m = new CopiaModelo(srv, reloj: () => ahora.AddMinutes(10));
                Esperar(m.ActualizarAsync());
                FilaDeVersion sosp = m.Versiones.Single(v => v.Sospechosa), buena = m.Versiones.Single(v => !v.Sospechosa);
                Check(sosp.Texto.Contains("SOSPECHOSA") && m.Indicador == Indicador.Alerta, "la sospechosa se ve marcada y el indicador está en rojo");
                Check(!m.PuedeDescartar, "sin elegir nada, no se puede descartar");
                m.FilaSeleccionada = buena;
                Check(!m.PuedeDescartar && m.PuedeRestaurar, "una versión buena: se puede restaurar pero NO «descartar la sospecha»");
                Esperar(m.DescartarSospechaAsync());
                Check(m.Versiones.Count(v => v.Sospechosa) == 1, "y pedirlo no cambia nada");
                m.FilaSeleccionada = sosp;
                Check(m.PuedeDescartar, "la sospechosa elegida: «Descartar la sospecha» disponible");
                var rota = new CopiaModelo(srv, descartar: (_, _) => (false, "No tienes permiso"));
                Esperar(rota.ActualizarAsync());
                rota.FilaSeleccionada = rota.Versiones.Single(v => v.Sospechosa);
                Esperar(rota.DescartarSospechaAsync());
                Check(rota.Mensaje.StartsWith("No se pudo descartar la sospecha: No tienes permiso") && rota.Versiones.Any(v => v.Sospechosa), "si no hay permiso, lo dice y no pasa nada");
                Esperar(m.DescartarSospechaAsync());
                Check(m.Mensaje.StartsWith("Listo") && !m.Versiones.Any(v => v.Sospechosa) && !m.PuedeDescartar, "descartar: la lista se recarga sin sospechosas");
                Check(!CopiaVersionada.Listar(c, out _).Any(v => v.Sospechosa) && CopiaVersionada.Verificar(c).Correcto, "en el disco también, y el contenido sigue intacto");
            }
            finally { try { Directory.Delete(r2, true); } catch { } }

            // ---- el lector con un JSON mal formado
            Check(LectorDeCopia.Estado(Json("{\"activo\":true}")).Error == "respuesta del servicio no reconocida", "un JSON incompleto es «no reconocida», no un verde inventado");
            Check(LectorDeCopia.Estado(new RespuestaCruda(false, "metodo desconocido", null)).Error!.Contains("no tiene copia"), "un servicio viejo sin copia.estado se explica");
        }
    }
}
