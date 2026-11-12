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
            public readonly List<string> Descartados = new();
            // null = el servicio hace de verdad el descarte sobre el destino del estado (como el servicio real, que usa SU destino).
            public Consulta<ResultadoDeDescartar>? AlDescartar;
            public Task<Consulta<EstadoDeCopiaVista>> EstadoAsync(CancellationToken ct) { Consultas++; return Task.FromResult(Estado); }
            public Task<Consulta<ResultadoDeHacerCopia>> HacerAsync(CancellationToken ct) { Pedidos++; return Task.FromResult(AlHacer); }
            public Task<Consulta<ResultadoDeDescartar>> DescartarAsync(string id, CancellationToken ct)
            {
                Descartados.Add(id);
                if (AlDescartar is not null) return Task.FromResult(AlDescartar);
                (bool ok, string? error) = CopiaVersionada.DescartarSospecha(Estado.Valor!.Destino!, id);
                return Task.FromResult(Consulta<ResultadoDeDescartar>.Bien(new ResultadoDeDescartar(ok, error)));
            }
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

            // ---- protección de la carpeta de copias y descarte por el servicio
            {
                string aviso = "El destino usa exFAT, que no admite permisos";
                var sinProteger = new CopiaFalsa { Estado = Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia(@"E:\", ultima: ahora.AddHours(-1), ultimo: UltimoBueno()) with { AvisoDeProteccion = aviso }) };
                var mp = new CopiaModelo(sinProteger, reloj: () => ahora);
                Esperar(mp.ActualizarAsync());
                Check(mp.Aviso.Contains("NO están protegidas") && mp.Aviso.Contains(aviso), "sin proteger: la pestaña lo dice con el motivo");
                var protegida = new CopiaFalsa { Estado = Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia(@"E:\", ultima: ahora.AddHours(-1), ultimo: UltimoBueno())) };
                var mq = new CopiaModelo(protegida, reloj: () => ahora);
                Esperar(mq.ActualizarAsync());
                Check(!mq.Aviso.Contains("protegidas"), "protegida: no hay aviso de más");
                sinProteger.AlHacer = Consulta<ResultadoDeHacerCopia>.Bien(new ResultadoDeHacerCopia(true, null, 3, 3, 0, false, null, aviso));
                Esperar(mp.HacerAhoraAsync());
                Check(mp.Mensaje.StartsWith("Copia hecha: 3 archivos") && mp.Mensaje.Contains("ATENCIÓN") && mp.Mensaje.Contains(aviso), "al hacer una copia sin protección, el mensaje lo avisa en el momento");
                protegida.AlHacer = Consulta<ResultadoDeHacerCopia>.Bien(new ResultadoDeHacerCopia(true, null, 3, 3, 0, false, null));
                Esperar(mq.HacerAhoraAsync());
                Check(!mq.Mensaje.Contains("ATENCIÓN"), "con protección, el mensaje no lleva el aviso");

                string r3 = Path.Combine(Path.GetTempPath(), "nexo-copia-ven3-" + Guid.NewGuid().ToString("N"));
                try
                {
                    string d = Path.Combine(r3, "d"), c = Path.Combine(r3, "c"); Directory.CreateDirectory(d);
                    for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(d, "f" + i), "x" + i);
                    var cfg3 = new ConfiguracionDeCopia(new[] { d }, c, 5);
                    CopiaVersionada.Copiar(cfg3, ahora);
                    for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(d, "f" + i), "CIFRADO " + i);
                    CopiaVersionada.Copiar(cfg3, ahora.AddMinutes(5));
                    var srv = new CopiaFalsa { Estado = Consulta<EstadoDeCopiaVista>.Bien(EstadoCopia(c, versiones: 2, ultima: ahora.AddMinutes(5), ultimo: UltimoBueno()) with { SospechosasGuardadas = 1 }) };
                    var m = new CopiaModelo(srv, reloj: () => ahora.AddMinutes(10));
                    Esperar(m.ActualizarAsync());
                    FilaDeVersion sosp = m.Versiones.Single(v => v.Sospechosa);
                    m.FilaSeleccionada = sosp;
                    Esperar(m.DescartarSospechaAsync());
                    Check(srv.Descartados.SequenceEqual(new[] { sosp.Id }), "descartar le pide al SERVICIO esa copia por su id (la ventana ya no escribe en la carpeta de copias)", string.Join(",", srv.Descartados));
                    Check(m.Mensaje.StartsWith("Listo") && !m.Versiones.Any(v => v.Sospechosa), "y la pestaña se recarga sin la sospechosa");

                    // El servicio se niega: se dice, no se finge.
                    CopiaVersionada.Copiar(new ConfiguracionDeCopia(new[] { d }, c, 5), ahora.AddMinutes(20));
                    for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(d, "f" + i), "OTRA " + i);
                    CopiaVersionada.Copiar(cfg3, ahora.AddMinutes(30));
                    var rechaza = new CopiaFalsa { Estado = srv.Estado, AlDescartar = Consulta<ResultadoDeDescartar>.Bien(new ResultadoDeDescartar(false, "No existe esa copia.")) };
                    var mr = new CopiaModelo(rechaza, reloj: () => ahora.AddMinutes(40));
                    Esperar(mr.ActualizarAsync());
                    mr.FilaSeleccionada = mr.Versiones.First(v => v.Sospechosa);
                    Esperar(mr.DescartarSospechaAsync());
                    Check(mr.Mensaje == "No se pudo descartar la sospecha: No existe esa copia." && mr.Versiones.Any(v => v.Sospechosa), "si el servicio dice que no, lo muestra y la sospecha sigue");
                    var caido = new CopiaFalsa { Estado = srv.Estado, AlDescartar = Consulta<ResultadoDeDescartar>.Mal("el servicio no está en marcha") };
                    var mc = new CopiaModelo(caido, reloj: () => ahora.AddMinutes(40));
                    Esperar(mc.ActualizarAsync());
                    mc.FilaSeleccionada = mc.Versiones.First(v => v.Sospechosa);
                    Esperar(mc.DescartarSospechaAsync());
                    Check(mc.Mensaje.Contains("el servicio no está en marcha") && mc.Versiones.Any(v => v.Sospechosa), "sin servicio: lo dice, no finge haberlo hecho");
                }
                finally { try { Directory.Delete(r3, true); } catch { } }

                // El lector del pipe
                Check(LectorDeCopia.Descartar(Json("{\"exito\":true,\"error\":null}")).Valor is { Exito: true, Error: null }, "lector: descartar bien");
                Check(LectorDeCopia.Descartar(Json("{\"exito\":false,\"error\":\"No existe esa copia.\"}")).Valor is { Exito: false, Error: "No existe esa copia." }, "lector: descartar con motivo");
                Check(LectorDeCopia.Descartar(Json("{\"exito\":false,\"error\":null}")).Valor is { Exito: false, Error: { Length: > 0 } }, "lector: un fallo sin motivo igual lleva un motivo");
                Check(LectorDeCopia.Descartar(new RespuestaCruda(false, "metodo desconocido", null)).Error!.Contains("actualízalo"), "lector: un servicio viejo sin copia.descartar se explica");
                Check(LectorDeCopia.Descartar(Json("{}")).Error == "respuesta del servicio no reconocida", "lector: JSON incompleto es «no reconocida»");
                Check(LectorDeCopia.Estado(Json("{\"activo\":true,\"destino\":\"E:\\\\\",\"destino_disponible\":true,\"versiones_a_conservar\":3,\"versiones_en_destino\":1,\"listas_ilegibles\":0,\"en_curso\":false,\"carpetas\":[],\"sin_copia\":[],\"nota\":\"n\",\"aviso_proteccion\":\"exFAT\"}")).Valor?.AvisoDeProteccion == "exFAT",
                      "lector: el estado trae el aviso de protección");
                Check(LectorDeCopia.Hacer(Json("{\"exito\":true,\"archivos\":1,\"nuevos\":1,\"omitidos\":0,\"sospechosa\":false,\"aviso_proteccion\":\"exFAT\"}")).Valor?.AvisoDeProteccion == "exFAT", "lector: copia.hacer trae el aviso de protección");
            }

            // ---- el lector con un JSON mal formado
            Check(LectorDeCopia.Estado(Json("{\"activo\":true}")).Error == "respuesta del servicio no reconocida", "un JSON incompleto es «no reconocida», no un verde inventado");
            Check(LectorDeCopia.Estado(new RespuestaCruda(false, "metodo desconocido", null)).Error!.Contains("no tiene copia"), "un servicio viejo sin copia.estado se explica");
        }
    }
}
