using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Reports;
using Nexo.Reports.Model;
using Nexo.Service;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Tray.Demo
{
    internal static partial class Program
    {
        private sealed class DiscoMinimo : IAccesoASenuelos
        {
            public readonly Dictionary<string, (byte[] Datos, ulong Id)> Archivos = new(StringComparer.OrdinalIgnoreCase);
            public readonly HashSet<string> Carpetas = new(StringComparer.OrdinalIgnoreCase);
            private ulong _id = 1;
            public bool CarpetaExiste(string c) => Carpetas.Contains(c);
            public bool Existe(string r) => Archivos.ContainsKey(r);
            public CreacionDeSenuelo Crear(string r, byte[] c)
            {
                if (Archivos.ContainsKey(r)) return new CreacionDeSenuelo(EstadoDeCreacion.Ocupado);
                Archivos[r] = (c.ToArray(), _id++);
                return new CreacionDeSenuelo(EstadoDeCreacion.Creado, _id - 1);
            }
            public LecturaDeSenuelo Leer(string r)
                => Archivos.TryGetValue(r, out var a) ? new LecturaDeSenuelo(EstadoDeLectura.Leido, a.Datos.Length, VigilanteDeSenuelos.Huella(a.Datos), a.Id) : LecturaDeSenuelo.NoExiste;
            public BusquedaPorId BuscarPorId(string c, ulong id)
            {
                foreach (var kv in Archivos) if (kv.Value.Id == id) return new BusquedaPorId(EstadoDeBusqueda.Encontrado, kv.Key);
                return new BusquedaPorId(EstadoDeBusqueda.NoExiste);
            }
            public void Mover(string de, string a) { var x = Archivos[de]; Archivos.Remove(de); Archivos[a] = x; }
        }

        private sealed class ListaMinima : IAlmacenDeSenuelos
        {
            private List<Senuelo> _l = new();
            public IReadOnlyList<Senuelo> Cargar(out string? problema) { problema = null; return _l.ToList(); }
            public string? Guardar(IReadOnlyList<Senuelo> s) { _l = s.ToList(); return null; }
        }

        private sealed class VaultNulo : IReportWriter
        {
            public Task<NoteRef> EscribirAsync(NexoEvent e, CancellationToken ct = default) => Task.FromResult<NoteRef>(null!);
            public Task InicializarVaultAsync(CancellationToken ct = default) => Task.CompletedTask;
        }

        private static InstantaneaDelServicio Sana(IReadOnlyList<SenueloTocadoVista>? tocados, bool rafaga = false, string? error = null)
            => new(true, "1", true, true, false, 0, 0, Array.Empty<DeteccionVista>(), null, null, null, 0, tocados, rafaga, error);

        /// <summary>
        /// La bandeja con el JSON REAL que produce ModuloSenuelos (no uno escrito a mano): lo lee, se pone en rojo, avisa una vez por señuelo,
        /// y nunca toma «no entendí la respuesta» por «ninguno tocado».
        /// </summary>
        private static async Task ProbarSenuelosEnLaBandeja()
        {
            Console.WriteLine("Señuelos en la bandeja (con el JSON real del servicio)");
            const string Docs = @"C:\Users\ana\Documents";
            DateTimeOffset ahora = new(2026, 11, 9, 21, 0, 0, TimeSpan.FromHours(-3));
            var disco = new DiscoMinimo();
            disco.Carpetas.Add(Docs);
            var v = new VigilanteDeSenuelos(disco, new ListaMinima(), new VaultNulo(), () => ahora);
            var modulo = new ModuloSenuelos(v, () => (new[] { Docs }, Array.Empty<CarpetaSinSenuelo>()), reloj: () => ahora);
            async Task<JsonElement> Estado() => JsonSerializer.SerializeToElement(await modulo.ManejarAsync("senuelos.estado", null, CancellationToken.None));

            await v.PrepararAsync(new[] { Docs });
            await v.RevisarAsync();
            var (l0, r0, e0) = ConsultorDelServicio.LeerSenuelos(await Estado());
            var m = new ModeloDeBandeja();
            m.Actualizar(Sana(l0, r0, e0));
            Check(l0 is { Count: 0 } && e0 is null && m.Estado == EstadoDeBandeja.Normal, "señuelos intactos: ninguno tocado y la bandeja en verde", m.Texto);

            // Contrato con la ventana (LectorDeSenuelosDelServicio): los campos que lee existen en la respuesta real.
            JsonElement est = await Estado();
            Check(est.TryGetProperty("rafaga", out _) && est.TryGetProperty("ultima_revision", out _) && est.TryGetProperty("sin_senuelo", out _) && est.TryGetProperty("aviso", out _)
                  && est.GetProperty("senuelos")[0].TryGetProperty("no_comprobado", out _) && est.GetProperty("senuelos")[0].TryGetProperty("carpeta", out _),
                "la respuesta real tiene todos los campos que leen la ventana y la bandeja");

            // Uno tocado.
            string d0 = Path.Combine(Docs, "!nexo-señuelo.docx"), d1 = Path.Combine(Docs, "zz-nexo-señuelo.xlsx");
            disco.Archivos[d0] = (new byte[] { 1 }, disco.Archivos[d0].Id);
            await v.RevisarAsync();
            var (l1, r1, e1) = ConsultorDelServicio.LeerSenuelos(await Estado());
            m.Actualizar(Sana(l1, r1, e1));
            Check(l1 is { Count: 1 } && l1[0].Tipo == "modificado" && l1[0].Severidad == "Alta" && l1[0].Ruta == d0 && !r1, "uno cifrado: se lee como modificado, Alta, sin ráfaga");
            Check(m.Estado == EstadoDeBandeja.Alerta && m.Texto == "Nexo: señuelo contra ransomware tocado" && m.SenuelosNuevos.Count == 1, "la bandeja se pone en rojo y hay un aviso nuevo", m.Texto);
            (string t1, string x1) = AccionesDelServicio.AvisoDeSenuelos(m.SenuelosNuevos, r1);
            Check(t1.Contains("señuelo") && x1.Contains(Docs) && x1.Contains("se modificó") && x1.Contains("desconecta"), "el globo dice dónde, qué pasó y qué hacer", t1 + " / " + x1);
            m.Actualizar(Sana(l1, r1, e1));
            Check(m.SenuelosNuevos.Count == 0 && m.Estado == EstadoDeBandeja.Alerta, "en la siguiente consulta NO se vuelve a avisar, pero sigue en rojo");
            m.MarcarRevisadas();
            Check(m.Estado == EstadoDeBandeja.Alerta, "abrir las detecciones no apaga la alerta de los señuelos (hay que reponerlos)");

            // Un fallo al consultar los señuelos no se toma por «ninguno tocado» ni re-avisa al volver.
            m.Actualizar(Sana(null, false, "el servicio no dio el estado de los señuelos"));
            Check(m.SenuelosNuevos.Count == 0, "sin poder leer los señuelos: nada nuevo que avisar");
            m.Actualizar(Sana(l1, r1, e1));
            Check(m.SenuelosNuevos.Count == 0, "y cuando vuelve a leerlos, el mismo señuelo no se avisa dos veces");

            // Un segundo en poco tiempo: ráfaga.
            ahora = ahora.AddMinutes(2);
            disco.Mover(d1, d1 + ".locked");
            await v.RevisarAsync();
            var (l2, r2, e2) = ConsultorDelServicio.LeerSenuelos(await Estado());
            m.Actualizar(Sana(l2, r2, e2));
            Check(l2!.Count == 2 && r2 && m.SenuelosNuevos.Count == 1 && m.SenuelosNuevos[0].Tipo == "renombrado", "el segundo: renombrado, ráfaga, y solo él es nuevo");
            Check(m.Texto.Contains("POSIBLE RANSOMWARE") && AccionesDelServicio.AvisoDeSenuelos(m.SenuelosNuevos, r2).Titulo.Contains("posible ransomware"), "con ráfaga: la bandeja y el globo dicen «posible ransomware»", m.Texto);
            ahora = ahora.AddMinutes(30);
            Check(!ConsultorDelServicio.LeerSenuelos(await Estado()).Item2, "pasados 10 minutos ya no es ráfaga (pero siguen tocados)");

            // Reponer: la alerta se va; si se vuelve a tocar, es un aviso nuevo.
            await v.ReponerAsync(v.PrepararReposicion());
            await v.RevisarAsync();
            var (l3, r3, e3) = ConsultorDelServicio.LeerSenuelos(await Estado());
            m.Actualizar(Sana(l3, r3, e3));
            Check(l3!.Count == 0 && m.Estado == EstadoDeBandeja.Normal, "repuestos: vuelve al verde", m.Texto);
            string nuevo = v.Estado().Senuelos.Single(s => s.Ranura == 0).Ruta;
            disco.Mover(nuevo, @"C:\$Recycle.Bin\S-1-5-21-1\$R1.docx");
            await v.RevisarAsync();
            var (l4, r4, e4) = ConsultorDelServicio.LeerSenuelos(await Estado());
            m.Actualizar(Sana(l4, r4, e4));
            Check(m.SenuelosNuevos.Count == 1 && l4![0].Severidad == "Media" && !r4 && AccionesDelServicio.AvisoDeSenuelos(m.SenuelosNuevos, r4).Texto.Contains("papelera"),
                "a la papelera: aviso nuevo, Media, y el globo dice «si fuiste tú, repónlo»");

            // Apagado y respuestas raras.
            var (la, ra, ea) = ConsultorDelServicio.LeerSenuelos(JsonSerializer.SerializeToElement(await new ModuloSenuelosApagado().ManejarAsync("senuelos.estado", null, CancellationToken.None)));
            Check(la is { Count: 0 } && !ra && ea is null, "apagados: ninguno tocado y sin error (son opcionales)");
            JsonElement rara = JsonDocument.Parse("{\"activo\":true,\"senuelos\":[{\"ruta\":\"C:\\\\x\",\"tocado\":true,\"hallazgo\":{\"tipo\":\"borrado\",\"detalle\":\"x\",\"cuando\":\"2026-11-09T20:00:00-03:00\"}}]}").RootElement;
            var (lr, _, er) = ConsultorDelServicio.LeerSenuelos(rara);
            Check(lr is null && er is not null, "una respuesta sin «severidad»: null y error, nunca «ninguno tocado»");
            m.Actualizar(Sana(lr, false, er));
            Check(m.Estado == EstadoDeBandeja.Atencion && m.Texto.Contains("señuelos"), "y la bandeja NO se pone en verde: atención, «no se pudo leer el estado de los señuelos»", m.Texto);

            // Reponer por el pipe: el «exito» del servicio manda.
            Check(AccionesDelServicio.MetodoDeAplicar(TipoDeAccion.Senuelos) == "senuelos.reponer", "TipoDeAccion.Senuelos va a «senuelos.reponer»");
            string pipe = "nexo-tray-senuelos-" + Guid.NewGuid().ToString("N");
            var falso = new ServicioQueContesta { Respuesta = new { exito = false, repuestos = 0, problemas = new[] { "C:\\x: todos los nombres posibles están ocupados" } } };
            await using (var servidor = new Nexo.Ipc.ServidorDePipe(pipe, falso))
            {
                servidor.Iniciar();
                ResultadoDeAplicar ra2 = await AccionesDelServicio.AplicarAsync(pipe, TipoDeAccion.Senuelos, new string('b', 64), TimeSpan.FromSeconds(5));
                Check(!ra2.Exito && ra2.Mensaje.Contains("ningún señuelo") && ra2.Mensaje.Contains("ocupados"), "reponer sin éxito: no se presenta como hecho, y dice por qué", ra2.Mensaje);
                falso.Respuesta = new { exito = true, repuestos = 2, problemas = Array.Empty<string>() };
                ResultadoDeAplicar rb = await AccionesDelServicio.AplicarAsync(pipe, TipoDeAccion.Senuelos, new string('b', 64), TimeSpan.FromSeconds(5));
                Check(rb.Exito && rb.Mensaje == "2 señuelos repuestos.", "reponer con éxito: «2 señuelos repuestos.»", rb.Mensaje);
            }
        }
    }
}
