using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Vuln.Demo
{
    internal static partial class Program
    {
        /// <summary>Un disco en memoria con números de archivo, para probar las reglas de los señuelos sin tocar el disco.</summary>
        private sealed class DiscoFalso : IAccesoASenuelos
        {
            public readonly Dictionary<string, (byte[] Datos, ulong Id)> Archivos = new(StringComparer.OrdinalIgnoreCase);
            public readonly HashSet<string> Carpetas = new(StringComparer.OrdinalIgnoreCase);
            public readonly Dictionary<string, string> NoLeibles = new(StringComparer.OrdinalIgnoreCase);
            public readonly List<string> Creados = new();
            public ulong SiguienteId = 1000;
            public bool BusquedaFalla, CrearSinId;
            public string? CrearFalla;

            public bool CarpetaExiste(string carpeta) => Carpetas.Contains(carpeta.TrimEnd('\\'));
            public bool Existe(string ruta) => Archivos.ContainsKey(ruta) || Carpetas.Contains(ruta);

            public CreacionDeSenuelo Crear(string ruta, byte[] contenido)
            {
                if (Existe(ruta)) return new CreacionDeSenuelo(EstadoDeCreacion.Ocupado);
                if (CrearFalla is not null) return new CreacionDeSenuelo(EstadoDeCreacion.Fallo, Motivo: CrearFalla);
                ulong id = SiguienteId++;
                Archivos[ruta] = (contenido.ToArray(), id);
                Creados.Add(ruta);
                return new CreacionDeSenuelo(EstadoDeCreacion.Creado, CrearSinId ? null : id);
            }

            public LecturaDeSenuelo Leer(string ruta)
            {
                if (NoLeibles.TryGetValue(ruta, out string? m)) return LecturaDeSenuelo.NoLeido(m);
                if (!Archivos.TryGetValue(ruta, out var a)) return LecturaDeSenuelo.NoExiste;
                return new LecturaDeSenuelo(EstadoDeLectura.Leido, a.Datos.Length, VigilanteDeSenuelos.Huella(a.Datos), a.Id);
            }

            public BusquedaPorId BuscarPorId(string carpeta, ulong id)
            {
                if (BusquedaFalla) return new BusquedaPorId(EstadoDeBusqueda.NoSePudo, Motivo: "acceso denegado");
                foreach (var kv in Archivos) if (kv.Value.Id == id) return new BusquedaPorId(EstadoDeBusqueda.Encontrado, kv.Key);
                return new BusquedaPorId(EstadoDeBusqueda.NoExiste);
            }

            // Lo que haría un ransomware (o el usuario).
            public void Cifrar(string ruta) { var a = Archivos[ruta]; Archivos[ruta] = (a.Datos.Select(b => (byte)(b ^ 0x5A)).ToArray(), a.Id); }
            public void Mover(string de, string a, bool cifrar = false)
            {
                var x = Archivos[de]; Archivos.Remove(de);
                Archivos[a] = (cifrar ? x.Datos.Select(b => (byte)(b ^ 0x5A)).ToArray() : x.Datos, x.Id);
            }
            public void Sustituir(string ruta) { var a = Archivos[ruta]; Archivos[ruta] = (a.Datos.Select(b => (byte)~b).ToArray(), SiguienteId++); }
        }

        private sealed class AlmacenFalso : IAlmacenDeSenuelos
        {
            public List<Senuelo> Guardado = new();
            public int Guardados;
            public string? Problema, FalloAlGuardar;
            public IReadOnlyList<Senuelo> Cargar(out string? problema) { problema = Problema; return Guardado.ToList(); }
            public string? Guardar(IReadOnlyList<Senuelo> s) { if (FalloAlGuardar is not null) return FalloAlGuardar; Guardados++; Guardado = s.ToList(); return null; }
        }

        private sealed class VaultFalso : IReportWriter
        {
            public readonly List<NexoEvent> Eventos = new();
            public bool Falla;
            public Task<NoteRef> EscribirAsync(NexoEvent evento, CancellationToken ct = default)
            {
                if (Falla) throw new IOException("vault caído");
                lock (Eventos) Eventos.Add(evento);
                return Task.FromResult<NoteRef>(null!);
            }
            public Task InicializarVaultAsync(CancellationToken ct = default) => Task.CompletedTask;
        }

        private const string Docs = @"C:\Users\ana\Documents", Escr = @"C:\Users\ana\Desktop", Imgs = @"C:\Users\ana\Pictures";

        private static T Esperar<T>(Task<T> t) => t.GetAwaiter().GetResult();
        private static void Esperar(Task t) => t.GetAwaiter().GetResult();

        public static void ProbarSenuelos()
        {
            Console.WriteLine("26. Señuelos contra ransomware: poner, revisar, avisar y reponer");
            DateTimeOffset ahora = new DateTimeOffset(2026, 11, 9, 20, 0, 0, TimeSpan.FromHours(-3));
            var disco = new DiscoFalso();
            disco.Carpetas.UnionWith(new[] { Docs, Escr });
            disco.Archivos[Path.Combine(Escr, "zz-nexo-señuelo.xlsx")] = (new byte[] { 1, 2, 3 }, 7);   // un archivo AJENO con el mismo nombre
            var almacen = new AlmacenFalso();
            var vault = new VaultFalso();
            var v = new VigilanteDeSenuelos(disco, almacen, vault, () => ahora);
            var alarmas = new List<IReadOnlyList<Senuelo>>();
            v.Alarma += x => alarmas.Add(x);

            // --- Poner ---
            Esperar(v.PrepararAsync(new[] { Docs, Escr + "\\", Imgs }));
            EstadoDeSenuelos e = v.Estado();
            Check(e.Senuelos.Count == 3 && disco.Creados.Count == 3, "pone 2 señuelos por carpeta existente salvo donde el nombre está ocupado (3)", string.Join(", ", disco.Creados));
            Check(disco.Creados.Contains(Path.Combine(Docs, "!nexo-señuelo.docx")) && disco.Creados.Contains(Path.Combine(Docs, "zz-nexo-señuelo.xlsx")),
                "nombres: uno se ordena al principio («!») y otro al final («zz»)");
            Check(string.Compare("!nexo-señuelo.docx", "0 algo.docx", StringComparison.OrdinalIgnoreCase) < 0
                  && string.Compare("zz-nexo-señuelo.xlsx", "Zoológico.xlsx", StringComparison.OrdinalIgnoreCase) > 0, "el orden se cumple contra nombres típicos");
            Check(disco.Archivos[Path.Combine(Escr, "zz-nexo-señuelo.xlsx")].Datos.SequenceEqual(new byte[] { 1, 2, 3 }), "el archivo ajeno NO se sobrescribe");
            Check(e.SinSenuelo.Any(s => s.Carpeta == Escr && s.Motivo.Contains("no es de Nexo")) && e.SinSenuelo.Any(s => s.Carpeta == Imgs && s.Motivo.Contains("no existe")),
                "dice qué carpeta quedó sin señuelo y por qué (nombre ocupado, carpeta inexistente)");
            var datos = e.Senuelos.Select(s => disco.Archivos[s.Ruta].Datos).ToList();
            Check(datos.All(d => d.Length >= VigilanteDeSenuelos.BytesMinimos && d.Length <= VigilanteDeSenuelos.BytesMaximos && d[0] == 'P' && d[1] == 'K'),
                "contenido de 40-96 KB que empieza como un .docx/.xlsx (PK)");
            Check(e.Senuelos.Select(s => s.Sha256).Distinct().Count() == 3 && e.Senuelos.All(s => s.Sha256 == VigilanteDeSenuelos.Huella(disco.Archivos[s.Ruta].Datos)),
                "cada señuelo tiene su propia huella, y es la del contenido escrito");
            Check(almacen.Guardados == 1 && almacen.Guardado.Count == 3, "la lista se guarda");
            Check(vault.Eventos.Count == 1 && vault.Eventos[0].Tipo == TipoEvento.SenuelosPuestos && vault.Eventos[0].Severidad == Severidad.Info
                  && vault.Eventos[0].Cuerpo!.Contains("Sin señuelo"), "un evento Info al ponerlos, con lo que quedó sin señuelo");

            Esperar(v.PrepararAsync(new[] { Docs, Escr }));
            Check(disco.Creados.Count == 3 && vault.Eventos.Count == 1 && almacen.Guardados == 1, "preparar otra vez no pone nada nuevo ni escribe nada");

            // --- Revisar sin cambios ---
            Check(Esperar(v.RevisarAsync()).Count == 0 && v.Estado().UltimaRevision == ahora && v.Estado().Intactos == 3 && vault.Eventos.Count == 1 && alarmas.Count == 0,
                "revisar sin cambios: nada que avisar, 3 intactos");

            // --- No se pudo leer ---
            string d0 = Path.Combine(Docs, "!nexo-señuelo.docx"), d1 = Path.Combine(Docs, "zz-nexo-señuelo.xlsx"), e0 = Path.Combine(Escr, "!nexo-señuelo.docx");
            disco.NoLeibles[d0] = "otro programa lo tiene abierto";
            Check(Esperar(v.RevisarAsync()).Count == 0 && v.Estado().NoComprobados.ContainsKey(d0) && v.Estado().Intactos == 2,
                "no se pudo leer: NO cuenta como intacto (no comprobado, con el motivo), y tampoco es una alarma");
            disco.NoLeibles.Clear();
            Check(Esperar(v.RevisarAsync()).Count == 0 && v.Estado().NoComprobados.Count == 0, "al poder leerlo otra vez, deja de estar «no comprobado»");

            // --- Modificado ---
            disco.Cifrar(d0);
            IReadOnlyList<Senuelo> n = Esperar(v.RevisarAsync());
            Check(n.Count == 1 && n[0].Hallazgo!.Tipo == TipoDeHallazgoDeSenuelo.Modificado && n[0].Hallazgo!.Cuando == ahora, "contenido cambiado: Modificado");
            NexoEvent ev = vault.Eventos.Last();
            Check(ev.Tipo == TipoEvento.SenueloTocado && ev.Severidad == Severidad.Alta && ev.Titulo.Contains("modificado") && ev.Cuerpo!.Contains("no sabe qué programa")
                  && (string)ev.Campos["ruta"] == d0, "evento Alta en el vault, que dice que Nexo no sabe qué programa fue");
            Check(alarmas.Count == 1 && alarmas[0].Count == 1, "se dispara la alarma (para la bandeja)");
            Check(almacen.Guardado.Single(s => s.Ruta == d0).Tocado, "el hallazgo se guarda (sobrevive a un reinicio)");
            Check(Esperar(v.RevisarAsync()).Count == 0 && vault.Eventos.Count(x => x.Tipo == TipoEvento.SenueloTocado) == 1, "un señuelo tocado no se vuelve a avisar en cada vuelta");
            Esperar(v.PrepararAsync(new[] { Docs, Escr }));
            Check(disco.Creados.Count == 3, "y no se vuelve a poner solo: el aviso sigue hasta reponerlo");

            // --- Renombrado (y cifrado), dentro de la ventana: ráfaga ---
            ahora = ahora.AddMinutes(3);
            disco.Mover(d1, d1 + ".locked", cifrar: true);
            n = Esperar(v.RevisarAsync());
            Check(n.Count == 1 && n[0].Hallazgo!.Tipo == TipoDeHallazgoDeSenuelo.Renombrado && n[0].Hallazgo!.NuevaRuta == d1 + ".locked"
                  && n[0].Hallazgo!.Detalle.Contains("Y su contenido cambió"), "renombrado a «.locked»: Renombrado, con la ruta nueva y que el contenido cambió", n.FirstOrDefault()?.Hallazgo?.Detalle);
            Check(vault.Eventos.Any(x => x.Severidad == Severidad.Critica && x.Titulo.Contains("Varios señuelos") && x.Cuerpo!.Contains("desconecta")),
                "dos tocados en menos de 10 min: evento Crítico de posible ransomware en marcha");

            // --- Borrado ---
            ahora = ahora.AddHours(1);
            disco.Archivos.Remove(e0);
            n = Esperar(v.RevisarAsync());
            Check(n.Count == 1 && n[0].Hallazgo!.Tipo == TipoDeHallazgoDeSenuelo.Borrado, "borrado: Borrado");
            Check(vault.Eventos.Count(x => x.Severidad == Severidad.Critica) == 1, "uno solo pasada la ventana de 10 min: sin evento Crítico nuevo");
            Esperar(v.PrepararAsync(new[] { Docs, Escr }));
            Check(disco.Creados.Count == 3 && !disco.Archivos.ContainsKey(e0) && !disco.Archivos.ContainsKey(d1),
                "con el nombre libre (renombrado o borrado), preparar tampoco lo pone solo: hace falta reponer");

            // --- Reponer ---
            PlanDeReposicion plan = v.PrepararReposicion();
            Check(plan.HayCambios && plan.Pasos.Count == 3, "plan de reposición con los 3 tocados");
            ReposicionDeSenuelo pMod = plan.Pasos.Single(p => p.RutaTocada == d0), pRen = plan.Pasos.Single(p => p.RutaTocada == d1), pBor = plan.Pasos.Single(p => p.RutaTocada == e0);
            Check(pMod.RutaNueva == Path.Combine(Docs, "!nexo-señuelo (2).docx") && pMod.RutaActualDelTocado == d0, "modificado: el nombre sigue ocupado -> «(2)», y el tocado se queda");
            Check(pRen.RutaNueva == d1 && pRen.RutaActualDelTocado == d1 + ".locked", "renombrado: el nombre original está libre, y se dice dónde quedó el tocado");
            Check(pBor.RutaNueva == e0 && pBor.RutaActualDelTocado is null, "borrado: mismo nombre");
            Check(plan.Describir().Contains("Nexo no lo borra") && plan.Describir().Contains("se da por visto"), "la vista previa dice que no se borra nada y que el aviso se da por visto", plan.Describir());

            byte[] cifrado = disco.Archivos[d0].Datos.ToArray();
            ResultadoDeReposicion r = Esperar(v.ReponerAsync(plan));
            Check(r.Repuestos == 3 && r.Problemas.Count == 0 && v.Estado().Tocados == 0 && v.Estado().Senuelos.Count == 3, "se reponen los 3", string.Join("; ", r.Problemas));
            Check(disco.Archivos[d0].Datos.SequenceEqual(cifrado) && disco.Archivos.ContainsKey(d1 + ".locked"), "los tocados siguen donde estaban, sin tocar");
            Check(Esperar(v.RevisarAsync()).Count == 0 && v.Estado().Intactos == 3, "los nuevos se revisan y están intactos");
            Check(vault.Eventos.Last().Tipo == TipoEvento.SenuelosPuestos && vault.Eventos.Last().Severidad == Severidad.Info, "evento Info al reponer");
            Check(Esperar(v.ReponerAsync(plan)).Problemas.Count == 3, "reponer otra vez con el mismo plan: ya no están tocados, no hace nada");

            // --- Reponer con un plan viejo: el nombre se ocupó entretanto ---
            disco.Archivos.Remove(e0);
            Esperar(v.RevisarAsync());
            PlanDeReposicion p2 = v.PrepararReposicion();
            disco.Archivos[e0] = (new byte[] { 9 }, 1);    // alguien crea un archivo con ese nombre después de la vista previa
            int creadosAntes = disco.Creados.Count;
            r = Esperar(v.ReponerAsync(p2));
            Check(r.Repuestos == 0 && r.Problemas.Single().Contains("volver a previsualizar") && disco.Archivos[e0].Datos.SequenceEqual(new byte[] { 9 }) && disco.Creados.Count == creadosAntes,
                "si el nombre previsto se ocupó: no se sobrescribe, se pide previsualizar otra vez", string.Join("; ", r.Problemas));
            Check(vault.Eventos.Last().Severidad == Severidad.Media && vault.Eventos.Last().Accion == Accion.Omitida, "y queda constancia (Media, omitida)");
        }

        public static void ProbarSenuelosCasos()
        {
            Console.WriteLine("27. Señuelos: búsqueda por número, papelera, sustitución, fallos y guardado");
            DateTimeOffset ahora = new DateTimeOffset(2026, 11, 9, 20, 0, 0, TimeSpan.FromHours(-3));
            (DiscoFalso disco, VigilanteDeSenuelos v, VaultFalso vault, AlmacenFalso alm) Nuevo()
            {
                var d = new DiscoFalso();
                d.Carpetas.Add(Docs);
                var a = new AlmacenFalso();
                var va = new VaultFalso();
                var vi = new VigilanteDeSenuelos(d, a, va, () => ahora);
                Esperar(vi.PrepararAsync(new[] { Docs }));
                return (d, vi, va, a);
            }
            string d0 = Path.Combine(Docs, "!nexo-señuelo.docx");

            var (disco, v, vault, alm) = Nuevo();
            disco.Mover(d0, @"C:\$Recycle.Bin\S-1-5-21-1\$RAB12CD.docx");
            Check(Esperar(v.RevisarAsync()).Single().Hallazgo is { Tipo: TipoDeHallazgoDeSenuelo.Borrado } h1 && h1.Detalle.Contains("papelera"),
                "borrado desde el Explorador (va a la papelera): Borrado, «se envió a la papelera»");
            Check(vault.Eventos.Last() is { Severidad: Severidad.Media } ep && ep.Cuerpo!.Contains("repónlo"), "a la papelera: Media (casi seguro una persona), y se dice cómo reponerlo");
            disco.Cifrar(Path.Combine(Docs, "zz-nexo-señuelo.xlsx"));
            Esperar(v.RevisarAsync());
            Check(!vault.Eventos.Any(x => x.Severidad == Severidad.Critica) && vault.Eventos.Last().Severidad == Severidad.Alta,
                "lo de la papelera no cuenta para la ráfaga: uno a la papelera + uno cifrado no es «varios»");

            (disco, v, vault, alm) = Nuevo();
            disco.Mover(d0, @"C:\Users\ana\Documents\otra\!nexo-señuelo.docx");
            Check(Esperar(v.RevisarAsync()).Single().Hallazgo is { Tipo: TipoDeHallazgoDeSenuelo.Renombrado } h2 && h2.Detalle.Contains("no cambió"),
                "movido sin cambiar el contenido: Renombrado, «su contenido no cambió»");

            (disco, v, vault, alm) = Nuevo();
            disco.Mover(d0, d0 + ".enc");
            disco.BusquedaFalla = true;
            Check(Esperar(v.RevisarAsync()).Single().Hallazgo is { Tipo: TipoDeHallazgoDeSenuelo.Desaparecido } h3 && h3.Detalle.Contains("acceso denegado"),
                "sin poder buscar por número: Desaparecido (no se inventa «borrado»), con el motivo");

            (disco, v, vault, alm) = Nuevo();
            disco.Sustituir(d0);
            Check(Esperar(v.RevisarAsync()).Single().Hallazgo is { Tipo: TipoDeHallazgoDeSenuelo.Modificado } h4 && h4.Detalle.Contains("otro archivo"),
                "cifrado en un archivo nuevo con el mismo nombre (otro número): Modificado, «ahora es otro archivo»");

            // Creado sin número: si desaparece, no se puede saber a dónde fue.
            var dSin = new DiscoFalso { CrearSinId = true };
            dSin.Carpetas.Add(Docs);
            var vSin = new VigilanteDeSenuelos(dSin, new AlmacenFalso(), new VaultFalso(), () => ahora);
            Esperar(vSin.PrepararAsync(new[] { Docs }));
            dSin.Mover(d0, d0 + ".x");
            Check(vSin.Estado().Senuelos.All(s => s.Id is null) && Esperar(vSin.RevisarAsync()).Single().Hallazgo!.Tipo == TipoDeHallazgoDeSenuelo.Desaparecido,
                "señuelo sin número de archivo: si no está, Desaparecido");

            // No se pudo crear.
            var dMal = new DiscoFalso { CrearFalla = "Windows no deja escribir en esa carpeta" };
            dMal.Carpetas.Add(Docs);
            var vMal = new VigilanteDeSenuelos(dMal, new AlmacenFalso(), new VaultFalso(), () => ahora);
            Esperar(vMal.PrepararAsync(new[] { Docs }));
            Check(vMal.Estado().Senuelos.Count == 0 && vMal.Estado().SinSenuelo.Count == 2 && vMal.Estado().SinSenuelo.All(s => s.Motivo.Contains("no deja escribir")),
                "no se pudo crear: sin señuelo, con el motivo de Windows");

            // Vault caído: la vigilancia sigue y se avisa.
            (disco, v, vault, alm) = Nuevo();
            vault.Falla = true;
            disco.Cifrar(d0);
            Check(Esperar(v.RevisarAsync()).Count == 1 && v.Estado().Aviso!.Contains("vault") && alm.Guardado.Any(s => s.Tocado),
                "si el vault falla: el hallazgo se guarda igual y el estado lo avisa");

            // No se pudo guardar la lista.
            (disco, v, vault, alm) = Nuevo();
            alm.FalloAlGuardar = "IOException";
            disco.Cifrar(d0);
            Esperar(v.RevisarAsync());
            Check(v.Estado().Aviso is { } av && av.Contains("no se pudo guardar"), "si no se pudo guardar la lista: se dice");

            // Reinicio: lo tocado mientras Nexo no miraba se detecta en la primera revisión.
            (disco, v, vault, alm) = Nuevo();
            disco.Cifrar(d0);
            var v2 = new VigilanteDeSenuelos(disco, alm, new VaultFalso(), () => ahora);
            Check(Esperar(v2.RevisarAsync()).Count == 1, "tras reiniciar el servicio, lo tocado mientras no vigilaba se avisa");

            // Lista dañada: se avisa, y los señuelos viejos no se adoptan.
            (disco, v, vault, alm) = Nuevo();
            alm.Guardado.Clear();
            alm.Problema = "la lista de señuelos estaba dañada";
            var v3 = new VigilanteDeSenuelos(disco, alm, new VaultFalso(), () => ahora);
            Esperar(v3.PrepararAsync(new[] { Docs }));
            Check(v3.Estado().Aviso == alm.Problema && v3.Estado().Senuelos.Count == 0 && v3.Estado().SinSenuelo.Count == 2,
                "lista dañada: se avisa y los archivos viejos NO se adoptan (no se sabe si son los originales)");

            // El almacén JSON de verdad.
            string dir = Path.Combine(Path.GetTempPath(), "nexo-senuelos-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                string ruta = Path.Combine(dir, "senuelos.json");
                var j = new AlmacenDeSenuelosJson(ruta);
                Check(j.Cargar(out string? p0).Count == 0 && p0 is null, "JSON: sin archivo = lista vacía, sin problema");
                var s1 = new Senuelo(Docs, 1, d0, new string('a', 64), 50000, 123456789012345UL, ahora)
                { Hallazgo = new HallazgoDeSenuelo(TipoDeHallazgoDeSenuelo.Renombrado, "x", ahora, d0 + ".lock") };
                Check(j.Guardar(new[] { s1, s1 with { Ranura = 0, Hallazgo = null, Id = null } }) is null, "JSON: guarda");
                IReadOnlyList<Senuelo> l = j.Cargar(out string? p1);
                Check(p1 is null && l.Count == 2 && l[0] == s1 && l[1].Hallazgo is null && l[1].Id is null, "JSON: se lee igual que se guardó (con hallazgo y número)");
                Check(Directory.GetFiles(dir).Length == 1, "JSON: no deja temporales");
                File.WriteAllText(ruta, "{ esto no es json");
                Check(j.Cargar(out string? p2).Count == 0 && p2!.Contains("dañada") && File.Exists(ruta + ".corrupto") && !File.Exists(ruta),
                    "JSON dañado: se aparta como .corrupto (no se borra) y se dice");
                File.WriteAllText(ruta, "{\"Version\":1,\"Senuelos\":[{\"Carpeta\":\"C:\\\\x\",\"Ranura\":5,\"Ruta\":\"C:\\\\x\\\\a\",\"Sha256\":\"ab\",\"Bytes\":1,\"Id\":null,\"Creado\":\"2026-11-09T20:00:00-03:00\"}]}");
                Check(j.Cargar(out string? p3).Count == 0 && p3 is not null, "JSON con una ranura imposible: se trata como dañado");
            }
            finally { try { Directory.Delete(dir, true); } catch (IOException) { } }
        }

        public static void ProbarCarpetasDeSenuelos()
        {
            Console.WriteLine("28. Señuelos: qué carpetas de cada perfil");
            var sinAbrir = new PerfilParaSenuelos("S-1-5-21-1", @"C:\Users\ana", null);
            IReadOnlyList<string> c = CarpetasParaSenuelos.Elegir(new[] { sinAbrir }, out var fuera);
            Check(c.SequenceEqual(new[] { @"C:\Users\ana\Documents", @"C:\Users\ana\Desktop", @"C:\Users\ana\Pictures" }) && fuera.Count == 0,
                "perfil sin abrir: Documentos, Escritorio e Imágenes por omisión", string.Join(" | ", c));

            var movido = new PerfilParaSenuelos("S-1-5-21-2", @"C:\Users\beto", new Dictionary<string, string>
            {
                ["Personal"] = @"D:\MisDocs",
                ["Desktop"] = @"%USERPROFILE%\OneDrive\Escritorio",
                ["My Pictures"] = @"%userprofile%\Fotos"
            });
            c = CarpetasParaSenuelos.Elegir(new[] { movido }, out fuera);
            Check(c.SequenceEqual(new[] { @"D:\MisDocs", @"C:\Users\beto\Fotos" }), "carpetas movidas: se sigue a donde están (%USERPROFILE% sin importar mayúsculas)", string.Join(" | ", c));
            Check(fuera.Single().Motivo.Contains("OneDrive"), "OneDrive: no se pone (se subiría a la nube), y se dice");

            var raro = new PerfilParaSenuelos("S-1-5-21-3", @"C:\Users\caro", new Dictionary<string, string>
            {
                ["Personal"] = @"\\servidor\docs",
                ["Desktop"] = @"%HOMEDRIVE%\Escritorio",
                ["My Pictures"] = @"C:\Users\caro\OneDrive - Empresa\Imágenes"
            });
            CarpetasParaSenuelos.Elegir(new[] { raro }, out fuera);
            Check(fuera.Count == 3 && fuera.Any(f => f.Motivo.Contains("red")) && fuera.Any(f => f.Motivo.Contains("variables")) && fuera.Any(f => f.Motivo.Contains("OneDrive")),
                "carpeta de red, variable sin resolver y «OneDrive - Empresa»: descartadas con motivo");

            c = CarpetasParaSenuelos.Elegir(new[] { sinAbrir, sinAbrir with { Sid = "S-1-5-21-9" }, new PerfilParaSenuelos("S-1-5-21-4", @"\\srv\perfiles\x", null) }, out fuera);
            Check(c.Count == 3 && fuera.Single().Motivo.Contains("sin una carpeta local"), "sin repetidas; perfil en red: descartado");
            Check(!CarpetasParaSenuelos.EnOneDrive(@"C:\Users\ana\OneDriveViejo\x") && CarpetasParaSenuelos.EnOneDrive(@"C:\Users\ana\onedrive\x"), "«OneDrive» como tramo completo, no como prefijo de otro nombre");
        }
    }
}
