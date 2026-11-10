using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Ransomware;
using Nexo.Reports.Model;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        /// <summary>Disco en memoria mínimo para el módulo del servicio (las reglas finas se prueban en Nexo.Vuln.Demo §26-28).</summary>
        private sealed class DiscoDeSenuelosFalso : IAccesoASenuelos
        {
            public readonly Dictionary<string, (byte[] Datos, ulong Id)> Archivos = new(StringComparer.OrdinalIgnoreCase);
            public readonly HashSet<string> Carpetas = new(StringComparer.OrdinalIgnoreCase);
            private ulong _id = 1;
            public bool Lanzar;
            public bool CarpetaExiste(string c) => Lanzar ? throw new InvalidOperationException("roto") : Carpetas.Contains(c);
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
                => Archivos.FirstOrDefault(kv => kv.Value.Id == id) is { Key: not null } kv ? new BusquedaPorId(EstadoDeBusqueda.Encontrado, kv.Key) : new BusquedaPorId(EstadoDeBusqueda.NoExiste);
        }

        private sealed class ListaDeSenuelosEnMemoria : IAlmacenDeSenuelos
        {
            private List<Senuelo> _l = new();
            public IReadOnlyList<Senuelo> Cargar(out string? problema) { problema = null; return _l.ToList(); }
            public string? Guardar(IReadOnlyList<Senuelo> s) { _l = s.ToList(); return null; }
        }

        private static async Task<(bool Ok, int Codigo, JsonElement? R)> PedirSenuelos(IModuloDelServicio m, string metodo, object? parametros)
        {
            try
            {
                JsonElement? p = parametros is null ? null : JsonSerializer.SerializeToElement(parametros);
                object? r = await m.ManejarAsync(metodo, p, CancellationToken.None).ConfigureAwait(false);
                return (true, 0, JsonSerializer.SerializeToElement(r));
            }
            catch (ErrorDeComando e) { return (false, e.Codigo, null); }
        }

        public static async Task ProbarSenuelosDelServicio()
        {
            Console.WriteLine("Señuelos contra ransomware por el servicio: senuelos.estado, senuelos.previsualizar, senuelos.reponer");
            const string Docs = @"C:\Users\ana\Documents";
            var disco = new DiscoDeSenuelosFalso();
            disco.Carpetas.Add(Docs);
            var w = new EscritorFalso();
            var v = new VigilanteDeSenuelos(disco, new ListaDeSenuelosEnMemoria(), w);
            int busquedas = 0;
            var descartada = new CarpetaSinSenuelo(@"C:\Users\ana\OneDrive\Escritorio", "carpeta de OneDrive");
            var m = new ModuloSenuelos(v, () => { busquedas++; return (new[] { Docs }, new[] { descartada }); }, TimeSpan.FromSeconds(1), PoliticaDeAprobacion.Ninguna);
            Check(m.Metodos.SequenceEqual(new[] { "senuelos.estado", "senuelos.previsualizar", "senuelos.reponer" }), "tres métodos: no hay ninguno para apagar ni para cambiar carpetas");
            Check(m.Intervalo == ModuloSenuelos.IntervaloMinimo, "un intervalo menor que el mínimo se sube a 5 s");

            var e0 = await PedirSenuelos(m, "senuelos.estado", null);
            Check(e0.Ok && e0.R!.Value.GetProperty("activo").GetBoolean() && !e0.R.Value.GetProperty("todo_en_orden").GetBoolean(),
                "antes de la primera revisión: activo, pero NO «todo en orden»");

            await m.UnaVueltaAsync(buscarCarpetas: true, CancellationToken.None);
            var e1 = (await PedirSenuelos(m, "senuelos.estado", null)).R!.Value;
            Check(busquedas == 1 && disco.Archivos.Count == 2 && e1.GetProperty("senuelos").GetArrayLength() == 2 && e1.GetProperty("todo_en_orden").GetBoolean(),
                "una vuelta: busca carpetas, pone 2 señuelos, revisa y queda «todo en orden»");
            Check(e1.GetProperty("sin_senuelo").EnumerateArray().Any(x => x.GetProperty("motivo").GetString() == "carpeta de OneDrive"),
                "las carpetas descartadas al buscar aparecen en «sin_senuelo»");
            Check(e1.GetProperty("nota").GetString()!.Contains("no puede impedirlo"), "la nota dice lo que NO hace");

            var sinNada = await PedirSenuelos(m, "senuelos.previsualizar", null);
            Check(sinNada.Ok && !sinNada.R!.Value.GetProperty("hay_cambios").GetBoolean() && sinNada.R.Value.GetProperty("token").ValueKind == JsonValueKind.Null,
                "sin tocados: previsualizar no da token");

            // Un programa cifra un señuelo.
            string d0 = Path.Combine(Docs, "!nexo-señuelo.docx");
            disco.Archivos[d0] = (new byte[] { 1, 2, 3 }, disco.Archivos[d0].Id);
            await m.UnaVueltaAsync(buscarCarpetas: false, CancellationToken.None);
            var e2 = (await PedirSenuelos(m, "senuelos.estado", null)).R!.Value;
            JsonElement tocado = e2.GetProperty("senuelos").EnumerateArray().Single(x => x.GetProperty("tocado").GetBoolean());
            Check(busquedas == 1 && e2.GetProperty("tocados").GetInt32() == 1 && !e2.GetProperty("todo_en_orden").GetBoolean()
                  && tocado.GetProperty("hallazgo").GetProperty("tipo").GetString() == "modificado", "un señuelo cifrado: «tocados» = 1, con el tipo; sin volver a buscar carpetas");
            Check(w.Eventos.Any(x => x.Tipo == TipoEvento.SenueloTocado && x.Severidad == Severidad.Alta), "evento Alta en el vault");

            // Reponer con aprobación «elevada»: la aprobación va antes que el token.
            var mElevada = new ModuloSenuelos(v, () => (new[] { Docs }, Array.Empty<CarpetaSinSenuelo>()), politica: PoliticaDeAprobacion.Elevada);
            string tokE = (await PedirSenuelos(mElevada, "senuelos.previsualizar", null)).R!.Value.GetProperty("token").GetString()!;
            var sinUac = await PedirSenuelos(mElevada, "senuelos.reponer", new { token = tokE });
            Check(!sinUac.Ok && sinUac.Codigo == PoliticaDeAprobacion.AprobacionRequerida && disco.Archivos.Count == 2, "con la política «elevada», reponer sin UAC se rechaza y no se crea nada");
            var falso = await PedirSenuelos(mElevada, "senuelos.reponer", new { token = new string('e', 64) });
            Check(!falso.Ok && falso.Codigo == PoliticaDeAprobacion.AprobacionRequerida, "la aprobación se exige ANTES de mirar el token (uno inventado da «aprobación»)");

            var pre = await PedirSenuelos(m, "senuelos.previsualizar", null);
            string? token = pre.R?.GetProperty("token").GetString();
            Check(pre.Ok && pre.R!.Value.GetProperty("hay_cambios").GetBoolean() && token?.Length == 64 && pre.R.Value.GetProperty("descripcion").GetString()!.Contains("Nexo no lo borra")
                  && disco.Archivos.Count == 2, "previsualizar: token y descripción, y NADA creado");
            Check(!(await PedirSenuelos(m, "senuelos.reponer", null)).Ok && !(await PedirSenuelos(m, "senuelos.reponer", new { token = 5 })).Ok
                  && !(await PedirSenuelos(m, "senuelos.reponer", new { token = new string('a', 80) })).Ok, "parámetros no válidos: rechazados");
            var rep = await PedirSenuelos(m, "senuelos.reponer", new { token });
            Check(rep.Ok && rep.R!.Value.GetProperty("exito").GetBoolean() && rep.R.Value.GetProperty("repuestos").GetInt32() == 1 && disco.Archivos.Count == 3
                  && disco.Archivos[d0].Datos.SequenceEqual(new byte[] { 1, 2, 3 }), "reponer: uno nuevo, y el tocado sigue igual");
            var otra = await PedirSenuelos(m, "senuelos.reponer", new { token });
            Check(!otra.Ok && otra.Codigo == ModuloSenuelos.TokenInvalido && disco.Archivos.Count == 3, "el token es de un solo uso");
            Check(!(await PedirSenuelos(m, "senuelos.borrar", null)).Ok, "un método desconocido se rechaza");

            // Un fallo inesperado no para la vigilancia y se ve en el estado.
            disco.Lanzar = true;
            await m.UnaVueltaAsync(buscarCarpetas: true, CancellationToken.None);
            var e3 = (await PedirSenuelos(m, "senuelos.estado", null)).R!.Value;
            Check(e3.GetProperty("aviso").GetString()!.Contains("falló") && !e3.GetProperty("todo_en_orden").GetBoolean(), "si una vuelta falla: se dice, y no hay «todo en orden»");
            disco.Lanzar = false;
            await m.UnaVueltaAsync(buscarCarpetas: true, CancellationToken.None);
            Check((await PedirSenuelos(m, "senuelos.estado", null)).R!.Value.GetProperty("todo_en_orden").GetBoolean(), "y al volver a funcionar, el aviso se va");

            // El bucle de verdad, con su espera.
            var disco2 = new DiscoDeSenuelosFalso();
            disco2.Carpetas.Add(Docs);
            var m2 = new ModuloSenuelos(new VigilanteDeSenuelos(disco2, new ListaDeSenuelosEnMemoria(), new EscritorFalso()), () => (new[] { Docs }, Array.Empty<CarpetaSinSenuelo>()),
                                        esperar: (t, ct) => Task.Delay(20, ct));
            m2.Iniciar();
            await Task.Delay(400);
            var e4 = (await PedirSenuelos(m2, "senuelos.estado", null)).R!.Value;
            await m2.DisposeAsync();
            Check(disco2.Archivos.Count == 2 && e4.GetProperty("todo_en_orden").GetBoolean(), "Iniciar arranca el bucle: pone y revisa solo");

            // Puestos pero sin revisar todavía: tampoco es «todo en orden».
            var disco3 = new DiscoDeSenuelosFalso();
            disco3.Carpetas.Add(Docs);
            var v3 = new VigilanteDeSenuelos(disco3, new ListaDeSenuelosEnMemoria(), new EscritorFalso());
            await v3.PrepararAsync(new[] { Docs });
            var e5 = (await PedirSenuelos(new ModuloSenuelos(v3, () => (new[] { Docs }, Array.Empty<CarpetaSinSenuelo>())), "senuelos.estado", null)).R!.Value;
            Check(e5.GetProperty("senuelos").GetArrayLength() == 2 && !e5.GetProperty("todo_en_orden").GetBoolean(), "señuelos puestos pero aún sin revisar: NO «todo en orden»");

            // Apagado.
            var ap = new ModuloSenuelosApagado();
            var ea = await PedirSenuelos(ap, "senuelos.estado", null);
            Check(ea.Ok && !ea.R!.Value.GetProperty("activo").GetBoolean() && ea.R.Value.GetProperty("nota").GetString()!.Contains("Nexo:Senuelos:Activo")
                  && !(await PedirSenuelos(ap, "senuelos.reponer", new { token = "x" })).Ok, "apagado: lo dice, con dónde activarlo, y reponer se rechaza");
        }
    }
}
