using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Nexo.Ipc;
using Nexo.Modules.Cleanup.Abstractions;
using Nexo.Modules.Cleanup.Junk;
using Nexo.Modules.Cleanup.Platform;
using Nexo.Reports;
using Nexo.Reports.Model;
using Nexo.Service;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        private static string _corpusLimpieza = "";
        private static bool _hayPerfil = true;

        private static readonly BorradorEspia Espia = new BorradorEspia();

        private static CatalogoDeRutas CatalogoDePrueba() => new CatalogoDeRutas(new List<ReglaDeLimpieza>
        {
            new ReglaDeLimpieza { Id = "prueba-temporales", Categoria = "Prueba", Nombre = "Temporales", Base = BaseDeRuta.RaizDePrueba,
                                  Subruta = "temp", Patron = "*.tmp", AntiguedadMinimaDias = 0, Riesgo = NivelRiesgo.Bajo },
            new ReglaDeLimpieza { Id = "prueba-medio", Categoria = "Prueba", Nombre = "Cache (riesgo medio)", Base = BaseDeRuta.RaizDePrueba,
                                  Subruta = "cache", Patron = "*.cache", AntiguedadMinimaDias = 0, Riesgo = NivelRiesgo.Medio },
            new ReglaDeLimpieza { Id = "prueba-admin", Categoria = "Sistema", Nombre = "Registros del sistema", Base = BaseDeRuta.RaizDePrueba,
                                  Subruta = "sistema", Patron = "*.log", AntiguedadMinimaDias = 0, Riesgo = NivelRiesgo.Bajo, RequiereAdmin = true },
        });

        private static IReadOnlyDictionary<BaseDeRuta, string>? BasesDePrueba(ContextoDeLlamada _)
            => _hayPerfil ? new Dictionary<BaseDeRuta, string> { [BaseDeRuta.RaizDePrueba] = _corpusLimpieza } : null;

        private static void Archivo(string carpeta, string nombre, int bytes = 100)
        {
            Directory.CreateDirectory(carpeta);
            File.WriteAllBytes(Path.Combine(carpeta, nombre), new byte[bytes]);
        }

        private static async Task ProbarLimpiezaPorIpc(string vault, string pipe, string raiz)
        {
            Console.WriteLine("10. Limpieza por el pipe: con la identidad y el perfil del llamador");

            _corpusLimpieza = Path.Combine(raiz, "corpus-limpieza");
            string temp = Path.Combine(_corpusLimpieza, "temp");
            Archivo(temp, "a.tmp", 100); Archivo(temp, "b.tmp", 200); Archivo(temp, "c.tmp", 300);
            Archivo(temp, "importante.txt", 50);                         // no coincide con el patron
            Archivo(Path.Combine(_corpusLimpieza, "cache"), "x.cache", 400);
            Archivo(Path.Combine(_corpusLimpieza, "cache"), "y.cache", 400);
            Archivo(Path.Combine(_corpusLimpieza, "sistema"), "z.log", 500);

            using IHost host = Crear(vault, pipe);
            await host.StartAsync().ConfigureAwait(false);
            await using ClienteDePipe ident = await ClienteDePipe.ConectarAsync(pipe, TimeSpan.FromSeconds(10), nivel: TokenImpersonationLevel.Identification).ConfigureAwait(false);
            await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(pipe, TimeSpan.FromSeconds(10)).ConfigureAwait(false);

            // --- Catalogo ---
            Respuesta reg = await c.LlamarAsync("limpieza.reglas").ConfigureAwait(false);
            Check(reg.Exito && R(reg).GetProperty("reglas").GetArrayLength() == 3, "limpieza.reglas lista el catalogo (lo que Nexo tiene permiso para borrar)");
            Check((await ident.LlamarAsync("limpieza.reglas").ConfigureAwait(false)).Exito, "y listarlo no necesita suplantar a nadie");
            Check(R(reg).GetProperty("modo").GetString() == "borrado-permanente",
                  "el modo informado es el del borrador (el de prueba borra de verdad)");

            // Regresion: el simulador tambien es "reversible", y el servicio lo informaba como "papelera".
            foreach ((IBorrador borrador, string esperado) in new (IBorrador, string)[]
                     { (new BorradorSimulado(), "simulado"), (new BorradorReal(), "borrado-permanente") })
            {
                var modulo = new ModuloLimpieza(CatalogoDePrueba(), borrador, new GrabadorDeReportes());
                JsonElement info = JsonSerializer.SerializeToElement(await modulo.ManejarAsync("limpieza.reglas", null, CancellationToken.None).ConfigureAwait(false));
                Check(info.GetProperty("modo").GetString() == esperado, "limpieza.reglas informa el modo '" + esperado + "' con " + borrador.GetType().Name);
            }

            // --- Sin identidad utilizable: se rechaza ---
            Respuesta sinId = await ident.LlamarAsync("limpieza.previsualizar").ConfigureAwait(false);
            Check(!sinId.Exito && sinId.Error!.Codigo == AccesoComoLlamador.SinIdentidad, "previsualizar con un cliente que no deja suplantarlo se RECHAZA (no se limpia como SYSTEM)");

            // --- Vista previa: solo las reglas de riesgo bajo, y no cambia nada ---
            Respuesta pv = await c.LlamarAsync("limpieza.previsualizar").ConfigureAwait(false);
            Check(pv.Exito && R(pv).GetProperty("total_archivos").GetInt32() == 3 && R(pv).GetProperty("total_bytes").GetInt64() == 600,
                  "por omision solo entran las reglas de riesgo bajo: 3 archivos y 600 bytes", pv.Error?.Mensaje);
            Check(Directory.GetFiles(temp).Length == 4 && File.Exists(Path.Combine(_corpusLimpieza, "cache", "x.cache")), "y previsualizar NO borra nada");
            Check(!EsAdmin ? R(pv).GetProperty("reglas_sin_permisos").GetArrayLength() == 1 : true,
                  "la regla que pide administrador se salta si el llamador no lo es, y se dice");
            Check(!R(pv).GetProperty("reversible").GetBoolean(), "informa si el borrado es reversible (aqui, el borrador de prueba es permanente)");
            string token = R(pv).GetProperty("token").GetString()!;

            // --- Reglas del catalogo por id; nunca rutas ---
            Respuesta medio = await c.LlamarAsync("limpieza.previsualizar", new { reglas = new[] { "prueba-medio" } }).ConfigureAwait(false);
            Check(medio.Exito && R(medio).GetProperty("total_archivos").GetInt32() == 2, "una regla de riesgo medio solo entra si se pide por su id");

            var malas = new (string Que, object P)[]
            {
                ("regla desconocida", new { reglas = new[] { "no-existe" } }),
                ("una ruta en vez de un id", new { reglas = new[] { @"C:\Windows\System32" } }),
                ("con '..'", new { reglas = new[] { "../x" } }),
                ("lista vacia", new { reglas = Array.Empty<string>() }),
                ("demasiadas", new { reglas = Enumerable.Repeat("prueba-temporales", 65).ToArray() }),
                ("no es lista", new { reglas = "prueba-temporales" }),
                ("id enorme", new { reglas = new[] { new string('x', 500) } }),
                ("no es texto", new { reglas = new object[] { 5 } }),
            };
            foreach ((string que, object p) in malas)
            {
                Respuesta r = await c.LlamarAsync("limpieza.previsualizar", p).ConfigureAwait(false);
                Check(!r.Exito && r.Error!.Codigo == CodigoDeError.ParametrosInvalidos, "reglas no validas: " + que);
            }

            // --- Aplicar ---
            Respuesta apIdent = await ident.LlamarAsync("limpieza.aplicar", new { token }).ConfigureAwait(false);
            Check(!apIdent.Exito && apIdent.Error!.Codigo == AccesoComoLlamador.SinIdentidad && Directory.GetFiles(temp).Length == 4,
                  "aplicar sin identidad utilizable se rechaza y no se borra nada");

            // Cambios despues de la vista previa: un archivo nuevo, y uno que cambia de tamano.
            Archivo(temp, "nuevo.tmp", 10);
            File.WriteAllBytes(Path.Combine(temp, "b.tmp"), new byte[999]);

            Respuesta ap = await c.LlamarAsync("limpieza.aplicar", new { token }).ConfigureAwait(false);
            Check(ap.Exito && R(ap).GetProperty("eliminados").GetInt32() == 2,
                  "el rechazo por identidad no gasto el token; aplicar borra lo aprobado que sigue igual (2 de 3)", ap.Error?.Mensaje);
            Check(!File.Exists(Path.Combine(temp, "a.tmp")) && !File.Exists(Path.Combine(temp, "c.tmp")), "se borraron a.tmp y c.tmp");
            Check(File.Exists(Path.Combine(temp, "b.tmp")), "b.tmp cambio de tamano desde la vista previa: NO se borra");
            Check(File.Exists(Path.Combine(temp, "nuevo.tmp")), "un archivo que aparecio despues de la vista previa NO se borra (solo lo aprobado)");
            Check(File.Exists(Path.Combine(temp, "importante.txt")) && File.Exists(Path.Combine(_corpusLimpieza, "cache", "x.cache")),
                  "lo que no era del plan sigue intacto");
            Check(R(ap).GetProperty("omitidos_total").GetInt32() >= 1, "y lo omitido se informa");
            Check(Espia.SeEjecutoSuplantando, "el borrado se ejecuto SUPLANTANDO al llamador, tambien despues de los await");

            Check((await c.LlamarAsync("limpieza.aplicar", new { token }).ConfigureAwait(false)).Error?.Codigo == ModuloFirewall.TokenInvalido, "el token sirve una sola vez");
            foreach (object? p in new object?[] { new { token = new string('a', 64) }, new { token = "corto" }, new { } })
            {
                Respuesta r = await c.LlamarAsync("limpieza.aplicar", p).ConfigureAwait(false);
                Check(!r.Exito, "token falso o ausente se rechaza: " + JsonSerializer.Serialize(p));
            }

            // --- Notas ---
            bool nota = false;
            for (int i = 0; i < 60 && !nota; i++)
            {
                nota = LeerTodo(Notas(vault)).Contains("sesion-limpieza");
                if (!nota) await Task.Delay(50).ConfigureAwait(false);
            }
            Check(nota, "deja la nota de la sesion de limpieza en el vault");

            // --- Sin perfil: no se limpia nada ---
            _hayPerfil = false;
            Respuesta sinPerfil = await c.LlamarAsync("limpieza.previsualizar").ConfigureAwait(false);
            Check(!sinPerfil.Exito && sinPerfil.Error!.Message().Contains("perfil"), "si no se encuentra el perfil del llamador, no se limpia nada");
            _hayPerfil = true;

            await host.StopAsync().ConfigureAwait(false);
            Console.WriteLine();

            await ProbarReportesFueraDeSuplantacion().ConfigureAwait(false);
        }

        private static string Message(this ErrorIpc e) => e.Mensaje;

        // ------------------------------------------------------------
        private static async Task ProbarReportesFueraDeSuplantacion()
        {
            Console.WriteLine("11. Suplantacion a traves de los await, y notas con la identidad del servicio");

            using WindowsIdentity yo = WindowsIdentity.GetCurrent();
            using var ctx = new ContextoDeLlamada(yo.User, TokenImpersonationLevel.Impersonation,
                                                  new WindowsIdentity(yo.AccessToken.DangerousGetHandle()));
            var grabador = new GrabadorDeReportes();
            var decorado = new ReportesFueraDeSuplantacion(grabador);

            bool antes = WindowsIdentity.GetCurrent(true) is null;
            bool dentro = false, trasAwait = false, alEscribir = true, tras = false;
            await ctx.EjecutarAsync(async () =>
            {
                dentro = WindowsIdentity.GetCurrent(true) is not null;
                await Task.Delay(30).ConfigureAwait(false);
                await Task.Yield();
                trasAwait = WindowsIdentity.GetCurrent(true) is not null;

                await decorado.EscribirAsync(new NexoEvent(ModuloOrigen.Sistema, "prueba", "x")).ConfigureAwait(false);
                alEscribir = grabador.ImpersonandoAlEscribir;
                tras = WindowsIdentity.GetCurrent(true) is not null;
                return 0;
            }).ConfigureAwait(false);
            bool despues = WindowsIdentity.GetCurrent(true) is null;

            Check(antes && despues, "fuera de EjecutarAsync no se esta suplantando a nadie");
            Check(dentro && trasAwait, "dentro de EjecutarAsync se suplanta, y se mantiene despues de un await y de cambiar de hilo");
            Check(!alEscribir, "pero la escritura de la nota se hace SIN suplantar (con la identidad del servicio)");
            Check(tras, "y al volver de escribir la nota se sigue suplantando al llamador");

            Console.WriteLine();
        }
    }

    /// <summary>Borra de verdad (sobre el corpus sintetico) y apunta si lo hizo suplantando al llamador.</summary>
    internal sealed class BorradorEspia : IBorrador
    {
        private readonly BorradorReal _real = new BorradorReal();
        public volatile bool SeEjecutoSuplantando;
        public bool EsReversible => false;

        public ResultadoBorrado Borrar(IReadOnlyList<(string Ruta, long Bytes)> elementos)
        {
            SeEjecutoSuplantando = System.Security.Principal.WindowsIdentity.GetCurrent(true) is not null;
            return _real.Borrar(elementos);
        }
    }

    internal sealed class GrabadorDeReportes : IReportWriter
    {
        public volatile bool ImpersonandoAlEscribir;

        public Task<NoteRef> EscribirAsync(NexoEvent evento, CancellationToken ct = default)
        {
            ImpersonandoAlEscribir = System.Security.Principal.WindowsIdentity.GetCurrent(true) is not null;
            return Task.FromResult<NoteRef>(null!);
        }

        public Task InicializarVaultAsync(CancellationToken ct = default) => Task.CompletedTask;
    }
}
