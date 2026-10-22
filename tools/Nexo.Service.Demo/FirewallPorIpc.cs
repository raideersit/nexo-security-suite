using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Nexo.Ipc;
using Nexo.Modules.Threats.Firewall;
using Nexo.Service;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        private static string Tok(Respuesta r) => r.Resultado!.Value.GetProperty("token").GetString()!;

        private static async Task ProbarFirewallPorIpc(string vault, string pipe, string raiz)
        {
            Console.WriteLine("4. Firewall por el pipe: vista previa, token de un solo uso, sin fiarse del cliente");

            string carpeta = Path.Combine(raiz, "apps");
            Directory.CreateDirectory(carpeta);
            string app = Path.Combine(carpeta, "app-prueba.exe");
            string falsoSvchost = Path.Combine(carpeta, "svchost.exe");
            File.WriteAllBytes(app, new byte[] { 0x4D, 0x5A });
            File.WriteAllBytes(falsoSvchost, new byte[] { 0x4D, 0x5A });

            using IHost host = Crear(vault, pipe);
            await host.StartAsync().ConfigureAwait(false);
            await using ClienteDePipe c = await ClienteDePipe.ConectarAsync(pipe, TimeSpan.FromSeconds(10)).ConfigureAwait(false);

            int antes = Almacen.Reglas.Count;

            // --- Previsualizar no cambia nada ---
            Respuesta v = await c.LlamarAsync("firewall.previsualizar", new { tipo = "regla", ruta = app, accion = "bloquear" }).ConfigureAwait(false);
            Check(v.Exito && v.Resultado!.Value.GetProperty("hay_cambios").GetBoolean()
                  && v.Resultado.Value.GetProperty("cambios").GetArrayLength() == 2, "la vista previa propone 2 reglas (saliente y entrante)");
            Check(Almacen.Reglas.Count == antes, "y NO cambia el firewall");
            string token = Tok(v);
            Check(token.Length == 64 && token.All(Uri.IsHexDigit), "emite un token opaco de 256 bits");

            // --- El cliente no puede cambiar el plan al aplicar ---
            Respuesta ap = await c.LlamarAsync("firewall.aplicar",
                new { token, ruta = falsoSvchost, accion = "permitir", tipo = "sigiloso" }).ConfigureAwait(false);
            JsonElement res = ap.Resultado!.Value;
            if (EsAdmin)
            {
                Check(ap.Exito && res.GetProperty("aplicados").GetInt32() == 2, "aplicar con el token ejecuta el plan guardado");
                Check(Almacen.Reglas.Count == antes + 2 && Almacen.Reglas.All(r => r.RutaApp is null || r.RutaApp == app),
                      "y SOLO ese plan: los parametros extra que mande el cliente se ignoran");
            }
            else
            {
                Check(ap.Exito && res.GetProperty("aplicados").GetInt32() == 0 && res.GetProperty("omitidos").GetArrayLength() == 2,
                      "sin administrador, el servicio NO finge haber aplicado: informa lo omitido");
                Check(Almacen.Reglas.Count == antes, "y no cambia nada");
            }

            // --- Un solo uso ---
            Respuesta otra = await c.LlamarAsync("firewall.aplicar", new { token }).ConfigureAwait(false);
            Check(!otra.Exito && otra.Error!.Codigo == ModuloFirewall.TokenInvalido, "el token no sirve una segunda vez");

            // --- Tokens falsos, ausentes o mal formados ---
            foreach (object? p in new object?[] { new { token = new string('a', 64) }, new { token = "corto" }, new { token = "" }, new { } })
            {
                Respuesta r = await c.LlamarAsync("firewall.aplicar", p).ConfigureAwait(false);
                Check(!r.Exito && (r.Error!.Codigo == ModuloFirewall.TokenInvalido || r.Error.Codigo == CodigoDeError.ParametrosInvalidos),
                      "rechaza un token falso o ausente: " + JsonSerializer.Serialize(p));
            }
            Check((await c.LlamarAsync("firewall.aplicar").ConfigureAwait(false)).Error?.Codigo == CodigoDeError.ParametrosInvalidos,
                  "aplicar sin parametros es un error de parametros");

            // --- Un token se consume aunque la aplicacion falle ---
            Respuesta v2 = await c.LlamarAsync("firewall.previsualizar", new { tipo = "sigiloso", activar = true }).ConfigureAwait(false);
            string t2 = Tok(v2);
            await c.LlamarAsync("firewall.aplicar", new { token = t2 }).ConfigureAwait(false);
            Check((await c.LlamarAsync("firewall.aplicar", new { token = t2 }).ConfigureAwait(false)).Error?.Codigo == ModuloFirewall.TokenInvalido,
                  "tambien se consume el token del modo sigiloso");

            // --- Las guardias de siempre siguen mandando ---
            Respuesta sv = await c.LlamarAsync("firewall.previsualizar", new { tipo = "regla", ruta = falsoSvchost, accion = "bloquear" }).ConfigureAwait(false);
            Check(sv.Exito && !sv.Resultado!.Value.GetProperty("hay_cambios").GetBoolean()
                  && sv.Resultado.Value.GetProperty("rechazos").GetArrayLength() == 1
                  && !sv.Resultado.Value.TryGetProperty("token", out _),
                  "bloquear un 'svchost.exe' se rechaza y no se emite token");

            Respuesta noExiste = await c.LlamarAsync("firewall.previsualizar", new { tipo = "regla", ruta = Path.Combine(carpeta, "no-existe.exe"), accion = "permitir" }).ConfigureAwait(false);
            Check(noExiste.Exito && !noExiste.Resultado!.Value.GetProperty("hay_cambios").GetBoolean(), "una ruta inexistente no genera plan");

            Respuesta ajena = await c.LlamarAsync("firewall.previsualizar", new { tipo = "quitar", nombre = "Compartir archivos e impresoras (eco ICMPv4)" }).ConfigureAwait(false);
            Check(ajena.Exito && !ajena.Resultado!.Value.GetProperty("hay_cambios").GetBoolean(), "quitar una regla que no es de Nexo no genera plan");

            // --- Parametros invalidos ---
            var malos = new (string Que, object? P)[]
            {
                ("sin tipo", new { ruta = app }),
                ("tipo desconocido", new { tipo = "formatear" }),
                ("accion desconocida", new { tipo = "regla", ruta = app, accion = "destruir" }),
                ("ruta que no es texto", new { tipo = "regla", ruta = 5, accion = "bloquear" }),
                ("ruta enorme", new { tipo = "regla", ruta = new string('x', 5000), accion = "bloquear" }),
                ("sigiloso sin booleano", new { tipo = "sigiloso", activar = "si" }),
                ("params no objeto", new object[] { 1, 2 }),
            };
            foreach ((string que, object? p) in malos)
            {
                Respuesta r = await c.LlamarAsync("firewall.previsualizar", p).ConfigureAwait(false);
                Check(!r.Exito && r.Error!.Codigo == CodigoDeError.ParametrosInvalidos, "parametros invalidos: " + que);
            }

            // --- estado ---
            Respuesta est = await c.LlamarAsync("firewall.estado").ConfigureAwait(false);
            Check(est.Exito && est.Resultado!.Value.TryGetProperty("sigiloso", out _), "firewall.estado responde");
            if (EsAdmin)
                Check(est.Resultado!.Value.GetProperty("sigiloso").GetBoolean(), "y refleja el modo sigiloso ya activado");

            await host.StopAsync().ConfigureAwait(false);
            Console.WriteLine();
        }

        // ============================================================
        private static void ProbarPlanes()
        {
            Console.WriteLine("5. Planes pendientes: caducidad, un solo uso y limite");

            var ahora = new DateTimeOffset(2026, 10, 22, 12, 0, 0, TimeSpan.Zero);
            var p = new PlanesPendientes<string>(TimeSpan.FromMinutes(10), maximo: 3, reloj: () => ahora);

            (string t, _) = p.Guardar("plan-a");
            Check(p.Tomar(t) == "plan-a" && p.Tomar(t) is null, "un token sirve una sola vez");

            (string t2, _) = p.Guardar("plan-b");
            ahora = ahora.AddMinutes(11);
            Check(p.Tomar(t2) is null, "un token caducado no sirve");

            ahora = new DateTimeOffset(2026, 10, 22, 13, 0, 0, TimeSpan.Zero);
            var tokens = new List<string>();
            for (int i = 0; i < 5; i++) { tokens.Add(p.Guardar("p" + i).Token); ahora = ahora.AddSeconds(1); }
            Check(p.Pendientes == 3, "no se acumulan planes sin limite (maximo 3)");
            Check(p.Tomar(tokens[0]) is null && p.Tomar(tokens[4]) == "p4", "al llegar al maximo se descarta el mas antiguo");
            Check(tokens.Distinct().Count() == 5, "los tokens no se repiten");
            Check(p.Tomar(null) is null && p.Tomar("") is null && p.Tomar(new string('z', 64)) is null, "null, vacio o inventado: nada");

            Console.WriteLine();
        }
    }

    internal sealed class AlmacenEnMemoria : IAlmacenDeFirewall
    {
        public List<ReglaDeFirewall> Reglas { get; } = new List<ReglaDeFirewall>
        {
            // Una regla ajena que Nexo no debe poder quitar.
            new ReglaDeFirewall("Compartir archivos e impresoras (eco ICMPv4)", null, DireccionDeRegla.Entrante,
                AccionDeRegla.Permitir, PerfilesDeRed.Privado, true, "Compartir archivos e impresoras")
        };

        public IReadOnlyList<ReglaDeFirewall> Enumerar() => Reglas.ToList();
        public void Agregar(ReglaDeFirewall regla) => Reglas.Add(regla);
        public void Eliminar(string nombre) => Reglas.RemoveAll(r => r.Nombre == nombre);

        public void Habilitar(string nombre, bool habilitada)
        {
            int i = Reglas.FindIndex(r => r.Nombre == nombre);
            if (i >= 0) Reglas[i] = Reglas[i] with { Habilitada = habilitada };
        }

        public IReadOnlyList<PoliticaDePerfil> LeerPoliticas() => new[]
        {
            new PoliticaDePerfil(PerfilesDeRed.Privado, true, AccionDeRegla.Bloquear, AccionDeRegla.Permitir)
        };
    }
}
