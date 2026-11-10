using System;
using System.Collections.Generic;
using System.Linq;
using Nexo.Modules.Threats.Criptojacking;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Vuln.Demo
{
    internal static partial class Program
    {
        private static ProcesoMuestreado Pr(int pid, string nombre, double cpu, bool frente = false, string? ruta = @"C:\Program Files\X\x.exe") => new(pid, nombre, ruta, cpu, frente);

        private static MuestraDeMineria Mu(IReadOnlyList<ProcesoMuestreado> procs, IReadOnlyList<ConexionDeProceso>? conex = null, bool procsOk = true, bool conexOk = true)
            => new(T0, procs, procsOk, conex ?? Array.Empty<ConexionDeProceso>(), conexOk);

        private static ResultadoDeAnalisis Repetir(VigilanteDeMineria v, int veces, Func<MuestraDeMineria> muestra)
        {
            ResultadoDeAnalisis r = null!;
            for (int i = 0; i < veces; i++) r = v.Evaluar(muestra());
            return r;
        }

        private static void ProbarListaDeMineria()
        {
            Console.WriteLine("31. Anti-criptojacking: la lista de servidores de minería");
            string texto = "# lista de prueba\n\n203.0.113.7\n198.51.100.0   # comentario al final\n2001:db8::1\n0.0.0.0 pool.ejemplo.net\n127.0.0.1 otro.pool.org\nminer.example.com\nesto no es nada\n1.2.3\n0.0.0.0\n::ffff:203.0.113.9\n";
            var (l, ign) = ListaDePools.Leer(texto);
            Check(l.EsPool("203.0.113.7") && l.EsPool("198.51.100.0") && l.EsPool("2001:db8::1"), "lee IP sueltas (v4 y v6) y con comentarios");
            Check(l.EsPool("::ffff:203.0.113.7"), "una IPv4 mapeada en IPv6 cuenta como la IPv4");
            Check(l.EsPool("203.0.113.9"), "y una de la lista escrita mapeada se guarda como IPv4");
            Check(l.EsDominioPool("pool.ejemplo.net") && l.EsDominioPool("OTRO.POOL.ORG.") && l.EsDominioPool("miner.example.com"), "lee dominios, también en formato hosts, sin importar mayúsculas ni el punto final");
            Check(!l.EsPool("203.0.113.8") && !l.EsDominioPool("example.com"), "lo que no está, no está (ni «example.com» por «miner.example.com»)");
            Check(ign == 3, "ignora lo que no entiende y se cuenta (3: texto libre, «1.2.3», «0.0.0.0»)", ign.ToString());
            Check(ListaDePools.Leer(null).Lista.Ips == 0 && ListaDePools.Leer("").Lista.Dominios == 0, "sin texto, lista vacía");
            Check(!ListaDePools.Vacia.EsPool("203.0.113.7"), "la lista vacía no reconoce nada");
        }

        private static void ProbarVigilanteDeMineria()
        {
            Console.WriteLine("32. Anti-criptojacking: CPU sostenida, conexiones y honestidad");
            var lista = new ListaDePools(new[] { "203.0.113.7" }, new[] { "pool.ejemplo.net" });
            int N = VigilanteDeMineria.MuestrasSostenidas;

            // Un equipo tranquilo
            var v0 = new VigilanteDeMineria(lista);
            ResultadoDeAnalisis tranquilo = Repetir(v0, N + 2, () => Mu(new[] { Pr(10, "chrome.exe", 5, frente: true), Pr(20, "code.exe", 12) }));
            Check(tranquilo.Hallazgos.Count == 0 && tranquilo.Completo, "equipo tranquilo: sin hallazgos y leído por completo");

            // CPU alta pero no sostenida
            var v1 = new VigilanteDeMineria(lista);
            ResultadoDeAnalisis corto = Repetir(v1, N - 1, () => Mu(new[] { Pr(30, "render.exe", 95) }));
            Check(corto.Hallazgos.Count == 0, "CPU alta durante menos muestras que las exigidas: nada");
            ResultadoDeAnalisis justo = v1.Evaluar(Mu(new[] { Pr(30, "render.exe", 95) }));
            Check(justo.Hallazgos.Count == 1 && justo.Hallazgos[0].Id == "MINERIA-CPU" && justo.Hallazgos[0].Severidad == Severidad.Baja, "al completar la racha: solo una señal BAJA");
            Check(justo.Hallazgos[0].Detalle.Contains("no es una prueba de minería"), "y el texto dice que no es una prueba");

            // Una muestra baja rompe la racha
            var v2 = new VigilanteDeMineria(lista);
            Repetir(v2, N - 1, () => Mu(new[] { Pr(30, "render.exe", 95) }));
            v2.Evaluar(Mu(new[] { Pr(30, "render.exe", 20) }));
            Check(v2.Evaluar(Mu(new[] { Pr(30, "render.exe", 95) })).Hallazgos.Count == 0 && v2.ProcesosEnRacha == 1, "una muestra por debajo del umbral reinicia la racha");

            // Primer plano no cuenta
            var v3 = new VigilanteDeMineria(lista);
            Check(Repetir(v3, N + 3, () => Mu(new[] { Pr(40, "juego.exe", 99, frente: true) })).Hallazgos.Count == 0, "un programa en primer plano (un juego) no se vigila");
            Check(Repetir(v3, N + 3, () => Mu(new[] { Pr(41, "MsMpEng.exe", 99) })).Hallazgos.Count == 0 && v3.ProcesosEnRacha == 0, "ni los procesos del sistema (Defender analizando)");

            // PID reutilizado por otro programa
            var v4 = new VigilanteDeMineria(lista);
            Repetir(v4, N - 1, () => Mu(new[] { Pr(50, "a.exe", 90) }));
            Check(v4.Evaluar(Mu(new[] { Pr(50, "b.exe", 90) })).Hallazgos.Count == 0, "un PID reutilizado por otro programa empieza de cero");
            // Un proceso que desaparece olvida su racha
            var v5 = new VigilanteDeMineria(lista);
            Repetir(v5, N - 1, () => Mu(new[] { Pr(60, "a.exe", 90) }));
            v5.Evaluar(Mu(Array.Empty<ProcesoMuestreado>()));
            Check(v5.ProcesosEnRacha == 0, "un proceso que desaparece olvida su racha");

            // Carpeta poco habitual
            var v6 = new VigilanteDeMineria(lista);
            ResultadoDeAnalisis rara = Repetir(v6, N, () => Mu(new[] { Pr(70, "svchost32.exe", 80, ruta: @"C:\Users\ana\AppData\Local\Temp\svchost32.exe") }));
            Check(rara.Hallazgos.Single().Id == "MINERIA-CPU-RUTA-RARA" && rara.Hallazgos.Single().Severidad == Severidad.Media, "CPU sostenida desde la carpeta Temp: Media");

            // Puerto de minería: solo con CPU sostenida
            var v7 = new VigilanteDeMineria(lista);
            var stratum = new[] { new ConexionDeProceso(80, "192.0.2.10", 3333) };
            Check(Repetir(v7, N + 2, () => Mu(new[] { Pr(80, "app.exe", 5) }, stratum)).Hallazgos.Count == 0, "un puerto «de minería» SIN CPU alta no es nada");
            var v8 = new VigilanteDeMineria(lista);
            ResultadoDeAnalisis cp = Repetir(v8, N, () => Mu(new[] { Pr(80, "app.exe", 85) }, stratum));
            Check(cp.Hallazgos.Single().Id == "MINERIA-CPU-Y-PUERTO" && cp.Hallazgos.Single().Severidad == Severidad.Alta && cp.Hallazgos.Single().Detalle.Contains("no está en la lista"), "CPU sostenida + puerto de minería: Alta, y se dice que la IP no está en la lista");

            // IP de la lista
            var v9 = new VigilanteDeMineria(lista);
            var pool = new[] { new ConexionDeProceso(90, "203.0.113.7", 443) };
            ResultadoDeAnalisis soloPool = v9.Evaluar(Mu(new[] { Pr(90, "navegador.exe", 3) }, pool));
            Check(soloPool.Hallazgos.Single().Id == "MINERIA-POOL" && soloPool.Hallazgos.Single().Severidad == Severidad.Alta && soloPool.Hallazgos.Single().Detalle.Contains("falso positivo"), "conexión a una IP de la lista sin CPU: Alta, con aviso de posible falso positivo");
            Check(v9.Evaluar(Mu(new[] { Pr(91, "x.exe", 3) }, new[] { new ConexionDeProceso(91, "::ffff:203.0.113.7", 80) })).Hallazgos.Single().Id == "MINERIA-POOL", "una IPv4 mapeada en IPv6 también se reconoce");
            Check(v9.Evaluar(Mu(new[] { Pr(92, "x.exe", 3) }, new[] { new ConexionDeProceso(92, "192.0.2.99", 3333) })).Hallazgos.Count == 0, "otra IP y otro puerto: nada");
            Check(v9.Evaluar(Mu(new[] { Pr(93, "x.exe", 3) }, new[] { new ConexionDeProceso(93, "192.0.2.50", 443, Host: "pool.ejemplo.net") })).Hallazgos.Single().Id == "MINERIA-POOL", "un nombre de la lista, aunque la IP no esté, también");

            // Las dos señales juntas
            var v10 = new VigilanteDeMineria(lista);
            ResultadoDeAnalisis ambas = Repetir(v10, N, () => Mu(new[] { Pr(100, "xmrig.exe", 92, ruta: @"C:\Users\ana\Downloads\xmrig.exe") }, new[] { new ConexionDeProceso(100, "203.0.113.7", 3333) }));
            Check(ambas.Hallazgos.Single().Id == "MINERIA-POOL-Y-CPU" && ambas.Maxima == Severidad.Critica, "CPU sostenida + IP de la lista: CRÍTICA (y un solo hallazgo, sin duplicar)");
            Check(ambas.Hallazgos.Single().Recomendacion.Contains("no lo detiene por ti"), "y se dice que Nexo no detiene nada");

            // Honestidad: lo que no se pudo leer
            var v11 = new VigilanteDeMineria(lista);
            ResultadoDeAnalisis sinProc = v11.Evaluar(Mu(Array.Empty<ProcesoMuestreado>(), procsOk: false));
            Check(!sinProc.Completo && sinProc.NoEvaluado.Any(x => x.StartsWith("procesos")) && sinProc.Hallazgos.Count == 0, "procesos ilegibles: «no evaluado», nunca «sin problemas»");
            ResultadoDeAnalisis sinCon = v11.Evaluar(Mu(new[] { Pr(1, "a.exe", 1) }, conexOk: false));
            Check(!sinCon.Completo && sinCon.NoEvaluado.Any(x => x.StartsWith("conexiones")), "conexiones ilegibles: «no evaluado»");
            ResultadoDeAnalisis sinLista = new VigilanteDeMineria(ListaDePools.Vacia).Evaluar(Mu(new[] { Pr(1, "a.exe", 1) }));
            Check(!sinLista.Completo && sinLista.NoEvaluado.Any(x => x.Contains("lista")), "sin lista de servidores: no es «todo bien», se dice que falta");
            var v12 = new VigilanteDeMineria(lista);
            Repetir(v12, N - 1, () => Mu(new[] { Pr(5, "a.exe", 90) }));
            v12.Evaluar(Mu(Array.Empty<ProcesoMuestreado>(), procsOk: false));
            Check(v12.Evaluar(Mu(new[] { Pr(5, "a.exe", 90) })).Hallazgos.Count == 1, "una lectura fallida en medio NO borra la racha");
        }
    }
}
