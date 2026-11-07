using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Modules.Threats.Windows;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Vuln.Windows.Demo
{
    internal static partial class Program
    {
        /// <summary>Muestra por pantalla lo UNICO que sale hacia NVD: la cadena CPE.</summary>
        private sealed class NvdConRegistro : IConsultaNvd
        {
            private readonly IConsultaNvd _real;
            public NvdConRegistro(IConsultaNvd real) => _real = real;
            public async Task<RespuestaHttp> ConsultarCvesAsync(string cpe, CancellationToken ct)
            {
                Console.WriteLine("      -> sale hacia NVD: " + cpe);
                RespuestaHttp r = await _real.ConsultarCvesAsync(cpe, ct);
                Console.WriteLine("      <- HTTP " + (r.Estado?.ToString() ?? "sin respuesta (" + r.Error + ")") + ", " + r.Texto.Length + " caracteres");
                return r;
            }
        }

        /// <summary>
        /// Prueba REAL contra https://services.nvd.nist.gov. Solo con <c>--nvd</c>: sale a Internet (unas 20 consultas, ~2,5 min por el limite
        /// de NVD). Sale solo producto y version.
        /// </summary>
        private static void ProbarNvdReal()
        {
            Console.WriteLine("7. NVD REAL (--nvd): cada producto del mapa con una version VIEJA conocida debe devolver fallos; despues, este equipo");
            DateTimeOffset Reloj() => DateTimeOffset.UtcNow;

            // Controles: versiones antiguas con fallos publicados y conocidos. Si un CPE del mapa estuviera mal escrito devolveria 0 y esto fallaria.
            var viejas = new (string Id, string Version)[]
            {
                ("RARLab.WinRAR", "6.22.0"), ("7zip.7zip", "21.07"), ("Google.Chrome", "100.0.4896.60"), ("Mozilla.Firefox", "90.0"),
                ("Microsoft.Edge", "100.0.1185.29"), ("Oracle.JavaRuntimeEnvironment", "8.0.4010.10"), ("VideoLAN.VLC", "3.0.10"), ("Git.Git", "2.30.0"), ("OpenJS.NodeJS.LTS", "12.0.0")
            };
            var apps = viejas.Select(v => new AplicacionDesactualizada(v.Id, v.Id, v.Version, "99.0", "winget")).ToList();
            using var nvd = new ConsultaNvdHttp();
            ResumenDeCruce c = CruceConCve.CruzarAsync(apps, new NvdConRegistro(nvd), (t, ct) => Task.Delay(t, ct), Reloj).GetAwaiter().GetResult();
            foreach (ResultadoDeCruce r in c.Resultados)
            {
                Console.WriteLine("      INFO: " + r.App.Id + " " + r.App.VersionInstalada + " -> " + r.Estado + (r.Cves.Count > 0 ? " (" + r.Cves.Count + " CVE, p. ej. " + r.Cves[0].Id + ")" : "") + (r.Motivo is null ? "" : " [" + r.Motivo + "]"));
                Check(r.Estado == EstadoDeCruce.ConFallos, "control: " + r.App.Id + " " + r.App.VersionInstalada + " (version vieja) devuelve fallos conocidos", r.Estado + " / " + r.Motivo);
            }
            Check(c.Resultados.Any(r => r.App.Id == "RARLab.WinRAR" && r.Cves.Any(x => x.Id == "CVE-2023-38831")), "control: WinRAR 6.22 incluye CVE-2023-38831 (el fallo famoso de 2023)");

            // Este equipo, de punta a punta: winget real -> analizador -> servicio de la pestaña.
            Console.WriteLine("      --- este equipo ---");
            var servicio = new ServicioDeSeguridadLocal();
            Consulta<RevisionDeSeccion> apl = servicio.RevisarAsync(SeccionDeSeguridad.Aplicaciones, CancellationToken.None).GetAwaiter().GetResult();
            Check(apl.Valor?.Aplicaciones is not null, "se leyeron las aplicaciones de este equipo con winget", apl.Error);
            if (apl.Valor?.Aplicaciones is not { } instaladas) return;
            Console.WriteLine("      INFO: " + instaladas.Count + " aplicaciones con version nueva; entran en el mapa: " + instaladas.Count(a => MapaDeProductos.Buscar(a.Id) is not null));

            using var nvd2 = new ConsultaNvdHttp();
            ResumenDeCruce eq = CruceConCve.CruzarAsync(instaladas, new NvdConRegistro(nvd2), (t, ct) => Task.Delay(t, ct), Reloj).GetAwaiter().GetResult();
            ResultadoDeAnalisis an = CruceConCve.Analizar(eq);
            foreach (HallazgoDeSistema h in an.Hallazgos) Console.WriteLine("      [" + h.Severidad + "] " + h.Titulo + " (" + h.Sujeto + ") :: " + h.Detalle);
            foreach (string n in an.NoEvaluado) Console.WriteLine("      NO EVALUADO: " + n);
            Check(eq.Resultados.Count + eq.SinMapa.Count == instaladas.Count, "ninguna aplicacion desaparece: consultadas + sin mapa = todas");
            Check(!eq.Resultados.Any(r => r.Estado == EstadoDeCruce.NoSePudoComprobar), "todas las consultadas de este equipo se pudieron comprobar (sin red caida ni limite)", string.Join("; ", eq.Resultados.Where(r => r.Estado == EstadoDeCruce.NoSePudoComprobar).Select(r => r.App.Id + ": " + r.Motivo)));

            ResultadoDeCruce? winrar = eq.Resultados.FirstOrDefault(r => r.App.Id == "RARLab.WinRAR");
            if (winrar is null) Console.WriteLine("      INFO: WinRAR ya no esta desactualizado en este equipo: no se puede comprobar el caso de WinRAR 7.01");
            else if (winrar.App.VersionInstalada.StartsWith("7.01"))
                Check(winrar.Estado == EstadoDeCruce.ConFallos && winrar.Cves.Any(x => x.Id == "CVE-2025-8088"), "WinRAR " + winrar.App.VersionInstalada + " de este equipo incluye CVE-2025-8088 (explotado en ataques reales)", winrar.Estado + " / " + string.Join(",", winrar.Cves.Select(x => x.Id)));
        }
    }
}
