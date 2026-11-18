using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Nexo.Modules.Threats.Apps;

namespace Nexo.Movil.Demo
{
    internal static partial class Program
    {
        private const string Nexo = "io.github.raideersit.nexo";

        private static ReglasDelFirewall Reglas(bool encendido, params string[] bloqueadas) =>
            new() { Encendido = encendido, Bloqueadas = new HashSet<string>(bloqueadas, StringComparer.Ordinal) };

        private static void ProbarFirewallMovil()
        {
            var instaladas = new HashSet<string> { Nexo, "com.sec.android.app.sbrowser", "com.android.chrome", "com.juego" };

            Titulo("Firewall: NUNCA se crea una VPN vacia (dejaria todo el telefono sin internet)");
            var p0 = PlanDeFirewallMovil.Calcular(Reglas(true), instaladas, Nexo);
            Check(!p0.Establecer && p0.Paquetes.Count == 0, "encendido sin apps marcadas: no se establece");
            var p1 = PlanDeFirewallMovil.Calcular(Reglas(true, Nexo), instaladas, Nexo);
            Check(!p1.Establecer && p1.Ignoradas.SequenceEqual(new[] { Nexo }), "encendido con solo Nexo marcado: no se establece y Nexo se ignora");
            var p2 = PlanDeFirewallMovil.Calcular(Reglas(true, "com.desinstalada"), instaladas, Nexo);
            Check(!p2.Establecer && p2.Ignoradas.SequenceEqual(new[] { "com.desinstalada" }), "encendido con solo apps desinstaladas: no se establece");
            var p3 = PlanDeFirewallMovil.Calcular(Reglas(true, "", "  "), instaladas, Nexo);
            Check(!p3.Establecer, "paquetes en blanco no cuentan");

            Titulo("Firewall: el plan normal");
            var r = Reglas(true, "com.sec.android.app.sbrowser", "com.desinstalada", Nexo, "com.juego");
            var p4 = PlanDeFirewallMovil.Calcular(r, instaladas, Nexo);
            Check(p4.Establecer && p4.Paquetes.SequenceEqual(new[] { "com.juego", "com.sec.android.app.sbrowser" }), "entran solo las instaladas que no son Nexo, en orden estable", string.Join(",", p4.Paquetes));
            Check(p4.Ignoradas.Count == 2 && r.Bloqueadas.Contains("com.desinstalada"), "la desinstalada se ignora pero sigue en las reglas (por si se reinstala)");
            Check(!PlanDeFirewallMovil.Calcular(Reglas(false, "com.juego"), instaladas, Nexo).Establecer, "apagado: no se establece aunque haya apps marcadas");
            Check(!PlanDeFirewallMovil.Calcular(r, instaladas, Nexo).Paquetes.Contains("com.android.chrome"), "una app no marcada nunca entra al tunel");

            Titulo("Firewall: que apps se pueden bloquear");
            var conInternet = App("com.conred", a => a with { PermisosPedidos = new HashSet<string> { PlanDeFirewallMovil.PermisoDeInternet } });
            var sinInternet = App("com.sinred", a => a with { PermisosPedidos = new HashSet<string> { "android.permission.CAMERA" } });
            var nexo = App(Nexo, a => a with { PermisosPedidos = new HashSet<string> { PlanDeFirewallMovil.PermisoDeInternet } });
            Check(PlanDeFirewallMovil.EsBloqueable(conInternet, Nexo), "una app que pide internet se puede bloquear");
            Check(!PlanDeFirewallMovil.EsBloqueable(sinInternet, Nexo), "una app sin permiso de internet no se lista (no hay nada que bloquear)");
            Check(!PlanDeFirewallMovil.EsBloqueable(nexo, Nexo), "Nexo no se puede bloquear a si mismo");

            Titulo("Firewall: persistencia");
            var ruta = Path.Combine(Path.GetTempPath(), "nexo-firewall-" + Guid.NewGuid().ToString("N") + ".json");
            try
            {
                var g = Reglas(true, "com.juego", "com.sec.android.app.sbrowser");
                g.Revocado = true;
                g.Guardar(ruta);
                var l = ReglasDelFirewall.Cargar(ruta, out var a1);
                Check(a1 == null && l.Encendido && l.Revocado && l.Bloqueadas.SetEquals(g.Bloqueadas), "guarda y carga lo mismo");
                File.WriteAllText(ruta, "{ roto");
                var d = ReglasDelFirewall.Cargar(ruta, out var a2);
                Check(a2 != null && !d.Encendido && d.Bloqueadas.Count == 0, "un archivo dañado queda APAGADO y lo dice");
                File.WriteAllText(ruta, "{\"Encendido\":true,\"Bloqueadas\":[\"com.juego\"],\"Version\":7}");
                var v = ReglasDelFirewall.Cargar(ruta, out var a3);
                Check(a3 != null && !v.Encendido, "una version desconocida queda APAGADA aunque diga encendido");
                Check(!ReglasDelFirewall.Cargar(ruta + ".no", out var a4).Encendido && a4 == null, "sin archivo: apagado, sin aviso");
            }
            finally { File.Delete(ruta); }
        }
    }
}
