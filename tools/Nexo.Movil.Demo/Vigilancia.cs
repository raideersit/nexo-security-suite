using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Nexo.Modules.Threats.Apps;

namespace Nexo.Movil.Demo
{
    internal static partial class Program
    {
        private const long Hora = 3_600_000;
        private static readonly string HuellaMala = new('a', 64);

        private static ModeloDeApp Normal(string paquete, long version = 1, long fecha = 1000) =>
            App(paquete, a => a with { VersionCode = version, UltimaActualizacionMs = fecha });

        /// <summary>Perfil «prioritaria»: Accesibilidad + SMS + instalada desde el navegador.</summary>
        private static ModeloDeApp Sospechosa(string paquete, long version = 1, long fecha = 1000) =>
            App(paquete, a => a with { VersionCode = version, UltimaActualizacionMs = fecha, InstaladoPor = "com.android.chrome", AccesibilidadActiva = true, PermisosConcedidos = Permisos("READ_SMS") });

        /// <summary>Perfil «a revisar» (4 puntos): Accesibilidad + archivo suelto.</summary>
        private static ModeloDeApp Dudosa(string paquete, long version = 1, long fecha = 1000, bool conSms = false) =>
            App(paquete, a => a with { VersionCode = version, UltimaActualizacionMs = fecha, InstaladoPor = null, AccesibilidadActiva = true, PermisosConcedidos = conSms ? Permisos("READ_SMS") : new HashSet<string>() });

        private static VigilanteDeInstalaciones NuevoVigilante() => new(new PuntuadorDeRiesgo(CatalogoDeSenales.Embebido()));

        private static ListaDeHuellas ListaMala() => ListaDeHuellas.Desde("lista-de-prueba.txt", new StringReader(HuellaMala));

        private static Dictionary<string, HuellaDeApp> HuellaDe(string paquete, string sha) =>
            new() { [paquete] = new HuellaDeApp(paquete, 1, 1, new[] { new HuellaDeArchivo("base.apk", 1, sha) }) };

        private static void ProbarVigilante()
        {
            var v = NuevoVigilante();

            Titulo("Vigilante: la primera vez solo anota (linea base)");
            var e = new EstadoDeVigilancia();
            var r0 = v.Revisar(new[] { Sospechosa("com.vieja.sospechosa"), Normal("com.normal") }, e, 1 * Hora);
            Check(r0.EraLineaBase && r0.Alertas.Count == 0, "no alerta por apps que ya estaban instaladas", $"{r0.Alertas.Count}");
            Check(e.Conocidas.Count == 2 && e.UltimaRevisionMs == 1 * Hora, "guarda lo que vio y cuando");
            var r1 = v.Revisar(new[] { Sospechosa("com.vieja.sospechosa"), Normal("com.normal") }, e, 2 * Hora);
            Check(!r1.EraLineaBase && r1.Alertas.Count == 0 && r1.Nuevas == 0 && r1.Actualizadas == 0, "sin cambios: nada que avisar");

            Titulo("Vigilante: app nueva");
            var actuales = new List<ModeloDeApp> { Sospechosa("com.vieja.sospechosa"), Normal("com.normal") };
            actuales.Add(Normal("com.nueva.normal"));
            var r2 = v.Revisar(actuales, e, 3 * Hora);
            Check(r2.Nuevas == 1 && r2.Alertas.Count == 0, "una app nueva normal se cuenta pero no alerta");
            actuales.Add(Sospechosa("com.nueva.sospechosa"));
            var r3 = v.Revisar(actuales, e, 4 * Hora);
            Check(r3.Alertas.Count == 1 && r3.Alertas[0].Paquete == "com.nueva.sospechosa" && r3.Alertas[0].Tipo == TipoDeCambio.Nueva, "una app nueva «prioritaria» alerta");
            Check(r3.Alertas[0].Titulo.Contains("se instaló") && r3.Alertas[0].Texto.Length > 10, "el aviso dice que se instalo y da un motivo");
            Check(!r3.Alertas[0].Titulo.Contains("malware", StringComparison.OrdinalIgnoreCase) && !r3.Alertas[0].Texto.Contains("malware", StringComparison.OrdinalIgnoreCase), "el aviso nunca dice «malware»");
            var r4 = v.Revisar(actuales, e, 5 * Hora);
            Check(r4.Alertas.Count == 0, "la misma app no vuelve a avisar en la revision siguiente");

            Titulo("Vigilante: huella conocida");
            var l = new[] { ListaMala() };
            var r5 = v.Revisar(actuales.Append(Normal("com.huella")).ToList(), e, 6 * Hora, HuellaDe("com.huella", HuellaMala), l);
            Check(r5.Alertas.Count == 1 && r5.Alertas[0].Coincidencias.Count == 1, "una app normal pero con huella conocida alerta");
            Check(r5.Alertas[0].Texto.Contains("lista-de-prueba.txt") && r5.Alertas[0].Texto.Contains("no un análisis"), "dice de que lista y que no es un analisis");
            var r6 = v.Revisar(actuales.Append(Normal("com.otra")).ToList(), e, 7 * Hora, HuellaDe("com.otra", new string('9', 64)), l);
            Check(r6.Alertas.Count == 0, "una huella que no esta en la lista no alerta");

            Titulo("Vigilante: actualizaciones");
            var e2 = new EstadoDeVigilancia();
            v.Revisar(new[] { Dudosa("com.dudosa"), Normal("com.limpia"), Dudosa("com.mejora") }, e2, 1 * Hora);
            var ra = v.Revisar(new[] { Dudosa("com.dudosa", 2, 2000), Normal("com.limpia"), Dudosa("com.mejora") }, e2, 2 * Hora);
            Check(ra.Actualizadas == 1 && ra.Alertas.Count == 0, "una app ya marcada que se actualiza sin empeorar NO vuelve a avisar", $"{ra.Alertas.Count}");
            var rb = v.Revisar(new[] { Dudosa("com.dudosa", 3, 3000, conSms: true), Normal("com.limpia"), Dudosa("com.mejora") }, e2, 3 * Hora);
            Check(rb.Alertas.Count == 1 && rb.Alertas[0].Tipo == TipoDeCambio.Actualizada && rb.Alertas[0].Titulo.Contains("se actualizó"), "si al actualizarse EMPEORA (gana el permiso de SMS), avisa");
            var rc = v.Revisar(new[] { Dudosa("com.dudosa", 3, 3000, conSms: true), Normal("com.limpia", 2, 4000), Dudosa("com.mejora") }, e2, 4 * Hora);
            Check(rc.Alertas.Count == 0 && rc.Actualizadas == 1, "una app limpia que se actualiza y sigue limpia no avisa");
            var rd = v.Revisar(new[] { Dudosa("com.dudosa", 3, 3000, conSms: true), Sospechosa("com.limpia", 3, 5000), Dudosa("com.mejora") }, e2, 5 * Hora);
            Check(rd.Alertas.Count == 1 && rd.Alertas[0].Paquete == "com.limpia", "una app limpia que se actualiza a un perfil de riesgo avisa");
            var re = v.Revisar(new[] { Dudosa("com.dudosa", 3, 3000, conSms: true), Sospechosa("com.limpia", 3, 5000), Normal("com.mejora", 9, 9000) }, e2, 6 * Hora);
            Check(re.Alertas.Count == 0, "una app que MEJORA al actualizarse no avisa");
            var rf = v.Revisar(new[] { Dudosa("com.dudosa", 3, 3000, conSms: true), Sospechosa("com.limpia", 3, 5000), Normal("com.mejora", 10, 10000) }, e2, 7 * Hora,
                HuellaDe("com.mejora", HuellaMala), l);
            Check(rf.Alertas.Count == 1 && rf.Alertas[0].Coincidencias.Count == 1, "una actualizacion que ahora coincide con una huella avisa aunque no empeore");

            Titulo("Vigilante: sistema, confianza, desinstalaciones");
            var e3 = new EstadoDeVigilancia();
            v.Revisar(new[] { Normal("com.a") }, e3, 1 * Hora);
            var sistema = new ModeloDeApp { Paquete = "com.sistema.nueva", EsDeSistema = true, AccesibilidadActiva = true, AdministradorActivo = true, InstaladoPor = null };
            var rs = v.Revisar(new[] { Normal("com.a"), sistema }, e3, 2 * Hora);
            Check(rs.Alertas.Count == 0 && rs.Nuevas == 0 && !e3.Conocidas.ContainsKey("com.sistema.nueva"), "las apps del sistema ni se vigilan ni se recuerdan");
            var confiadas = new HashSet<string> { "com.confio" };
            var rt = v.Revisar(new[] { Normal("com.a"), Sospechosa("com.confio") }, e3, 3 * Hora, null, null, confiadas);
            Check(rt.Alertas.Count == 0 && rt.Nuevas == 1, "«confio en esta app» silencia el aviso de riesgo");
            var rt2 = v.Revisar(new[] { Normal("com.a"), Sospechosa("com.confio"), Normal("com.confio2") }, e3, 4 * Hora, HuellaDe("com.confio2", HuellaMala), l, new HashSet<string> { "com.confio", "com.confio2" });
            Check(rt2.Alertas.Count == 1, "pero NO silencia una coincidencia exacta con una huella conocida");
            var rdes = v.Revisar(new[] { Normal("com.a") }, e3, 5 * Hora);
            Check(rdes.Desinstaladas == 2 && e3.Conocidas.Count == 1, "cuenta las 2 desinstaladas (de 3 conocidas) y las olvida", rdes.Desinstaladas.ToString());
            Check(e3.Avisadas.Count == 0, "tambien olvida los avisos de apps que ya no estan");
            var e4 = new EstadoDeVigilancia(); v.Revisar(new[] { Normal("com.a") }, e4, 1 * Hora);
            v.Revisar(new[] { Normal("com.a"), Sospechosa("com.reinstalada", 1, 1000) }, e4, 2 * Hora);
            v.Revisar(new[] { Normal("com.a") }, e4, 3 * Hora);
            var rrr = v.Revisar(new[] { Normal("com.a"), Sospechosa("com.reinstalada", 1, 8000) }, e4, 4 * Hora);
            Check(rrr.Alertas.Count == 1, "desinstalar y volver a instalar la misma app vuelve a avisar");

            Titulo("Vigilante: telefono sin apps de usuario");
            var e5 = new EstadoDeVigilancia();
            var rv = v.Revisar(Array.Empty<ModeloDeApp>(), e5, 1 * Hora);
            Check(rv.EraLineaBase && e5.UltimaRevisionMs == 1 * Hora, "una linea base vacia tambien cuenta como hecha");
            var rv2 = v.Revisar(new[] { Sospechosa("com.primera") }, e5, 2 * Hora);
            Check(!rv2.EraLineaBase && rv2.Alertas.Count == 1, "y la primera app que llega despues SI alerta (no se confunde con una linea base)");
        }

        private static void ProbarEstadoDeVigilancia()
        {
            Titulo("Estado de vigilancia en disco");
            var dir = Path.Combine(Path.GetTempPath(), "nexo-movil-vig-" + Guid.NewGuid().ToString("N"));
            try
            {
                var v = NuevoVigilante();
                var ruta = Path.Combine(dir, "vigilancia.json");
                var e = new EstadoDeVigilancia();
                v.Revisar(new[] { Normal("com.a") }, e, 1 * Hora);
                v.Revisar(new[] { Normal("com.a"), Sospechosa("com.b") }, e, 2 * Hora);
                e.Guardar(ruta);
                Check(File.Exists(ruta) && !File.Exists(ruta + ".tmp"), "guarda sin dejar temporal");
                var e2 = EstadoDeVigilancia.Cargar(ruta, out var aviso);
                Check(aviso == null && e2.Conocidas.Count == 2 && e2.UltimaRevisionMs == 2 * Hora && e2.Avisadas.Count == 1, "recarga todo lo guardado");
                var r = v.Revisar(new[] { Normal("com.a"), Sospechosa("com.b") }, e2, 3 * Hora);
                Check(r.Alertas.Count == 0, "tras reiniciar la app NO repite el aviso ya dado");
                Check(EstadoDeVigilancia.Cargar(Path.Combine(dir, "no.json"), out var a0).Conocidas.Count == 0 && a0 == null, "sin archivo: estado nuevo sin aviso");
                File.WriteAllText(ruta, "{roto");
                var d = EstadoDeVigilancia.Cargar(ruta, out var a1);
                Check(d.Conocidas.Count == 0 && a1 != null && d.UltimaRevisionMs == null, "un archivo roto se descarta con aviso y empieza una linea base nueva");
                File.WriteAllText(ruta, "{\"Version\":7,\"Conocidas\":{},\"Avisadas\":[]}");
                Check(EstadoDeVigilancia.Cargar(ruta, out var a2).Conocidas.Count == 0 && a2 != null, "una version desconocida tambien");
            }
            finally { try { Directory.Delete(dir, true); } catch (IOException) { } }

            Titulo("Retraso de la revision (fabricantes que matan tareas)");
            var dia = TimeSpan.FromHours(24);
            Check(!VigilanteDeInstalaciones.EstaAtrasada(100 * Hora, 0, 123 * Hora, dia), "hace 23 h: al dia");
            Check(VigilanteDeInstalaciones.EstaAtrasada(100 * Hora, 0, 125 * Hora, dia), "hace 25 h: atrasada");
            Check(!VigilanteDeInstalaciones.EstaAtrasada(null, 100 * Hora, 110 * Hora, dia), "recien activada y sin revisiones aun: no es retraso");
            Check(VigilanteDeInstalaciones.EstaAtrasada(null, 100 * Hora, 130 * Hora, dia), "activada hace 30 h y nunca reviso: atrasada");
            Check(!VigilanteDeInstalaciones.EstaAtrasada(120 * Hora, 100 * Hora, 130 * Hora, dia), "cuenta desde la ultima revision, no desde la activacion");
        }
    }
}
