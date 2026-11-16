using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Nexo.Modules.Threats.Apps;

namespace Nexo.Movil.Demo
{
    internal static partial class Program
    {
        private static int _fallos;
        private static int _total;

        public static int Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            ProbarCatalogo();
            ProbarValidacionDelCatalogo();
            ProbarOrigenes();
            ProbarPuntuacion();
            ProbarAppsConocidasYConfianza();
            ProbarOrden();
            Console.WriteLine();
            Console.WriteLine(_fallos == 0 ? $"TODAS LAS VERIFICACIONES PASARON ({_total})" : $"{_fallos} VERIFICACIONES FALLIDAS de {_total}");
            return _fallos == 0 ? 0 : 1;
        }

        private static void Check(bool condicion, string descripcion, string? detalle = null)
        {
            _total++;
            if (!condicion) _fallos++;
            Console.WriteLine((condicion ? "  [OK]    " : "  [FALLA] ") + descripcion + (!condicion && detalle != null ? "  -> " + detalle : ""));
        }

        private static void Titulo(string t) { Console.WriteLine(); Console.WriteLine("== " + t); }

        private static ModeloDeApp App(string paquete, Func<ModeloDeApp, ModeloDeApp>? ajustar = null)
        {
            var a = new ModeloDeApp { Paquete = paquete, Nombre = paquete, InstaladoPor = "com.android.vending" };
            return ajustar is null ? a : ajustar(a);
        }

        private static HashSet<string> Permisos(params string[] p) => new(p.Select(x => "android.permission." + x));

        private static void ProbarCatalogo()
        {
            Titulo("Catalogo embebido");
            var c = CatalogoDeSenales.Embebido();
            Check(c.Senales.Count >= 12, "carga el catalogo real", $"{c.Senales.Count} senales");
            Check(c.UmbralARevisar < c.UmbralPrioritaria, "umbrales coherentes");
            Check(c.Combinaciones.All(x => x.Requiere.All(c.Senales.ContainsKey)), "toda combinacion nombra senales que existen");
            Check(c.Senales.Values.All(s => s.Motivo.Length > 10), "toda senal trae un motivo en lenguaje simple");
            Check(c.Senales.Values.All(s => !s.Motivo.Contains("malware", StringComparison.OrdinalIgnoreCase)), "ningun motivo afirma «malware»");
            Check(c.Senales["camara"].Peso == 0 && c.Senales["accesibilidad"].Peso > 0, "la camara sola no pesa; la Accesibilidad si");
        }

        private static void ProbarValidacionDelCatalogo()
        {
            Titulo("Un catalogo roto falla en voz alta");
            const string Base = """{"umbrales":{"aRevisar":4,"prioritaria":7},"senales":[{"id":"a","peso":1,"motivo":"motivo de prueba largo"},{"id":"b","peso":1,"motivo":"motivo de prueba largo"}],"combinaciones":[],"origenes":{},"appsConocidas":[]}""";
            Check(Lanza(Base) is null, "el catalogo minimo valido carga");
            Check(Lanza(Base.Replace("\"requiere\"", "x").Replace("\"combinaciones\":[]", "\"combinaciones\":[{\"id\":\"c\",\"requiere\":[\"a\",\"zzz\"],\"peso\":2,\"motivo\":\"m\"}]"))?.Contains("zzz") == true, "combinacion con senal inexistente");
            Check(Lanza(Base.Replace("\"prioritaria\":7", "\"prioritaria\":3")) is not null, "umbrales al reves");
            Check(Lanza(Base.Replace("\"peso\":1,\"motivo\":\"motivo de prueba largo\"},{\"id\":\"b\"", "\"peso\":-1,\"motivo\":\"motivo de prueba largo\"},{\"id\":\"b\"")) is not null, "peso negativo");
            Check(Lanza(Base.Replace("\"id\":\"b\"", "\"id\":\"a\"")) is not null, "senal repetida");
            Check(Lanza("{no es json") is not null, "JSON ilegible");
            Check(Lanza("null") is not null, "JSON vacio");
            Check(Lanza(Base.Replace("\"appsConocidas\":[]", "\"appsConocidas\":[{\"paquete\":\"x\",\"permite\":[\"nada\"]}]")) is not null, "app conocida que permite una senal inexistente");
        }

        private static string? Lanza(string json)
        {
            try { CatalogoDeSenales.Desde(json); return null; }
            catch (InvalidDataException ex) { return ex.Message; }
        }

        private static void ProbarOrigenes()
        {
            Titulo("Origen de la instalacion");
            var c = CatalogoDeSenales.Embebido();
            Check(c.ClasificarOrigen("com.android.vending") == OrigenDeInstalacion.TiendaOficial, "Play Store = tienda oficial");
            Check(c.ClasificarOrigen("com.sec.android.app.samsungapps") == OrigenDeInstalacion.TiendaConocida, "Galaxy Store = tienda conocida");
            Check(c.ClasificarOrigen("com.android.chrome") == OrigenDeInstalacion.Navegador, "Chrome = navegador");
            Check(c.ClasificarOrigen("com.google.android.packageinstaller") == OrigenDeInstalacion.ArchivoOAdb, "instalador de paquetes = archivo");
            Check(c.ClasificarOrigen(null) == OrigenDeInstalacion.ArchivoOAdb, "sin instalador (adb) = archivo");
            Check(c.ClasificarOrigen("com.tienda.rara") == OrigenDeInstalacion.OtraTienda, "desconocida = otra tienda");
        }

        private static void ProbarPuntuacion()
        {
            Titulo("Puntuacion");
            var p = new PuntuadorDeRiesgo(CatalogoDeSenales.Embebido());

            var camara = p.Evaluar(App("com.app.camara", a => a with { PermisosConcedidos = Permisos("CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "READ_CONTACTS") }));
            Check(camara.Nivel == NivelDeRiesgo.Normal && camara.Puntos == 0, "camara+microfono+ubicacion+contactos concedidos, de Play: normal, 0 puntos", $"{camara.Nivel} {camara.Puntos}");
            Check(camara.Motivos.Count == 0, "lo que no pesa no se lista como motivo");
            Check(camara.SenalesActivas.Contains("camara"), "pero la senal queda registrada como contexto");

            var troyano = p.Evaluar(App("com.falsa.factura", a => a with
            {
                InstaladoPor = "com.android.chrome",
                AccesibilidadActiva = true,
                PermisosConcedidos = Permisos("READ_SMS", "RECEIVE_SMS"),
            }));
            Check(troyano.Nivel == NivelDeRiesgo.Prioritaria, "Accesibilidad + SMS + instalada desde el navegador: prioritaria", $"{troyano.Nivel} {troyano.Puntos}");
            Check(troyano.Motivos.Count >= 3, "explica con varios motivos");
            Check(troyano.Motivos[0].Contains("Accesibilidad") && troyano.Motivos[^1].Contains("tienda"), "ordena los motivos del mas pesado al menos pesado", troyano.Motivos[0] + " / " + troyano.Motivos[^1]);
            Check(troyano.Motivos.All(m => !m.Contains("malware", StringComparison.OrdinalIgnoreCase)), "los motivos nunca dicen «malware»");

            var combo = p.Evaluar(App("com.x", a => a with { AccesibilidadActiva = true, PermisosConcedidos = Permisos("READ_SMS") }));
            Check(combo.Puntos == 3 + 2 + 3, "las senales suman y la combinacion se agrega una sola vez", combo.Puntos.ToString());

            var sola = p.Evaluar(App("com.solo.accesibilidad", a => a with { AccesibilidadActiva = true }));
            Check(sola.Nivel == NivelDeRiesgo.Normal, "Accesibilidad sola, de Play: sigue en normal (3 < 4)", $"{sola.Nivel} {sola.Puntos}");
            var soloMasArchivo = p.Evaluar(App("com.solo.accesibilidad", a => a with { AccesibilidadActiva = true, InstaladoPor = null }));
            Check(soloMasArchivo.Nivel == NivelDeRiesgo.ARevisar, "Accesibilidad + archivo suelto: a revisar", $"{soloMasArchivo.Nivel} {soloMasArchivo.Puntos}");

            var sistema = p.Evaluar(App("com.android.settings", a => a with { EsDeSistema = true, AccesibilidadActiva = true, AdministradorActivo = true }));
            Check(sistema.Nivel == NivelDeRiesgo.NoEvaluada && sistema.Puntos == 0, "una app del sistema no se evalua");

            var depuracion = p.Evaluar(App("com.dev.build", a => a with { FirmaDeDepuracion = true, SinIconoEnLanzador = true }));
            Check(depuracion.SenalesActivas.Contains("firma_depuracion") && depuracion.SenalesActivas.Contains("sin_icono"), "detecta firma de depuracion y falta de icono");

            var permitidoSoloPedido = p.Evaluar(App("com.pide.sms", a => a with { PermisosPedidos = Permisos("READ_SMS") }));
            Check(permitidoSoloPedido.Puntos == 0, "pedir un permiso sin tenerlo concedido no suma");
        }

        private static void ProbarAppsConocidasYConfianza()
        {
            Titulo("Apps conocidas y «confio en esta app»");
            var p = new PuntuadorDeRiesgo(CatalogoDeSenales.Embebido());

            var gestorConocido = p.Evaluar(App("com.x8bit.bitwarden", a => a with { AccesibilidadActiva = true, SuperposicionConcedida = true }));
            Check(gestorConocido.Nivel == NivelDeRiesgo.Normal && gestorConocido.Puntos == 0, "un gestor de contrasenas conocido, de Play, con Accesibilidad no se marca", $"{gestorConocido.Nivel} {gestorConocido.Puntos}");
            var gestorSuelto = p.Evaluar(App("com.x8bit.bitwarden", a => a with { AccesibilidadActiva = true, SuperposicionConcedida = true, InstaladoPor = null }));
            Check(gestorSuelto.Nivel != NivelDeRiesgo.Normal, "el MISMO nombre de paquete instalado desde un archivo suelto SI se marca (no se puede falsificar)", $"{gestorSuelto.Nivel} {gestorSuelto.Puntos}");
            var impostorEnNavegador = p.Evaluar(App("com.antivirus", a => a with { InstaladoPor = "com.android.chrome", AccesibilidadActiva = true, SuperposicionConcedida = true, PermisosConcedidos = Permisos("READ_SMS") }));
            Check(impostorEnNavegador.Nivel == NivelDeRiesgo.Prioritaria, "un «com.antivirus» bajado del navegador es prioritario", $"{impostorEnNavegador.Nivel} {impostorEnNavegador.Puntos}");
            // Perfil observado en un telefono real (Android 13): antivirus legitimos de Play con Accesibilidad, superposicion y SMS.
            foreach (var av in new[] { "com.antivirus", "com.bitdefender.security" })
            {
                var r = p.Evaluar(App(av, a => a with { AccesibilidadActiva = true, SuperposicionConcedida = true, OyenteDeNotificacionesActivo = true, PermisosConcedidos = Permisos("READ_SMS", "RECEIVE_SMS", "READ_CALL_LOG") }));
                Check(r.Nivel == NivelDeRiesgo.Normal, $"antivirus conocido de Play ({av}) con permisos de proteccion: normal", $"{r.Nivel} {r.Puntos}");
            }
            var impostor = p.Evaluar(App("com.x8bit.bitwarden.falso", a => a with { AccesibilidadActiva = true, SuperposicionConcedida = true, InstaladoPor = null }));
            Check(impostor.Nivel != NivelDeRiesgo.Normal, "el mismo perfil con otro nombre de paquete SI se marca", $"{impostor.Nivel}");
            var otraSenal = p.Evaluar(App("com.x8bit.bitwarden", a => a with { AccesibilidadActiva = true, PermisosConcedidos = Permisos("READ_SMS") }));
            Check(otraSenal.SenalesActivas.Contains("sms") && otraSenal.Puntos == 2, "lo permitido son solo las senales esperables: el SMS sigue contando", otraSenal.Puntos.ToString());

            var confiadas = new HashSet<string> { "com.falsa.factura" };
            var app = App("com.falsa.factura", a => a with { InstaladoPor = "com.android.chrome", AccesibilidadActiva = true, PermisosConcedidos = Permisos("READ_SMS") });
            var sinConfianza = p.Evaluar(app);
            var conConfianza = p.Evaluar(app, confiadas);
            Check(conConfianza.Nivel == NivelDeRiesgo.Confiada, "«confio en esta app» la saca de las alertas");
            Check(conConfianza.Puntos == sinConfianza.Puntos && conConfianza.Motivos.Count == sinConfianza.Motivos.Count, "pero conserva sus puntos y motivos (no se esconde nada)");
            var normalConfiada = p.Evaluar(App("com.nada", a => a), new HashSet<string> { "com.nada" });
            Check(normalConfiada.Nivel == NivelDeRiesgo.Normal, "confiar en una app normal no cambia nada");
        }

        private static void ProbarOrden()
        {
            Titulo("Orden de la lista");
            var p = new PuntuadorDeRiesgo(CatalogoDeSenales.Embebido());
            var apps = new[]
            {
                App("com.normal"),
                App("com.alta", a => a with { InstaladoPor = "com.android.chrome", AccesibilidadActiva = true, PermisosConcedidos = Permisos("READ_SMS") }),
                App("com.media", a => a with { AccesibilidadActiva = true, InstaladoPor = null }),
                App("com.sistema", a => a with { EsDeSistema = true }),
            };
            var r = p.EvaluarTodas(apps);
            Check(r[0].Paquete == "com.alta" && r[1].Paquete == "com.media", "primero lo prioritario, luego lo a revisar", string.Join(",", r.Select(x => x.Paquete)));
            Check(r.Count == 4, "no se pierde ninguna app");
            Check(p.EvaluarTodas(apps).Select(x => x.Paquete).SequenceEqual(r.Select(x => x.Paquete)), "el orden es estable entre corridas");
        }
    }
}
