using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Nexo.Modules.Threats.Apps;
using Nexo.Reports;
using Nexo.Reports.Model;
using Nexo.Reports.Vault;

namespace Nexo.Movil.Demo
{
    internal static partial class Program
    {
        private static string TodoElVault(string raiz) =>
            string.Join("\n=====\n", Directory.EnumerateFiles(raiz, "*.md", SearchOption.AllDirectories).OrderBy(f => f).Select(f => "### " + Path.GetRelativePath(raiz, f) + "\n" + File.ReadAllText(f)));

        private static void ProbarReportes()
        {
            var raiz = Path.Combine(Path.GetTempPath(), "nexo-movil-vault-" + Guid.NewGuid().ToString("N"));
            try
            {
                var opciones = new VaultOptions { RutaVault = raiz, Equipo = "Android de prueba" };
                using var w = new ReportWriter(opciones);
                w.InicializarVaultAsync().GetAwaiter().GetResult();
                var catalogo = CatalogoDeSenales.Embebido();
                var p = new PuntuadorDeRiesgo(catalogo);

                Titulo("Reportes: aviso de una app instalada");
                var riesgosa = p.Evaluar(Sospechosa("com.falsa.factura") with { Nombre = "Factura Falsa" });
                var e0 = new EstadoDeVigilancia(); var vig = new VigilanteDeInstalaciones(p);
                vig.Revisar(new[] { Normal("com.a") }, e0, 1);
                var a1 = vig.Revisar(new[] { Normal("com.a"), Sospechosa("com.falsa.factura") with { Nombre = "Factura Falsa" } }, e0, 2).Alertas.Single();
                var nota1 = w.EscribirAsync(EventosDeApps.DeAlerta(a1)).GetAwaiter().GetResult();
                var texto1 = File.ReadAllText(nota1.RutaAbsoluta);
                Check(texto1.Contains("tipo: app-instalada"), "la nota lleva el tipo «app-instalada» en su front matter", texto1.Split('\n').Take(12).Aggregate((a, b) => a + " | " + b));
                Check(texto1.Contains("com.falsa.factura") && texto1.Contains("Factura Falsa"), "nombra la app y su paquete");
                Check(texto1.Contains("no un análisis"), "aclara que es una puntuacion, no un analisis");
                Check(!texto1.Contains("malware", StringComparison.OrdinalIgnoreCase), "no dice «malware»");
                Check(texto1.Contains("severidad: alta"), "una app prioritaria se escribe con severidad alta");
                Check(TodoElVault(raiz).Contains("Factura Falsa"), "la app tiene su nota de entidad enlazada");

                Titulo("Reportes: coincidencia con una huella");
                var lista = ListaDeHuellas.Desde("lista-de-prueba.txt", new StringReader(HuellaMala));
                var e1 = new EstadoDeVigilancia(); vig.Revisar(new[] { Normal("com.a") }, e1, 1);
                var a2 = vig.Revisar(new[] { Normal("com.a"), Normal("com.huella") }, e1, 2, HuellaDe("com.huella", HuellaMala), new[] { lista }).Alertas.Single();
                var nota2 = w.EscribirAsync(EventosDeApps.DeAlerta(a2)).GetAwaiter().GetResult();
                var texto2 = File.ReadAllText(nota2.RutaAbsoluta);
                Check(texto2.Contains("huella-coincidente") && texto2.Contains("lista-de-prueba.txt"), "tipo «huella-coincidente» y nombra la lista");
                Check(!texto2.Contains(HuellaMala), "no escribe la huella completa en la nota");

                Titulo("Reportes: la revision completa NO filtra la lista de apps");
                var todas = Enumerable.Range(0, 100).Select(i => Normal("com.privada.app" + i) with { Nombre = "AppPrivada" + i }).ToList();
                todas.Add(Dudosa("com.dudosa.una") with { Nombre = "UnaDudosa" });
                var res = p.EvaluarTodas(todas);
                var nota3 = w.EscribirAsync(EventosDeApps.RevisionDeApps(res)).GetAwaiter().GetResult();
                var texto3 = File.ReadAllText(nota3.RutaAbsoluta);
                Check(texto3.Contains("com.dudosa.una") && texto3.Contains("UnaDudosa"), "lista la app que salio «a revisar»");
                Check(!TodoElVault(raiz).Contains("AppPrivada") && !TodoElVault(raiz).Contains("com.privada"), "ninguna de las 100 apps normales aparece en TODO el vault", "se filtro una app normal");
                Check(texto3.Contains("no un veredicto"), "aclara que es una puntuacion, no un veredicto");

                var limpia = w.EscribirAsync(EventosDeApps.RevisionDeApps(p.EvaluarTodas(todas.Take(100)))).GetAwaiter().GetResult();
                var textoLimpia = File.ReadAllText(limpia.RutaAbsoluta);
                Check(textoLimpia.Contains("Ninguna app tiene señales") && !textoLimpia.Contains("AppPrivada"), "sin apps marcadas: lo dice y no lista ninguna");
                Check(!TodoElVault(raiz).Contains("AppPrivada"), "tras escribir tambien la revision limpia, el vault sigue sin apps normales");

                Titulo("Reportes: el chequeo del equipo");
                var filas = ChequeoDelEquipo.Evaluar(Sano() with
                {
                    BloqueoDePantalla = false, DepuracionUsb = null, Wifi = SeguridadDeWifi.Abierta,
                    AppsQueInstalan = new[] { new AppQueInstala("AppQueInstalaSecreta", "com.secreta.instala", NivelDeRiesgo.Normal) },
                }, Hoy, catalogo);
                var nota4 = w.EscribirAsync(EventosDeApps.DelChequeo(filas)).GetAwaiter().GetResult();
                var texto4 = File.ReadAllText(nota4.RutaAbsoluta);
                Check(texto4.Contains("chequeo-del-equipo") && texto4.Contains("Bloqueo de pantalla") && texto4.Contains("Sin evaluar"), "tabla con una fila por comprobacion y «sin evaluar» donde no hubo dato");
                Check(texto4.Contains("Chequeo del equipo: 2 aviso(s)"), "el titulo cuenta los avisos (bloqueo y Wi-Fi abierta)");
                Check(!TodoElVault(raiz).Contains("AppQueInstalaSecreta") && !TodoElVault(raiz).Contains("com.secreta.instala"), "el chequeo NO escribe los nombres de las apps que instalan otras apps", "se filtro el nombre de una app");
                Check(texto4.Contains("1 con el permiso concedido"), "pero si dice cuantas son");

                Titulo("Reportes: la nota diaria y los nombres");
                var todo = TodoElVault(raiz);
                Check(todo.Contains("[[") && todo.Contains(Path.GetFileNameWithoutExtension(nota1.RutaAbsoluta)), "la nota diaria enlaza el evento");
                Check(Directory.EnumerateFiles(raiz, "*.md", SearchOption.AllDirectories).All(f => Path.GetFileName(f).Length <= opciones.MaxLargoNombreArchivo + 10), "ningun nombre de nota excede el largo permitido");
                Check(NombresDeNotasLimpios(raiz), "los nombres de nota no traen caracteres prohibidos en rutas");
                Check(todo.Contains("Android de prueba"), "cada nota lleva el nombre del equipo");
            }
            finally { try { Directory.Delete(raiz, true); } catch (IOException) { } }
        }

        private static bool NombresDeNotasLimpios(string raiz) =>
            Directory.EnumerateFiles(raiz, "*.md", SearchOption.AllDirectories).All(f => Path.GetFileName(f).IndexOfAny(new[] { '<', '>', ':', '"', '/', '\\', '|', '?', '*' }) < 0);
    }
}
