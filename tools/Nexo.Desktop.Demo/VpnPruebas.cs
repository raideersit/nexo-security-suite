using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Avalonia.Headless;
using Avalonia.Threading;
using Nexo.Modules.Threats.Vpn;
using Nexo.Ui.Desktop;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        private sealed class LectorDeWireGuardFalso : ILectorDeWireGuard
        {
            public EstadoDeWireGuard Valor = new(false, null, null, Array.Empty<TunelInstalado>(), false, null);
            public int Llamadas;
            public EstadoDeWireGuard Leer() { Llamadas++; return Valor; }
        }

        private static readonly string PrivadaVpn = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        private static readonly string PublicaVpn = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        private static string ConfVpn(string allowed = "0.0.0.0/0, ::/0", string extra = "")
            => "[Interface]\nPrivateKey = " + PrivadaVpn + "\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n" + extra + "\n[Peer]\nPublicKey = " + PublicaVpn +
               "\nAllowedIPs = " + allowed + "\nEndpoint = 149.88.104.1:51820\n";

        private static MemoryStream Flujo(string t) => new(Encoding.UTF8.GetBytes(t));

        /// <summary>Todo el texto que expone el modelo (propiedades y listas), para buscar en el lo que no debe estar.</summary>
        private static string TodoElTexto(object modelo)
        {
            var sb = new StringBuilder();
            foreach (var p in modelo.GetType().GetProperties().Where(p => p.GetIndexParameters().Length == 0))
            {
                object? v = p.GetValue(modelo);
                if (v is string s) sb.Append(s).Append('\n');
                else if (v is IEnumerable e and not string) foreach (object? x in e) sb.Append(x).Append('\n');
            }
            return sb.ToString();
        }

        public static void ProbarVpn()
        {
            Console.WriteLine("Pestaña VPN (solo lectura)");
            var f = new LectorDeWireGuardFalso();
            var r = new RastroFalso();
            var m = new VpnModelo(f) { Rastro = r };
            Check(m.EstadoTitulo == "Sin leer todavía" && f.Llamadas == 0, "al crearla no lee nada");
            Esperar(m.ActualizarAsync());
            Check(m.EstadoTitulo == "WireGuard no está instalado" && m.EstadoDetalle.Contains("winget install WireGuard.WireGuard") && m.EstadoDetalle.Contains("no lo instala solo"),
                "sin WireGuard: lo dice, con cómo instalarlo y que Nexo no lo instala", m.EstadoDetalle);
            f.Valor = new EstadoDeWireGuard(true, "1.1.1", @"C:\Program Files\WireGuard\wireguard.exe",
                new[] { new TunelInstalado("proton-CL-12", EstadoDeTunel.Activo), new TunelInstalado("trabajo", EstadoDeTunel.Detenido) }, true, null);
            Esperar(m.ActualizarAsync());
            Check(m.EstadoTitulo == "WireGuard 1.1.1 instalado: 1 túnel activo" && m.Tuneles.Count == 2 && m.Tuneles[0].Estado.StartsWith("Activo") && m.EstadoDetalle.Contains("no se puede comprobar"),
                "con túneles: cuántos activos, la lista, y que «activo» no prueba que el servidor responda", m.EstadoTitulo + " / " + m.EstadoDetalle);
            Check(m.Tuneles.All(t => !ReferenceEquals(t.Color, Colores.De(Indicador.Correcto))), "un túnel activo NO se pinta de verde (no se sabe si el servidor responde)");
            f.Valor = EstadoDeWireGuard.NoSePudo("no se pudo leer la lista de servicios de Windows (Win32Exception)");
            Esperar(m.ActualizarAsync());
            Check(m.EstadoTitulo.StartsWith("No se pudo saber") && m.Tuneles.Count == 0, "si no se pudo leer, lo dice (no «no instalado»)", m.EstadoTitulo);

            Check(m.ArchivoTitulo == "Ningún archivo revisado", "sin archivo: lo dice");
            Esperar(m.RevisarArchivoAsync(Flujo(ConfVpn()), "proton-CL-12.conf"));
            Check(m.ArchivoIndicador == Indicador.Correcto && m.ArchivoTitulo == "«proton-CL-12.conf» está bien" && m.ArchivoDetalle.Contains("«proton-CL-12»") && !m.HayErrores,
                "un archivo bueno: verde (se leyó entero y no tiene problemas), con el nombre que tendrá el túnel", m.ArchivoTitulo + " / " + m.ArchivoDetalle);
            Check(r.Avisos.Count == 1 && r.Avisos[0].Tipo == "vpn.revision" && r.Avisos[0].Campos.Keys.OrderBy(k => k).SequenceEqual(new[] { "completa", "hallazgos", "maxima" }) && !Todo(r).Contains("proton"),
                "el rastro: solo conteos (ni el nombre del túnel ni el servidor)", Todo(r));
            Esperar(m.RevisarArchivoAsync(Flujo(ConfVpn(allowed: "0.0.0.0/0")), "solo-v4.conf"));
            Check(m.ArchivoIndicador == Indicador.Atencion && m.Hallazgos.Any(h => h.Titulo.Contains("IPv6")), "solo IPv4: amarillo, con el aviso de fuga IPv6", m.ArchivoTitulo);
            Esperar(m.RevisarArchivoAsync(Flujo(ConfVpn(extra: "PostUp = powershell -c calc\n")), "raro.conf"));
            Check(m.ArchivoIndicador == Indicador.Alerta && m.ArchivoTitulo.StartsWith("Cuidado"), "con comandos PostUp: rojo", m.ArchivoTitulo);
            Esperar(m.RevisarArchivoAsync(Flujo(ConfVpn(extra: "SaveConfig = true\n")), "malo.conf"));
            Check(m.ArchivoTitulo == "WireGuard rechazará «malo.conf»" && m.HayErrores && m.Errores[0].Contains("saveconfig") && !m.HayHallazgos,
                "con una clave desconocida: «WireGuard rechazará», con el error y su línea", m.ArchivoTitulo + " / " + string.Join(" | ", m.Errores));
            Esperar(m.RevisarArchivoAsync(Flujo(ConfVpn()), "mi vpn.conf"));
            Check(m.ArchivoIndicador == Indicador.Atencion && m.ArchivoTitulo.Contains("el nombre no") && m.ArchivoDetalle.Contains("Renombra"), "contenido bien y nombre con espacios: amarillo, renombrar", m.ArchivoTitulo);
            Esperar(m.RevisarArchivoAsync(Flujo(new string('#', ParserDeWireGuard.MaximoDeCaracteres + 10)), "enorme.conf"));
            Check(m.ArchivoTitulo.StartsWith("No se pudo revisar") && m.ArchivoDetalle.Contains("demasiado grande"), "un archivo de más de 64 KB: no se revisa y se dice", m.ArchivoDetalle);

            Esperar(m.RevisarArchivoAsync(Flujo(ConfVpn(extra: "PostUp = x\n")), "proton-CL-12.conf"));
            string todo = TodoElTexto(m);
            Check(todo.Contains("149.88.104.1") && !todo.Contains(PrivadaVpn), "la clave privada no aparece en NINGUNA propiedad del modelo (el servidor sí)");
            m.OlvidarArchivo();
            Check(m.ArchivoTitulo == "Ningún archivo revisado" && !m.HayHallazgos, "«olvidar» el archivo lo quita de la vista");
            Check(f.Llamadas == 3, "revisar archivos no vuelve a leer los servicios", f.Llamadas.ToString());
        }

        private static void ProbarVentanaDeVpn(MainWindow w, VpnModelo m, LectorDeWireGuardFalso f, string? captura)
        {
            w.Pestanas.SelectedIndex = 10;
            Dispatcher.UIThread.RunJobs();
            Esperar(m.ActualizarAsync());
            Dispatcher.UIThread.RunJobs();
            Check(w.Pestanas.ItemCount == 11 && f.Llamadas >= 1 && w.TituloDeVpn.Text == "WireGuard no está instalado", "pestaña VPN: al entrar lee el estado (solo lectura)", w.TituloDeVpn.Text);
            Check(w.BotonRevisarConf.IsEnabled && w.BotonActualizarVpn.IsEnabled && w.TituloDeArchivoVpn.Text == "Ningún archivo revisado", "los dos botones y el título del archivo");
            Esperar(m.RevisarArchivoAsync(Flujo(ConfVpn(extra: "SaveConfig = true\n")), "malo.conf"));
            Dispatcher.UIThread.RunJobs();
            Check(w.TituloDeArchivoVpn.Text == "WireGuard rechazará «malo.conf»" && w.ListaDeErroresVpn.ItemCount == 1, "un archivo con errores se ve en la pestaña, con su lista de errores", w.TituloDeArchivoVpn.Text);
            Esperar(m.RevisarArchivoAsync(Flujo(ConfVpn(allowed: "0.0.0.0/0")), "proton-CL-12.conf"));
            Dispatcher.UIThread.RunJobs();
            if (captura is not null)
            {
                Avalonia.Headless.AvaloniaHeadlessPlatform.ForceRenderTimerTick();
                string ruta = Path.ChangeExtension(captura, null) + "-vpn.png";
                w.CaptureRenderedFrame()?.Save(ruta);
                Console.WriteLine("           captura: " + ruta);
            }
        }
    }
}
