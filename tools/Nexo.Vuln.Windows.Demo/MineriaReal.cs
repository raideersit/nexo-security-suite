using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Nexo.Modules.Threats.Criptojacking;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Modules.Threats.Windows;
using Nexo.Native.Network;

namespace Nexo.Vuln.Windows.Demo
{
    internal static partial class Program
    {
        /// <summary>Lectores de anti-criptojacking contra Windows REAL (sin administrador): conexiones por PID, CPU por proceso y primer plano.</summary>
        public static void ProbarMineriaReal()
        {
            Console.WriteLine("14. Lectores de anti-criptojacking sobre Windows REAL (sin administrador)");
            Check(TablaTcp.PuertoDeRed(0x5000) == 80 && TablaTcp.PuertoDeRed(unchecked((int)0xFFFF5000)) == 80, "el puerto se lee en orden de red y solo de los 2 bytes bajos");

            // --- Conexiones por PID: una conexion que creamos nosotros debe aparecer con nuestro PID y el puerto exacto ---
            var escucha = new TcpListener(IPAddress.Loopback, 0);
            escucha.Start();
            int puerto = ((IPEndPoint)escucha.LocalEndpoint).Port;
            using var cliente = new TcpClient();
            cliente.Connect(IPAddress.Loopback, puerto);
            using var servidor = escucha.AcceptTcpClient();
            var escucha6 = new TcpListener(IPAddress.IPv6Loopback, 0);
            escucha6.Start();
            int puerto6 = ((IPEndPoint)escucha6.LocalEndpoint).Port;
            using var cliente6 = new TcpClient(AddressFamily.InterNetworkV6);
            cliente6.Connect(IPAddress.IPv6Loopback, puerto6);
            using var servidor6 = escucha6.AcceptTcpClient();
            try
            {
                LecturaTcp t = TablaTcp.Leer();
                Check(t.Conexiones.Any(c => c.Pid == Environment.ProcessId && c.IpRemota == "::1" && c.PuertoRemoto == puerto6), "ve tambien una conexion IPv6 propia (::1, puerto " + puerto6 + ")");
                Check(t.Correcta, "TablaTcp.Leer funciona", "error " + t.CodigoDeError);
                int yo = Environment.ProcessId;
                Check(t.Conexiones.Any(c => c.Pid == yo && c.IpRemota == "127.0.0.1" && c.PuertoRemoto == puerto), "ve la conexion que acabamos de abrir (nuestro PID, 127.0.0.1, puerto " + puerto + ")");
                Check(t.Conexiones.Count(c => c.Pid == yo && c.PuertoRemoto == puerto) == 1, "esa conexion sale una sola vez (el lado servidor tiene otro puerto remoto)");

                // Cruce con netstat: cada conexion ESTABLISHED de netstat debe estar en nuestra lectura (con el mismo PID).
                var netstat = Netstat();
                int faltan = 0, vistas = 0;
                foreach (var (ip, p, pid) in netstat)
                {
                    vistas++;
                    if (!t.Conexiones.Any(c => c.Pid == pid && c.PuertoRemoto == p && string.Equals(Normal(c.IpRemota), Normal(ip), StringComparison.OrdinalIgnoreCase))) faltan++;
                }
                Console.WriteLine("      INFO: netstat ve " + vistas + " conexiones establecidas; Nexo ve " + t.Conexiones.Count);
                Check(Math.Abs(t.Conexiones.Count - vistas) <= Math.Max(3, vistas / 10), "Nexo no ve de mas: solo cuenta las ESTABLECIDAS (netstat " + vistas + ", Nexo " + t.Conexiones.Count + ")");
                Check(vistas > 0 && faltan <= Math.Max(2, vistas / 20), "las conexiones de netstat estan en la lectura de Nexo (tolera cambios entre las dos lecturas)", faltan + " de " + vistas + " faltan");
            }
            finally { escucha.Stop(); escucha6.Stop(); }

            // --- CPU por proceso: un hijo que gira sin parar debe verse con CPU alta; uno quieto, no ---
            using Process? ocupado = Process.Start(new ProcessStartInfo("powershell.exe", "-NoProfile -Command \"while($true){}\"") { CreateNoWindow = true, UseShellExecute = false });
            try
            {
                Thread.Sleep(3000); // que PowerShell termine de arrancar y ya gire cuando se toma la primera muestra
                var lector = new LectorDeMineriaWindows();
                MuestraDeMineria m0 = lector.Tomar();
                Check(m0.ProcesosLeidos && m0.ConexionesLeidas, "la primera muestra lee procesos y conexiones", m0.MotivoProcesos + " / " + m0.MotivoConexiones);
                Check(m0.Procesos.All(p => p.CpuPorCiento == 0), "la primera muestra no inventa CPU (no hay con que comparar)");
                Thread.Sleep(4000);
                MuestraDeMineria m1 = lector.Tomar();
                var hijo = m1.Procesos.FirstOrDefault(p => ocupado != null && p.Pid == ocupado.Id);
                double esperado = 100.0 / Environment.ProcessorCount; // un hilo ocupado al 100 % de un nucleo
                Console.WriteLine("      INFO: " + Environment.ProcessorCount + " nucleos; el hijo ocupado marca " + (hijo?.CpuPorCiento.ToString("F1") ?? "no visto") + " % (esperado ~" + esperado.ToString("F1") + ")");
                Check(hijo is not null && hijo.CpuPorCiento > esperado * 0.6 && hijo.CpuPorCiento < esperado * 1.5, "un proceso que gira sin parar se ve con ~1 nucleo de CPU (ni mas ni menos)");
                Check(m1.Procesos.Count(p => p.CpuPorCiento > 0) >= 1 && m1.Procesos.All(p => p.CpuPorCiento is >= 0 and <= 100), "todos los porcentajes estan entre 0 y 100");
                int fg = Nexo.Native.Shell.VentanaActiva.PidEnPrimerPlano();
                Console.WriteLine("      INFO: proceso en primer plano segun Windows: " + (fg > 0 ? fg + " (" + (m1.Procesos.FirstOrDefault(p => p.Pid == fg)?.Nombre ?? "no visible") + ")" : "ninguno"));
                Check(fg <= 0 || !m1.Procesos.Any(p => p.Pid == fg) || m1.Procesos.Single(p => p.EnPrimerPlano).Pid == fg, "el proceso marcado en primer plano es el que dice Windows");
                Check(m1.Procesos.Count(p => p.EnPrimerPlano) <= 1, "como mucho un proceso esta en primer plano");
                Check(m1.Procesos.Any(p => p.Pid == Environment.ProcessId && p.Ruta is not null), "lee la ruta de un proceso propio");

                // --- De punta a punta: el vigilante con lectores reales no acusa a nadie tras 2 muestras ---
                var v = new VigilanteDeMineria(ListaDePools.Vacia);
                v.Evaluar(m0);
                ResultadoDeAnalisis r = v.Evaluar(m1);
                Check(r.Hallazgos.Count == 0, "con 2 muestras (menos de la racha de 8) no hay hallazgos aunque haya un proceso ocupado", string.Join("; ", r.Hallazgos.Select(h => h.Titulo)));
            }
            finally { try { ocupado?.Kill(true); } catch { } }
        }

        private static string Normal(string ip) => IPAddress.TryParse(ip, out var a) ? a.ToString() : ip;

        private static System.Collections.Generic.List<(string Ip, int Puerto, int Pid)> Netstat()
        {
            var lista = new System.Collections.Generic.List<(string, int, int)>();
            var psi = new ProcessStartInfo("netstat.exe", "-ano -p tcp") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using Process p = Process.Start(psi)!;
            string salida = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            // Version v6 aparte
            psi = new ProcessStartInfo("netstat.exe", "-ano -p tcpv6") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using (Process p6 = Process.Start(psi)!) { salida += "\n" + p6.StandardOutput.ReadToEnd(); p6.WaitForExit(); }
            foreach (string linea in salida.Split('\n'))
            {
                string[] c = linea.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (c.Length < 5 || c[0] != "TCP") continue;
                if (!c[3].StartsWith("ESTABL", StringComparison.OrdinalIgnoreCase)) continue; // ESTABLISHED / ESTABLECIDO
                string remoto = c[2];
                int i = remoto.LastIndexOf(':');
                if (i < 0 || !int.TryParse(remoto[(i + 1)..], out int puerto) || !int.TryParse(c[4].Trim(), out int pid)) continue;
                string ip = remoto[..i].Trim('[', ']');
                int pc = ip.IndexOf('%'); if (pc >= 0) ip = ip[..pc];
                lista.Add((ip, puerto, pid));
            }
            return lista;
        }
    }
}
