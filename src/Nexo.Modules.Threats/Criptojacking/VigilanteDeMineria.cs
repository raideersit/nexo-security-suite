using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Criptojacking
{
    // =====================================================================================================
    //  ANTI-CRIPTOJACKING (Salida 0, fila 4). Núcleo portable: no lee procesos ni red, recibe «muestras».
    //
    //  Heurística combinada, como dice el plan: (1) un proceso que no está en primer plano y gasta mucha CPU de forma SOSTENIDA,
    //  y (2) conexiones a servidores de minería conocidos (lista pública gratuita de IP, tipo CoinBlockerLists) o a puertos que usa
    //  el protocolo Stratum. Ninguna de las dos señales es una prueba sola:
    //   - mucha CPU sostenida también la gastan compiladores, renderizadores, antivirus y juegos: sola es un hallazgo BAJO (o Medio si el
    //     programa vive en una carpeta poco habitual: Temp, Descargas...);
    //   - un puerto «de minería» sin CPU no es nada (3333, 4444, 5555... los usa mucho software legítimo);
    //   - una IP de la lista puede ser compartida (CDN, alojamiento): sin CPU alta es ALTA pero se dice que puede ser un falso positivo;
    //   - CPU sostenida + conexión a un pool conocido = CRÍTICA (las dos señales coinciden).
    //
    //  Lo que NO hace: no detiene ni borra nada (decide la persona), no mira la GPU, no mira dentro de la memoria (YARA sobre procesos
    //  queda para otro paso) y no ve mineros que usen un proxy o un dominio nuevo que no esté en la lista.
    //  Lo que no se pudo leer es «no evaluado», nunca «sin problemas».
    // =====================================================================================================

    public sealed record ProcesoMuestreado(int Pid, string Nombre, string? Ruta, double CpuPorCiento, bool EnPrimerPlano);

    /// <summary>Una conexión TCP de un proceso. <c>Host</c> si se sabe a qué nombre corresponde la IP (resuelto de la lista).</summary>
    public sealed record ConexionDeProceso(int Pid, string IpRemota, int PuertoRemoto, string? Host = null);

    /// <summary>Lo que se vio en un instante. «Leída» false = no se pudo leer (no es «ninguno»).</summary>
    public sealed record MuestraDeMineria(DateTimeOffset Cuando, IReadOnlyList<ProcesoMuestreado> Procesos, bool ProcesosLeidos,
                                          IReadOnlyList<ConexionDeProceso> Conexiones, bool ConexionesLeidas, string? MotivoProcesos = null, string? MotivoConexiones = null);

    /// <summary>Servidores de minería conocidos: IP exactas y, si se resolvieron, los nombres. Se llena desde una lista pública.</summary>
    public sealed class ListaDePools
    {
        public static readonly ListaDePools Vacia = new(Array.Empty<string>(), Array.Empty<string>());

        private readonly HashSet<string> _ips;
        private readonly HashSet<string> _dominios;

        public ListaDePools(IEnumerable<string> ips, IEnumerable<string> dominios)
        {
            _ips = new HashSet<string>(ips, StringComparer.OrdinalIgnoreCase);
            _dominios = new HashSet<string>(dominios, StringComparer.OrdinalIgnoreCase);
        }

        public int Ips => _ips.Count;
        public int Dominios => _dominios.Count;
        public bool EsPool(string ip) => _ips.Contains(Canonica(ip));
        public bool EsDominioPool(string host) => _dominios.Contains(host.Trim().TrimEnd('.').ToLowerInvariant());
        public IReadOnlyCollection<string> ListaDeDominios => _dominios;

        /// <summary>IPv4/IPv6 en forma canónica (y una IPv4 mapeada en IPv6 como IPv4); lo que no es una IP, tal cual.</summary>
        public static string Canonica(string ip)
        {
            if (!IPAddress.TryParse(ip.Trim(), out IPAddress? a)) return ip.Trim();
            if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
            return a.ToString();
        }

        /// <summary>
        /// Lee una lista de texto: una entrada por línea (IP o dominio), con «#» de comentario, y también el formato de «hosts» («0.0.0.0 pool.ejemplo»).
        /// Lo que no se entiende se cuenta como ignorado: no se inventa una entrada.
        /// </summary>
        public static (ListaDePools Lista, int Ignoradas) Leer(string? texto)
        {
            var ips = new List<string>(); var dominios = new List<string>(); int ignoradas = 0;
            foreach (string cruda in (texto ?? "").Split('\n'))
            {
                string l = cruda.Trim();
                int c = l.IndexOf('#');
                if (c >= 0) l = l.Substring(0, c).Trim();
                if (l.Length == 0) continue;
                string[] partes = l.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                // Formato hosts: «0.0.0.0 dominio» o «127.0.0.1 dominio»: vale el segundo campo.
                string entrada = partes.Length == 2 && (partes[0] == "0.0.0.0" || partes[0] == "127.0.0.1") ? partes[1] : partes.Length == 1 ? partes[0] : "";
                if (entrada.Length == 0) { ignoradas++; continue; }
                if (EsIp(entrada)) { string ip = Canonica(entrada); if (ip != "0.0.0.0" && ip != "127.0.0.1") ips.Add(ip); else ignoradas++; }
                else if (EsDominio(entrada)) dominios.Add(entrada.TrimEnd('.').ToLowerInvariant());
                else ignoradas++;
            }
            return (new ListaDePools(ips, dominios), ignoradas);
        }

        /// <summary>Una IP escrita completa. .NET acepta «1.2.3» como 1.2.0.3: aquí un IPv4 exige sus cuatro números.</summary>
        private static bool EsIp(string s)
            => IPAddress.TryParse(s, out IPAddress? a) && (a.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || s.Split('.').Length == 4);

        private static bool EsDominio(string s)
            => s.Length is > 3 and <= 253 && s.Contains('.') && !s.StartsWith('.') && s.All(ch => char.IsAsciiLetterOrDigit(ch) || ch == '.' || ch == '-' || ch == '_')
               && !s.TrimEnd('.').Split('.').Last().All(char.IsAsciiDigit); // la última etiqueta no es solo números (así «1.2.3» no pasa por dominio)
    }

    public sealed class VigilanteDeMineria
    {
        /// <summary>CPU (del total de la máquina) a partir de la cual una muestra cuenta como «alta».</summary>
        public const double UmbralDeCpu = 60;
        /// <summary>Cuántas muestras seguidas por encima del umbral hacen «sostenida» (con una muestra cada 30 s, unos 4 minutos).</summary>
        public const int MuestrasSostenidas = 8;

        /// <summary>Puertos que usa el protocolo Stratum de varios pools. Solos no prueban nada: se usan con CPU alta.</summary>
        public static readonly IReadOnlySet<int> PuertosDeMineria = new HashSet<int> { 3333, 4444, 5555, 7777, 14433, 14444, 45560, 45700 };

        /// <summary>Procesos que gastan CPU a ratos por su trabajo (análisis de Defender, instalaciones, indexado): no se evalúan, y se dice.</summary>
        public static readonly IReadOnlySet<string> ProcesosDelSistema = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "system", "idle", "system idle process", "msmpeng.exe", "msmpeng", "tiworker.exe", "tiworker", "trustedinstaller.exe", "searchindexer.exe", "searchindexer",
            "mpcmdrun.exe", "wuauclt.exe", "dwm.exe", "dwm", "audiodg.exe", "memory compression", "registry"
        };

        private static readonly string[] CarpetasPocoHabituales =
            { @"\appdata\local\temp\", @"\windows\temp\", @"\temp\", @"\downloads\", @"\descargas\", @"\$recycle.bin\", @"\users\public\" };

        private readonly ListaDePools _lista;
        private readonly Dictionary<string, int> _rachas = new(StringComparer.OrdinalIgnoreCase);

        public VigilanteDeMineria(ListaDePools lista) => _lista = lista;

        /// <summary>La clave de un proceso entre muestras: PID + nombre (un PID reutilizado por otro programa empieza de cero).</summary>
        private static string Clave(ProcesoMuestreado p) => p.Pid + "|" + p.Nombre;

        /// <summary>
        /// Incorpora una muestra y evalúa. Las rachas de CPU alta se mantienen entre llamadas; un proceso que baja del umbral, pasa a primer plano
        /// o desaparece pierde su racha.
        /// </summary>
        public ResultadoDeAnalisis Evaluar(MuestraDeMineria m)
        {
            var hallazgos = new List<HallazgoDeSistema>();
            var no = new List<string>();

            if (!m.ProcesosLeidos) no.Add("procesos: " + (m.MotivoProcesos ?? "no se pudo leer el uso de CPU"));
            if (!m.ConexionesLeidas) no.Add("conexiones: " + (m.MotivoConexiones ?? "no se pudo leer las conexiones de red"));
            if (_lista.Ips == 0) no.Add("lista de servidores de minería: vacía (sin ella solo se mira la CPU y los puertos)");

            var vivos = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var porPid = m.Conexiones.GroupBy(c => c.Pid).ToDictionary(g => g.Key, g => g.ToList());

            if (m.ProcesosLeidos)
            {
                foreach (ProcesoMuestreado p in m.Procesos)
                {
                    if (ProcesosDelSistema.Contains(p.Nombre)) continue;
                    string k = Clave(p);
                    if (!p.EnPrimerPlano && p.CpuPorCiento >= UmbralDeCpu) { _rachas[k] = _rachas.GetValueOrDefault(k) + 1; vivos.Add(k); }
                    else _rachas.Remove(k);
                }
                foreach (string k in _rachas.Keys.Where(k => !vivos.Contains(k)).ToList()) _rachas.Remove(k);
            }

            // Conexiones a servidores conocidos: se evalúan por proceso, con o sin CPU.
            var conPool = new HashSet<int>();
            if (m.ConexionesLeidas)
            {
                foreach (var (pid, conexiones) in porPid)
                {
                    ConexionDeProceso? pool = conexiones.FirstOrDefault(c => _lista.EsPool(c.IpRemota) || (c.Host is { } h && _lista.EsDominioPool(h)));
                    if (pool is null) continue;
                    conPool.Add(pid);
                    ProcesoMuestreado? p = m.Procesos.FirstOrDefault(x => x.Pid == pid);
                    bool sostenida = p is not null && _rachas.GetValueOrDefault(Clave(p)) >= MuestrasSostenidas;
                    string quien = p is null ? "El proceso " + pid : "«" + p.Nombre + "»";
                    string destino = (pool.Host ?? pool.IpRemota) + ":" + pool.PuertoRemoto;
                    if (sostenida)
                        hallazgos.Add(new HallazgoDeSistema("MINERIA-POOL-Y-CPU", Severidad.Critica, quien + " gasta mucha CPU y está conectado a un servidor de minería conocido",
                            quien + " lleva varios minutos usando " + p!.CpuPorCiento.ToString("0") + " % de la CPU sin estar en primer plano y tiene una conexión a " + destino + ", que figura en la lista de servidores de minería. Las dos señales coinciden.",
                            "Si no reconoces el programa, ciérralo desde el Administrador de tareas, mira dónde está (" + (p.Ruta ?? "ruta desconocida") + ") y analízalo con Nexo. Nexo no lo detiene por ti.", p.Nombre));
                    else
                        hallazgos.Add(new HallazgoDeSistema("MINERIA-POOL", Severidad.Alta, quien + " está conectado a un servidor de minería conocido",
                            quien + " tiene una conexión a " + destino + ", que figura en la lista de servidores de minería. Puede ser un falso positivo: algunas direcciones de la lista son compartidas con servicios legítimos. No se vio un uso de CPU sostenido.",
                            "Comprueba qué programa es" + (p?.Ruta is { } r ? " (" + r + ")" : "") + " y si lo instalaste tú.", p?.Nombre ?? pid.ToString()));
                }
            }

            // CPU sostenida: sola es una señal débil; con un puerto de Stratum sube.
            if (m.ProcesosLeidos)
            {
                foreach (ProcesoMuestreado p in m.Procesos)
                {
                    if (conPool.Contains(p.Pid)) continue; // ya cubierto arriba
                    if (_rachas.GetValueOrDefault(Clave(p)) < MuestrasSostenidas) continue;
                    ConexionDeProceso? stratum = porPid.TryGetValue(p.Pid, out var cs) ? cs.FirstOrDefault(c => PuertosDeMineria.Contains(c.PuertoRemoto)) : null;
                    bool rara = EnCarpetaPocoHabitual(p.Ruta);
                    if (stratum is not null)
                        hallazgos.Add(new HallazgoDeSistema("MINERIA-CPU-Y-PUERTO", Severidad.Alta, "«" + p.Nombre + "» gasta mucha CPU y usa un puerto típico de minería",
                            "«" + p.Nombre + "» lleva varios minutos usando " + p.CpuPorCiento.ToString("0") + " % de la CPU sin estar en primer plano y tiene una conexión al puerto " + stratum.PuertoRemoto + " de " + stratum.IpRemota
                            + ", un puerto que usan muchos pools de minería (pero también otros programas). Esa dirección no está en la lista de servidores conocidos.",
                            "Comprueba qué programa es (" + (p.Ruta ?? "ruta desconocida") + ") y si lo instalaste tú.", p.Nombre));
                    else
                        hallazgos.Add(new HallazgoDeSistema(rara ? "MINERIA-CPU-RUTA-RARA" : "MINERIA-CPU", rara ? Severidad.Media : Severidad.Baja,
                            "«" + p.Nombre + "» gasta mucha CPU en segundo plano" + (rara ? " y vive en una carpeta poco habitual" : ""),
                            "«" + p.Nombre + "» lleva varios minutos usando " + p.CpuPorCiento.ToString("0") + " % de la CPU sin estar en primer plano" + (rara ? ", desde " + p.Ruta : "")
                            + ". Compiladores, renderizadores, copias de seguridad y juegos abiertos también lo hacen: no es una prueba de minería.",
                            rara ? "Mira qué programa es y si lo instalaste tú." : "Si no esperabas ese consumo, mira qué programa es en el Administrador de tareas.", p.Nombre));
                }
            }

            return new ResultadoDeAnalisis(hallazgos, no);
        }

        public static bool EnCarpetaPocoHabitual(string? ruta)
        {
            if (string.IsNullOrEmpty(ruta)) return false;
            string r = ruta.Replace('/', '\\').ToLowerInvariant();
            return CarpetasPocoHabituales.Any(c => r.Contains(c));
        }

        /// <summary>Cuántos procesos llevan racha de CPU alta (lo usan las pruebas).</summary>
        public int ProcesosEnRacha => _rachas.Count;
    }
}
