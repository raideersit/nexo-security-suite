using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Enlaces;
using Nexo.Modules.Threats.Vpn;

namespace Nexo.Vpn.Demo
{
    internal static class ExtensionesDePrueba
    {
        /// <summary>El unico rechazo; si hay cero o varios, un texto que hace FALLAR la comprobacion (sin tirar el programa).</summary>
        public static string Unico(this IReadOnlyList<string> l) => l.Count == 1 ? l[0] : "(" + l.Count + " rechazos)";
    }

    internal static partial class Program
    {
        internal sealed class EjecutorFalso : IEjecutorDeWireGuard
        {
            public readonly HashSet<string> DeNexo = new(StringComparer.OrdinalIgnoreCase);
            public readonly List<string> Llamadas = new();
            public string? ConfRecibida;
            public bool Falla;
            public string Carpeta => @"C:\ProgramData\Nexo\vpn";
            public bool EsDeNexo(string tunel) => DeNexo.Contains(tunel);
            public Task<ResultadoDeVpn> ConectarAsync(string tunel, string conf, CancellationToken ct)
            {
                Llamadas.Add("conectar:" + tunel); ConfRecibida = conf;
                if (Falla) return Task.FromResult(new ResultadoDeVpn(false, "WireGuard no pudo instalar el túnel (código 1)"));
                DeNexo.Add(tunel);
                return Task.FromResult(new ResultadoDeVpn(true, "Túnel «" + tunel + "» instalado y en marcha."));
            }
            public Task<ResultadoDeVpn> DesconectarAsync(string tunel, CancellationToken ct)
            {
                Llamadas.Add("desconectar:" + tunel);
                DeNexo.Remove(tunel);
                return Task.FromResult(new ResultadoDeVpn(true, "Túnel «" + tunel + "» desconectado y quitado."));
            }
        }

        private static EstadoDeWireGuard Instalado(params TunelInstalado[] t) => new(true, "1.1.1", @"C:\Program Files\WireGuard\wireguard.exe", t, true, null);
        private static readonly EstadoDeWireGuard SinWireGuard = new(false, null, null, Array.Empty<TunelInstalado>(), false, null);

        private static void ProbarPlanes()
        {
            Console.WriteLine("7. Planes para conectar y desconectar (paso 2)");
            var ej = new EjecutorFalso();
            string Rech(PlanDeVpn p) => string.Join(" | ", p.Rechazos);

            PlanDeVpn bien = PlanificadorDeVpn.PrepararConexion(Conf(), "proton-CL-12.conf", Instalado(), ej);
            Check(bien.HayCambios && bien.Tunel == "proton-CL-12" && bien.Cambios.Count == 3 && bien.Advertencias.Count == 0, "un archivo bueno: 3 cambios, sin avisos", Rech(bien));
            Check(bien.Cambios[0].Contains("solo pueden leer SYSTEM y los administradores") && bien.Cambios[1].Contains("WireGuardTunnel$proton-CL-12") && bien.Cambios[2].Contains("149.88.104.1:51820") && bien.Cambios[2].Contains("lo verá todo"),
                "la vista previa dice dónde se guarda, qué servicio se crea y por dónde pasará el tráfico", string.Join(" | ", bien.Cambios));
            Check(!bien.Describir().Contains(Privada) && bien.ConfParaEjecutar() == Conf(), "la descripción NO lleva la clave privada; el texto solo queda para ejecutar");

            Check(PlanificadorDeVpn.PrepararConexion(Conf(), "x.conf", SinWireGuard, ej).Rechazos.Unico().Contains("no está instalado"), "sin WireGuard: rechazado");
            Check(PlanificadorDeVpn.PrepararConexion(Conf(), "x.conf", EstadoDeWireGuard.NoSePudo("fallo"), ej).Rechazos.Unico().Contains("no se pudo saber"), "sin saber el estado: rechazado");
            PlanDeVpn mala = PlanificadorDeVpn.PrepararConexion(Conf(extraInterfaz: "SaveConfig = true\n"), "x.conf", Instalado(), ej);
            Check(!mala.HayCambios && mala.Rechazos.Unico().StartsWith("WireGuard rechazaría el archivo") && mala.ConfParaEjecutar() is null, "un archivo que WireGuard rechazaría: rechazado, y el texto no se guarda en el plan", Rech(mala));
            Check(PlanificadorDeVpn.PrepararConexion(Conf(), "mi vpn.conf", Instalado(), ej).Rechazos.Unico().Contains("renombra"), "un nombre inválido: rechazado (renombrar)");
            PlanDeVpn scripts = PlanificadorDeVpn.PrepararConexion(Conf(extraInterfaz: "PostUp = powershell -c calc\n"), "x.conf", Instalado(), ej);
            Check(!scripts.HayCambios && scripts.Rechazos.Unico().Contains("Nexo no instala archivos con comandos"), "con comandos PostUp: rechazado (una sola vez, no también como «Alta»)", Rech(scripts));
            var lista = new ListasDePhishing(ParserDeListas.LeerPhishingArmy(ArmyCon("vpn-gratis-malo.example"), DateTimeOffset.UtcNow).Lista, null);
            PlanDeVpn enLista = PlanificadorDeVpn.PrepararConexion(Conf(endpoint: "nodo.vpn-gratis-malo.example:51820"), "x.conf", Instalado(), ej, lista);
            Check(!enLista.HayCambios && enLista.Rechazos.Unico().Contains("lista de phishing"), "servidor en la lista de phishing: rechazado", Rech(enLista));
            Check(PlanificadorDeVpn.PrepararConexion(Conf(), "Proton-cl-12.conf", Instalado(new TunelInstalado("proton-CL-12", EstadoDeTunel.Detenido)), ej).Rechazos.Unico().Contains("ya hay un túnel"),
                "ya existe un túnel con ese nombre (sin distinguir mayúsculas): rechazado");
            PlanDeVpn avisos = PlanificadorDeVpn.PrepararConexion(Conf(allowed: "0.0.0.0/0"), "nuevo.conf", Instalado(new TunelInstalado("trabajo", EstadoDeTunel.Activo)), ej);
            Check(avisos.HayCambios && avisos.Advertencias.Any(a => a.Contains("IPv6")) && avisos.Advertencias.Any(a => a.Contains("«trabajo»")), "lo Media no impide conectar, pero se avisa (y otro túnel activo también)", string.Join(" | ", avisos.Advertencias));
            PlanDeVpn parcial = PlanificadorDeVpn.PrepararConexion(Conf(allowed: "10.0.0.0/8"), "trabajo2.conf", Instalado(), ej);
            Check(parcial.Cambios[2].StartsWith("solo el tráfico hacia 10.0.0.0/8"), "un túnel parcial lo dice en la vista previa", parcial.Cambios[2]);

            ej.DeNexo.Add("mio");
            var conTuneles = Instalado(new TunelInstalado("mio", EstadoDeTunel.Activo), new TunelInstalado("ajeno", EstadoDeTunel.Activo));
            PlanDeVpn des = PlanificadorDeVpn.PrepararDesconexion("mio", conTuneles, ej);
            Check(des.HayCambios && des.Cambios.Count == 2 && des.Cambios[0].Contains("volverá a salir directo"), "desconectar uno de Nexo: 2 cambios", Rech(des));
            Check(PlanificadorDeVpn.PrepararDesconexion("ajeno", conTuneles, ej).Rechazos.Unico().Contains("no lo instaló Nexo"), "uno que no instaló Nexo: rechazado (se hace desde WireGuard)");
            Check(PlanificadorDeVpn.PrepararDesconexion("otro", conTuneles, ej).Rechazos.Unico().Contains("no hay ningún túnel"), "uno que no existe: rechazado");
            Check(PlanificadorDeVpn.PrepararDesconexion("a\" & del x", conTuneles, ej).Rechazos.Unico().Contains("no es válido"), "un nombre con caracteres raros ni se busca");
        }

        private static async Task ProbarAplicarPlanes()
        {
            Console.WriteLine("8. Aplicar un plan (volviendo a mirar el estado)");
            var ej = new EjecutorFalso();
            PlanDeVpn p = PlanificadorDeVpn.PrepararConexion(Conf(), "proton-CL-12.conf", Instalado(), ej);
            ResultadoDeVpn r = await PlanificadorDeVpn.AplicarAsync(p, Instalado(), ej, CancellationToken.None);
            Check(r.Exito && ej.Llamadas.SequenceEqual(new[] { "conectar:proton-CL-12" }) && ej.ConfRecibida == Conf(), "conectar: se llama una vez, con el texto exacto del archivo");

            var ej2 = new EjecutorFalso();
            ResultadoDeVpn tarde = await PlanificadorDeVpn.AplicarAsync(p, Instalado(new TunelInstalado("proton-CL-12", EstadoDeTunel.Activo)), ej2, CancellationToken.None);
            Check(!tarde.Exito && ej2.Llamadas.Count == 0 && tarde.Mensaje.Contains("No se cambió nada"), "si mientras tanto apareció un túnel con ese nombre: no se toca nada", tarde.Mensaje);
            ResultadoDeVpn sinWg = await PlanificadorDeVpn.AplicarAsync(p, SinWireGuard, ej2, CancellationToken.None);
            Check(!sinWg.Exito && ej2.Llamadas.Count == 0, "si WireGuard se desinstaló mientras tanto: no se toca nada");

            var ej3 = new EjecutorFalso();
            ej3.DeNexo.Add("mio");
            var est = Instalado(new TunelInstalado("mio", EstadoDeTunel.Activo));
            PlanDeVpn d = PlanificadorDeVpn.PrepararDesconexion("mio", est, ej3);
            ej3.DeNexo.Clear();
            ResultadoDeVpn yaNo = await PlanificadorDeVpn.AplicarAsync(d, est, ej3, CancellationToken.None);
            Check(!yaNo.Exito && ej3.Llamadas.Count == 0, "si el túnel dejó de ser de Nexo: no se desconecta");
            ej3.DeNexo.Add("mio");
            ResultadoDeVpn ok = await PlanificadorDeVpn.AplicarAsync(d, est, ej3, CancellationToken.None);
            Check(ok.Exito && ej3.Llamadas.SequenceEqual(new[] { "desconectar:mio" }), "desconectar: se llama una vez");
            ResultadoDeVpn yaNoExiste = await PlanificadorDeVpn.AplicarAsync(d, Instalado(), ej3, CancellationToken.None);
            Check(!yaNoExiste.Exito && ej3.Llamadas.Count == 1, "si el túnel ya no existe: no se llama a nada");

            PlanDeVpn rechazado = PlanificadorDeVpn.PrepararConexion(Conf(), "x.conf", SinWireGuard, ej3);
            Check(!(await PlanificadorDeVpn.AplicarAsync(rechazado, Instalado(), ej3, CancellationToken.None)).Exito && ej3.Llamadas.Count == 1, "un plan rechazado nunca se aplica");
        }
    }
}
