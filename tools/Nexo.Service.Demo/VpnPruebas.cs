using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Threats.Vpn;
using Nexo.Reports.Model;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        private sealed class LectorWgFalso : ILectorDeWireGuard
        {
            public EstadoDeWireGuard Valor = new(true, "1.1.1", @"C:\Program Files\WireGuard\wireguard.exe", Array.Empty<TunelInstalado>(), true, null);
            public EstadoDeWireGuard Leer() => Valor;
        }

        private sealed class EjecutorWgFalso : IEjecutorDeWireGuard
        {
            public readonly HashSet<string> DeNexo = new(StringComparer.OrdinalIgnoreCase);
            public readonly List<string> Llamadas = new();
            public string Carpeta => @"C:\ProgramData\Nexo\vpn";
            public bool EsDeNexo(string tunel) => DeNexo.Contains(tunel);
            public Task<ResultadoDeVpn> ConectarAsync(string tunel, string conf, CancellationToken ct) { Llamadas.Add("conectar:" + tunel); DeNexo.Add(tunel); return Task.FromResult(new ResultadoDeVpn(true, "Túnel «" + tunel + "» instalado y en marcha.")); }
            public Task<ResultadoDeVpn> DesconectarAsync(string tunel, CancellationToken ct) { Llamadas.Add("desconectar:" + tunel); return Task.FromResult(new ResultadoDeVpn(true, "ok")); }
        }

        private static async Task<(bool Ok, int Codigo, JsonElement? R)> PedirVpn(ModuloVpn m, string metodo, object? parametros)
        {
            try
            {
                JsonElement? p = parametros is null ? null : JsonSerializer.SerializeToElement(parametros);
                object? r = await m.ManejarAsync(metodo, p, CancellationToken.None).ConfigureAwait(false);
                return (true, 0, JsonSerializer.SerializeToElement(r));
            }
            catch (ErrorDeComando e) { return (false, e.Codigo, null); }
        }

        public static async Task ProbarVpnDelServicio()
        {
            Console.WriteLine("VPN por el servicio: vpn.estado, vpn.previsualizar, vpn.aplicar");
            string privada = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            string conf = "[Interface]\nPrivateKey = " + privada + "\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n[Peer]\nPublicKey = " + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) +
                          "\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 149.88.104.1:51820\n";
            var l = new LectorWgFalso();
            var ej = new EjecutorWgFalso();
            var w = new EscritorFalso();
            var m = new ModuloVpn(l, ej, w, PoliticaDeAprobacion.Ninguna);
            Check(m.Metodos.SequenceEqual(new[] { "vpn.estado", "vpn.previsualizar", "vpn.aplicar" }), "tres métodos");

            ej.DeNexo.Add("mio");
            l.Valor = l.Valor with { Tuneles = new[] { new TunelInstalado("mio", EstadoDeTunel.Activo), new TunelInstalado("ajeno", EstadoDeTunel.Detenido) } };
            var est = await PedirVpn(m, "vpn.estado", null);
            Check(est.Ok && est.R!.Value.GetProperty("tuneles").GetArrayLength() == 2 && est.R.Value.GetProperty("tuneles")[0].GetProperty("de_nexo").GetBoolean() && !est.R.Value.GetProperty("tuneles")[1].GetProperty("de_nexo").GetBoolean(),
                "vpn.estado: los túneles, y cuál instaló Nexo");

            var pre = await PedirVpn(m, "vpn.previsualizar", new { tipo = "conectar", conf, archivo = "proton-CL-12.conf" });
            string? token = pre.R?.GetProperty("token").GetString();
            Check(pre.Ok && pre.R!.Value.GetProperty("hay_cambios").GetBoolean() && token?.Length == 64 && ej.Llamadas.Count == 0, "previsualizar conectar: token y NADA ejecutado");
            Check(!pre.R!.Value.GetRawText().Contains(privada) && !pre.R.Value.GetRawText().Contains(privada.Replace("+", "\\u002B")), "la respuesta de la vista previa no lleva la clave privada");

            var mElevada = new ModuloVpn(l, ej, w, PoliticaDeAprobacion.Elevada);
            var preE = await PedirVpn(mElevada, "vpn.previsualizar", new { tipo = "conectar", conf, archivo = "otro.conf" });
            string tokE = preE.R!.Value.GetProperty("token").GetString()!;
            var sinUac = await PedirVpn(mElevada, "vpn.aplicar", new { token = tokE });
            Check(!sinUac.Ok && sinUac.Codigo == PoliticaDeAprobacion.AprobacionRequerida && ej.Llamadas.Count == 0, "con la política «elevada», aplicar sin UAC se rechaza y no se conecta nada");

            var ap = await PedirVpn(m, "vpn.aplicar", new { token });
            Check(ap.Ok && ap.R!.Value.GetProperty("exito").GetBoolean() && ej.Llamadas.SequenceEqual(new[] { "conectar:proton-CL-12" }), "aplicar con el token: se conecta una vez");
            var otraVez = await PedirVpn(m, "vpn.aplicar", new { token });
            Check(!otraVez.Ok && otraVez.Codigo == ModuloVpn.TokenInvalido && ej.Llamadas.Count == 1, "el token es de un solo uso");
            NexoEvent? ev = w.Eventos.LastOrDefault(e => e.Tipo == TipoEvento.ConexionVpn);
            Check(ev is not null && ev.Titulo == "VPN conectada: proton-CL-12" && !(ev.Titulo + ev.Cuerpo + string.Join(",", ev.Campos.Values)).Contains(privada),
                "queda en el vault («VPN conectada»), sin la clave privada", ev?.Titulo);

            var rech = await PedirVpn(m, "vpn.previsualizar", new { tipo = "desconectar", tunel = "ajeno" });
            Check(rech.Ok && !rech.R!.Value.GetProperty("hay_cambios").GetBoolean() && rech.R.Value.GetProperty("token").ValueKind == JsonValueKind.Null && rech.R.Value.GetProperty("descripcion").GetString()!.Contains("no lo instaló Nexo"),
                "desconectar un túnel ajeno: sin token y con el motivo");
            var des = await PedirVpn(m, "vpn.previsualizar", new { tipo = "desconectar", tunel = "mio" });
            var apDes = await PedirVpn(m, "vpn.aplicar", new { token = des.R!.Value.GetProperty("token").GetString() });
            Check(apDes.Ok && ej.Llamadas.Last() == "desconectar:mio" && w.Eventos.Last().Titulo == "VPN desconectada: mio", "desconectar uno de Nexo: se hace y se registra");

            Check(!(await PedirVpn(m, "vpn.previsualizar", new { tipo = "borrar" })).Ok, "un tipo desconocido se rechaza");
            Check(!(await PedirVpn(m, "vpn.previsualizar", new { tipo = "conectar", archivo = "x.conf" })).Ok, "conectar sin 'conf' se rechaza");
            Check(!(await PedirVpn(m, "vpn.previsualizar", new { tipo = "conectar", conf = new string('#', ParserDeWireGuard.MaximoDeCaracteres + 1), archivo = "x.conf" })).Ok, "un 'conf' de más de 64 KB se rechaza");
            Check(!(await PedirVpn(m, "vpn.previsualizar", new { tipo = "conectar", conf = 5, archivo = "x.conf" })).Ok, "un 'conf' que no es texto se rechaza");
            Check(!(await PedirVpn(m, "vpn.aplicar", new { token = "abc" })).Ok, "un token con otra forma se rechaza");
        }
    }
}
