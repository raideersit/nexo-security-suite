using System;
using System.Collections.Generic;
using System.Linq;
using Nexo.Modules.Threats.Enlaces;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Vpn
{
    /// <summary>
    /// Revisa una configuracion de WireGuard ya leida. Reglas de honestidad:
    ///  - Una VPN no te hace anonimo: cambia en quien confias (el servidor ve todo lo que pasa por ella). Se dice siempre.
    ///  - Las «fugas» se describen como lo que el archivo PERMITE, no como algo comprobado en la red (Nexo no se conecta para mirarlo).
    ///  - La clave privada nunca se muestra (el lector ni siquiera la guarda).
    /// </summary>
    public static class AnalizadorDeVpn
    {
        public static bool EsRutaPorDefectoV4(string cidr) => cidr is "0.0.0.0/0" or "0.0.0.0/1" or "128.0.0.0/1";
        public static bool EsRutaPorDefectoV6(string cidr) => cidr is "::/0" or "::/1" or "8000::/1";

        /// <summary>Todo el trafico IPv4 va por la VPN: 0.0.0.0/0, o las dos mitades 0.0.0.0/1 + 128.0.0.0/1.</summary>
        public static bool TodoIpv4(IEnumerable<string> ips)
        {
            var l = ips.ToList();
            return l.Contains("0.0.0.0/0") || (l.Contains("0.0.0.0/1") && l.Contains("128.0.0.0/1"));
        }

        public static bool TodoIpv6(IEnumerable<string> ips)
        {
            var l = ips.ToList();
            return l.Contains("::/0") || (l.Contains("::/1") && l.Contains("8000::/1"));
        }

        public static ResultadoDeAnalisis Analizar(ConfiguracionWg c, ListasDePhishing? listas = null)
        {
            if (c is null) throw new ArgumentNullException(nameof(c));
            var hs = new List<HallazgoDeSistema>();
            var noEvaluado = new List<string>();
            List<string> todas = c.Peers.SelectMany(p => p.IpsPermitidas).ToList();

            if (c.Interfaz.Scripts.Count > 0)
                hs.Add(new HallazgoDeSistema("VPN-SCRIPTS", Severidad.Alta, "El archivo trae comandos para ejecutar (" + string.Join(", ", c.Interfaz.Scripts.Select(s => s.Clave).Distinct()) + ")",
                    "Comandos: " + string.Join(" | ", c.Interfaz.Scripts.Take(4).Select(s => s.Clave + ": «" + Recortar(s.Comando, 90) + "»")) +
                    ". WireGuard para Windows NO los ejecuta salvo que se active «DangerousScriptExecution» en el registro, y entonces correrían como SYSTEM (control total del equipo).",
                    "No actives la ejecución de scripts. Un proveedor de VPN no necesita esto en Windows: pide un archivo sin ellos."));

            if (c.Peers.Count == 0)
                hs.Add(new HallazgoDeSistema("VPN-SIN-SERVIDOR", Severidad.Media, "El archivo no tiene ningún servidor ([Peer])",
                    "Sin [Peer], el túnel no se conecta a nada.", "Pide el archivo completo a tu proveedor de VPN."));

            bool v4 = TodoIpv4(todas), v6 = TodoIpv6(todas);
            if (v4 && !v6)
                hs.Add(new HallazgoDeSistema("VPN-FUGA-IPV6", Severidad.Media, "El tráfico IPv6 puede salir por fuera de la VPN",
                    "El archivo manda por la VPN todo el tráfico IPv4 (0.0.0.0/0) pero no el IPv6 (falta «::/0» en AllowedIPs). Si tu conexión tiene IPv6, lo que vaya por IPv6 no pasará por la VPN.",
                    "Pide a tu proveedor un archivo con «::/0», o desactiva IPv6 en el adaptador de red mientras uses la VPN."));
            if ((v4 || v6) && c.Interfaz.Dns.Count == 0)
                hs.Add(new HallazgoDeSistema("VPN-SIN-DNS", Severidad.Media, "No indica un DNS",
                    "Todo el tráfico va por la VPN, pero el archivo no dice qué servidor DNS usar: las consultas de nombres (qué sitios visitas) pueden salir por fuera o fallar.",
                    "Los proveedores ponen «DNS = ...» en [Interface]; pide el archivo con esa línea."));
            if (!v4 && !v6 && c.Peers.Count > 0)
                hs.Add(new HallazgoDeSistema("VPN-TUNEL-PARCIAL", Severidad.Info, "Solo una parte del tráfico pasa por la VPN",
                    "Por la VPN va solo el tráfico hacia: " + string.Join(", ", todas.Take(6)) + (todas.Count > 6 ? " y " + (todas.Count - 6) + " más" : "") +
                    ". El resto sale directo por tu conexión. Es normal para entrar a una red de trabajo; no sirve para ocultar tu navegación.",
                    "Si querías que TODO pasara por la VPN, el archivo debería tener «AllowedIPs = 0.0.0.0/0, ::/0»."));

            foreach (PeerWg p in c.Peers)
            {
                if (p.Endpoint is null)
                    hs.Add(new HallazgoDeSistema("VPN-SIN-ENDPOINT", Severidad.Media, "Un servidor no tiene dirección (Endpoint)",
                        "El [Peer] " + Corta(p.ClavePublica) + " no dice a qué dirección conectarse: este equipo no podrá iniciar la conexión con él.",
                        "Pide el archivo completo a tu proveedor.", Corta(p.ClavePublica)));
                else
                {
                    hs.Add(new HallazgoDeSistema("VPN-SERVIDOR", Severidad.Info, "Te conectarás a " + p.Endpoint,
                        "Ese servidor es de tu proveedor de VPN y ve todo el tráfico que pase por la VPN. Una VPN no te hace anónimo: cambia en quién confías (de tu proveedor de Internet al de la VPN).",
                        "Usa un proveedor en el que confíes.", p.Endpoint));
                    if (listas is not null && p.HostDelEndpoint is string h && listas.CoincidenciaEnPhishingArmy(h) is string enLista)
                        hs.Add(new HallazgoDeSistema("VPN-SERVIDOR-EN-LISTA", Severidad.Alta, "El servidor está en una lista de phishing",
                            "«" + enLista + "» figura en la lista de Phishing Army.", "No uses este archivo.", p.Endpoint));
                }
            }
            if (c.Peers.Count > 1)
                hs.Add(new HallazgoDeSistema("VPN-VARIOS-SERVIDORES", Severidad.Info, "El archivo tiene " + c.Peers.Count + " servidores",
                    "Es poco habitual en una VPN comercial (suele haber uno). No es un problema por sí mismo.", "Si no lo esperabas, pregunta a quien te dio el archivo."));

            if (c.Interfaz.Mtu is int mtu && mtu < 1280)
                hs.Add(new HallazgoDeSistema("VPN-MTU", Severidad.Baja, "MTU muy bajo (" + mtu + ")",
                    "Con un MTU menor de 1280 el IPv6 no funciona por el túnel y algunas páginas pueden cargar mal.", "Si tienes problemas, prueba sin la línea MTU."));

            hs.Add(new HallazgoDeSistema("VPN-ARCHIVO-CON-CLAVE", Severidad.Info, "El archivo contiene tu clave privada",
                "Quien tenga este archivo puede usar tu VPN como si fueras tú. Nexo no muestra la clave ni la guarda.",
                "Guárdalo en un lugar seguro y no lo compartas ni lo subas a la nube sin cifrar."));

            return new ResultadoDeAnalisis(
                hs.OrderByDescending(h => h.Severidad).ThenBy(h => h.Id, StringComparer.Ordinal).ToList(), noEvaluado);
        }

        /// <summary>Los primeros 8 caracteres de una clave publica (para nombrar un servidor sin llenar la pantalla).</summary>
        public static string Corta(string clavePublica) => clavePublica.Length > 8 ? clavePublica.Substring(0, 8) + "…" : clavePublica;

        private static string Recortar(string s, int max) => s.Length <= max ? s : s.Substring(0, max) + "…";
    }
}
