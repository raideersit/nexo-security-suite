using System;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Cleanup.Perfiles;
using Nexo.Service;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Tray.Demo
{
    internal static partial class Program
    {
        /// <summary>El aviso de Wi-Fi sin cifrado en la bandeja, con el JSON REAL de ModuloPerfil: un globo por conexión, pendiente hasta mostrarse.</summary>
        private static async Task ProbarWifiEnLaBandeja()
        {
            Console.WriteLine("Wi-Fi sin cifrado en la bandeja (con el JSON real del servicio)");
            static JsonElement J(object? o) => JsonSerializer.SerializeToElement(o);

            Check(!ConsultorDelServicio.LeerWifiSinCifrado(J(await new ModuloPerfilApagado().ManejarAsync("perfil.estado", null, CancellationToken.None))), "perfiles apagados: sin aviso");

            bool? abierto = true; bool lanzar = false;
            var t = new DateTimeOffset(2026, 11, 11, 12, 0, 0, TimeSpan.Zero);
            var modulo = new ModuloPerfil(() => new SenalesDeActividad(FuenteDeEnergia.Corriente, null, null, EstadoDePantalla.Libre, null), reloj: () => t,
                                          wifiAbierto: () => lanzar ? throw new InvalidOperationException("sin WLAN") : abierto, wifiCada: TimeSpan.FromSeconds(1));
            async Task<JsonElement> Estado() => J(await modulo.ManejarAsync("perfil.estado", null, CancellationToken.None));

            Check(!ConsultorDelServicio.LeerWifiSinCifrado(await Estado()), "sin lecturas todavía: sin aviso");
            modulo.UnaVuelta();
            Check(ConsultorDelServicio.LeerWifiSinCifrado(await Estado()), "Wi-Fi sin cifrado leído: true");

            var m = new ModeloDeBandeja();
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { WifiSinCifrado = true });
            Check(m.WifiSinCifradoNuevo, "el modelo lo da como pendiente la primera vez");
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { WifiSinCifrado = true });
            Check(m.WifiSinCifradoNuevo, "sigue pendiente hasta que la bandeja de verdad muestre el globo (no se pierde si coincide con algo más grave)");
            m.MarcarWifiAvisado();
            Check(!m.WifiSinCifradoNuevo, "ya mostrado: no está pendiente");
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { WifiSinCifrado = true });
            Check(!m.WifiSinCifradoNuevo, "y en las siguientes consultas NO se repite mientras siga en esa red");

            // Sin poder hablar con el servicio no se cambia nada.
            m.Actualizar(InstantaneaDelServicio.SinConexion("x"));
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { WifiSinCifrado = true });
            Check(!m.WifiSinCifradoNuevo, "tras un corte del servicio, la misma red no se vuelve a avisar");

            // Se desconecta (cierra) y se conecta a otra abierta: aviso nuevo.
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { WifiSinCifrado = false });
            m.Actualizar(Sana(Array.Empty<SenueloTocadoVista>()) with { WifiSinCifrado = true });
            Check(m.WifiSinCifradoNuevo, "al pasar por una red cifrada y volver a una abierta: aviso nuevo");

            // Lectura fallida del Wi-Fi en el servicio: no es «abierto».
            lanzar = true; t = t.AddSeconds(2); modulo.UnaVuelta();
            Check(!ConsultorDelServicio.LeerWifiSinCifrado(await Estado()), "si el servicio no pudo leer el Wi-Fi: sin aviso (no se afirma lo que no se sabe)");
            lanzar = false; abierto = false; t = t.AddSeconds(2); modulo.UnaVuelta();
            Check(!ConsultorDelServicio.LeerWifiSinCifrado(await Estado()), "Wi-Fi cifrado: sin aviso");

            // Formas raras: false.
            Check(!ConsultorDelServicio.LeerWifiSinCifrado(JsonDocument.Parse("{\"activo\":true}").RootElement), "sin los campos del Wi-Fi: false");
            Check(!ConsultorDelServicio.LeerWifiSinCifrado(JsonDocument.Parse("{\"activo\":true,\"wifi_leido\":false,\"wifi_abierto\":true}").RootElement), "wifi_abierto sin wifi_leido: false (no se fía)");

            Check(AccionesDelServicio.TextoDeWifiSinCifrado.Contains("VPN") && AccionesDelServicio.TextoDeWifiSinCifrado.Contains("no desconecta ni cambia nada"), "el texto dice qué hacer y que Nexo no cambia nada");
        }
    }
}
