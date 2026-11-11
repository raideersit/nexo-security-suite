using System;
using System.Linq;
using Nexo.Ui.Desktop.Nucleo;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        private static string EstadoP(string perfil = "\"Normal\"", bool pospone = false, string motivos = "", string no = "", string pospuestas = "", bool wifi = false, bool wifiLeido = true,
                                      string aviso = "null", double max = 6)
            => "{\"activo\":true,\"intervalo_segundos\":10,\"ultima_lectura\":\"2026-11-11T11:00:00-03:00\",\"perfil\":" + perfil + ",\"desde\":\"2026-11-11T10:00:00-03:00\",\"pospone_tareas_pesadas\":" + (pospone ? "true" : "false")
             + ",\"maximo_espera_horas\":" + max.ToString(System.Globalization.CultureInfo.InvariantCulture) + ",\"wifi_abierto\":" + (wifi ? "true" : "false") + ",\"wifi_leido\":" + (wifiLeido ? "true" : "false")
             + ",\"motivos\":[" + motivos + "],\"no_evaluado\":[" + no + "],\"pospuestas\":[" + pospuestas + "],\"aviso\":" + aviso + ",\"nota\":\"x\"}";

        private static FilaDeModulo FilaPerfil(string json)
        {
            var c = LectorDeModulos.Perfil(JsonS(json));
            var e = Completo(Conectada()) with { Perfil = c };
            return Resumen(e).Modulos.Single(f => f.Modulo == Resumir.Perfil);
        }

        private static void ProbarPerfilEnLaVentana()
        {
            Console.WriteLine("Pestaña Estado: fila «Perfil de actividad» (lo que dice el servicio)");

            FilaDeModulo f = FilaPerfil("{\"activo\":false,\"pospone_tareas_pesadas\":false,\"nota\":\"apagado\"}");
            Check(f.Estado == "Apagado" && f.Indicador == Indicador.SinDatos && f.Detalle.Contains("Nexo:Perfiles:Activo"), "apagado: gris, con dónde activarlo");

            f = FilaPerfil(EstadoP("null"));
            Check(f.Estado == "Sin lecturas todavía" && f.Indicador == Indicador.SinDatos, "sin lecturas: nunca «Normal»");

            f = FilaPerfil(EstadoP());
            Check(f.Estado == "Todo normal" && f.Indicador == Indicador.Correcto && f.Detalle == "Nexo trabaja con normalidad.", "normal con Wi-Fi leído: verde y sin ruido", f.Detalle);

            f = FilaPerfil(EstadoP(perfil: "\"JuegoOVideo\"", pospone: true, motivos: "\"hay un juego\"",
                pospuestas: "{\"tarea\":\"copia\",\"desde\":\"2026-11-11T10:30:00-03:00\",\"forzada\":false}"));
            Check(f.Estado == "Hay un juego o vídeo a pantalla completa: tareas pospuestas" && f.Indicador == Indicador.Correcto && f.Detalle.Contains("tiempo real sigue activo")
                  && f.Detalle.Contains("La copia de seguridad espera desde las") && f.Detalle.Contains("como mucho espera 6 h"), "juego: verde, dice qué se pospone, desde cuándo y el máximo", f.Detalle);

            f = FilaPerfil(EstadoP(perfil: "\"Bateria\"", pospone: true, pospuestas: "{\"tarea\":\"escaneo-programado\",\"desde\":\"2026-11-11T10:30:00-03:00\",\"forzada\":true}"));
            Check(f.Estado.Contains("batería") && f.Detalle.Contains("El escaneo programado espera") && f.Detalle.Contains("correrá igual"), "batería + forzada: «correrá igual, porque ya cumplió el máximo»", f.Detalle);

            f = FilaPerfil(EstadoP(wifi: true));
            Check(f.Estado == "Wi-Fi sin cifrado" && f.Indicador == Indicador.Atencion && f.Detalle.Contains("VPN"), "Wi-Fi sin cifrado: atención, con qué hacer");

            f = FilaPerfil(EstadoP(wifiLeido: false));
            Check(f.Indicador == Indicador.Correcto && f.Detalle.Contains("No se sabe si el Wi-Fi está abierto"), "Wi-Fi no leído: lo dice, sin inventar «cerrado»");

            f = FilaPerfil(EstadoP(aviso: "\"la última lectura falló (IOException): no se pospone nada\""));
            Check(f.Indicador == Indicador.Atencion && f.Detalle.Contains("no se pospone nada"), "un aviso del servicio: atención");

            f = FilaPerfil(EstadoP(no: "\"energía: no se pudo saber si está enchufado\""));
            Check(f.Indicador == Indicador.Atencion && f.Detalle.Contains("No se pudo leer: energía"), "lo no evaluado: atención, nunca verde a ciegas");

            // Formas raras: nunca «normal» por no entender.
            Check(LectorDeModulos.Perfil(JsonS(EstadoP("\"Cosa\""))).Error == "respuesta del servicio no reconocida", "un perfil desconocido invalida la respuesta entera");
            Check(LectorDeModulos.Perfil(JsonS(EstadoP(max: 0))).Error is not null, "máximo de espera 0: no válido");
            Check(LectorDeModulos.Perfil(JsonS(EstadoP().Replace("\"pospuestas\":[],", ""))).Error is not null, "sin «pospuestas»: no se interpreta a medias");
            Check(LectorDeModulos.Perfil(new RespuestaCruda(false, "metodo desconocido", null)).Error!.Contains("error"), "un servicio antiguo (método desconocido): «no se pudo consultar»");
            f = Resumen(InstantaneaDelServicio.SinConexion("x")).Modulos.Single(x => x.Modulo == Resumir.Perfil);
            Check(f.Indicador == Indicador.SinDatos, "sin conexión: sin datos");
        }
    }
}
