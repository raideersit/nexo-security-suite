using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>El resultado de consultar un modulo: o el valor, o por que no se supo. Nunca las dos cosas, nunca ninguna.</summary>
    public sealed record Consulta<T>(T? Valor, string? Error) where T : class
    {
        public static Consulta<T> Bien(T valor) => new Consulta<T>(valor, null);
        public static Consulta<T> Mal(string error) => new Consulta<T>(null, error);
    }

    /// <summary>Una respuesta del pipe sin depender de Nexo.Ipc (que es solo Windows): asi el lector se prueba en Linux.</summary>
    public readonly record struct RespuestaCruda(bool Exito, string? Error, JsonElement? Resultado);

    /// <summary>escaneo.estado: si el motor (clamd) contesta.</summary>
    public sealed record EstadoDelMotor(bool Disponible, string? Motor, string? Version);

    /// <summary>escaneo-programado.estado.</summary>
    public sealed record EstadoDeEscaneoProgramado(
        bool Activo,
        string UltimoResultado,          // nunca | limpio | con_detecciones | incompleto | fallido | desconocido
        DateTimeOffset? UltimoCompleto,
        DateTimeOffset? Proxima,
        bool Vencido,
        bool Corriendo,
        int Detecciones,
        string? Motivo);

    public sealed record PerfilDeFirewall(string Perfil, bool Activo);

    /// <summary>firewall.estado.</summary>
    public sealed record EstadoDeFirewall(int ReglasDeNexo, bool Sigiloso, IReadOnlyList<PerfilDeFirewall> Perfiles);

    /// <summary>cuarentena.listar, resumido.</summary>
    public sealed record EstadoDeCuarentena(int Elementos, DateTimeOffset? ProximoVencimiento);

    /// <summary>Una tarea pesada de Nexo que está esperando por el perfil (§2az). <c>Forzada</c>: ya cumplió el máximo de espera y correrá igual.</summary>
    public sealed record TareaPospuestaVista(string Tarea, DateTimeOffset Desde, bool Forzada);

    /// <summary>perfil.estado (§2az). <c>Perfil</c> null = el servicio aún no ha leído nada. <c>WifiLeido</c> false = no se sabe si el Wi-Fi está abierto.</summary>
    public sealed record EstadoDePerfil(
        bool Activo,
        string? Perfil,
        bool Pospone,
        double MaximoEsperaHoras,
        IReadOnlyList<string> Motivos,
        IReadOnlyList<string> NoEvaluado,
        IReadOnlyList<TareaPospuestaVista> Pospuestas,
        bool WifiAbierto,
        bool WifiLeido,
        string? Aviso);

    /// <summary>Todo lo que la pestaña «Estado» pide en una vuelta.</summary>
    public sealed record EstadoCompleto(
        InstantaneaDelServicio Servicio,
        Consulta<EstadoDelMotor> Motor,
        Consulta<EstadoDeEscaneoProgramado> Programado,
        Consulta<EstadoDeFirewall> Firewall,
        Consulta<EstadoDeCuarentena> Cuarentena,
        Consulta<EstadoDeDiscos>? Disco = null,
        Consulta<EstadoDePerfil>? Perfil = null)
    {
        /// <summary>Solo se sabe lo del tiempo real (o ni eso): el resto de modulos, con el motivo.</summary>
        public static EstadoCompleto SoloServicio(InstantaneaDelServicio s, string motivo)
            => new EstadoCompleto(s, Consulta<EstadoDelMotor>.Mal(motivo), Consulta<EstadoDeEscaneoProgramado>.Mal(motivo),
                                  Consulta<EstadoDeFirewall>.Mal(motivo), Consulta<EstadoDeCuarentena>.Mal(motivo),
                                  Consulta<EstadoDeDiscos>.Mal(motivo), Consulta<EstadoDePerfil>.Mal(motivo));

        public static EstadoCompleto SinConexion(InstantaneaDelServicio s) => SoloServicio(s, "sin conexión con el servicio");
    }

    /// <summary>
    /// Lee las respuestas del servicio. Una respuesta con error, vacia o con otra forma NO se interpreta a medias: queda como
    /// «no se pudo consultar» con el motivo. Los campos que el servicio omite por ser nulos se toman como ausentes.
    /// </summary>
    public static class LectorDeModulos
    {
        public static Consulta<EstadoDelMotor> Motor(RespuestaCruda r)
            => Leer(r, e => new EstadoDelMotor(e.GetProperty("motor_disponible").GetBoolean(), Texto(e, "motor"), Texto(e, "version")));

        public static Consulta<EstadoDeEscaneoProgramado> Programado(RespuestaCruda r)
            => Leer(r, e => new EstadoDeEscaneoProgramado(
                Activo: e.GetProperty("activo").GetBoolean(),
                UltimoResultado: Texto(e, "ultimo_resultado") ?? "nunca",
                UltimoCompleto: Fecha(e, "ultimo_completo"),
                Proxima: Fecha(e, "proxima"),
                // Si el servicio no lo dijera, no se supone «al dia».
                Vencido: !e.TryGetProperty("vencido", out JsonElement v) || v.GetBoolean(),
                Corriendo: e.TryGetProperty("corriendo", out JsonElement c) && c.GetBoolean(),
                Detecciones: e.TryGetProperty("detecciones", out JsonElement d) ? d.GetInt32() : 0,
                Motivo: Texto(e, "motivo")));

        /// <summary>
        /// «perfil.estado». Apagado = solo <c>activo:false</c>. Una forma rara invalida TODA la respuesta (nunca «Normal» por no entenderla).
        /// </summary>
        public static Consulta<EstadoDePerfil> Perfil(RespuestaCruda r)
            => Leer(r, e =>
            {
                if (!e.GetProperty("activo").GetBoolean())
                    return new EstadoDePerfil(false, null, false, 0, Array.Empty<string>(), Array.Empty<string>(), Array.Empty<TareaPospuestaVista>(), false, false, null);
                string? perfil = Texto(e, "perfil");
                if (perfil is not null && perfil is not ("Normal" or "JuegoOVideo" or "Bateria")) throw new FormatException();
                var motivos = e.GetProperty("motivos").EnumerateArray().Select(x => x.GetString() ?? throw new FormatException()).ToList();
                var no = e.GetProperty("no_evaluado").EnumerateArray().Select(x => x.GetString() ?? throw new FormatException()).ToList();
                var pos = e.GetProperty("pospuestas").EnumerateArray()
                    .Select(x => new TareaPospuestaVista(x.GetProperty("tarea").GetString() ?? throw new FormatException(), x.GetProperty("desde").GetDateTimeOffset(), x.GetProperty("forzada").GetBoolean())).ToList();
                double max = e.GetProperty("maximo_espera_horas").GetDouble();
                if (max <= 0) throw new FormatException();
                return new EstadoDePerfil(true, perfil, e.GetProperty("pospone_tareas_pesadas").GetBoolean(), max, motivos, no, pos,
                    e.GetProperty("wifi_abierto").GetBoolean(), e.GetProperty("wifi_leido").GetBoolean(), Texto(e, "aviso"));
            });

        public static Consulta<EstadoDeFirewall> Firewall(RespuestaCruda r)
            => Leer(r, e => new EstadoDeFirewall(
                ReglasDeNexo: e.GetProperty("reglas_de_nexo").GetArrayLength(),
                Sigiloso: e.GetProperty("sigiloso").GetBoolean(),
                Perfiles: e.GetProperty("perfiles").EnumerateArray()
                    .Select(p => new PerfilDeFirewall(p.GetProperty("perfil").GetString() ?? "?", p.GetProperty("activo").GetBoolean()))
                    .ToList()));

        public static Consulta<EstadoDeCuarentena> Cuarentena(RespuestaCruda r)
            => Leer(r, e =>
            {
                var vencimientos = e.GetProperty("elementos").EnumerateArray().Select(x => x.GetProperty("vence").GetDateTimeOffset()).ToList();
                return new EstadoDeCuarentena(vencimientos.Count, vencimientos.Count == 0 ? null : vencimientos.Min());
            });

        private static Consulta<T> Leer<T>(RespuestaCruda r, Func<JsonElement, T> leer) where T : class
        {
            if (!r.Exito) return Consulta<T>.Mal("el servicio contestó con un error (" + (string.IsNullOrEmpty(r.Error) ? "sin detalle" : r.Error) + ")");
            if (r.Resultado is not JsonElement e || e.ValueKind != JsonValueKind.Object) return Consulta<T>.Mal("respuesta vacía del servicio");
            try
            {
                return Consulta<T>.Bien(leer(e));
            }
            catch (Exception ex) when (ex is KeyNotFoundException || ex is InvalidOperationException || ex is FormatException)
            {
                return Consulta<T>.Mal("respuesta del servicio no reconocida");
            }
        }

        private static string? Texto(JsonElement e, string nombre)
            => e.TryGetProperty(nombre, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

        private static DateTimeOffset? Fecha(JsonElement e, string nombre)
            => e.TryGetProperty(nombre, out JsonElement v) && v.ValueKind != JsonValueKind.Null ? v.GetDateTimeOffset() : null;
    }
}
