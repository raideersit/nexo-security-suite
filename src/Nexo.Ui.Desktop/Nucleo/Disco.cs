using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>Un disco de disco.estado. <see cref="Severidad"/>: info | baja | media | alta | critica (la del evaluador).</summary>
    public sealed record DiscoVista(
        string Modelo,
        string Serie,
        bool SinDatos,
        bool? PrediccionDeFallo,
        int AtributosLeidos,
        IReadOnlyList<int> AtributosClaveLeidos,
        int? TemperaturaC,
        int? DesgastePorcentaje,
        long? HorasEncendido,
        string Severidad,
        IReadOnlyList<string> Alertas,
        IReadOnlyList<string> Limitaciones);

    /// <summary>
    /// disco.estado. <see cref="Estado"/>: nunca | listo | fallido | apagado. Los discos son siempre los de la ultima lectura que
    /// salio bien (fecha en <see cref="UltimaLectura"/>), aunque el ultimo intento haya fallado.
    /// </summary>
    public sealed record EstadoDeDiscos(
        string Estado,
        bool Leyendo,
        DateTimeOffset? UltimaLectura,
        DateTimeOffset? ProximaLectura,
        string? Error,
        string? AdvertenciaDeHistorial,
        IReadOnlyList<DiscoVista> Discos);

    public sealed record PedidoDeLectura(bool Iniciada, string Motivo);

    /// <summary>
    /// La salud de los discos vista desde la ventana. Consultar no lee los discos: devuelve lo que el servicio leyo (al arrancar
    /// y cada pocas horas). Pedir una lectura nueva solo lee, y el servicio la limita a una cada 5 minutos.
    /// </summary>
    public interface IServicioDeDisco
    {
        Task<Consulta<EstadoDeDiscos>> EstadoAsync(CancellationToken ct);
        Task<Consulta<PedidoDeLectura>> PedirLecturaAsync(CancellationToken ct);
    }

    public sealed class ServicioDeDiscoNoDisponible : IServicioDeDisco
    {
        private readonly string _motivo;

        public ServicioDeDiscoNoDisponible(string motivo) => _motivo = motivo;

        public Task<Consulta<EstadoDeDiscos>> EstadoAsync(CancellationToken ct) => Task.FromResult(Consulta<EstadoDeDiscos>.Mal(_motivo));
        public Task<Consulta<PedidoDeLectura>> PedirLecturaAsync(CancellationToken ct) => Task.FromResult(Consulta<PedidoDeLectura>.Mal(_motivo));
    }

    public static class LectorDeDisco
    {
        private static readonly string[] Severidades = { "info", "baja", "media", "alta", "critica" };

        /// <summary>disco.estado. Un disco con otra forma (o una severidad desconocida) invalida la respuesta entera.</summary>
        public static Consulta<EstadoDeDiscos> Estado(RespuestaCruda r)
            => Leer(r, e => new EstadoDeDiscos(
                Estado: e.GetProperty("estado").GetString() ?? throw new InvalidOperationException(),
                Leyendo: e.GetProperty("leyendo").GetBoolean(),
                UltimaLectura: Fecha(e, "ultima_lectura"),
                ProximaLectura: Fecha(e, "proxima_lectura"),
                Error: Texto(e, "error"),
                AdvertenciaDeHistorial: Texto(e, "advertencia_historial"),
                Discos: e.GetProperty("discos").EnumerateArray().Select(d => new DiscoVista(
                    d.GetProperty("modelo").GetString() ?? throw new InvalidOperationException(),
                    Texto(d, "serie") ?? "",
                    d.GetProperty("sin_datos").GetBoolean(),
                    d.TryGetProperty("prediccion_fallo", out JsonElement p) && p.ValueKind != JsonValueKind.Null ? p.GetBoolean() : null,
                    d.GetProperty("atributos_leidos").GetInt32(),
                    d.GetProperty("atributos_clave_leidos").EnumerateArray().Select(x => x.GetInt32()).ToList(),
                    Entero(d, "temperatura_c"),
                    Entero(d, "desgaste_porcentaje"),
                    d.TryGetProperty("horas_encendido", out JsonElement h) && h.ValueKind != JsonValueKind.Null ? h.GetInt64() : null,
                    Severidades.Contains(d.GetProperty("severidad").GetString()) ? d.GetProperty("severidad").GetString()! : throw new InvalidOperationException(),
                    Textos(d.GetProperty("alertas")),
                    Textos(d.GetProperty("limitaciones")))).ToList()));

        public static Consulta<PedidoDeLectura> Pedido(RespuestaCruda r)
            => Leer(r, e => new PedidoDeLectura(e.GetProperty("iniciada").GetBoolean(), Texto(e, "motivo") ?? ""));

        private static Consulta<T> Leer<T>(RespuestaCruda r, Func<JsonElement, T> leer) where T : class
        {
            if (!r.Exito) return Consulta<T>.Mal(string.IsNullOrEmpty(r.Error) ? "el servicio contestó con un error" : r.Error);
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

        private static IReadOnlyList<string> Textos(JsonElement a) => a.EnumerateArray().Select(x => x.GetString() ?? "").ToList();

        private static string? Texto(JsonElement e, string nombre)
            => e.TryGetProperty(nombre, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

        private static int? Entero(JsonElement e, string nombre)
            => e.TryGetProperty(nombre, out JsonElement v) && v.ValueKind != JsonValueKind.Null ? v.GetInt32() : null;

        private static DateTimeOffset? Fecha(JsonElement e, string nombre)
            => e.TryGetProperty(nombre, out JsonElement v) && v.ValueKind != JsonValueKind.Null ? v.GetDateTimeOffset() : null;
    }

    /// <summary>
    /// Como se presenta la salud. Reglas:
    /// - un disco sin datos, o del que solo se leyo temperatura/desgaste (sin la bandera ni ningun atributo clave), NO es «correcto»;
    /// - «sin alertas» dice que se pudo leer;
    /// - una lectura fallida se dice, y los datos anteriores llevan su fecha.
    /// </summary>
    public static class ResumirDisco
    {
        public static (Indicador Indicador, string Estado, string Detalle) Disco(DiscoVista d)
        {
            if (d.SinDatos)
                return (Indicador.SinDatos, "Sin datos", "No se pudo leer nada de este disco"
                        + (d.Limitaciones.Count > 0 ? ": " + d.Limitaciones[0].TrimEnd('.') + "." : "."));

            switch (d.Severidad)
            {
                case "critica":
                case "alta":
                    return (Indicador.Alerta, d.Severidad == "critica" ? "Riesgo de fallo" : "Con problemas",
                        Primera(d) + " Haga una copia de seguridad de lo importante.");
                case "media":
                case "baja":
                    return (Indicador.Atencion, "Vigilar", Primera(d));
            }

            bool evaluable = d.PrediccionDeFallo is not null || d.AtributosClaveLeidos.Count > 0;
            if (!evaluable)
                return (Indicador.SinDatos, "Sin evaluar",
                    "No expone la bandera de fallo ni los atributos S.M.A.R.T. que anticipan fallos; solo "
                    + Leido(d) + ". Eso no basta para decir que está bien.");

            var leido = new List<string>();
            if (d.PrediccionDeFallo is not null) leido.Add("la bandera de fallo");
            if (d.AtributosClaveLeidos.Count > 0)
                leido.Add(d.AtributosClaveLeidos.Count + " de " + 5 + " atributos que anticipan fallos");
            return (Indicador.Correcto, "Sin alertas", "Se revisó " + string.Join(" y ", leido) + ".");
        }

        public static (Indicador Indicador, string Estado, string Detalle) General(Consulta<EstadoDeDiscos>? c)
        {
            if (c is null) return (Indicador.SinDatos, "Sin consultar", "Todavía no se ha preguntado al servicio.");
            if (c.Valor is not EstadoDeDiscos s) return (Indicador.SinDatos, "Sin datos", "No se pudo consultar: " + c.Error + ".");
            if (s.Estado == "apagado") return (Indicador.SinDatos, "Apagado", "No está activado (Nexo:Disco:Activo en appsettings.json).");
            if (s.Estado == "nunca")
                return (Indicador.SinDatos, s.Leyendo ? "Leyendo" : "Sin leer todavía",
                    s.Leyendo ? "El servicio está leyendo los discos por primera vez." : "El servicio aún no ha leído los discos.");
            if (s.Estado != "listo" && s.Estado != "fallido") return (Indicador.SinDatos, "Sin datos", "El servicio contestó un estado desconocido.");

            string? fallo = s.Estado == "fallido" ? "La última lectura falló (" + (s.Error ?? "sin motivo") + ")" : null;
            if (s.Discos.Count == 0)
                return (fallo is null ? Indicador.SinDatos : Indicador.Atencion, fallo is null ? "Ningún disco" : "Falló la lectura",
                    fallo is null ? "El servicio no encontró ningún disco que leer." : fallo + ".");

            var filas = s.Discos.Select(Disco).ToList();
            int alertas = filas.Count(f => f.Indicador == Indicador.Alerta);
            int atencion = filas.Count(f => f.Indicador == Indicador.Atencion);
            int bien = filas.Count(f => f.Indicador == Indicador.Correcto);
            int sinDatos = filas.Count - alertas - atencion - bien;
            string fecha = s.UltimaLectura is DateTimeOffset u ? " (leído el " + Resumir.Fecha(u) + ")" : "";

            (Indicador ind, string estado, string detalle) r;
            if (alertas > 0)
                r = (Indicador.Alerta, alertas == 1 ? "1 disco con problemas" : alertas + " discos con problemas",
                     NombreDelPeor(s.Discos, filas, Indicador.Alerta) + fecha + ".");
            else if (atencion > 0)
                r = (Indicador.Atencion, "Vigilar " + (atencion == 1 ? "1 disco" : atencion + " discos"),
                     NombreDelPeor(s.Discos, filas, Indicador.Atencion) + fecha + ".");
            else if (bien == 0)
                r = (Indicador.SinDatos, "Sin evaluar", "No se pudo evaluar ningún disco" + fecha + ".");
            else
                r = (Indicador.Correcto, "Sin alertas",
                     (bien == filas.Count ? (bien == 1 ? "1 disco revisado" : bien + " discos revisados")
                                          : bien + " de " + filas.Count + " discos revisados; " + sinDatos + " sin datos") + fecha + ".");

            // Una lectura fallida no es un problema del disco, pero los datos ya no son de ahora: al menos «atencion».
            if (fallo is not null)
                r = (r.ind == Indicador.Alerta ? Indicador.Alerta : Indicador.Atencion, r.ind == Indicador.Alerta ? r.estado : "Falló la lectura",
                     fallo + ". Datos anteriores: " + r.detalle);
            return r;
        }

        /// <summary>Temperatura, desgaste y horas en texto; «—» si el disco no lo informa.</summary>
        public static string Temperatura(DiscoVista d) => d.TemperaturaC is int t ? t + " °C" : "—";
        public static string Desgaste(DiscoVista d) => d.DesgastePorcentaje is int w ? w + " %" : "—";
        public static string Horas(DiscoVista d)
            => d.HorasEncendido is long h ? h.ToString("#,0", CultureInfo.InvariantCulture).Replace(",", " ") + " h" : "—";

        private static string Primera(DiscoVista d)
            => d.Alertas.Count == 0 ? "El evaluador lo marcó sin detallar por qué."
             : d.Alertas[0] + "." + (d.Alertas.Count > 1 ? " Y " + (d.Alertas.Count - 1) + " más." : "");

        private static string Leido(DiscoVista d)
        {
            var l = new List<string>();
            if (d.TemperaturaC is not null) l.Add("la temperatura");
            if (d.DesgastePorcentaje is not null) l.Add("el desgaste");
            if (d.HorasEncendido is not null) l.Add("las horas de uso");
            if (d.AtributosLeidos > 0 && d.AtributosClaveLeidos.Count == 0) l.Add(d.AtributosLeidos + " atributos que no anticipan fallos");
            return l.Count == 0 ? "datos sueltos" : string.Join(", ", l);
        }

        private static string NombreDelPeor(IReadOnlyList<DiscoVista> discos, List<(Indicador Indicador, string Estado, string Detalle)> filas, Indicador i)
        {
            int k = filas.FindIndex(f => f.Indicador == i);
            return discos[k].Modelo + ": " + filas[k].Detalle.TrimEnd('.');
        }
    }
}
