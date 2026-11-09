using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Service
{
    /// <summary>
    /// El rastro de lo que hace la ventana (revisiones de seguridad, bóveda de contraseñas) en el vault de reportes. La ventana corre
    /// con el usuario y NO escribe en el vault (es del servicio): avisa por el pipe, y el servicio escribe. Reglas, porque el cliente
    /// no es de fiar:
    ///  - El cliente solo elige una clave de un catalogo fijo («tipo») y unos pocos numeros o etiquetas acotadas. El TEXTO del evento
    ///    lo pone siempre el servicio: ningun programa puede colar texto propio en las notas.
    ///  - Solo cuentas y etiquetas: jamas nombres de cuenta, de redes Wi-Fi, de programas, sitios, usuarios ni contraseñas.
    ///  - Cada nota dice que la informo la ventana y que el servicio no lo comprobo (un proceso del mismo usuario podria mentir).
    ///  - Tope de avisos: un minimo entre dos del mismo tipo y un maximo por hora (un programa no puede inundar el vault).
    /// </summary>
    public sealed class ModuloRastroDeVentana : IModuloDelServicio
    {
        public const string Registrar = "ventana.registrar";
        public static readonly TimeSpan MinimoEntreIguales = TimeSpan.FromSeconds(2);
        public const int MaximoPorHora = 120;

        private sealed record Definicion(ModuloOrigen Modulo, string Tipo, string Titulo, bool Revision, bool Bloqueo = false, bool Entradas = false, bool Auditoria = false);

        private static readonly Dictionary<string, Definicion> Catalogo = new(StringComparer.Ordinal)
        {
            ["seguridad.cuentas"] = new(ModuloOrigen.Amenazas, TipoEvento.VulnerabilidadDetectada, "Revisión de cuentas y contraseñas del sistema (desde la ventana)", Revision: true),
            ["seguridad.wifi"] = new(ModuloOrigen.Amenazas, TipoEvento.VulnerabilidadDetectada, "Revisión de Wi-Fi (desde la ventana)", Revision: true),
            ["seguridad.aplicaciones"] = new(ModuloOrigen.Amenazas, TipoEvento.VulnerabilidadDetectada, "Revisión de aplicaciones desactualizadas (desde la ventana)", Revision: true),
            ["seguridad.dispositivos"] = new(ModuloOrigen.Privacidad, TipoEvento.AccesoDispositivo, "Revisión de uso de cámara y micrófono (desde la ventana)", Revision: true),
            ["seguridad.fallos_conocidos"] = new(ModuloOrigen.Amenazas, TipoEvento.VulnerabilidadDetectada, "Consulta de fallos conocidos en NVD (desde la ventana)", Revision: true),
            ["vpn.revision"] = new(ModuloOrigen.Privacidad, TipoEvento.ConfiguracionVpnRevisada, "Revisión de un archivo de VPN (desde la ventana)", Revision: true),
            ["enlaces.revision"] = new(ModuloOrigen.Privacidad, TipoEvento.MensajeRevisado, "Revisión de un mensaje o enlace contra phishing (desde la ventana)", Revision: true),
            ["boveda.creada"] = new(ModuloOrigen.Identidad, TipoEvento.BovedaCreada, "Bóveda de contraseñas creada (desde la ventana)", Revision: false),
            ["boveda.desbloqueada"] = new(ModuloOrigen.Identidad, TipoEvento.BovedaDesbloqueada, "Bóveda de contraseñas desbloqueada (desde la ventana)", Revision: false, Entradas: true),
            ["boveda.bloqueada"] = new(ModuloOrigen.Identidad, TipoEvento.BovedaBloqueada, "Bóveda de contraseñas bloqueada (desde la ventana)", Revision: false, Bloqueo: true),
            ["boveda.fallo_de_desbloqueo"] = new(ModuloOrigen.Identidad, TipoEvento.BovedaFalloDeDesbloqueo, "Intento fallido de abrir la bóveda (desde la ventana)", Revision: false),
            ["boveda.copia_guardada"] = new(ModuloOrigen.Identidad, TipoEvento.BovedaCopiaGuardada, "Copia de seguridad de la bóveda guardada (desde la ventana)", Revision: false),
            ["boveda.restaurada"] = new(ModuloOrigen.Identidad, TipoEvento.BovedaRestaurada, "Bóveda restaurada desde una copia (desde la ventana)", Revision: false),
            ["boveda.auditoria"] = new(ModuloOrigen.Identidad, TipoEvento.BovedaAuditada, "Comprobación de filtraciones de la bóveda (desde la ventana)", Revision: false, Auditoria: true)
        };

        public static readonly IReadOnlyList<string> Claves = new List<string>(Catalogo.Keys);

        private static readonly string[] Motivos = { "manual", "inactividad", "minimizar", "sesion", "cierre" };
        private static readonly string[] Gravedades = { "Info", "Baja", "Media", "Alta", "Critica" };

        private readonly IReportWriter _reportes;
        private readonly Func<DateTimeOffset> _reloj;
        private readonly Dictionary<string, DateTimeOffset> _ultimo = new(StringComparer.Ordinal);
        private readonly Queue<DateTimeOffset> _hora = new();
        private readonly object _cerrojo = new();

        public ModuloRastroDeVentana(IReportWriter reportes, Func<DateTimeOffset>? reloj = null)
        {
            _reportes = reportes;
            _reloj = reloj ?? (() => DateTimeOffset.UtcNow);
        }

        public IReadOnlyList<string> Metodos { get; } = new[] { Registrar };

        public async Task<object?> ManejarAsync(string metodo, JsonElement? p, CancellationToken ct)
        {
            if (metodo != Registrar) throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            if (p is not { ValueKind: JsonValueKind.Object } o) throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "faltan los parametros");

            string tipo = Texto(o, "tipo") ?? throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta el tipo");
            if (!Catalogo.TryGetValue(tipo, out Definicion? d)) throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "tipo desconocido");

            // Solo los campos que ese tipo admite; cualquier otro, o un valor fuera de rango, se rechaza (no se ignora en silencio).
            var permitidos = new HashSet<string>(StringComparer.Ordinal) { "tipo" };
            if (d.Revision) { permitidos.Add("hallazgos"); permitidos.Add("maxima"); permitidos.Add("completa"); }
            if (d.Bloqueo) permitidos.Add("motivo");
            if (d.Entradas) permitidos.Add("entradas");
            if (d.Auditoria) { permitidos.Add("comprobadas"); permitidos.Add("comprometidas"); }
            foreach (JsonProperty prop in o.EnumerateObject())
                if (!permitidos.Contains(prop.Name)) throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "parametro no admitido: " + prop.Name);

            Severidad sev = Severidad.Info;
            var campos = new Dictionary<string, object?>(StringComparer.Ordinal) { ["origen"] = "ventana" };
            var cuerpo = new System.Text.StringBuilder();

            if (d.Revision)
            {
                int hallazgos = Entero(o, "hallazgos", 0, 1000);
                string maxima = Texto(o, "maxima") ?? "Info";
                if (Array.IndexOf(Gravedades, maxima) < 0) throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "gravedad no valida");
                bool completa = Logico(o, "completa");
                if (hallazgos == 0 && maxima != "Info") throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "sin hallazgos no puede haber gravedad");
                campos["hallazgos"] = hallazgos;
                campos["completa"] = completa;
                if (hallazgos > 0)
                {
                    sev = (Severidad)Array.IndexOf(Gravedades, maxima);
                    campos["gravedad_maxima"] = maxima;
                }
                // Incompleta sin hallazgos: lo desconocido no es «bien» (misma regla que las revisiones del servicio).
                else if (!completa) sev = Severidad.Media;
                cuerpo.AppendLine(hallazgos == 0 ? (completa ? "Sin hallazgos." : "Sin hallazgos, pero la revisión quedó **incompleta**: esto NO significa que esté bien.")
                                                  : hallazgos + " hallazgo(s), el más grave de gravedad " + maxima.ToLowerInvariant() + (completa ? "." : ". La revisión quedó **incompleta**."));
            }
            if (d.Bloqueo)
            {
                string motivo = Texto(o, "motivo") ?? "manual";
                if (Array.IndexOf(Motivos, motivo) < 0) throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "motivo no valido");
                campos["motivo"] = motivo;
                cuerpo.AppendLine("Motivo del bloqueo: " + motivo + ".");
            }
            if (d.Entradas) campos["entradas"] = Entero(o, "entradas", 0, 100000);
            if (d.Auditoria)
            {
                int comprobadas = Entero(o, "comprobadas", 0, 100000), comprometidas = Entero(o, "comprometidas", 0, 100000);
                if (comprometidas > comprobadas) throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "hay mas comprometidas que comprobadas");
                campos["comprobadas"] = comprobadas;
                campos["comprometidas"] = comprometidas;
                if (comprometidas > 0) sev = Severidad.Alta;
            }
            cuerpo.AppendLine();
            cuerpo.AppendLine("*Informado por la ventana; el servicio no lo comprobó por su cuenta. Solo lleva conteos: nunca nombres de cuentas, redes, programas, sitios ni contraseñas.*");
            var e = new NexoEvent(d.Modulo, d.Tipo, d.Titulo) { Severidad = sev, Accion = Accion.Registrada, Cuerpo = cuerpo.ToString() };
            foreach (KeyValuePair<string, object?> kv in campos) e.Campos[kv.Key] = kv.Value;

            if (!Admitir(tipo)) return new { registrado = false, motivo = "demasiados avisos seguidos: este no se registró" };
            await _reportes.EscribirAsync(e, ct).ConfigureAwait(false);
            return new { registrado = true, motivo = "" };
        }

        /// <summary>Los topes de frecuencia. false = no se registra (y no cuenta como aviso admitido).</summary>
        private bool Admitir(string tipo)
        {
            lock (_cerrojo)
            {
                DateTimeOffset ahora = _reloj();
                while (_hora.Count > 0 && ahora - _hora.Peek() >= TimeSpan.FromHours(1)) _hora.Dequeue();
                if (_hora.Count >= MaximoPorHora) return false;
                if (_ultimo.TryGetValue(tipo, out DateTimeOffset u) && ahora - u < MinimoEntreIguales) return false;
                _ultimo[tipo] = ahora;
                _hora.Enqueue(ahora);
                return true;
            }
        }

        private static string? Texto(JsonElement o, string nombre)
            => o.TryGetProperty(nombre, out JsonElement v) ? (v.ValueKind == JsonValueKind.String ? v.GetString() : throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, nombre + " debe ser texto")) : null;

        private static int Entero(JsonElement o, string nombre, int min, int max)
        {
            if (!o.TryGetProperty(nombre, out JsonElement v)) return min;
            if (v.ValueKind != JsonValueKind.Number || !v.TryGetInt32(out int n) || n < min || n > max)
                throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, nombre + " fuera de rango");
            return n;
        }

        private static bool Logico(JsonElement o, string nombre)
        {
            if (!o.TryGetProperty(nombre, out JsonElement v)) throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, "falta " + nombre);
            if (v.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new ErrorDeComando(CodigoDeError.ParametrosInvalidos, nombre + " debe ser verdadero o falso");
            return v.GetBoolean();
        }
    }
}
