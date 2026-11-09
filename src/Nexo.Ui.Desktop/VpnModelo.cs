using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Avalonia.Media;
using Nexo.Modules.Threats.Enlaces;
using Nexo.Modules.Threats.Vpn;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Ui.Desktop
{
    public sealed record FilaDeTunel(string Nombre, string Estado, IBrush Color);

    /// <summary>Sin Windows (o en la vista de diseño) no hay servicios que leer: se dice, no se inventa «no instalado».</summary>
    public sealed class LectorDeWireGuardNoDisponible : ILectorDeWireGuard
    {
        private readonly string _motivo;
        public LectorDeWireGuardNoDisponible(string motivo) => _motivo = motivo;
        public EstadoDeWireGuard Leer() => EstadoDeWireGuard.NoSePudo(_motivo);
    }

    /// <summary>
    /// La pestaña «VPN». En este paso es de SOLO LECTURA: mira si WireGuard esta instalado y que tuneles hay, y revisa archivos .conf. Conectar y
    /// desconectar (que necesita administrador) llegara por el servicio con aprobacion. Reglas (probadas en tools/Nexo.Desktop.Demo):
    ///  - La clave privada nunca se muestra ni queda en el modelo (el lector la valida y la descarta).
    ///  - «Túnel activo» es lo que Windows dice del servicio; que el servidor responda no se comprueba sin administrador, y se dice.
    ///  - Revisar un archivo no lo instala, no lo copia y no se conecta a nada.
    /// </summary>
    public sealed class VpnModelo : INotifyPropertyChanged
    {
        private readonly ILectorDeWireGuard _lector;
        private readonly Func<ListasDePhishing> _listas;
        private EstadoDeWireGuard? _estado;
        private bool _leyendo;
        private LecturaDeConfiguracionWg? _lectura;
        private ResultadoDeAnalisis? _analisis;
        private string? _archivo;
        private string? _errorDeArchivo;
        private readonly IServicioDeVpn _servicio;
        // El texto del archivo revisado (lleva la clave privada): PRIVADO, solo para enviarlo al servicio al conectar. Ninguna propiedad lo
        // expone, y se olvida al revisar otro archivo, al olvidar este y tras intentar conectar.
        private string? _textoParaConectar;

        public VpnModelo(ILectorDeWireGuard lector, Func<ListasDePhishing>? listas = null, IServicioDeVpn? servicio = null)
        {
            _servicio = servicio ?? new ServicioDeVpnNoDisponible("sin conexión con el servicio de Nexo");
            _lector = lector;
            _listas = listas ?? (() => ListasDePhishing.Vacias);
            Calcular();
        }

        public static VpnModelo PorOmision(Func<ListasDePhishing>? listas = null, IRastroDeVentana? rastro = null, IServicioDeVpn? servicio = null)
        {
#if WINDOWS
            ILectorDeWireGuard l = new Nexo.Modules.Threats.Windows.LectorDeWireGuardWindows();
#else
            ILectorDeWireGuard l = new LectorDeWireGuardNoDisponible("WireGuard para Windows solo existe en Windows");
#endif
            return new VpnModelo(l, listas, servicio) { Rastro = rastro ?? RastroNulo.Instancia };
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public IRastroDeVentana Rastro { get; set; } = RastroNulo.Instancia;

        public string EstadoTitulo { get; private set; } = "";
        public string EstadoDetalle { get; private set; } = "";
        public IBrush EstadoColor { get; private set; } = Colores.De(Indicador.SinDatos);
        public IReadOnlyList<FilaDeTunel> Tuneles { get; private set; } = Array.Empty<FilaDeTunel>();
        public bool HayTuneles => Tuneles.Count > 0;
        public bool PuedeActualizar => !_leyendo;

        public string ArchivoTitulo { get; private set; } = "";
        public string ArchivoDetalle { get; private set; } = "";
        public IBrush ArchivoColor { get; private set; } = Colores.De(Indicador.SinDatos);
        public Indicador ArchivoIndicador { get; private set; } = Indicador.SinDatos;
        public IReadOnlyList<string> Errores { get; private set; } = Array.Empty<string>();
        public bool HayErrores => Errores.Count > 0;
        public IReadOnlyList<FilaDeHallazgoVista> Hallazgos { get; private set; } = Array.Empty<FilaDeHallazgoVista>();
        public bool HayHallazgos => Hallazgos.Count > 0;

        /// <summary>Solo con un archivo que WireGuard aceptaria (el servicio vuelve a revisar todo y puede rechazarlo igual).</summary>
        public bool PuedeConectar => _textoParaConectar is not null && _lectura?.Valida == true && !_ocupado;
        private bool _ocupado;

        /// <summary>Pide al servicio el plan para conectar con el archivo revisado. No cambia nada.</summary>
        public async Task<Consulta<PlanDelServicio>> PrevisualizarConexionAsync(System.Threading.CancellationToken ct = default)
        {
            if (_textoParaConectar is null || _archivo is null) return Consulta<PlanDelServicio>.Mal("primero elige un archivo .conf válido");
            return await _servicio.PrevisualizarConexionAsync(_textoParaConectar, _archivo, ct).ConfigureAwait(true);
        }

        public Task<Consulta<PlanDelServicio>> PrevisualizarDesconexionAsync(string tunel, System.Threading.CancellationToken ct = default)
            => _servicio.PrevisualizarDesconexionAsync(tunel, ct);

        /// <summary>Aplica un plan confirmado. Tras intentarlo se olvida el texto del archivo y se vuelve a leer el estado.</summary>
        public async Task<ResultadoDeAccion> AplicarAsync(string token, bool eraConexion, System.Threading.CancellationToken ct = default)
        {
            _ocupado = true;
            Calcular();
            try
            {
                ResultadoDeAccion r = await _servicio.AplicarAsync(token, ct).ConfigureAwait(true);
                if (eraConexion && !r.PidioAprobacion) _textoParaConectar = null;
                return r;
            }
            finally
            {
                _ocupado = false;
                await ActualizarAsync().ConfigureAwait(true);
            }
        }

        public async Task ActualizarAsync()
        {
            if (_leyendo) return;
            _leyendo = true;
            Calcular();
            try
            {
                try { _estado = await Task.Run(() => _lector.Leer()).ConfigureAwait(true); }
                catch (Exception e) { _estado = EstadoDeWireGuard.NoSePudo("no se pudo leer el estado (" + e.GetType().Name + ")"); }
            }
            finally
            {
                _leyendo = false;
                Calcular();
            }
        }

        /// <summary>Lee y revisa un archivo .conf. No lo instala, no lo copia y no se conecta a nada.</summary>
        public async Task RevisarArchivoAsync(Stream archivo, string nombre)
        {
            _lectura = null; _analisis = null; _errorDeArchivo = null; _textoParaConectar = null;
            _archivo = nombre;
            try
            {
                string? texto = await Task.Run(() => LeerTexto(archivo)).ConfigureAwait(true);
                if (texto is null) _errorDeArchivo = "el archivo es demasiado grande para ser una configuración de WireGuard";
                else
                {
                    ListasDePhishing listas = _listas();
                    (_lectura, _analisis) = await Task.Run(() =>
                    {
                        LecturaDeConfiguracionWg l = ParserDeWireGuard.Leer(texto, nombre);
                        return (l, l.Configuracion is null ? null : AnalizadorDeVpn.Analizar(l.Configuracion, listas));
                    }).ConfigureAwait(true);
                    AvisarRastro();
                    if (_lectura.Valida) _textoParaConectar = texto;
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or DecoderFallbackException)
            {
                _errorDeArchivo = "no se pudo leer el archivo (" + e.GetType().Name + ")";
            }
            Calcular();
        }

        private static string? LeerTexto(Stream s)
        {
            using var lector = new StreamReader(s, new UTF8Encoding(false, false), detectEncodingFromByteOrderMarks: true);
            var buf = new char[ParserDeWireGuard.MaximoDeCaracteres + 1];
            int total = 0, n;
            while (total < buf.Length && (n = lector.Read(buf, total, buf.Length - total)) > 0) total += n;
            if (total > ParserDeWireGuard.MaximoDeCaracteres) return null;
            string t = new string(buf, 0, total);
            Array.Clear(buf);
            return t;
        }

        public void OlvidarArchivo()
        {
            _lectura = null; _analisis = null; _archivo = null; _errorDeArchivo = null; _textoParaConectar = null;
            Calcular();
        }

        /// <summary>Solo conteos y gravedad: ni el nombre del túnel, ni el servidor, ni claves.</summary>
        private void AvisarRastro()
        {
            ResultadoDeAnalisis? a = _analisis;
            int n = a?.Hallazgos.Count(h => h.Severidad != Severidad.Info) ?? 0;
            string maxima = n == 0 ? "Info" : a!.Hallazgos.Where(h => h.Severidad != Severidad.Info).Max(h => h.Severidad).ToString();
            var campos = new Dictionary<string, object?>(StringComparer.Ordinal) { ["hallazgos"] = n, ["maxima"] = maxima, ["completa"] = _lectura?.Valida ?? false };
            try { Rastro.Avisar("vpn.revision", campos); } catch (Exception) { /* el rastro nunca rompe la revision */ }
        }

        private void Calcular()
        {
            (Indicador ie, string te, string de) = ResumirVpn.Estado(_estado, _leyendo);
            EstadoTitulo = te; EstadoDetalle = de; EstadoColor = Colores.De(ie);
            Tuneles = _estado?.Tuneles.Select(t => new FilaDeTunel(t.Nombre, ResumirVpn.Tunel(t.Estado), Colores.De(t.Estado == EstadoDeTunel.Desconocido ? Indicador.Atencion : Indicador.SinDatos))).ToList()
                      ?? (IReadOnlyList<FilaDeTunel>)Array.Empty<FilaDeTunel>();

            (Indicador ia, string ta, string da) = ResumirVpn.Archivo(_archivo, _errorDeArchivo, _lectura, _analisis);
            ArchivoIndicador = ia; ArchivoTitulo = ta; ArchivoDetalle = da; ArchivoColor = Colores.De(ia);
            Errores = _lectura?.Errores ?? (IReadOnlyList<string>)Array.Empty<string>();
            Hallazgos = _analisis?.Hallazgos.Select(h => new FilaDeHallazgoVista(ResumirSeguridad.Gravedad(h.Severidad), Colores.De(ResumirSeguridad.IndicadorDe(h.Severidad)),
                                                    h.Titulo, h.Sujeto ?? "", h.Sujeto is not null, h.Detalle, h.Recomendacion)).ToList()
                        ?? (IReadOnlyList<FilaDeHallazgoVista>)Array.Empty<FilaDeHallazgoVista>();

            foreach (string p in new[] { nameof(EstadoTitulo), nameof(EstadoDetalle), nameof(EstadoColor), nameof(Tuneles), nameof(HayTuneles), nameof(PuedeActualizar),
                                         nameof(ArchivoTitulo), nameof(ArchivoDetalle), nameof(ArchivoColor), nameof(ArchivoIndicador), nameof(Errores), nameof(HayErrores),
                                         nameof(Hallazgos), nameof(HayHallazgos), nameof(PuedeConectar) })
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));
        }
    }

    /// <summary>Los textos y colores de la pestaña «VPN», sin interfaz.</summary>
    public static class ResumirVpn
    {
        public const string Instalar = "El cliente oficial de WireGuard es gratuito (licencia MIT). Se instala con «winget install WireGuard.WireGuard» o desde wireguard.com; Nexo no lo instala solo.";

        public static string Tunel(EstadoDeTunel e) => e switch
        {
            EstadoDeTunel.Activo => "Activo (Windows lo tiene en marcha)",
            EstadoDeTunel.Detenido => "Detenido",
            EstadoDeTunel.Cambiando => "Arrancando o deteniéndose",
            _ => "No se pudo saber"
        };

        /// <summary>Gris siempre que no hay problema: que el túnel esté en marcha no prueba que el servidor responda.</summary>
        public static (Indicador, string, string) Estado(EstadoDeWireGuard? e, bool leyendo)
        {
            if (leyendo) return (Indicador.SinDatos, "Leyendo...", "");
            if (e is null) return (Indicador.SinDatos, "Sin leer todavía", "Pulsa «Actualizar» para ver si WireGuard está instalado y qué túneles hay.");
            if (e.Error is not null) return (Indicador.Atencion, "No se pudo saber el estado de WireGuard", e.Error + ".");
            if (!e.Instalado)
                return (Indicador.SinDatos, "WireGuard no está instalado",
                    Instalar + (e.Tuneles.Count > 0 ? " Ojo: Windows tiene servicios de túnel de WireGuard aunque el programa no está; puede ser una instalación a medias." : " Revisar archivos .conf funciona igual sin él."));
            int activos = e.Tuneles.Count(t => t.Estado == EstadoDeTunel.Activo);
            string version = "WireGuard " + (e.Version ?? "(versión desconocida)") + " instalado";
            if (e.Tuneles.Count == 0) return (Indicador.SinDatos, version + ", sin túneles", "Todavía no hay ningún túnel instalado.");
            return (Indicador.SinDatos, activos == 0 ? version + ": ningún túnel activo" : version + ": " + activos + (activos == 1 ? " túnel activo" : " túneles activos"),
                activos == 0 ? "La VPN no está conectada." : "«Activo» es lo que Windows dice del servicio del túnel: que el servidor responda no se puede comprobar sin permisos de administrador.");
        }

        public static (Indicador, string, string) Archivo(string? archivo, string? error, LecturaDeConfiguracionWg? l, ResultadoDeAnalisis? a)
        {
            if (archivo is null) return (Indicador.SinDatos, "Ningún archivo revisado", "Elige el archivo .conf que te dio tu proveedor de VPN. Nexo lo lee y lo revisa en tu equipo: no lo instala ni se conecta.");
            string nombre = "«" + archivo + "»";
            if (error is not null) return (Indicador.Atencion, "No se pudo revisar " + nombre, error + ".");
            if (l is null) return (Indicador.SinDatos, "Revisando " + nombre + "...", "");
            if (l.Configuracion is null)
                return (Indicador.Atencion, "WireGuard rechazará " + nombre, "El archivo tiene errores (abajo). No es un problema de seguridad: el programa no lo aceptará tal cual.");
            Severidad max = a?.Maxima ?? Severidad.Info;
            string nombreTunel = l.ErrorDeNombre is null ? " El túnel se llamará «" + l.NombreDeTunel + "»." : " Pero WireGuard no aceptará el nombre «" + l.NombreDeTunel + "»: " + l.ErrorDeNombre + ". Renombra el archivo.";
            if (max >= Severidad.Alta) return (Indicador.Alerta, "Cuidado con " + nombre, "Tiene problemas graves (abajo)." + nombreTunel);
            if (max >= Severidad.Baja) return (Indicador.Atencion, nombre + " funcionará, pero revisa lo de abajo", "Hay cosas que conviene corregir." + nombreTunel);
            if (l.ErrorDeNombre is not null) return (Indicador.Atencion, "El contenido de " + nombre + " está bien, pero el nombre no", nombreTunel.Trim());
            return (Indicador.Correcto, nombre + " está bien", "El archivo es válido y no tiene fugas ni comandos peligrosos." + nombreTunel + " Abajo hay notas que conviene saber.");
        }
    }
}
