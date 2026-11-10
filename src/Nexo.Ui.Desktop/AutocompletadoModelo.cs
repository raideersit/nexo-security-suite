using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Identity.Autocompletado;
using Nexo.Modules.Identity.Boveda;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Ui.Desktop
{
    /// <summary>
    /// La parte del autocompletado que vive en la ventana (§2ao): atiende el pipe del host nativo con el <see cref="PuenteDeAutocompletado"/> sobre
    /// la bóveda ABIERTA de esta ventana, y enseña los navegadores emparejados. Reglas:
    ///  - Emparejar solo se admite durante <see cref="PlazoParaEmparejar"/> tras pulsar «Emparejar un navegador…» aquí. Fuera de ese plazo no se
    ///    pregunta nada (un programa no puede hacer saltar la pregunta para que la aceptes sin querer) y se avisa de que alguien lo intentó.
    ///  - Tras una respuesta (sí o no) el plazo se cierra: un emparejamiento por vez.
    ///  - Lo que pide el navegador NO cuenta como actividad: la bóveda se sigue bloqueando sola.
    ///  - Si el canal ya lo atiende otro (otra ventana de Nexo u otro programa con tu usuario), esta ventana NO se suma y lo dice.
    ///  - Al rastro del servicio solo va QUÉ pasó, nunca el navegador ni el sitio.
    /// </summary>
    public sealed class AutocompletadoModelo : INotifyPropertyChanged, IAsyncDisposable
    {
        public static readonly TimeSpan PlazoParaEmparejar = TimeSpan.FromMinutes(2);
        public const string NoSolicitado = "en Nexo, abre «Contraseñas» y pulsa «Emparejar un navegador…» antes de pedirlo aquí";

        private readonly INavegadoresEmparejados _emparejados;
        private readonly string _pipe;
        private readonly Func<DateTimeOffset> _reloj;
        private readonly Action<Action> _enUi;
        private readonly PuenteDeAutocompletado _puente;
        private ServidorDeAutocompletado? _servidor;
        private long _armadoHastaTicks;              // 0 = no se admite emparejar; se lee desde el hilo del pipe
        private string _estado = "El autocompletado aún no se ha iniciado.";
        private string _aviso = "";
        private string _ultimaActividad = "";
        private string? _seleccionado;
        private IReadOnlyList<string> _navegadores = Array.Empty<string>();

        /// <param name="entradas">Las entradas de la bóveda abierta, o null si está bloqueada (normalmente <see cref="ContrasenasModelo.EntradasParaAutocompletar"/>).</param>
        /// <param name="enUi">Cómo pasar trabajo al hilo de la interfaz (los avisos del puente llegan desde el hilo del pipe).</param>
        public AutocompletadoModelo(Func<IReadOnlyList<EntradaDeBoveda>?> entradas, INavegadoresEmparejados emparejados, string nombrePipe,
                                    Action<Action> enUi, Func<DateTimeOffset>? reloj = null)
        {
            _emparejados = emparejados;
            _pipe = nombrePipe;
            _enUi = enUi;
            _reloj = reloj ?? (() => DateTimeOffset.Now);
            _puente = new PuenteDeAutocompletado(entradas, emparejados, ConfirmarAsync, _reloj, _ => Armado ? null : NoSolicitado);
            _puente.Emparejado += n => _enUi(() =>
            {
                Desarmar();
                UltimaActividad = "Emparejado «" + n + "» a las " + Hora() + ".";
                AvisarRastro("autocompletado.emparejado");
                RefrescarNavegadores();
            });
            _puente.EmparejamientoRechazado += n => _enUi(() =>
            {
                Desarmar();
                UltimaActividad = "No se emparejó «" + n + "» (" + Hora() + ").";
                AvisarRastro("autocompletado.rechazado");
            });
            _puente.EmparejamientoNoAdmitido += n => _enUi(() =>
            {
                Aviso = "A las " + Hora() + " algo («" + n + "») pidió emparejarse con la bóveda sin que pulsaras «Emparejar un navegador…». "
                      + "No se le dio nada. Si no fuiste tú desde la extensión de Nexo, revisa el equipo.";
                AvisarRastro("autocompletado.no_solicitado");
            });
            _puente.Rellenado += (n, sitio) => _enUi(() =>
            {
                UltimaActividad = "Último rellenado: «" + n + "» en " + sitio + ", a las " + Hora() + ".";
                AvisarRastro("autocompletado.rellenado");
            });
            RefrescarNavegadores();
        }

        /// <summary>La de verdad: lista junto a la bóveda y el pipe de este usuario.</summary>
        public static AutocompletadoModelo PorOmision(ContrasenasModelo boveda, string rutaDeLaBoveda, Action<Action> enUi)
        {
            string carpeta = Path.GetDirectoryName(Path.GetFullPath(rutaDeLaBoveda)) ?? ".";
            return new AutocompletadoModelo(boveda.EntradasParaAutocompletar, new NavegadoresEmparejadosJson(Path.Combine(carpeta, "navegadores-emparejados.json")),
                                            CanalDeAutocompletado.NombreDePipeActual(), enUi) { Rastro = boveda.Rastro };
        }

        /// <summary>El texto de la pregunta de emparejamiento: qué navegador, el código a comparar y qué hacer si no lo pediste.</summary>
        public static string TextoDePregunta(string navegador, string codigo)
            => "El navegador «" + navegador + "» quiere usar tu bóveda de Nexo para rellenar contraseñas.\n\n"
             + "Acepta SOLO si la extensión de Nexo en ese navegador muestra este mismo código:\n\n"
             + "        " + codigo + "\n\n"
             + "Si los códigos no coinciden o no lo pediste tú, pulsa «No».";

        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>Pregunta a la persona (navegador, código). La pone la ventana (diálogo en español, «No» por omisión). Sin ventana: «No».</summary>
        public Func<string, string, CancellationToken, Task<bool>> Preguntar { get; set; } = (_, _, _) => Task.FromResult(false);

        public IRastroDeVentana Rastro { get; set; } = RastroNulo.Instancia;

        /// <summary>El puente, para las pruebas (se le pueden mandar peticiones como las del navegador).</summary>
        internal PuenteDeAutocompletado Puente => _puente;

        public bool Escuchando => _servidor is not null;
        public string Estado { get => _estado; private set { if (_estado == value) return; _estado = value; Avisar(); } }
        public string Aviso { get => _aviso; private set { if (_aviso == value) return; _aviso = value; Avisar(); } }
        public string UltimaActividad { get => _ultimaActividad; private set { if (_ultimaActividad == value) return; _ultimaActividad = value; Avisar(); } }

        public IReadOnlyList<string> Navegadores { get => _navegadores; private set { _navegadores = value; Avisar(); Avisar(nameof(SinNavegadores)); Avisar(nameof(HayNavegadores)); } }
        public bool HayNavegadores => _navegadores.Count > 0;
        public string SinNavegadores => _navegadores.Count == 0 ? "Ninguno todavía." : "";
        public string? Seleccionado { get => _seleccionado; set { if (_seleccionado == value) return; _seleccionado = value; Avisar(); Avisar(nameof(HaySeleccionado)); } }
        public bool HaySeleccionado => _seleccionado is not null;

        public bool Armado
        {
            get
            {
                long t = Volatile.Read(ref _armadoHastaTicks);
                return t != 0 && _reloj().UtcTicks < t;
            }
        }
        public bool PuedeArmar => Escuchando && !Armado;
        public string TextoDeEmparejamiento
        {
            get
            {
                long t = Volatile.Read(ref _armadoHastaTicks);
                if (t == 0) return "";
                // Redondeo hacia arriba: recién pulsado dice «2:00», y «0:00» solo cuando ya se acabó.
                int segundos = (int)Math.Ceiling(TimeSpan.FromTicks(Math.Max(0, t - _reloj().UtcTicks)).TotalSeconds);
                return "Esperando al navegador (quedan " + segundos / 60 + ":" + (segundos % 60).ToString("00", CultureInfo.InvariantCulture)
                     + "). En el navegador, pulsa el botón de Nexo y luego «Emparejar con Nexo». Acepta solo si los dos códigos coinciden.";
            }
        }

        /// <summary>Abre el canal. Si ya lo atiende alguien (otra ventana de Nexo u otro programa), esta ventana no se suma.</summary>
        public async Task IniciarAsync()
        {
            if (_servidor is not null) return;
            byte[] r = await new RelevoNativo(_pipe, conectar: TimeSpan.FromMilliseconds(300), respuesta: TimeSpan.FromSeconds(2))
                .ReenviarAsync(Encoding.UTF8.GetBytes("{\"tipo\":\"estado\",\"navegador\":\"nexo-ventana\"}")).ConfigureAwait(true);
            if (!Encoding.UTF8.GetString(r).Contains("\"sin_nexo\"", StringComparison.Ordinal))
            {
                Estado = "No disponible: otra ventana de Nexo ya atiende al navegador. Si no tienes otra abierta, algo más está ocupando el canal: "
                       + "no uses el autocompletado hasta revisar el equipo.";
                Avisar(nameof(Escuchando));
                Avisar(nameof(PuedeArmar));
                return;
            }
            try
            {
                var s = new ServidorDeAutocompletado(_pipe, _puente.AtenderAsync);
                s.Iniciar();
                _servidor = s;
                Estado = "Atendiendo a la extensión de Nexo en tus navegadores (solo tu usuario puede conectarse). Solo rellena con la bóveda abierta.";
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Estado = "No disponible: no se pudo abrir el canal con el navegador (" + ex.GetType().Name + ").";
            }
            Avisar(nameof(Escuchando));
            Avisar(nameof(PuedeArmar));
        }

        public void ArmarEmparejamiento()
        {
            if (!Escuchando) return;
            Volatile.Write(ref _armadoHastaTicks, (_reloj() + PlazoParaEmparejar).UtcTicks);
            Aviso = "";
            AvisarArmado();
        }

        public void CancelarEmparejamiento() => Desarmar();

        /// <summary>Cada segundo, desde la ventana: la cuenta atrás y el cierre del plazo.</summary>
        public void Tic()
        {
            long t = Volatile.Read(ref _armadoHastaTicks);
            if (t == 0) return;
            if (_reloj().UtcTicks >= t)
            {
                Desarmar();
                UltimaActividad = "Se acabó el plazo para emparejar sin que llegara ningún navegador.";
                return;
            }
            Avisar(nameof(TextoDeEmparejamiento));
        }

        public void OlvidarSeleccionado()
        {
            if (_seleccionado is not string n) return;
            if (_emparejados.Olvidar(n))
            {
                UltimaActividad = "Quitado «" + n + "»: ese navegador tendrá que volver a emparejarse.";
                AvisarRastro("autocompletado.olvidado");
            }
            else Aviso = "No se pudo quitar «" + n + "».";
            Seleccionado = null;
            RefrescarNavegadores();
        }

        public void RefrescarNavegadores()
        {
            Navegadores = _emparejados.Lista();
            if (_seleccionado is not null && !_navegadores.Contains(_seleccionado)) Seleccionado = null;
            if (_emparejados is NavegadoresEmparejadosJson j && j.Problema is string p) Aviso = p;
        }

        private async Task<bool> ConfirmarAsync(string navegador, string codigo, CancellationToken ct)
        {
            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _enUi(async () =>
            {
                try { tcs.TrySetResult(await Preguntar(navegador, codigo, ct).ConfigureAwait(true)); }
                catch (Exception ex) { tcs.TrySetException(ex); }
            });
            try { return await tcs.Task.ConfigureAwait(false); }
            finally { _enUi(Desarmar); }
        }

        private void Desarmar()
        {
            Volatile.Write(ref _armadoHastaTicks, 0);
            AvisarArmado();
        }

        private void AvisarArmado()
        {
            Avisar(nameof(Armado));
            Avisar(nameof(PuedeArmar));
            Avisar(nameof(TextoDeEmparejamiento));
        }

        private string Hora() => _reloj().ToString("HH:mm", CultureInfo.InvariantCulture);

        private void AvisarRastro(string tipo)
        {
            try { Rastro.Avisar(tipo); } catch (Exception) { /* el rastro nunca rompe el autocompletado */ }
        }

        private void Avisar([CallerMemberName] string? nombre = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nombre));

        public async ValueTask DisposeAsync()
        {
            Desarmar();
            if (_servidor is ServidorDeAutocompletado s)
            {
                _servidor = null;
                await s.DisposeAsync().ConfigureAwait(false);
            }
        }
    }
}
