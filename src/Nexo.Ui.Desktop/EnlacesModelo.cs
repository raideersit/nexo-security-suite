using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Media;
using Nexo.Modules.Threats.Enlaces;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Ui.Desktop
{
    public sealed record FilaDeEnlaceVista(string Veredicto, IBrush Color, string Sitio, string Original, bool MostrarOriginal, IReadOnlyList<FilaDeHallazgoVista> Hallazgos)
    {
        public bool HayHallazgos => Hallazgos.Count > 0;
    }

    /// <summary>
    /// La pestaña «Enlaces»: pegar un mensaje (SMS, correo, WhatsApp) y revisar sus enlaces. Corre en el proceso de la ventana, con el
    /// usuario. Reglas (probadas en tools/Nexo.Desktop.Demo):
    ///  - Nexo NUNCA abre el enlace ni pregunta a nadie por el: todo se compara en el equipo. El texto pegado no se guarda ni sale del
    ///    equipo; el rastro del vault solo lleva conteos y gravedad.
    ///  - Lo unico que sale a Internet es la descarga de las listas, y solo con su boton (con aviso previo).
    ///  - Nunca verde: «sin señales» es gris y dice que NO prueba que sea seguro.
    ///  - Si el texto cambia despues de revisar, el resultado anterior desaparece (jamas se muestra el veredicto de otro texto).
    /// </summary>
    public sealed class EnlacesModelo : INotifyPropertyChanged
    {
        private readonly AlmacenDeListas _almacen;
        private readonly Func<IDescargaDeListas> _descarga;
        private readonly Func<DateTimeOffset> _reloj;
        private ListasDePhishing _listas = ListasDePhishing.Vacias;
        private Task? _carga;
        private bool _cargadas;
        private IReadOnlyList<string> _avisosDeCarga = Array.Empty<string>();
        private RevisionDeMensaje? _revision;
        private string _texto = "";
        private bool _actualizando;
        private bool _revisando;

        public EnlacesModelo(AlmacenDeListas almacen, Func<IDescargaDeListas> descarga, Func<DateTimeOffset>? reloj = null)
        {
            _almacen = almacen;
            _descarga = descarga;
            _reloj = reloj ?? (() => DateTimeOffset.UtcNow);
            Calcular();
        }

        /// <summary>El de la ventana real: listas en %LOCALAPPDATA%\Nexo\listas y descarga por HTTPS.</summary>
        public static EnlacesModelo PorOmision(IRastroDeVentana? rastro = null)
            => new(new AlmacenDeListas(AlmacenDeListas.CarpetaPorOmision()), () => new DescargaDeListasHttp()) { Rastro = rastro ?? RastroNulo.Instancia };

        public event PropertyChangedEventHandler? PropertyChanged;

        public IRastroDeVentana Rastro { get; set; } = RastroNulo.Instancia;

        public const string TextoDeAvisoDeDescarga =
            "Se descargarán dos listas públicas y gratuitas de sitios de phishing (unos 3 MB):\n\n" +
            "• Phishing Army (phishing.army), gratis para uso personal.\n" +
            "• El feed comunitario de OpenPhish (en GitHub), gratis para uso no comercial.\n\n" +
            "Solo se pide la lista entera: no se envía ningún enlace ni mensaje tuyo. Las listas quedan guardadas en tu perfil y los enlaces se comparan en tu equipo.\n\n" +
            "¿Descargar ahora?";

        public string Texto
        {
            get => _texto;
            set
            {
                string v = value ?? "";
                if (v == _texto) return;
                _texto = v;
                // El resultado era de OTRO texto: fuera.
                _revision = null;
                Calcular();
            }
        }

        public string Titulo { get; private set; } = "";
        public string Explicacion { get; private set; } = "";
        public IBrush Color { get; private set; } = Colores.De(Indicador.SinDatos);
        public Indicador Indicador { get; private set; } = Indicador.SinDatos;
        public IReadOnlyList<FilaDeEnlaceVista> Enlaces { get; private set; } = Array.Empty<FilaDeEnlaceVista>();
        public IReadOnlyList<FilaDeHallazgoVista> HallazgosDelMensaje { get; private set; } = Array.Empty<FilaDeHallazgoVista>();
        public IReadOnlyList<string> NoEvaluado { get; private set; } = Array.Empty<string>();
        public bool HayEnlaces => Enlaces.Count > 0;
        public bool HayHallazgosDelMensaje => HallazgosDelMensaje.Count > 0;
        public bool HayNoEvaluado => NoEvaluado.Count > 0;
        public bool PuedeRevisar { get; private set; }
        public bool PuedeActualizar { get; private set; }
        public string EstadoDeListas { get; private set; } = "";
        public string? MensajeDeActualizacion { get; private set; }
        public bool HayMensajeDeActualizacion => !string.IsNullOrEmpty(MensajeDeActualizacion);

        /// <summary>Lee las listas guardadas (una vez). La ventana lo llama al entrar en la pestaña; revisar tambien lo espera.</summary>
        public Task CargarSiHaceFaltaAsync()
        {
            _carga ??= CargarAsync();
            return _carga;
        }

        private async Task CargarAsync()
        {
            Calcular();
            CargaDeListas c;
            try { c = await Task.Run(() => _almacen.Cargar()).ConfigureAwait(true); }
            catch (Exception e) { c = new CargaDeListas(ListasDePhishing.Vacias, new[] { "No se pudieron leer las listas guardadas (" + e.GetType().Name + ")." }); }
            _listas = c.Listas;
            _avisosDeCarga = c.Avisos;
            // Marca explicita: aqui dentro la tarea de carga todavia no figura como terminada.
            _cargadas = true;
            Calcular();
        }

        public async Task RevisarAsync()
        {
            if (_revisando || string.IsNullOrWhiteSpace(_texto)) return;
            _revisando = true;
            string texto = _texto;
            _revision = null;
            Calcular();
            try
            {
                await CargarSiHaceFaltaAsync().ConfigureAwait(true);
                ListasDePhishing listas = _listas;
                DateTimeOffset ahora = _reloj();
                RevisionDeMensaje r = await Task.Run(() => AnalizadorDeMensajes.Analizar(texto, listas, ahora)).ConfigureAwait(true);
                // Si el texto cambio mientras se revisaba, este resultado ya no corresponde a lo que se ve.
                if (texto == _texto)
                {
                    _revision = r;
                    AvisarRastro(r);
                }
            }
            finally
            {
                _revisando = false;
                Calcular();
            }
        }

        public async Task ActualizarListasAsync(CancellationToken ct = default)
        {
            if (_actualizando) return;
            _actualizando = true;
            MensajeDeActualizacion = "Descargando las listas...";
            Calcular();
            try
            {
                await CargarSiHaceFaltaAsync().ConfigureAwait(true);
                IDescargaDeListas d = _descarga();
                try
                {
                    ResultadoDeActualizacion r = await _almacen.ActualizarAsync(d, _listas, _reloj(), ct).ConfigureAwait(true);
                    _listas = r.Listas;
                    _avisosDeCarga = Array.Empty<string>();
                    MensajeDeActualizacion = string.Join("\n", r.Fuentes.Select(f => f.Mensaje));
                }
                finally
                {
                    (d as IDisposable)?.Dispose();
                }
                // Un veredicto calculado con las listas de antes ya no vale: se borra (el usuario vuelve a pulsar «Revisar»).
                if (_revision is not null)
                {
                    _revision = null;
                    MensajeDeActualizacion += "\nVuelve a pulsar «Revisar»: el resultado anterior era con las listas de antes.";
                }
            }
            catch (OperationCanceledException)
            {
                MensajeDeActualizacion = "Descarga cancelada.";
            }
            catch (Exception e)
            {
                MensajeDeActualizacion = "No se pudieron actualizar las listas (" + e.GetType().Name + ").";
            }
            finally
            {
                _actualizando = false;
                Calcular();
            }
        }

        public void Borrar()
        {
            _texto = "";
            _revision = null;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Texto)));
            Calcular();
        }

        /// <summary>Solo conteos y gravedad: ni el texto, ni los enlaces, ni los sitios.</summary>
        private void AvisarRastro(RevisionDeMensaje r)
        {
            int n = r.Analisis.Hallazgos.Count(h => h.Severidad != Severidad.Info);
            string maxima = n == 0 ? "Info" : r.Analisis.Hallazgos.Where(h => h.Severidad != Severidad.Info).Max(h => h.Severidad).ToString();
            var campos = new Dictionary<string, object?>(StringComparer.Ordinal) { ["hallazgos"] = n, ["maxima"] = maxima, ["completa"] = r.Analisis.Completo };
            try { Rastro.Avisar("enlaces.revision", campos); } catch (Exception) { /* el rastro nunca rompe la revision */ }
        }

        private void Calcular()
        {
            DateTimeOffset ahora = _reloj();
            (Indicador ind, string titulo, string explicacion) = ResumirEnlaces.General(_revision, _revisando, string.IsNullOrWhiteSpace(_texto));
            Indicador = ind;
            Titulo = titulo;
            Explicacion = explicacion;
            Color = Colores.De(ind);

            if (_revision is RevisionDeMensaje r)
            {
                Enlaces = r.Enlaces.Select(e => new FilaDeEnlaceVista(
                    ResumirEnlaces.Veredicto(e.Veredicto), Colores.De(ResumirEnlaces.IndicadorDe(e.Veredicto)),
                    e.SitioLegible == e.Sitio ? e.Sitio : e.SitioLegible + "  (nombre real: " + e.Sitio + ")",
                    e.Original, e.Original != e.Sitio,
                    e.Hallazgos.Select(Vista).ToList())).ToList();
                HallazgosDelMensaje = r.Analisis.Hallazgos.Where(h => h.Id.StartsWith("MSJ-", StringComparison.Ordinal)).Select(Vista).ToList();
                NoEvaluado = r.Analisis.NoEvaluado;
            }
            else
            {
                Enlaces = Array.Empty<FilaDeEnlaceVista>();
                HallazgosDelMensaje = Array.Empty<FilaDeHallazgoVista>();
                NoEvaluado = Array.Empty<string>();
            }

            PuedeRevisar = !_revisando && !string.IsNullOrWhiteSpace(_texto);
            PuedeActualizar = !_actualizando;
            EstadoDeListas = ResumirEnlaces.EstadoDeListas(_listas, _cargadas, _avisosDeCarga, ahora);

            foreach (string p in new[] { nameof(Titulo), nameof(Explicacion), nameof(Color), nameof(Indicador), nameof(Enlaces), nameof(HallazgosDelMensaje), nameof(NoEvaluado),
                                         nameof(HayEnlaces), nameof(HayHallazgosDelMensaje), nameof(HayNoEvaluado), nameof(PuedeRevisar), nameof(PuedeActualizar),
                                         nameof(EstadoDeListas), nameof(MensajeDeActualizacion), nameof(HayMensajeDeActualizacion) })
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));
        }

        private static FilaDeHallazgoVista Vista(HallazgoDeSistema h)
            => new(ResumirSeguridad.Gravedad(h.Severidad), Colores.De(ResumirSeguridad.IndicadorDe(h.Severidad)), h.Titulo, "", false, h.Detalle, h.Recomendacion);
    }

    /// <summary>Los textos y colores de la pestaña «Enlaces», sin interfaz.</summary>
    public static class ResumirEnlaces
    {
        public static string Veredicto(Veredicto v) => v switch
        {
            Modules.Threats.Enlaces.Veredicto.Peligroso => "Peligroso",
            Modules.Threats.Enlaces.Veredicto.Sospechoso => "Sospechoso",
            _ => "Sin señales conocidas"
        };

        /// <summary>Nunca verde: «sin señales» no es «seguro», es «no se sabe nada malo» (gris).</summary>
        public static Indicador IndicadorDe(Veredicto v) => v switch
        {
            Modules.Threats.Enlaces.Veredicto.Peligroso => Indicador.Alerta,
            Modules.Threats.Enlaces.Veredicto.Sospechoso => Indicador.Atencion,
            _ => Indicador.SinDatos
        };

        public static (Indicador, string, string) General(RevisionDeMensaje? r, bool revisando, bool textoVacio)
        {
            if (revisando) return (Indicador.SinDatos, "Revisando...", "");
            if (r is null)
                return (Indicador.SinDatos, "Sin revisar",
                    textoVacio ? "Pega aquí un mensaje (SMS, correo, WhatsApp) o un enlace y pulsa «Revisar». Nexo no abre el enlace: lo compara en tu equipo."
                               : "Pulsa «Revisar» para comprobar este texto.");

            string incompleta = r.Analisis.Completo ? "" : " Revisión incompleta: mira abajo lo que no se pudo comprobar.";
            switch (r.Veredicto)
            {
                case Modules.Threats.Enlaces.Veredicto.Peligroso:
                    return (Indicador.Alerta, "Peligroso: no abras el enlace ni respondas",
                        "Hay señales claras de estafa o phishing. Si crees que el mensaje puede ser real, entra escribiendo tú la dirección oficial o llama a un número que ya conoces." + incompleta);
                case Modules.Threats.Enlaces.Veredicto.Sospechoso:
                    return (Indicador.Atencion, "Sospechoso: ten cuidado",
                        "Hay señales de que puede ser una estafa. No escribas claves ni datos de tarjetas desde este mensaje." + incompleta);
                default:
                    if (r.Enlaces.Count == 0 && r.EnlacesIlegibles == 0)
                        return (Indicador.SinDatos, "No se encontró ningún enlace",
                            (r.Analisis.Hallazgos.Count == 0 ? "Tampoco frases típicas de estafa (solo se reconocen en español). " : "") +
                            "Nexo reconoce enlaces con «http», con «www.» o con un nombre que termina en «.cl», «.com» y similares." + incompleta);
                    return (Indicador.SinDatos, "Sin señales conocidas (esto NO prueba que sea seguro)",
                        "No está en las listas de phishing y no tiene los trucos que Nexo reconoce. Los sitios de phishing nuevos tardan horas o días en entrar en las listas: si no esperabas el mensaje, desconfía igual." + incompleta);
            }
        }

        public static string EstadoDeListas(ListasDePhishing l, bool cargadas, IReadOnlyList<string> avisos, DateTimeOffset ahora)
        {
            if (!cargadas) return "Listas de phishing: sin leer todavía.";
            var lineas = new List<string>();
            foreach (FuenteDeLista f in new[] { FuenteDeLista.PhishingArmy, FuenteDeLista.OpenPhish })
            {
                ListaCargada? x = l.De(f);
                string nombre = AnalizadorDeMensajes.NombreDe(f);
                if (x is null) { lineas.Add(nombre + ": no descargada."); continue; }
                TimeSpan a = x.Antiguedad(ahora);
                string edad = a.TotalHours < 1 ? "hace menos de una hora" : a.TotalDays < 2 ? "hace " + (int)a.TotalHours + " h" : "hace " + (int)a.TotalDays + " días";
                lineas.Add(nombre + ": " + x.Entradas.ToString("N0", CultureInfo.GetCultureInfo("es-CL")) + (f == FuenteDeLista.PhishingArmy ? " sitios" : " direcciones") + ", de " + edad +
                           (a > AnalizadorDeMensajes.ListaVieja ? " (vieja: conviene actualizarla)." : "."));
            }
            lineas.AddRange(avisos);
            return string.Join("\n", lineas);
        }
    }
}
