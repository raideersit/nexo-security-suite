using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Ui.Tray
{
    /// <summary>
    /// El icono de la bandeja y su menu. Es una capa fina: toda la decision (color, texto, que es nuevo) esta en
    /// <see cref="ModeloDeBandeja"/> y todo lo que cambia algo pasa por <see cref="AccionesDelServicio"/>, es decir, por el
    /// servicio con su vista previa, su token y, si lo exige, el aviso de UAC.
    /// </summary>
    internal sealed class Bandeja : IDisposable
    {
        private static readonly TimeSpan Sondeo = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan Espera = TimeSpan.FromSeconds(3);

        private readonly string _pipe;
        private readonly NotifyIcon _icono;
        private readonly ModeloDeBandeja _modelo = new ModeloDeBandeja();
        private readonly System.Windows.Forms.Timer _reloj;
        private readonly ToolStripMenuItem _estado = new ToolStripMenuItem { Enabled = false };
        private readonly ToolStripMenuItem _detecciones = new ToolStripMenuItem();
        private readonly ToolStripMenuItem _revisar = new ToolStripMenuItem();
        private bool _revisando;    // hay una revision en marcha: no se lanza otra
        private readonly Dictionary<EstadoDeBandeja, Icon> _iconos;
        private readonly ILanzadorElevado _lanzador;
        private bool _consultando;
        private bool _ocupado;      // hay un dialogo abierto: no se abren dos a la vez

        public Bandeja(string pipe)
        {
            _pipe = pipe;
            _lanzador = new LanzadorElevado(pipe);
            _iconos = new Dictionary<EstadoDeBandeja, Icon>
            {
                [EstadoDeBandeja.Desconectado] = Circulo(Color.Gray),
                [EstadoDeBandeja.Normal] = Circulo(Color.SeaGreen),
                [EstadoDeBandeja.Atencion] = Circulo(Color.Orange),
                [EstadoDeBandeja.Alerta] = Circulo(Color.Crimson)
            };

            _detecciones.Click += async (_, _) => await RevisarDeteccionesAsync();
            _revisar.Click += async (_, _) => await RevisarLoNoVistoAsync();
            var limpieza = new ToolStripMenuItem("Limpiar archivos basura…");
            limpieza.Click += async (_, _) => await LimpiarAsync();
            var salir = new ToolStripMenuItem("Salir de la bandeja");
            salir.Click += (_, _) => { _icono!.Visible = false; Application.ExitThread(); };

            var menu = new ContextMenuStrip();
            menu.Items.AddRange(new ToolStripItem[] { _estado, new ToolStripSeparator(), _detecciones, _revisar, limpieza, new ToolStripSeparator(), salir });

            _icono = new NotifyIcon { Icon = _iconos[EstadoDeBandeja.Desconectado], Text = _modelo.Texto, ContextMenuStrip = menu, Visible = true };
            _icono.BalloonTipClicked += async (_, _) => await RevisarDeteccionesAsync();
            _icono.DoubleClick += async (_, _) => await RevisarDeteccionesAsync();

            _reloj = new System.Windows.Forms.Timer { Interval = (int)Sondeo.TotalMilliseconds };
            _reloj.Tick += async (_, _) => await ConsultarAsync();
            _reloj.Start();
            _ = ConsultarAsync();
            Pintar();
        }

        // ------------------------------------------------------------
        private async Task ConsultarAsync()
        {
            if (_consultando) return;
            _consultando = true;
            try
            {
                InstantaneaDelServicio i = await ConsultorDelServicio.ConsultarAsync(_pipe, Espera);
                foreach (DeteccionVista d in _modelo.Actualizar(i))
                    _icono.ShowBalloonTip(8000, "Nexo: amenaza detectada",
                        d.Firma + " en " + System.IO.Path.GetFileName(d.Ruta) + ". Pulsa para revisarla.", ToolTipIcon.Warning);
                Pintar();
            }
            finally { _consultando = false; }
        }

        private void Pintar()
        {
            _icono.Icon = _iconos[_modelo.Estado];
            _icono.Text = _modelo.Texto;
            _estado.Text = _modelo.Texto;
            int n = _modelo.Todas.Count;
            _detecciones.Text = n == 0 ? "Detecciones (ninguna)" : "Revisar detecciones (" + n + ")…";
            _detecciones.Enabled = n > 0;
            int r = _modelo.Ultima.CarpetasPorRevisar.Count;
            _revisar.Text = _revisando ? "Revisando lo que no se vio…" : r == 0 ? "Nada por revisar" : "Revisar lo que no se vio (" + r + (r == 1 ? " carpeta" : " carpetas") + ")…";
            _revisar.Enabled = r > 0 && !_revisando;
        }

        /// <summary>
        /// Escanea bajo demanda (solo lee) las carpetas donde el tiempo real perdio o no pudo analizar algo. Lo ofrece, no lo
        /// lanza solo. Cuando termina completo, el servicio las da por revisadas y dejan de contar para la cobertura.
        /// </summary>
        private async Task RevisarLoNoVistoAsync()
        {
            if (_ocupado || _revisando) return;
            IReadOnlyList<string> rutas = AccionesDelServicio.RutasParaRevisar(_modelo.Ultima.CarpetasPorRevisar);
            if (rutas.Count == 0) return;

            _ocupado = true;
            string? id;
            try
            {
                int total = _modelo.Ultima.CarpetasPorRevisar.Count;
                string texto = "El tiempo real no pudo analizar todo lo que cambio en estas carpetas:\n\n" +
                               string.Join("\n", rutas.Select(x => "  • " + x)) +
                               (total > rutas.Count ? "\n\n(Hay mas; se revisaran en otra pasada.)" : "") +
                               "\n\n¿Escanearlas ahora? Solo se leen los archivos: no se mueve ni borra nada. Puede tardar varios minutos.";
                if (MessageBox.Show(texto, "Nexo — revisar lo que no se vio", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

                string? motivo;
                (id, motivo) = await AccionesDelServicio.IniciarRevisionAsync(_pipe, rutas, Espera);
                if (id is null)
                {
                    MessageBox.Show("No se pudo iniciar la revision: " + motivo, "Nexo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
            }
            catch (Exception ex) when (ex is TimeoutException || ex is System.IO.IOException)
            {
                MessageBox.Show("No se pudo hablar con el servicio.", "Nexo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            finally { _ocupado = false; }

            _revisando = true;
            Pintar();
            try
            {
                string? resumen = null;
                for (int i = 0; i < 720 && resumen is null; i++)     // hasta una hora
                {
                    await Task.Delay(Sondeo);
                    try { resumen = await AccionesDelServicio.ResultadoDeRevisionAsync(_pipe, id, Espera); }
                    catch (Exception ex) when (ex is TimeoutException || ex is System.IO.IOException) { /* se reintenta */ }
                }
                _icono.ShowBalloonTip(10000, "Nexo: revision", resumen ?? "La revision sigue en marcha tras una hora; su resultado quedara en el vault.",
                                      ToolTipIcon.Info);
            }
            finally { _revisando = false; await ConsultarAsync(); }
        }

        // ------------------------------------------------------------
        private async Task RevisarDeteccionesAsync()
        {
            if (_ocupado || _modelo.Todas.Count == 0) return;
            _ocupado = true;
            try
            {
                _modelo.MarcarRevisadas();
                Pintar();

                var sb = new StringBuilder("Nexo detecto:\n\n");
                foreach (DeteccionVista d in _modelo.Todas.Take(10))
                    sb.Append("  • ").Append(d.Firma).Append("\n    ").Append(d.Ruta).Append('\n');
                if (_modelo.Todas.Count > 10) sb.Append("  … y ").Append(_modelo.Todas.Count - 10).Append(" mas\n");
                sb.Append("\nLos archivos NO se han tocado. ¿Preparar el traslado a cuarentena? (podras revisar el plan antes de aprobarlo)");

                if (MessageBox.Show(sb.ToString(), "Nexo — detecciones", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

                PlanPropuesto plan = await AccionesDelServicio.PrevisualizarCuarentenaAsync(_pipe, "tiempo-real", Espera);
                await ConfirmarYAplicarAsync("Poner en cuarentena", plan, TipoDeAccion.Cuarentena);
            }
            catch (Exception ex) when (ex is TimeoutException || ex is System.IO.IOException)
            {
                MessageBox.Show("No se pudo hablar con el servicio.", "Nexo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally { _ocupado = false; await ConsultarAsync(); }
        }

        private async Task LimpiarAsync()
        {
            if (_ocupado) return;
            _ocupado = true;
            try
            {
                PlanPropuesto plan = await AccionesDelServicio.PrevisualizarLimpiezaAsync(_pipe, Espera);
                await ConfirmarYAplicarAsync("Limpiar archivos basura", plan, TipoDeAccion.Limpieza);
            }
            catch (Exception ex) when (ex is TimeoutException || ex is System.IO.IOException)
            {
                MessageBox.Show("No se pudo hablar con el servicio.", "Nexo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally { _ocupado = false; }
        }

        /// <summary>Muestra el plan EXACTO que preparo el servicio, y solo si el usuario acepta lo aplica (con UAC si hace falta).</summary>
        private async Task ConfirmarYAplicarAsync(string titulo, PlanPropuesto plan, TipoDeAccion tipo)
        {
            if (!plan.HayCambios || plan.Token is null)
            {
                MessageBox.Show(plan.Descripcion.Length > 0 ? plan.Descripcion : "No hay nada que hacer.", titulo, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var sb = new StringBuilder(plan.Descripcion);
            if (plan.Avisos.Count > 0) sb.Append("\n").Append(string.Join("\n", plan.Avisos.Select(a => "• " + a)));
            sb.Append("\n\n¿Aplicar este plan? Windows puede pedirte confirmacion (UAC).");

            if (MessageBox.Show(sb.ToString(), titulo, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

            ResultadoDeAplicar r = await AccionesDelServicio.AplicarConAprobacionAsync(_pipe, tipo, plan.Token, _lanzador, Espera);
            MessageBox.Show(r.Mensaje, titulo, MessageBoxButtons.OK, r.Exito ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }

        // ------------------------------------------------------------
        private static Icon Circulo(Color color)
        {
            using var bmp = new Bitmap(16, 16);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                using var pincel = new SolidBrush(color);
                using var borde = new Pen(Color.FromArgb(220, Color.White), 1.5f);
                g.FillEllipse(pincel, 1, 1, 13, 13);
                g.DrawEllipse(borde, 1, 1, 13, 13);
            }
            // Son 4 iconos que viven lo que vive el proceso: no se libera el manejador (y asi no hace falta P/Invoke aqui;
            // todo el P/Invoke del proyecto va en Nexo.Native).
            return Icon.FromHandle(bmp.GetHicon());
        }

        public void Dispose()
        {
            _reloj.Dispose();
            _icono.Visible = false;
            _icono.Dispose();
            foreach (Icon i in _iconos.Values) i.Dispose();
        }
    }
}
