using System.Drawing;
using System.Windows.Forms;

namespace Nexo.Ui.Tray
{
    /// <summary>
    /// Sustituto de <see cref="MessageBox"/> con los botones en español. El MessageBox de Windows pone «Yes/No/OK»
    /// segun el idioma del sistema, no el de Nexo. Solo admite OK y YesNo, que son los que la bandeja usa.
    /// </summary>
    internal static class Dialogo
    {
        public static DialogResult Mostrar(string texto, string titulo, MessageBoxButtons botones, MessageBoxIcon icono)
        {
            bool pregunta = botones == MessageBoxButtons.YesNo;
            using var f = new Form
            {
                Text = titulo,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterScreen,
                MinimizeBox = false,
                MaximizeBox = false,
                ShowInTaskbar = true,
                TopMost = true,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Padding = new Padding(12)
            };
            var cuerpo = new TableLayoutPanel { AutoSize = true, ColumnCount = 1, Dock = DockStyle.Fill };
            cuerpo.Controls.Add(new Label
            {
                Text = texto,
                AutoSize = true,
                MaximumSize = new Size(520, 0),
                Margin = new Padding(0, 0, 0, 12)
            });
            var fila = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill };
            if (pregunta)
            {
                var no = new Button { Text = "No", DialogResult = DialogResult.No, AutoSize = true };
                var si = new Button { Text = "Sí", DialogResult = DialogResult.Yes, AutoSize = true };
                fila.Controls.Add(no);
                fila.Controls.Add(si);
                f.AcceptButton = si;
                f.CancelButton = no;
            }
            else
            {
                var ok = new Button { Text = "Aceptar", DialogResult = DialogResult.OK, AutoSize = true };
                fila.Controls.Add(ok);
                f.AcceptButton = ok;
                f.CancelButton = ok;
            }
            cuerpo.Controls.Add(fila);
            f.Controls.Add(cuerpo);
            switch (icono)
            {
                case MessageBoxIcon.Error: System.Media.SystemSounds.Hand.Play(); break;
                case MessageBoxIcon.Warning: System.Media.SystemSounds.Exclamation.Play(); break;
            }
            DialogResult r = f.ShowDialog();
            return pregunta && r != DialogResult.Yes ? DialogResult.No : r;
        }
    }
}
