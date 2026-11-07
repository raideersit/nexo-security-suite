using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Nexo.Modules.Identity.Boveda;
using Nexo.Ui.Desktop;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        public static void ProbarTotpEnLaVentana()
        {
            Console.WriteLine("Contraseñas: códigos 2FA (modelo)");
            string dir = Path.Combine(Path.GetTempPath(), "nexo-totp-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var c = new Controles();
                c.Ahora = new DateTime(2026, 11, 7, 12, 0, 12);
                var clip = new PortapapelesFalso();
                var m = Modelo(Ruta(dir, "t"), c, clip);
                Esperar(m.CrearAsync(Maestra, Maestra));
                const string secreto = "JBSWY3DPEHPK3PXP";
                GeneradorDeTotp.TryParsear(secreto, out ConfiguracionTotp? cfg, out _);

                // Alta con 2FA desde el formulario del modelo.
                m.NuevaEntrada();
                m.EdSitio = "con2fa.ejemplo.cl"; m.EdUsuario = "ana"; m.EdContrasena = "clave-larga-1"; m.EdTotp = "basura!";
                Check(!Esperar(m.GuardarEdicionAsync()) && m.EdicionVisible && m.Cantidad == 0 && m.Mensaje.Length > 0 && !m.Mensaje.Contains("Parameter"), "una clave 2FA invalida no se guarda: el formulario sigue abierto y el motivo se ve", m.Mensaje);
                m.EdTotp = "  " + secreto + " ";
                Check(Esperar(m.GuardarEdicionAsync()) && m.Cantidad == 1, "con una clave 2FA valida se guarda");

                m.Seleccionada = m.Entradas[0];
                Check(m.HayTotp, "la entrada con 2FA lo indica (el boton «Copiar código 2FA» se ve)");
                Esperar(m.CopiarCodigoTotpAsync());
                string esperado = GeneradorDeTotp.Codigo(cfg!, new DateTimeOffset(c.Ahora));
                Check(clip.Texto == esperado && esperado.Length == 6, "«Copiar código 2FA» pone en el portapapeles el codigo de ESTE instante", clip.Texto + " vs " + esperado);
                int resto = GeneradorDeTotp.SegundosRestantes(cfg!, new DateTimeOffset(c.Ahora));
                Check(m.Mensaje.Contains("vale " + resto + " segundos más") && m.Mensaje.Contains("30 s"), "el mensaje dice cuanto le queda (" + resto + " s) y que se borra a los 30 s", m.Mensaje);
                Check(!m.Mensaje.Contains(esperado) && !m.Mensaje.Contains(secreto), "el mensaje NO repite el codigo ni la clave");

                // El codigo cambia con el tiempo.
                c.Ahora = c.Ahora.AddSeconds(31);
                Esperar(m.CopiarCodigoTotpAsync());
                Check(clip.Texto == GeneradorDeTotp.Codigo(cfg!, new DateTimeOffset(c.Ahora)) && clip.Texto != esperado, "31 s despues se copia otro codigo (se calcula al pulsar, no se guarda)");

                // Aviso de codigo a punto de caducar.
                c.Ahora = new DateTime(2026, 11, 7, 12, 0, 0);
                long u = new DateTimeOffset(c.Ahora).ToUnixTimeSeconds();
                c.Ahora = c.Ahora.AddSeconds(30 - (u % 30) - 3); // a 3 s del cambio
                Esperar(m.CopiarCodigoTotpAsync());
                Check(m.Mensaje.Contains("vale 3 segundos más") && m.Mensaje.Contains("a punto de cambiar"), "a 3 s de caducar avisa que esta a punto de cambiar", m.Mensaje);

                // Borrado del portapapeles como la contraseña.
                int puertas = c.Puertas.Count;
                Check(m.HayTextoEnElPortapapeles, "el codigo copiado cuenta como texto de Nexo en el portapapeles");
                m.Bloquear();
                Check(EsperarA(() => clip.Texto is null), "al bloquear la boveda, el codigo copiado se borra del portapapeles");

                // Sin 2FA.
                Esperar(m.DesbloquearAsync(Maestra));
                m.NuevaEntrada();
                m.EdSitio = "sin2fa.ejemplo.cl"; m.EdContrasena = "clave-larga-2";
                Esperar(m.GuardarEdicionAsync());
                m.Seleccionada = m.Entradas.Single(e => e.Sitio == "sin2fa.ejemplo.cl");
                Check(!m.HayTotp, "una entrada sin 2FA no muestra el boton");
                clip.Texto = "otra cosa";
                Esperar(m.CopiarCodigoTotpAsync());
                Check(m.Mensaje == "Esta entrada no tiene clave 2FA." && clip.Texto == "otra cosa", "si se pulsa igualmente: lo dice y no toca el portapapeles");

                // Editar: carga la clave, null no la borra desde la interfaz, vaciarla la quita.
                m.Seleccionada = m.Entradas.Single(e => e.Sitio == "con2fa.ejemplo.cl");
                m.EditarSeleccionada();
                Check(m.EdTotp == secreto, "al editar, el formulario trae la clave 2FA guardada");
                m.EdNotas = "una nota";
                Esperar(m.GuardarEdicionAsync());
                m.Seleccionada = m.Entradas.Single(e => e.Sitio == "con2fa.ejemplo.cl");
                Check(m.HayTotp, "editar otra cosa conserva la clave 2FA");
                m.EditarSeleccionada();
                m.EdTotp = "";
                Esperar(m.GuardarEdicionAsync());
                m.Seleccionada = m.Entradas.Single(e => e.Sitio == "con2fa.ejemplo.cl");
                Check(!m.HayTotp, "vaciar el campo la quita");
                m.Seleccionada = m.Entradas.Single(e => e.Sitio == "con2fa.ejemplo.cl");
                m.EditarSeleccionada();
                m.EdTotp = secreto;
                Esperar(m.GuardarEdicionAsync());
                m.Seleccionada = m.Entradas.Single(e => e.Sitio == "con2fa.ejemplo.cl");
                m.EditarSeleccionada();
                Check(m.EdTotp == secreto, "(preparacion) editando una entrada con 2FA");
                m.NuevaEntrada();
                Check(m.EdTotp == "", "pulsar «nueva» con otra entrada a medio editar NO hereda su clave 2FA");
            }
            finally { try { Directory.Delete(dir, true); } catch (IOException) { } }
        }
    }
}
