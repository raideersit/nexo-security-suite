using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Nexo.Modules.Identity.Boveda;
using Nexo.Modules.Identity.Filtraciones;
using Nexo.Ui.Desktop;
using Nexo.Ui.Desktop.Nucleo;
using Bov = Nexo.Modules.Identity.Boveda.Boveda;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        private static readonly ParametrosDeClave Rapidos = new(1024, 1, 1);
        private const string Maestra = "una-maestra-bien-larga-1";
        private const string SufijoPassword = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"; // SHA-1("password") = 5BAA6 + este sufijo

        private sealed class PortapapelesFalso : IPortapapeles
        {
            public string? Texto;
            public bool Fallar;
            public int Borrados;
            public Task<bool> PonerAsync(string texto) { if (Fallar) return Task.FromResult(false); Texto = texto; return Task.FromResult(true); }
            public Task<string?> LeerAsync() => Task.FromResult(Texto);
            public Task BorrarAsync() { Texto = null; Borrados++; return Task.CompletedTask; }
        }

        private sealed class RangosFalsos : IConsultaDeRangos
        {
            public int Llamadas;
            public bool Caido;
            public Task<RespuestaDeRango> ObtenerAsync(string prefijo, CancellationToken ct)
            {
                Llamadas++;
                if (Caido) return Task.FromResult(RespuestaDeRango.Fallo("sin red"));
                var sb = new StringBuilder();
                for (int i = 0; i < 40; i++) sb.Append(i.ToString("X").PadLeft(35, 'A')).Append(":3\r\n");
                if (prefijo == "5BAA6") sb.Append(SufijoPassword).Append(":5000000\r\n");
                return Task.FromResult(RespuestaDeRango.Ok(sb.ToString()));
            }
        }

        /// <summary>Un reloj que se mueve a mano y una «espera» que solo termina cuando la prueba lo decide.</summary>
        private sealed class Controles
        {
            public DateTime Ahora = new(2026, 11, 7, 12, 0, 0);
            public readonly List<TaskCompletionSource<bool>> Puertas = new();
            public Task Espera(TimeSpan t) { var p = new TaskCompletionSource<bool>(); Puertas.Add(p); return p.Task; }
            public void Abrir(int i) => Puertas[i].SetResult(true);
        }

        private static ContrasenasModelo Modelo(string ruta, Controles c, PortapapelesFalso clip, RangosFalsos? rangos = null, TimeSpan? inactividad = null)
            => new(ruta, Rapidos, permitirParametrosDebiles: true, consulta: () => rangos ?? new RangosFalsos(), portapapeles: clip,
                   reloj: () => c.Ahora, inactividad: inactividad ?? TimeSpan.FromMinutes(5), borrado: TimeSpan.FromSeconds(30), espera: c.Espera);

        private static string Ruta(string dir, string nombre) => Path.Combine(dir, nombre + ".nxv");

        private static async Task Alta(ContrasenasModelo m, string sitio, string usuario, string clave, string notas = "")
        {
            m.NuevaEntrada();
            m.EdSitio = sitio; m.EdUsuario = usuario; m.EdContrasena = clave; m.EdNotas = notas;
            await m.GuardarEdicionAsync();
        }

        /// <summary>Espera a lo sumo unos segundos: si una regresion deja una espera abierta, la prueba FALLA en vez de colgarse.</summary>
        private static bool EsperarHasta(Task t, int ms = 3000)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            while (!t.IsCompleted && sw.ElapsedMilliseconds < ms) { Dispatcher.UIThread.RunJobs(); Thread.Sleep(2); }
            return t.IsCompleted;
        }

        /// <summary>Espera una tarea que devuelve un valor, bombeando la interfaz mientras tanto.</summary>
        private static T Esperar<T>(Task<T> t)
        {
            while (!t.IsCompleted) Dispatcher.UIThread.RunJobs();
            return t.GetAwaiter().GetResult();
        }

        private static readonly string[] SinTildeContrasenas =
        {
            "contrasena", "contrasenas", "boveda", "politica", "sesion", "version", "revision", "configuracion", "conexion", "informacion", "aplicacion",
            "automatico", "automatica", "minima", "unica", "tamano", "anos", "espanol", "codigo", "linea", "debil", "despues", "asi", "mas", "ningun",
            "limite", "dia", "vacia", "vacio", "podria", "agoto", "maximo", "parametros", "verificacion"
        };

        public static void ProbarContrasenas()
        {
            Console.WriteLine("Pestaña Contraseñas: el modelo");
            string dir = Path.Combine(Path.GetTempPath(), "nexo-contrasenas-demo-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try { ProbarContrasenasEn(dir); }
            finally { try { Directory.Delete(dir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { } }
        }

        private static void ProbarContrasenasEn(string dir)
        {
            var c = new Controles();
            var clip = new PortapapelesFalso();
            var rangos = new RangosFalsos();
            string ruta = Ruta(dir, "principal");
            var textos = new HashSet<string>(StringComparer.Ordinal);
            void Espiar(ContrasenasModelo mod)
            {
                string[] nombres = { "Mensaje", "Titulo", "Explicacion", "Auditoria", "BotonMostrar", "EdicionTitulo", "DetalleFechas", "ResumenDeInactividad", "TextoDeCopia" };
                mod.PropertyChanged += (_, e) =>
                {
                    if (e.PropertyName is { } n && Array.IndexOf(nombres, n) >= 0)
                        if (typeof(ContrasenasModelo).GetProperty(n)!.GetValue(mod) is string s && s.Length > 0) textos.Add(s);
                };
            }

            // ---- sin boveda
            var m = Modelo(ruta, c, clip, rangos);
            Espiar(m);
            m.Refrescar();
            Check(m.Fase == FaseDeBoveda.SinBoveda && m.EsSinBoveda && !m.EsBloqueada && !m.EsAbierta, "sin archivo: fase «SinBoveda»");
            Check(m.Titulo == "Todavía no tienes una bóveda" && m.Explicacion.Contains("AES-256-GCM") && m.Explicacion.Contains("Nada sale de este equipo"), "el titulo y la explicacion (cifrado local)");
            Check(m.Archivo == "Archivo: " + ruta, "dice donde se guardara el archivo");
            Check(rangos.Llamadas == 0, "al crearse NO consulta nada en Internet");

            // ---- crear: validaciones
            Check(!Esperar(m.CrearAsync("corta", "corta")) && m.Mensaje == "La contraseña maestra debe tener al menos 10 caracteres." && !File.Exists(ruta), "una maestra corta se rechaza y no crea nada");
            Check(!Esperar(m.CrearAsync(Maestra, Maestra + "x")) && m.Mensaje == "Las dos contraseñas no coinciden." && !File.Exists(ruta), "dos maestras distintas se rechazan y no crean nada");
            Check(!m.Ocupado, "y no queda «ocupado»");

            // ---- crear
            var t1 = m.CrearAsync(Maestra, Maestra);
            var t2 = m.CrearAsync(Maestra, Maestra);
            Esperar(t1); Esperar(t2);
            Check(t1.Result && !t2.Result, "dos «Crear» a la vez: el segundo se ignora (no crea dos veces)");
            Check(m.Fase == FaseDeBoveda.Abierta && File.Exists(ruta) && m.Titulo == "Bóveda abierta: 0 entradas", "crea la bóveda, queda abierta y existe el archivo", m.Titulo);
            Check(m.Mensaje.Contains("no hay forma de recuperar"), "al crear, avisa que si se olvida la maestra no hay recuperacion");
            Check(!m.Ocupado && m.NoOcupado, "al terminar no queda «ocupado»");

            // ---- altas
            Esperar(Alta(m, "banco.ejemplo.cl", "ana", "S3creto!Banco"));
            Esperar(Alta(m, "correo.ejemplo.com", "ana@ejemplo.com", "password", "mi nota"));
            Esperar(Alta(m, "aaa-primero.example", "zeta", "otra-clave-larga-9"));
            Check(m.Cantidad == 3 && m.Entradas.Count == 3 && m.Titulo == "Bóveda abierta: 3 entradas", "3 altas: la lista y el titulo lo reflejan", m.Titulo);
            Check(m.Entradas.Select(e => e.Sitio).SequenceEqual(new[] { "aaa-primero.example", "banco.ejemplo.cl", "correo.ejemplo.com" }), "la lista sale ordenada por sitio", string.Join(",", m.Entradas.Select(e => e.Sitio)));
            Check(!m.EdicionVisible && m.Mensaje == "Entrada guardada.", "tras guardar se cierra el formulario");

            byte[] disco = File.ReadAllBytes(ruta);
            bool esta(string s) => disco.AsSpan().IndexOf(Encoding.UTF8.GetBytes(s)) >= 0 || disco.AsSpan().IndexOf(Encoding.Unicode.GetBytes(s)) >= 0;
            Check(!esta("banco.ejemplo.cl") && !esta("S3creto!Banco") && !esta("ana@ejemplo.com") && !esta("mi nota") && !esta(Maestra), "en el disco no hay nada en claro: ni sitios, ni usuarios, ni contraseñas, ni notas, ni la maestra");

            // ---- alta invalida
            m.NuevaEntrada();
            Check(m.EdicionVisible && m.EdicionTitulo == "Nueva entrada" && m.EdSitio == "", "«Nueva» abre el formulario vacio");
            m.EdSitio = "   ";
            Check(!Esperar(m.GuardarEdicionAsync()) && m.Mensaje == "El sitio no puede estar vacío." && m.EdicionVisible, "un sitio vacio no se guarda y el formulario sigue abierto");
            m.EdSitio = new string('x', 2000);
            Check(!Esperar(m.GuardarEdicionAsync()) && m.Mensaje.StartsWith("No se pudo guardar:") && m.Cantidad == 3, "un sitio de 2000 caracteres se rechaza con el motivo y no se agrega", m.Mensaje);
            m.CancelarEdicion();
            Check(!m.EdicionVisible && m.EdSitio == "", "«Cancelar» cierra y limpia el formulario");

            // ---- generador
            m.GenerarContrasena();
            Check(m.EdContrasena == "", "generar sin formulario abierto no hace nada");
            m.NuevaEntrada();
            m.GenerarContrasena();
            Check(m.EdContrasena.Length == 20 && m.MostrarContrasena && m.CaracterDeClave == '\0', "generar: 20 caracteres, y se muestran para poder anotarlos");
            string g1 = m.EdContrasena;
            m.GenerarContrasena();
            Check(m.EdContrasena != g1, "cada vez sale una distinta");
            m.CancelarEdicion();

            // ---- seleccion y detalle
            m.Seleccionada = m.Entradas.First(e => e.Sitio == "banco.ejemplo.cl");
            Check(m.DetalleVisible && m.DetalleSitio == "banco.ejemplo.cl" && m.DetalleUsuario == "ana", "al elegir una fila se ve el detalle");
            Check(m.DetalleContrasena == "••••••••" && !m.MostrarContrasena && m.BotonMostrar == "Mostrar", "la contraseña esta oculta por omision");
            m.Seleccionada = m.Entradas.First(e => e.Sitio == "aaa-primero.example");
            Check(m.DetalleContrasena == "••••••••", "y con otra contraseña distinta (de otro largo) se oculta con los MISMOS 8 puntos: no se adivina el largo");
            m.AlternarContrasena();
            Check(m.DetalleContrasena == "otra-clave-larga-9" && m.BotonMostrar == "Ocultar", "«Mostrar» enseña la contraseña");
            m.Seleccionada = m.Entradas.First(e => e.Sitio == "banco.ejemplo.cl");
            Check(m.DetalleContrasena == "••••••••" && !m.MostrarContrasena, "al cambiar de entrada vuelve a ocultarse");
            Check(m.DetalleFechas.StartsWith("Creada ") && m.DetalleFechas.Contains("modificada"), "el detalle muestra las fechas");

            // ---- editar
            m.EditarSeleccionada();
            Check(m.EdicionVisible && m.EdicionTitulo == "Editar entrada" && m.EdSitio == "banco.ejemplo.cl" && m.EdContrasena == "S3creto!Banco" && !m.DetalleVisible, "«Editar» carga los datos de la entrada y esconde el detalle");
            m.EdContrasena = "Nueva-Clave-Banco-77";
            Check(Esperar(m.GuardarEdicionAsync()) && m.Mensaje == "Entrada actualizada.", "guardar la edicion");
            m.AlternarContrasena();
            Check(m.DetalleContrasena == "Nueva-Clave-Banco-77", "la edicion se ve");

            // ---- filtro
            m.Filtro = "BANCO";
            Check(m.Entradas.Count == 1 && m.Entradas[0].Sitio == "banco.ejemplo.cl", "el filtro ignora mayusculas y busca en el sitio");
            m.Filtro = "zeta";
            Check(m.Entradas.Count == 1 && m.Entradas[0].Usuario == "zeta", "y en el usuario");
            m.Filtro = "no-existe";
            Check(m.Entradas.Count == 0 && m.Cantidad == 3, "sin coincidencias la lista queda vacia pero la boveda sigue teniendo 3");
            m.Filtro = "";
            Check(m.Entradas.Count == 3, "un filtro vacio muestra todo");

            // ---- portapapeles
            m.Seleccionada = m.Entradas.First(e => e.Sitio == "correo.ejemplo.com");
            Esperar(m.CopiarContrasenaAsync());
            Check(clip.Texto == "password" && m.Mensaje == "Contraseña copiada. Se borrará del portapapeles en 30 s." && m.HayTextoEnElPortapapeles, "copiar la contraseña la pone en el portapapeles y avisa de que se borrara en 30 s");
            Check(clip.Borrados == 0 && c.Puertas.Count == 1, "todavia no se ha borrado (esta esperando los 30 s)");
            c.Abrir(0);
            EsperarHasta(m.EsperarBorradoAsync());
            Check(clip.Texto is null && clip.Borrados == 1 && m.Mensaje == "Portapapeles borrado." && !m.HayTextoEnElPortapapeles, "pasados los 30 s se borra y lo dice");

            // otra cosa en el portapapeles: no se toca
            Esperar(m.CopiarContrasenaAsync());
            clip.Texto = "algo que copio el usuario";
            c.Abrir(1);
            EsperarHasta(m.EsperarBorradoAsync());
            Check(clip.Texto == "algo que copio el usuario" && clip.Borrados == 1 && m.Mensaje == "El portapapeles ya tenía otra cosa: no se tocó.", "si el usuario copio otra cosa mientras tanto, NO se borra");

            // dos copias seguidas: solo cuenta la ultima
            Esperar(m.CopiarContrasenaAsync());     // puerta 2
            m.Seleccionada = m.Entradas.First(e => e.Sitio == "aaa-primero.example");
            Esperar(m.CopiarContrasenaAsync());     // puerta 3
            c.Abrir(2);                              // la espera de la PRIMERA termina: ya no debe borrar
            Dispatcher.UIThread.RunJobs();
            Check(clip.Texto == "otra-clave-larga-9" && clip.Borrados == 1, "si se copia otra contraseña antes de los 30 s, la espera de la primera ya no borra la segunda");
            c.Abrir(3);
            EsperarHasta(m.EsperarBorradoAsync());
            Check(clip.Texto is null && clip.Borrados == 2, "y la espera de la segunda si la borra");

            // el usuario no se borra solo (no es secreto) y no programa nada
            int puertas = c.Puertas.Count;
            Esperar(m.CopiarUsuarioAsync());
            Check(clip.Texto == "zeta" && m.Mensaje == "Usuario copiado." && c.Puertas.Count == puertas, "copiar el usuario no programa ningun borrado");
            clip.Texto = null;

            clip.Fallar = true;
            Esperar(m.CopiarContrasenaAsync());
            Check(m.Mensaje == "No se pudo usar el portapapeles." && !m.HayTextoEnElPortapapeles, "si el portapapeles falla, lo dice y no finge haber copiado");
            clip.Fallar = false;

            // bloquear con una contraseña copiada: se borra en el acto
            Esperar(m.CopiarContrasenaAsync());
            Check(clip.Texto == "otra-clave-larga-9", "control: hay una contraseña en el portapapeles");

            // ---- filtraciones
            Check(rangos.Llamadas == 0, "hasta ahora no se hizo ninguna consulta a Internet");
            Esperar(m.AuditarAsync());
            Check(rangos.Llamadas == 3 && m.HayAuditoria, "«Comprobar filtraciones» consulta una vez por cada contraseña distinta (3)", rangos.Llamadas.ToString());
            Check(m.IndicadorDeAuditoria == Indicador.Alerta && m.Auditoria.StartsWith("1 contraseña aparece en filtraciones públicas"), "«password» aparece: alerta y lo dice", m.Auditoria);
            FilaDeEntrada fPass = m.Entradas.First(e => e.Sitio == "correo.ejemplo.com");
            Check(fPass.TieneFiltracion && fPass.Filtracion == "Filtrada (5.000.000 veces)", "la fila dice «Filtrada (5.000.000 veces)»", fPass.Filtracion);
            Check(m.Entradas.Where(e => e.Sitio != "correo.ejemplo.com").All(e => e.Filtracion == "No aparece en filtraciones conocidas"), "las otras: «No aparece en filtraciones conocidas» (y no «es buena»)");

            // editar o eliminar invalida lo comprobado de esa entrada
            m.Seleccionada = m.Entradas.First(e => e.Sitio == "correo.ejemplo.com");
            m.EditarSeleccionada();
            m.EdContrasena = "una-clave-nueva-y-larga-5";
            Esperar(m.GuardarEdicionAsync());
            Check(!m.Entradas.First(e => e.Sitio == "correo.ejemplo.com").TieneFiltracion, "editar la contraseña borra su resultado de filtraciones (ya no vale)");

            // sin red: nunca verde
            rangos.Caido = true;
            Esperar(m.AuditarAsync());
            Check(m.IndicadorDeAuditoria == Indicador.Atencion && m.Auditoria.Contains("no significa que estén bien") && m.Entradas.All(e => e.Filtracion == "Sin comprobar"),
                  "sin Internet: «Sin comprobar» en todas, atencion, y dice que no significa que esten bien", m.Auditoria);
            rangos.Caido = false;
            Esperar(m.AuditarAsync());
            Check(m.IndicadorDeAuditoria == Indicador.Correcto && m.Auditoria.Contains("no significa que sean fuertes"), "todo comprobado y limpio: correcto, pero aclara que eso no significa que sean fuertes", m.Auditoria);

            // ---- eliminar
            m.Seleccionada = m.Entradas.First(e => e.Sitio == "aaa-primero.example");
            Check(Esperar(m.EliminarSeleccionadaAsync()) && m.Cantidad == 2 && m.Seleccionada is null && m.Mensaje.Contains("ya no está en el archivo"), "eliminar quita la entrada y dice que ya no esta en el archivo");
            Check(!Esperar(m.EliminarSeleccionadaAsync()), "sin seleccion, eliminar no hace nada");

            // ---- bloquear
            m.Seleccionada = m.Entradas.First(e => e.Sitio == "banco.ejemplo.cl");
            m.AlternarContrasena();
            Check(m.DetalleContrasena == "Nueva-Clave-Banco-77", "control: con la contraseña a la vista");
            m.Bloquear();
            Check(m.Fase == FaseDeBoveda.Bloqueada && m.EsBloqueada && !m.EsAbierta, "bloquear: fase «Bloqueada» (el archivo sigue existiendo)");
            Check(m.Entradas.Count == 0 && m.Cantidad == 0 && m.Seleccionada is null && m.DetalleContrasena == "" && m.DetalleSitio == "" && !m.MostrarContrasena, "bloquear olvida la lista, la seleccion y oculta la contraseña");
            Check(!m.HayAuditoria && m.Filtro == "" && m.EdContrasena == "", "y borra los resultados de filtraciones, el filtro y el formulario");
            Check(m.Mensaje == "Bóveda bloqueada." && m.Titulo == "La bóveda está bloqueada", "mensaje y titulo");
            EsperarHasta(m.EsperarBorradoAsync());
            Check(clip.Texto is null && !m.HayTextoEnElPortapapeles, "y la contraseña que seguia en el portapapeles se borro EN EL ACTO al bloquear (sin esperar los 30 s)");

            // lo del modelo bloqueado no hace nada
            Esperar(m.AuditarAsync());
            Check(!m.HayAuditoria, "bloqueada, «Comprobar filtraciones» no hace nada");
            m.NuevaEntrada(); m.EditarSeleccionada();
            Check(!m.EdicionVisible, "bloqueada, no se puede abrir el formulario");

            // ---- desbloquear
            Check(!Esperar(m.DesbloquearAsync("")) && m.Mensaje == "Escribe la contraseña maestra.", "una maestra vacia no se intenta");
            Check(!Esperar(m.DesbloquearAsync("esta-no-es-la-clave-123")) && m.Fase == FaseDeBoveda.Bloqueada
                  && m.Mensaje == "Contraseña incorrecta, o el archivo fue alterado: no se puede distinguir una cosa de la otra.", "maestra equivocada: sigue bloqueada, y el texto no finge saber si fue la contraseña o el archivo");
            Check(m.Cantidad == 0, "y no entra ninguna entrada");
            Check(Esperar(m.DesbloquearAsync(Maestra)) && m.Fase == FaseDeBoveda.Abierta && m.Cantidad == 2 && m.Mensaje == "", "la maestra correcta abre y trae las 2 entradas que quedaban");
            Check(m.Entradas.Select(e => e.Sitio).SequenceEqual(new[] { "banco.ejemplo.cl", "correo.ejemplo.com" }), "las entradas son las que habia (la eliminada no volvio)");

            // ---- inactividad
            c.Ahora = c.Ahora.AddMinutes(4).AddSeconds(59);
            Check(!m.ComprobarInactividad() && m.Fase == FaseDeBoveda.Abierta, "a los 4:59 sin actividad NO se bloquea");
            m.Actividad();
            c.Ahora = c.Ahora.AddMinutes(4).AddSeconds(59);
            Check(!m.ComprobarInactividad() && m.Fase == FaseDeBoveda.Abierta, "una actividad reinicia la cuenta");
            c.Ahora = c.Ahora.AddSeconds(2);
            Check(m.ComprobarInactividad() && m.Fase == FaseDeBoveda.Bloqueada && m.Mensaje == "La bóveda se bloqueó por inactividad.", "a los 5 min sin actividad se bloquea y lo dice");
            Check(!m.ComprobarInactividad(), "ya bloqueada, no hay nada que bloquear");
            Check(m.ResumenDeInactividad == "Se bloquea sola tras 5 minutos sin usarla.", "el texto dice cuanto es");

            // ---- cambiar la maestra
            Esperar(m.DesbloquearAsync(Maestra));
            Check(!Esperar(m.CambiarMaestraAsync("equivocada", "otra-maestra-nueva-77", "otra-maestra-nueva-77")) && m.Mensaje == "La contraseña maestra actual no es correcta.", "con la maestra actual equivocada no cambia");
            Check(!Esperar(m.CambiarMaestraAsync(Maestra, "corta", "corta")) && m.Mensaje == "La contraseña nueva debe tener al menos 10 caracteres.", "una nueva corta se rechaza");
            Check(!Esperar(m.CambiarMaestraAsync(Maestra, "otra-maestra-nueva-77", "otra-maestra-nueva-78")) && m.Mensaje == "Las dos contraseñas nuevas no coinciden.", "dos nuevas distintas se rechazan");
            Check(Esperar(m.CambiarMaestraAsync(Maestra, "otra-maestra-nueva-77", "otra-maestra-nueva-77")) && m.Mensaje == "Contraseña maestra cambiada. La anterior ya no abre la bóveda.", "cambiar la maestra");
            m.Bloquear();
            Check(!Esperar(m.DesbloquearAsync(Maestra)) && Esperar(m.DesbloquearAsync("otra-maestra-nueva-77")) && m.Cantidad == 2, "la vieja ya no abre; la nueva si, con las 2 entradas");
            m.Bloquear();

            // ---- copia de seguridad
            const string maestraActual = "otra-maestra-nueva-77";
            Check(!m.HayCopiaReciente && m.TextoDeCopia == "Todavía no guardaste ninguna copia en esta sesión.", "sin copias en la sesión, el recordatorio lo dice");
            string copiaRuta = Path.Combine(dir, "respaldos", "copia.nxv");
            Check(!Esperar(m.GuardarCopiaAsync(copiaRuta)) && !File.Exists(copiaRuta), "con la bóveda bloqueada no se puede guardar una copia (y no se crea nada)");
            Esperar(m.DesbloquearAsync(maestraActual));
            c.Ahora = new DateTime(2026, 11, 7, 18, 45, 0);
            m.Actividad();
            Check(Esperar(m.GuardarCopiaAsync(copiaRuta)) && File.Exists(copiaRuta), "guardar una copia en una carpeta que no existe: la crea");
            Check(m.Mensaje.StartsWith("Copia guardada en «") && m.Mensaje.Contains("seguirá en esta copia") && m.Mensaje.Contains("otro disco"), "el mensaje avisa que lo borrado después seguirá en la copia y recomienda otro disco", m.Mensaje);
            Check(m.HayCopiaReciente && m.TextoDeCopia == "Última copia de esta sesión: 07/11 18:45.", "y el recordatorio muestra la hora de la última copia", m.TextoDeCopia);
            ResultadoDeApertura rc = Esperar(Bov.AbrirAsync(copiaRuta, maestraActual));
            Check(rc.Abierta && rc.Boveda!.Entradas.Count == 2, "la copia abre con la contraseña maestra actual y trae las 2 entradas");
            rc.Boveda?.Dispose();
            Check(!Esperar(m.GuardarCopiaAsync(ruta)) && m.Mensaje == "No se pudo guardar la copia: La copia no puede ser el mismo archivo de la bóveda.", "no acepta guardar la copia sobre la propia bóveda", m.Mensaje);
            Check(!Esperar(m.GuardarCopiaAsync(copiaRuta)) && m.Mensaje.StartsWith("No se pudo guardar la copia: Ya existe un archivo en ese destino"), "ni sobre otra copia que ya existe, salvo permiso expreso", m.Mensaje);
            Check(Esperar(m.GuardarCopiaAsync(copiaRuta, sobrescribir: true)) && !m.Ocupado, "con permiso expreso la sobrescribe, y no queda «ocupado»");
            Check(!m.PuedeRestaurar && !Esperar(m.RestaurarAsync(copiaRuta, maestraActual)), "con la bóveda abierta no se puede restaurar (no hace nada)");
            m.Bloquear();
            Check(!m.HayCopiaReciente && m.PuedeRestaurar && m.ExisteBoveda, "al bloquear se olvida la «última copia de esta sesión»; ahora sí se puede restaurar, y hay una bóveda que se apartaría");

            // la bóveda cambia DESPUES de la copia (otra contraseña maestra); luego se restaura la copia
            Esperar(m.DesbloquearAsync(maestraActual));
            Esperar(m.CambiarMaestraAsync(maestraActual, "maestra-posterior-55", "maestra-posterior-55"));
            m.Bloquear();
            Check(!Esperar(m.RestaurarAsync(copiaRuta, "")) && m.Mensaje == "Escribe primero la contraseña maestra de la copia.", "restaurar sin escribir la contraseña de la copia: lo pide");
            Check(!Esperar(m.RestaurarAsync(copiaRuta, "no-es-la-maestra-de-la-copia")) && m.Mensaje.StartsWith("Contraseña incorrecta, o la copia fue alterada") && m.Mensaje.EndsWith("No se cambió nada."),
                  "con la contraseña equivocada: rechazada y lo dice, sin cambiar nada", m.Mensaje);
            Check(Esperar(m.DesbloquearAsync("maestra-posterior-55")) && m.Cantidad == 2, "control: la bóveda sigue intacta (abre con su contraseña actual)");
            m.Bloquear();

            Check(Esperar(m.RestaurarAsync(copiaRuta, maestraActual)) && m.Fase == FaseDeBoveda.Bloqueada, "restaurar la copia con su contraseña: queda BLOQUEADA, a la espera de abrirla");
            Check(m.Mensaje.StartsWith("Copia restaurada. Escribe la contraseña maestra de la copia para abrirla.") && m.Mensaje.Contains("se guardó aparte como «") && m.Mensaje.Contains("no se borró"),
                  "y dice que la bóveda anterior se guardó aparte y no se borró", m.Mensaje);
            Check(!Esperar(m.DesbloquearAsync("maestra-posterior-55")) && Esperar(m.DesbloquearAsync(maestraActual)) && m.Cantidad == 2, "ahora abre con la contraseña de la COPIA, no con la posterior");
            m.Bloquear();
            string[] apartadas = Directory.GetFiles(dir, Path.GetFileName(ruta) + ".anterior-*");
            Check(apartadas.Length == 1, "hay exactamente un archivo apartado", string.Join(",", apartadas.Select(Path.GetFileName)));
            ResultadoDeApertura ap = Esperar(Bov.AbrirAsync(apartadas[0], "maestra-posterior-55"));
            Check(ap.Abierta && ap.Boveda!.Entradas.Count == 2, "y la bóveda apartada sigue abriendo con SU contraseña (no se perdió nada)");
            ap.Boveda?.Dispose();

            string mala = Path.Combine(dir, "copia-mala.nxv");
            File.WriteAllBytes(mala, new byte[100]);
            Check(!Esperar(m.RestaurarAsync(mala, maestraActual)) && m.Mensaje.StartsWith("El archivo no es una copia de bóveda de Nexo o está dañado.") && m.Mensaje.EndsWith("No se cambió nada."), "un archivo que no es una copia: rechazado, sin cambiar nada");
            Check(!Esperar(m.RestaurarAsync(Path.Combine(dir, "no-existe.nxv"), maestraActual)) && m.Mensaje == "El archivo de la copia no existe.", "una copia que no existe");
            Check(!Esperar(m.RestaurarAsync(ruta, maestraActual)) && m.Mensaje == "Elegiste el archivo de la propia bóveda: no hay nada que restaurar.", "elegir la propia bóveda como copia: no hay nada que restaurar");
            Check(Directory.GetFiles(dir, Path.GetFileName(ruta) + ".anterior-*").Length == 1, "los rechazos no dejan archivos apartados de más");

            // sin bóveda: restaurar crea la bóveda desde la copia
            var mn = Modelo(Ruta(dir, "desdecopia"), c, clip);
            Espiar(mn);
            Check(mn.EsSinBoveda && mn.PuedeRestaurar && !mn.ExisteBoveda, "sin bóveda también se puede restaurar (y no hay nada que apartar)");
            Check(Esperar(mn.RestaurarAsync(copiaRuta, maestraActual)) && mn.EsBloqueada && !mn.Mensaje.Contains("aparte"), "restaurar sin bóveda previa: queda bloqueada y no habla de «aparte»");
            Check(Esperar(mn.DesbloquearAsync(maestraActual)) && mn.Cantidad == 2, "y abre con la contraseña de la copia, con sus 2 entradas");
            mn.Bloquear();
            Check(Regex.IsMatch(ContrasenasModelo.NombreSugeridoDeCopia(), @"^boveda-copia-\d{8}\.nxv$"), "el nombre sugerido de la copia lleva la fecha");

            // ---- archivos raros
            string original = ruta;
            byte[] bytes = File.ReadAllBytes(original);
            string ilegible = Ruta(dir, "ilegible");
            File.WriteAllBytes(ilegible, bytes.AsSpan(0, 40).ToArray());
            var mi = Modelo(ilegible, c, clip); Espiar(mi);
            Check(mi.Fase == FaseDeBoveda.Bloqueada && !Esperar(mi.DesbloquearAsync(Maestra)) && mi.Mensaje.StartsWith("El archivo no es una bóveda de Nexo o está dañado."), "un archivo truncado: «no es una bóveda o está dañado»", mi.Mensaje);
            string hostil = Ruta(dir, "hostil");
            byte[] h = (byte[])bytes.Clone();
            BitConverter.GetBytes(0xFFFFFFFFu).CopyTo(h, 6);
            File.WriteAllBytes(hostil, h);
            var mh = Modelo(hostil, c, clip); Espiar(mh);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            Check(!Esperar(mh.DesbloquearAsync(Maestra)) && mh.Mensaje.Contains("fuera de lo aceptable") && sw.ElapsedMilliseconds < 3000, "un archivo que pide 4 GiB: se rechaza en milisegundos con una explicacion", mh.Mensaje + " " + sw.ElapsedMilliseconds + " ms");
            string version = Ruta(dir, "version");
            byte[] v = (byte[])bytes.Clone(); v[4] = 9;
            File.WriteAllBytes(version, v);
            var mv = Modelo(version, c, clip); Espiar(mv);
            Check(!Esperar(mv.DesbloquearAsync(Maestra)) && mv.Mensaje.Contains("versión más nueva de Nexo"), "una version futura: pide actualizar Nexo");

            // el archivo desaparece mientras esta bloqueada
            string efimera = Ruta(dir, "efimera");
            File.Copy(original, efimera);
            var me = Modelo(efimera, c, clip); Espiar(me);
            Check(me.Fase == FaseDeBoveda.Bloqueada, "control: existe y esta bloqueada");
            File.Delete(efimera);
            Check(!Esperar(me.DesbloquearAsync("otra-maestra-nueva-77")) && me.Fase == FaseDeBoveda.SinBoveda && me.Mensaje == "El archivo de la bóveda ya no existe.", "si el archivo desaparece, vuelve a «sin bóveda» y lo dice");

            // ---- la maestra no queda en ninguna propiedad del modelo
            Esperar(m.DesbloquearAsync("otra-maestra-nueva-77"));
            var propiedades = typeof(ContrasenasModelo).GetProperties(BindingFlags.Public | BindingFlags.Instance).Where(p => p.PropertyType == typeof(string));
            var campos = typeof(ContrasenasModelo).GetFields(BindingFlags.NonPublic | BindingFlags.Instance).Where(f => f.FieldType == typeof(string));
            bool fuga = propiedades.Any(p => (p.GetValue(m) as string ?? "").Contains("otra-maestra-nueva-77")) || campos.Any(f => (f.GetValue(m) as string ?? "").Contains("otra-maestra-nueva-77"))
                        || textos.Any(t => t.Contains("otra-maestra-nueva-77") || t.Contains(Maestra));
            Check(!fuga, "la contraseña maestra no queda en ninguna propiedad ni campo de texto del modelo, ni en ningun mensaje");
            Check(!textos.Any(t => t.Contains("Nueva-Clave-Banco-77") || t.Contains("S3creto!Banco") || t.Contains("otra-clave-larga-9") || t.Contains("password")), "y los mensajes tampoco llevan contraseñas de las entradas");
            m.Bloquear();

            // ---- ruta
            bool lanzo = false;
            try { _ = new ContrasenasModelo("relativa/boveda.nxv"); } catch (ArgumentException) { lanzo = true; }
            Check(lanzo, "una ruta relativa se rechaza");
            string porOmision = ContrasenasModelo.RutaPorOmision();
            Check(porOmision.EndsWith("boveda.nxv") && porOmision.Contains("Nexo") && !porOmision.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), StringComparison.OrdinalIgnoreCase)
                  || Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) == "",
                  "por omision va en el perfil del usuario, NO en ProgramData", porOmision);

            // ---- tildes
            var banales = new SortedSet<string>(StringComparer.Ordinal);
            foreach (string t in textos)
                foreach (Match mm in Regex.Matches(Regex.Replace(t, "«[^»]*»", "«»"), @"[A-Za-zÁÉÍÓÚáéíóúñÑ]+"))
                    if (Array.IndexOf(SinTildeContrasenas, mm.Value.ToLowerInvariant()) >= 0) banales.Add(mm.Value + " en «" + t + "»");
            Check(textos.Count > 25 && banales.Count == 0, "los " + textos.Count + " textos distintos que mostro la pestaña llevan sus tildes y eñes", string.Join(" | ", banales.Take(4)));
        }

        // ---------------------------------------------------------------- la ventana de verdad
        private static bool EsperarA(Func<bool> condicion, int ms = 15000)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            while (!condicion() && sw.ElapsedMilliseconds < ms) { Dispatcher.UIThread.RunJobs(); Thread.Sleep(5); }
            Dispatcher.UIThread.RunJobs();
            return condicion();
        }

        private static void Clic(Button b) { b.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); Dispatcher.UIThread.RunJobs(); }

        public static void ProbarBloqueoDeSeguridadDelModelo()
        {
            Console.WriteLine("Contraseñas: bloqueo por seguridad (modelo)");
            string dir = Path.Combine(Path.GetTempPath(), "nexo-bloqueo-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var c = new Controles();
                var m = Modelo(Ruta(dir, "b"), c, new PortapapelesFalso());
                Check(!m.BloquearPorSeguridad("x") && m.Fase == FaseDeBoveda.SinBoveda, "sin bóveda no hace nada");
                Esperar(m.CrearAsync(Maestra, Maestra));
                Check(m.EsAbierta, "(preparacion) bóveda creada y abierta");
                var ocupado = typeof(ContrasenasModelo).GetProperty("Ocupado")!;

                // Una operacion en curso no se interrumpe: el bloqueo espera a que termine.
                ocupado.SetValue(m, true);
                Check(!m.BloquearPorSeguridad("motivo en espera") && m.Fase == FaseDeBoveda.Abierta, "con una operación en curso NO la interrumpe: la bóveda sigue abierta");
                ocupado.SetValue(m, false);
                Check(m.Fase == FaseDeBoveda.Bloqueada && m.Mensaje == "motivo en espera", "en cuanto la operación termina, se bloquea con el motivo pedido", m.Fase + " / " + m.Mensaje);

                // Un bloqueo pendiente no sobrevive a un bloqueo a mano ni se aplica a una sesion nueva.
                Esperar(m.DesbloquearAsync(Maestra));
                ocupado.SetValue(m, true);
                m.BloquearPorSeguridad("pendiente viejo");
                m.Bloquear();
                ocupado.SetValue(m, false);
                Esperar(m.DesbloquearAsync(Maestra));
                ocupado.SetValue(m, true);
                ocupado.SetValue(m, false);
                Check(m.Fase == FaseDeBoveda.Abierta, "un bloqueo pendiente se olvida si ya se bloqueó a mano: no cierra la sesión siguiente");

                // Abierta y libre: bloquea al instante.
                Check(m.BloquearPorSeguridad("ahora") && m.Fase == FaseDeBoveda.Bloqueada && m.Mensaje == "ahora", "abierta y libre: bloquea al instante");
                Check(!m.BloquearPorSeguridad("de nuevo") && m.Mensaje == "ahora", "bloqueada: no cambia nada");
            }
            finally { try { Directory.Delete(dir, true); } catch (IOException) { } }
        }

        private static void ProbarVentanaDeContrasenas(MainWindow w, ContrasenasModelo m, PortapapelesFalso clip, string? captura)
        {
            Console.WriteLine("Pestaña Contraseñas: la ventana");
            w.Pestanas.SelectedIndex = 8;
            Dispatcher.UIThread.RunJobs();
            Check(w.Pestanas.ItemCount == 10 && w.TituloDeContrasenas.Text == "Todavía no tienes una bóveda", "pestaña Contraseñas: sin archivo, «Todavía no tienes una bóveda»", w.TituloDeContrasenas.Text);
            Check(w.PanelSinBoveda.IsVisible && !w.PanelBloqueada.IsVisible && !w.PanelAbierta.IsVisible, "solo se ve el panel de crear");
            Check(w.PanelDeRestauracion.IsVisible && w.BotonRestaurarCopia.IsEnabled, "y debajo, el panel «Restaurar desde una copia» (se puede restaurar sin tener bóveda)");
            if (captura is not null) Foto(w, captura, "contrasenas-crear");

            // crear con clic real en el boton
            w.CajaMaestraNueva.Text = "una-maestra-bien-larga-1";
            w.CajaMaestraRepetida.Text = "una-maestra-bien-larga-2";
            Clic(w.BotonCrearBoveda);
            EsperarA(() => !m.Ocupado);
            Check(w.PanelSinBoveda.IsVisible && w.MensajeDeContrasenas.Text == "Las dos contraseñas no coinciden.", "con dos maestras distintas, el clic no crea y el mensaje se ve", w.MensajeDeContrasenas.Text);
            w.CajaMaestraRepetida.Text = "una-maestra-bien-larga-1";
            Clic(w.BotonCrearBoveda);
            Check(EsperarA(() => m.EsAbierta), "con las dos iguales, el clic crea la bóveda");
            Check(w.PanelAbierta.IsVisible && !w.PanelSinBoveda.IsVisible && !w.PanelBloqueada.IsVisible, "se ve solo el panel de la bóveda abierta");
            Check(w.CajaMaestraNueva.Text == "" && w.CajaMaestraRepetida.Text == "", "y las cajas de la maestra se vaciaron");
            Check(w.PanelDeCopia.IsEffectivelyVisible && !w.PanelDeRestauracion.IsEffectivelyVisible, "con la bóveda abierta se ve «Copia de seguridad» y NO «Restaurar» (restaurar sobre una bóveda abierta no existe)");
            Check(w.TextoDeCopiaGuardada.Text == "Todavía no guardaste ninguna copia en esta sesión." && w.BotonGuardarCopia.IsEnabled, "y el recordatorio dice que aún no hay copia en esta sesión");
            Check(w.CajaMaestraNueva.PasswordChar == '•' && w.CajaMaestra.PasswordChar == '•' && w.CajaMaestraActual.PasswordChar == '•', "las cajas de la maestra ocultan lo que se escribe");

            // alta por la interfaz
            Clic(w.BotonNuevaEntrada);
            Check(w.PanelDeEdicion.IsVisible && !w.PanelDeDetalle.IsVisible, "«Nueva...» muestra el formulario");
            w.CajaDeSitio.Text = "tienda.example";
            w.CajaDeUsuario.Text = "ana";
            w.CajaDeContrasena.Text = "mi-clave-de-tienda-1";
            Check(w.CajaDeContrasena.PasswordChar == '•', "la caja de la contraseña de la entrada esta oculta por omision");
            Clic(w.BotonGenerar);
            Check(w.CajaDeContrasena.Text!.Length == 20 && w.CajaDeContrasena.PasswordChar == '\0', "«Generar» pone una de 20 caracteres y la deja a la vista");
            if (captura is not null) Foto(w, captura, "contrasenas-edicion");
            Clic(w.BotonGuardarEntrada);
            Check(EsperarA(() => w.ListaDeEntradas.ItemCount == 1) && !w.PanelDeEdicion.IsVisible, "«Guardar»: aparece en la lista y se cierra el formulario");
            Check(w.PanelDeDetalle.IsVisible && w.TextoDeContrasena.Text == "••••••••", "queda elegida, con la contraseña oculta");
            Clic(w.BotonMostrarContrasena);
            Check(w.TextoDeContrasena.Text!.Length == 20 && w.BotonMostrarContrasena.Content as string == "Ocultar", "«Mostrar» la enseña");

            // portapapeles por la interfaz
            Clic(w.BotonCopiarContrasena);
            EsperarA(() => clip.Texto is not null);
            Check(clip.Texto!.Length == 20 && m.HayTextoEnElPortapapeles, "«Copiar contraseña» la pone en el portapapeles");

            if (captura is not null) Foto(w, captura, "contrasenas-abierta");

            // bloquear con clic, y desbloquear con la maestra
            Clic(w.BotonBloquearBoveda);
            Check(EsperarA(() => w.PanelBloqueada.IsVisible) && !w.PanelAbierta.IsVisible, "«Bloquear»: se ve solo el panel de desbloquear");
            Check(w.PanelDeRestauracion.IsEffectivelyVisible && !w.PanelDeCopia.IsEffectivelyVisible, "y vuelve el panel «Restaurar desde una copia» (y el de «Copia de seguridad» deja de verse)");
            EsperarA(() => clip.Texto is null);
            Check(clip.Texto is null, "y al bloquear el portapapeles queda limpio");
            if (captura is not null) Foto(w, captura, "contrasenas-bloqueada");
            w.CajaMaestra.Text = "maestra-equivocada-99";
            Clic(w.BotonDesbloquear);
            EsperarA(() => !m.Ocupado);
            Check(w.PanelBloqueada.IsVisible && w.MensajeDeContrasenas.Text!.StartsWith("Contraseña incorrecta, o el archivo fue alterado"), "una maestra equivocada: sigue bloqueada y lo dice");
            w.CajaMaestra.Text = "una-maestra-bien-larga-1";
            Clic(w.BotonDesbloquear);
            Check(EsperarA(() => m.EsAbierta) && w.ListaDeEntradas.ItemCount == 1 && w.CajaMaestra.Text == "", "la correcta abre, trae la entrada y vacia la caja");

            // auditoria por la interfaz (consulta falsa)
            Check(!w.PanelDeAuditoria.IsVisible, "antes de pulsar, no hay resultado de filtraciones a la vista");
            Clic(w.BotonAuditar);
            Check(EsperarA(() => m.HayAuditoria && !m.Ocupado) && w.PanelDeAuditoria.IsVisible && w.ResumenDeAuditoria.Text!.Contains("no significa que sean fuertes"), "«Comprobar filtraciones»: aparece el resultado y su aviso");

            // bloqueo por seguridad: minimizar la ventana y sesion/suspension (la ventana lo llama con el motivo)
            m.Seleccionada = m.Entradas[0];
            Clic(w.BotonCopiarContrasena);
            EsperarA(() => clip.Texto is not null);
            Check(m.EsAbierta && clip.Texto is not null, "control: abierta y con una contraseña copiada antes de minimizar");
            w.WindowState = Avalonia.Controls.WindowState.Minimized;
            Dispatcher.UIThread.RunJobs();
            Check(EsperarA(() => m.Fase == FaseDeBoveda.Bloqueada) && m.Mensaje == MainWindow.MotivoAlMinimizar, "al MINIMIZAR la ventana, la bóveda se bloquea y dice por qué", m.Mensaje);
            Check(EsperarA(() => clip.Texto is null), "y la contraseña copiada se borra del portapapeles");
            Check(w.PanelBloqueada.IsVisible && !w.PanelAbierta.IsVisible, "y la ventana muestra el panel de desbloquear");
            w.WindowState = Avalonia.Controls.WindowState.Normal;
            Dispatcher.UIThread.RunJobs();
            Check(m.Fase == FaseDeBoveda.Bloqueada, "al restaurar la ventana NO se desbloquea sola");
            w.CajaMaestra.Text = "una-maestra-bien-larga-1";
            Clic(w.BotonDesbloquear);
            Check(EsperarA(() => m.EsAbierta), "(preparacion) se desbloquea con la maestra");
            Check(w.BloquearBovedaPorSeguridad("La bóveda se bloqueó porque se bloqueó la sesión de Windows.") && m.Fase == FaseDeBoveda.Bloqueada && m.Mensaje == "La bóveda se bloqueó porque se bloqueó la sesión de Windows.",
                "la sesión de Windows bloqueada (o suspensión) bloquea la bóveda con su propio motivo");
            Check(!w.BloquearBovedaPorSeguridad("otra vez") && m.Mensaje == "La bóveda se bloqueó porque se bloqueó la sesión de Windows.", "ya bloqueada, un segundo aviso no cambia nada ni pisa el mensaje");
            w.CajaMaestra.Text = "una-maestra-bien-larga-1";
            Clic(w.BotonDesbloquear);
            Check(EsperarA(() => m.EsAbierta), "(preparacion) se vuelve a desbloquear");

            // cerrar la ventana con una contraseña copiada: se espera a borrarla
            m.Seleccionada = m.Entradas[0];
            Clic(w.BotonCopiarContrasena);
            EsperarA(() => clip.Texto is not null);
            Check(clip.Texto is not null, "control: hay una contraseña copiada antes de cerrar");
            w.Close();
            Check(EsperarA(() => clip.Texto is null), "al cerrar la ventana, la contraseña copiada se borra del portapapeles");
            Check(EsperarA(() => m.Fase == FaseDeBoveda.Bloqueada), "y la bóveda queda bloqueada");
        }

        private static void Foto(MainWindow w, string captura, string nombre)
        {
            // Una pestaña recien mostrada necesita su pasada de diseño antes de dibujarse: sin esto, la primera captura sale con los controles sin medir.
            w.UpdateLayout();
            Dispatcher.UIThread.RunJobs();
            AvaloniaHeadlessPlatform.ForceRenderTimerTick();
            string f = Path.ChangeExtension(captura, null) + "-" + nombre + ".png";
            w.CaptureRenderedFrame()?.Save(f);
            Console.WriteLine("           captura: " + f);
        }
    }
}
