using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;
using Nexo.Ui.Desktop;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Desktop.Demo
{
    internal static partial class Program
    {
        private sealed class RastroFalso : IRastroDeVentana
        {
            public readonly List<(string Tipo, IReadOnlyDictionary<string, object?> Campos)> Avisos = new();
            public bool Lanzar;
            public void Avisar(string tipo, IReadOnlyDictionary<string, object?>? campos = null)
            {
                Avisos.Add((tipo, campos ?? new Dictionary<string, object?>()));
                if (Lanzar) throw new InvalidOperationException("el rastro fallo");
            }
        }

        private static string Todo(RastroFalso r) => string.Join("|", r.Avisos.Select(a => a.Tipo + ":" + string.Join(",", a.Campos.Select(k => k.Key + "=" + k.Value))));

        public static void ProbarRastroDeLaVentana()
        {
            Console.WriteLine("Rastro de la ventana: lo que se avisa al servicio");

            // ---- revisiones de seguridad
            var f = new SeguridadFalsa();
            var r = new RastroFalso();
            var m = new SeguridadModelo(f) { Rastro = r };
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Cuentas));
            Check(r.Avisos.Count == 1 && r.Avisos[0].Tipo == "seguridad.cuentas" && (int)r.Avisos[0].Campos["hallazgos"]! == 0 && (string)r.Avisos[0].Campos["maxima"]! == "Info" && (bool)r.Avisos[0].Campos["completa"]!,
                "una revision limpia y completa avisa: 0 hallazgos, Info, completa", Todo(r));
            r.Avisos.Clear();
            f.Responde = s => Rev(s, new[] { Hallazgo(Severidad.Media, "Una red llamada MiCasa", "MiCasa"), Hallazgo(Severidad.Alta, "Otra con clave 1234", "Cafe Central"), Hallazgo(Severidad.Info, "Nota") });
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Wifi));
            Check(r.Avisos.Single().Tipo == "seguridad.wifi" && (int)r.Avisos[0].Campos["hallazgos"]! == 2 && (string)r.Avisos[0].Campos["maxima"]! == "Alta",
                "con hallazgos: los cuenta SIN las notas Info (2) y manda la gravedad maxima (Alta)", Todo(r));
            Check(!Todo(r).Contains("MiCasa") && !Todo(r).Contains("Cafe") && !Todo(r).Contains("1234") && r.Avisos[0].Campos.Keys.OrderBy(k => k).SequenceEqual(new[] { "completa", "hallazgos", "maxima" }),
                "el aviso solo lleva hallazgos, maxima y completa: ningun nombre de red, cuenta ni texto");
            r.Avisos.Clear();
            f.Responde = s => Rev(s, new[] { Hallazgo(Severidad.Info, "Solo nota") });
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Aplicaciones));
            Check((int)r.Avisos.Single().Campos["hallazgos"]! == 0 && (string)r.Avisos[0].Campos["maxima"]! == "Info", "solo notas Info: 0 hallazgos");
            r.Avisos.Clear();
            f.Responde = s => Rev(s, Array.Empty<HallazgoDeSistema>(), new[] { "no se pudo leer algo" });
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Cuentas));
            Check(!(bool)r.Avisos.Single().Campos["completa"]!, "una revision incompleta avisa «completa = falso»");
            r.Avisos.Clear();
            f.Responde = s => Consulta<RevisionDeSeccion>.Mal("winget no responde");
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Aplicaciones));
            Check(r.Avisos.Single().Tipo == "seguridad.aplicaciones" && (int)r.Avisos[0].Campos["hallazgos"]! == 0 && !(bool)r.Avisos[0].Campos["completa"]!, "una revision que fallo avisa incompleta (lo desconocido no es «bien»)", Todo(r));
            r.Avisos.Clear();
            Esperar(m.RevisarAsync(SeccionDeSeguridad.Aplicaciones));

            var fn = new SeguridadConNvdFalsa { Apps = new[] { AppNvd("WinRAR 7.01", "RARLab.WinRAR", "7.01.0") } };
            var rn = new RastroFalso();
            var mn = new SeguridadModelo(fn) { Rastro = rn };
            Esperar(mn.RevisarAsync(SeccionDeSeguridad.Aplicaciones));
            rn.Avisos.Clear();
            Esperar(mn.RevisarAsync(SeccionDeSeguridad.FallosConocidos));
            Check(rn.Avisos.Single().Tipo == "seguridad.fallos_conocidos", "la consulta a NVD avisa como «seguridad.fallos_conocidos»", Todo(rn));
            var rt = new RastroFalso();
            var mt = new SeguridadModelo(new SeguridadConNvdFalsa()) { Rastro = rt };
            Esperar(mt.RevisarTodoAsync());
            Check(rt.Avisos.Select(a => a.Tipo).SequenceEqual(new[] { "seguridad.cuentas", "seguridad.wifi", "seguridad.aplicaciones" }), "«Revisar todo» avisa de las 3 locales, nunca de NVD", Todo(rt));
            var rx = new RastroFalso { Lanzar = true };
            var mx = new SeguridadModelo(new SeguridadFalsa()) { Rastro = rx };
            Esperar(mx.RevisarAsync(SeccionDeSeguridad.Cuentas));
            Check(mx.Secciones[0].Estado == "Sin hallazgos", "si el rastro lanza una excepcion, la revision sigue y se muestra igual");

            // ---- boveda
            string dir = Path.Combine(Path.GetTempPath(), "nexo-rastro-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var c = new Controles();
                var clip = new PortapapelesFalso();
                var rb = new RastroFalso();
                var b = Modelo(Ruta(dir, "b"), c, clip);
                b.Rastro = rb;
                Esperar(b.CrearAsync(Maestra, Maestra));
                Check(rb.Avisos.Select(a => a.Tipo).SequenceEqual(new[] { "boveda.creada" }), "crear la boveda avisa «boveda.creada»", Todo(rb));
                Esperar(Alta(b, "banco-secreto.ejemplo.cl", "usuario-secreto", "clave-secreta-123!"));
                b.Bloquear();
                Check(rb.Avisos[^1].Tipo == "boveda.bloqueada" && (string)rb.Avisos[^1].Campos["motivo"]! == "manual", "bloquear a mano avisa con motivo «manual»", Todo(rb));
                int n = rb.Avisos.Count;
                b.Bloquear();
                Check(rb.Avisos.Count == n, "bloquear una boveda YA bloqueada no avisa otra vez");
                Esperar(b.DesbloquearAsync("esta-no-es-la-maestra-99"));
                Check(rb.Avisos[^1].Tipo == "boveda.fallo_de_desbloqueo" && rb.Avisos[^1].Campos.Count == 0, "una maestra equivocada avisa el intento fallido, sin contenido", Todo(rb));
                Esperar(b.DesbloquearAsync(Maestra));
                Check(rb.Avisos[^1].Tipo == "boveda.desbloqueada" && (int)rb.Avisos[^1].Campos["entradas"]! == 1, "desbloquear avisa con el numero de entradas", Todo(rb));
                c.Ahora = c.Ahora.AddMinutes(6);
                b.ComprobarInactividad();
                Check(rb.Avisos[^1].Tipo == "boveda.bloqueada" && (string)rb.Avisos[^1].Campos["motivo"]! == "inactividad", "bloqueo por inactividad: motivo «inactividad»");
                Esperar(b.DesbloquearAsync(Maestra));
                b.BloquearPorSeguridad("x", "minimizar");
                Check((string)rb.Avisos[^1].Campos["motivo"]! == "minimizar", "bloqueo por minimizar: motivo «minimizar»");
                Esperar(b.DesbloquearAsync(Maestra));
                b.BloquearPorSeguridad("x");
                Check((string)rb.Avisos[^1].Campos["motivo"]! == "sesion", "bloqueo por sesion de Windows: motivo «sesion» (el de omision)");
                Esperar(b.DesbloquearAsync(Maestra));
                b.Bloquear(motivoDeRastro: "cierre");
                Check((string)rb.Avisos[^1].Campos["motivo"]! == "cierre", "al cerrar la ventana: motivo «cierre»");

                // Un bloqueo que esperaba a una operacion en curso conserva SU motivo.
                Esperar(b.DesbloquearAsync(Maestra));
                var ocupado = typeof(ContrasenasModelo).GetProperty("Ocupado")!;
                ocupado.SetValue(b, true);
                b.BloquearPorSeguridad("espera", "minimizar");
                ocupado.SetValue(b, false);
                Check(b.Fase == FaseDeBoveda.Bloqueada && (string)rb.Avisos[^1].Campos["motivo"]! == "minimizar", "un bloqueo que espero a una operacion conserva su motivo", Todo(rb));

                // Copia, restauracion y auditoria.
                Esperar(b.DesbloquearAsync(Maestra));
                string copia = Path.Combine(dir, "copia.nxv");
                Esperar(b.GuardarCopiaAsync(copia));
                Check(rb.Avisos[^1].Tipo == "boveda.copia_guardada" && rb.Avisos[^1].Campos.Count == 0, "guardar una copia avisa, sin la ruta ni nada mas", Todo(rb));
                Esperar(b.AuditarAsync());
                Check(rb.Avisos[^1].Tipo == "boveda.auditoria" && (int)rb.Avisos[^1].Campos["comprobadas"]! == 1 && (int)rb.Avisos[^1].Campos["comprometidas"]! == 0, "comprobar filtraciones avisa los conteos", Todo(rb));
                b.Bloquear();
                Esperar(b.RestaurarAsync(copia, Maestra));
                Check(rb.Avisos[^1].Tipo == "boveda.restaurada", "restaurar una copia avisa «boveda.restaurada»", Todo(rb));

                // PRIVACIDAD: nada del contenido sale nunca.
                string todo = Todo(rb);
                Check(!todo.Contains("secreto") && !todo.Contains("clave-secreta") && !todo.Contains(Maestra) && !todo.Contains(dir) && !todo.Contains("esta-no-es", StringComparison.Ordinal),
                    "ningun aviso de la boveda contiene sitio, usuario, contraseña, maestra ni rutas", todo);
                Check(rb.Avisos.SelectMany(a => a.Campos.Values).All(v => v is int or bool or string { Length: < 12 }), "todos los valores son numeros, booleanos o etiquetas cortas");

                // Un rastro que falla no rompe la boveda.
                var rf = new RastroFalso { Lanzar = true };
                b.Rastro = rf;
                Esperar(b.DesbloquearAsync(Maestra));
                b.Bloquear();
                Check(b.Fase == FaseDeBoveda.Bloqueada, "si el rastro lanza una excepcion, la boveda se bloquea igual");
            }
            finally { try { Directory.Delete(dir, true); } catch (IOException) { } }
        }
    }
}
