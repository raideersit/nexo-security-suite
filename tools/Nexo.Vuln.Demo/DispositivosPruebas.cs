using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Vuln.Demo
{
    internal static partial class Program
    {
        private static long Ft(DateTimeOffset d) => d.ToFileTime();

        private static RegistroDeDispositivo Reg(string disp, string clave, bool paquete = false, string? permiso = "", long? inicio = null, long? fin = null)
            => new(disp, clave, paquete, permiso, inicio, fin);

        private static InstantaneaDeDispositivos Disp(params RegistroDeDispositivo[] r)
            => new(EstadoDeLecturaDispositivos.Correcta, "Allow", "Allow", r, 0);

        private static readonly DateTimeOffset AhoraDisp = new(2026, 11, 7, 12, 0, 0, TimeSpan.Zero);

        public static void ProbarDispositivos()
        {
            Console.WriteLine("22. Cámara y micrófono: qué programas los usaron");

            // Valores REALES del registro de este equipo (ConsentStore del microfono, 2026-11-07).
            var real = new RegistroDeDispositivo("microphone", @"C:#Program Files (x86)#ClownfishVoiceChanger#ClownfishVoiceChanger.exe", false, "", 134380644432518857, 134380644525886612);
            DateTimeOffset finReal = AnalizadorDeDispositivos.Fecha(real.FinFiletime)!.Value;
            Check(finReal.Year == 2026 && finReal > AnalizadorDeDispositivos.Fecha(real.InicioFiletime)!.Value, "un FILETIME real se convierte a una fecha de 2026 y el fin es posterior al inicio", finReal.ToString("O"));
            Check(AnalizadorDeDispositivos.ProgramaDe(real) == "ClownfishVoiceChanger.exe" && AnalizadorDeDispositivos.RutaDe(real) == @"C:\Program Files (x86)\ClownfishVoiceChanger\ClownfishVoiceChanger.exe",
                "la clave real se lee: «#» vuelve a ser «\\» y el nombre del programa sale de la ruta", AnalizadorDeDispositivos.RutaDe(real));
            ResultadoDeAnalisis rr = AnalizadorDeDispositivos.Analizar(Disp(real), finReal.AddHours(1));
            Check(rr.Completo && rr.Hallazgos.Count(h => h.Id == "DISP-RECIENTE") == 1 && rr.Hallazgos[0].Detalle.Contains("ClownfishVoiceChanger.exe") && rr.Hallazgos[0].Titulo.StartsWith("1 programa usó"), "el uso real reciente sale en un resumen con el programa", string.Join("|", rr.Hallazgos.Select(h => h.Titulo)));
            Check(AnalizadorDeDispositivos.Analizar(Disp(real), finReal.AddDays(8)).Hallazgos.Count == 0, "pasados 8 dias ya no cuenta como reciente");

            // Sin uso: NO se dice «nadie lo uso».
            ResultadoDeAnalisis vacio = AnalizadorDeDispositivos.Analizar(Disp(), AhoraDisp);
            Check(vacio.Completo && vacio.Hallazgos.Count == 0, "sin ningun registro: completo y sin hallazgos");

            // Reciente: agrupa por programa y no cuenta dos veces el mismo (versiones distintas del mismo ejecutable no se confunden: son rutas distintas, pero el nombre se dedupe).
            var recientes = Disp(
                Reg("webcam", @"C:#Program Files#Zoom#bin#Zoom.exe", inicio: Ft(AhoraDisp.AddDays(-1)), fin: Ft(AhoraDisp.AddDays(-1).AddMinutes(30))),
                Reg("webcam", @"C:#Program Files#Zoom#bin#Zoom.exe", inicio: Ft(AhoraDisp.AddDays(-2)), fin: Ft(AhoraDisp.AddDays(-2).AddMinutes(5))),
                Reg("webcam", "Microsoft.WindowsCamera_8wekyb3d8bbwe", paquete: true, inicio: Ft(AhoraDisp.AddDays(-3)), fin: Ft(AhoraDisp.AddDays(-3).AddMinutes(1))),
                Reg("microphone", @"C:#Program Files#Discord#Discord.exe", inicio: Ft(AhoraDisp.AddHours(-2)), fin: Ft(AhoraDisp.AddHours(-1))));
            ResultadoDeAnalisis ar = AnalizadorDeDispositivos.Analizar(recientes, AhoraDisp);
            HallazgoDeSistema cam = ar.Hallazgos.Single(h => h.Id == "DISP-RECIENTE" && h.Titulo.Contains("cámara"));
            Check(cam.Titulo.StartsWith("2 programas usaron la cámara") && cam.Detalle.Contains("WindowsCamera") && cam.Detalle.Contains("Zoom.exe"), "la camara: 2 programas (Zoom cuenta una vez) y el de la Tienda con su nombre corto", cam.Titulo + " / " + cam.Detalle);
            Check(ar.Hallazgos.Any(h => h.Titulo == "1 programa usó el micrófono en los últimos 7 días") && ar.Hallazgos.Any(h => h.Titulo == "2 programas usaron la cámara en los últimos 7 días"),
                "la gramatica: «la cámara» (femenino) y «el micrófono» (masculino)", string.Join("|", ar.Hallazgos.Select(h => h.Titulo)));
            Check(!ar.Hallazgos.Any(h => (h.Titulo + h.Detalle).Contains("la micrófono") || (h.Titulo + h.Detalle).Contains("el cámara")), "nunca «la micrófono» ni «el cámara»");
            ResultadoDeAnalisis dm = AnalizadorDeDispositivos.Analizar(new InstantaneaDeDispositivos(EstadoDeLecturaDispositivos.Correcta, "allow", "Deny", Array.Empty<RegistroDeDispositivo>(), 0), AhoraDisp);
            Check(dm.Hallazgos.Single().Titulo == "El acceso al micrófono está desactivado en Windows" && dm.Hallazgos[0].Detalle.Contains("usarlo mientras"), "«El acceso al micrófono» y «usarlo» (no «a la micrófono» ni «usarla»)", dm.Hallazgos[0].Titulo);
            Check(AnalizadorDeDispositivos.Analizar(new InstantaneaDeDispositivos(EstadoDeLecturaDispositivos.Correcta, "Deny", "allow", Array.Empty<RegistroDeDispositivo>(), 0), AhoraDisp).Hallazgos.Single().Titulo == "El acceso a la cámara está desactivado en Windows", "«El acceso a la cámara»");
            Check(ar.Hallazgos.All(h => h.Severidad == Severidad.Info), "usar la camara con un programa normal es solo informacion (Info), nunca una alarma");

            // En uso ahora (fin = 0).
            ResultadoDeAnalisis enUso = AnalizadorDeDispositivos.Analizar(Disp(Reg("microphone", @"C:#Program Files#Discord#Discord.exe", inicio: Ft(AhoraDisp.AddMinutes(-10)), fin: 0)), AhoraDisp);
            HallazgoDeSistema eu = enUso.Hallazgos.Single(h => h.Id == "DISP-EN-USO");
            Check(eu.Sujeto == "Discord.exe" && eu.Detalle.Contains("puede ser viejo") && eu.Severidad == Severidad.Info, "fin = 0: «en uso ahora», con la advertencia de que puede ser un dato viejo");
            Check(AnalizadorDeDispositivos.Analizar(Disp(Reg("microphone", @"C:#x#a.exe", inicio: Ft(AhoraDisp.AddMinutes(-10)), fin: Ft(AhoraDisp.AddMinutes(-5)))), AhoraDisp).Hallazgos.All(h => h.Id != "DISP-EN-USO"), "con fin posterior al inicio ya no esta en uso");
            // Caso REAL de este equipo: cuatro versiones viejas de Discord con fin = 0 (de junio a octubre) y el programa abierto.
            var discord = Disp(
                Reg("microphone", @"C:#Users#alvar#AppData#Local#Discord#app-1.0.9242#Discord.exe", inicio: 134260933880000000, fin: 0),
                Reg("microphone", @"C:#Users#alvar#AppData#Local#Discord#app-1.0.9243#Discord.exe", inicio: 134268059170000000, fin: 0),
                Reg("microphone", @"C:#Users#alvar#AppData#Local#Discord#app-1.0.9259#Discord.exe", inicio: 134360943050000000, fin: 0),
                Reg("microphone", @"C:#Users#alvar#AppData#Local#Discord#app-1.0.9260#Discord.exe", inicio: 134366001480000000, fin: 0));
            DateTimeOffset hoyReal = new(2026, 11, 7, 20, 0, 0, TimeSpan.Zero);
            Check(AnalizadorDeDispositivos.Analizar(discord, hoyReal).Hallazgos.All(h => h.Id != "DISP-EN-USO"), "REAL: cuatro versiones viejas con fin = 0 NO son «en uso ahora» (Windows nunca cerró esas filas)");
            var frescas = Disp(
                Reg("microphone", @"C:#Users#ana#AppData#Local#Discord#app-1.0.9259#Discord.exe", inicio: Ft(AhoraDisp.AddHours(-3)), fin: 0),
                Reg("microphone", @"C:#Users#ana#AppData#Local#Discord#app-1.0.9260#Discord.exe", inicio: Ft(AhoraDisp.AddHours(-2)), fin: 0));
            Check(AnalizadorDeDispositivos.Analizar(frescas, AhoraDisp).Hallazgos.Count(h => h.Id == "DISP-EN-USO") == 1, "dos versiones del mismo programa en uso dan UN solo aviso (por programa, no por ruta)");
            Check(AnalizadorDeDispositivos.Analizar(Disp(Reg("microphone", @"C:#x#a.exe", inicio: Ft(AhoraDisp.AddHours(-23)), fin: 0)), AhoraDisp).Hallazgos.Any(h => h.Id == "DISP-EN-USO")
                  && AnalizadorDeDispositivos.Analizar(Disp(Reg("microphone", @"C:#x#a.exe", inicio: Ft(AhoraDisp.AddHours(-25)), fin: 0)), AhoraDisp).Hallazgos.All(h => h.Id != "DISP-EN-USO"), "el limite es de 24 horas: a las 23 h si, a las 25 h no");
            Check(AnalizadorDeDispositivos.Analizar(Disp(Reg("microphone", @"C:#x#a.exe", inicio: Ft(AhoraDisp.AddHours(2)), fin: 0)), AhoraDisp).Hallazgos.All(h => h.Id != "DISP-EN-USO"), "un inicio en el futuro no es «en uso»");
            Check(AnalizadorDeDispositivos.Analizar(Disp(Reg("microphone", @"C:#x#a.exe", inicio: 0, fin: 0)), AhoraDisp).Hallazgos.Count == 0, "inicio = 0 y fin = 0 es «nunca usado», no «en uso»");
            Check(AnalizadorDeDispositivos.Analizar(Disp(Reg("microphone", @"C:#x#a.exe", inicio: null, fin: 0)), AhoraDisp).Hallazgos.Count == 0, "sin inicio no hay «en uso»");

            // Carpeta poco habitual.
            string[] raras = { @"C:#Users#ana#Downloads#instalador.exe", @"C:#Users#ana#AppData#Local#Temp#x.exe", @"C:#Windows#Temp#y.exe", @"C:#Users#Public#z.exe", @"C:#Users#ana#Descargas#w.exe", @"D:#$Recycle.Bin#S-1#v.exe" };
            foreach (string ruta in raras)
            {
                ResultadoDeAnalisis r = AnalizadorDeDispositivos.Analizar(Disp(Reg("webcam", ruta, inicio: Ft(AhoraDisp.AddDays(-3)), fin: Ft(AhoraDisp.AddDays(-3).AddMinutes(1)))), AhoraDisp);
                Check(r.Hallazgos.Any(h => h.Id == "DISP-CARPETA-RARA" && h.Severidad == Severidad.Media), "carpeta poco habitual -> Media: " + ruta.Replace('#', '\\'));
            }
            foreach (string ruta in new[] { @"C:#Program Files#Zoom#Zoom.exe", @"C:#Users#ana#AppData#Local#Discord#app#Discord.exe", @"C:#Users#ana#Documents#downloadsanalyzer#x.exe", @"C:#Users#ana#temporal#x.exe" })
                Check(AnalizadorDeDispositivos.Analizar(Disp(Reg("webcam", ruta, inicio: Ft(AhoraDisp.AddDays(-3)), fin: Ft(AhoraDisp.AddDays(-3).AddMinutes(1)))), AhoraDisp).Hallazgos.All(h => h.Id != "DISP-CARPETA-RARA"), "carpeta normal: sin alarma: " + ruta.Replace('#', '\\'));
            Check(AnalizadorDeDispositivos.Analizar(Disp(Reg("webcam", @"C:#Users#ana#Downloads#viejo.exe", inicio: Ft(AhoraDisp.AddDays(-40)), fin: Ft(AhoraDisp.AddDays(-40).AddMinutes(1)))), AhoraDisp).Hallazgos.All(h => h.Id != "DISP-CARPETA-RARA"), "uso de hace 40 dias en Descargas: ya no alarma (solo cuenta el último mes)");
            Check(AnalizadorDeDispositivos.Analizar(Disp(Reg("webcam", @"C:#Users#ana#Downloads#viejo.exe", inicio: Ft(AhoraDisp.AddDays(-29)), fin: Ft(AhoraDisp.AddDays(-29)))), AhoraDisp).Hallazgos.Any(h => h.Id == "DISP-CARPETA-RARA"), "a 29 dias todavia alarma");
            Check(AnalizadorDeDispositivos.Analizar(Disp(Reg("webcam", @"Programa_Descargas_x", paquete: true, inicio: Ft(AhoraDisp.AddDays(-3)), fin: Ft(AhoraDisp.AddDays(-3)))), AhoraDisp).Hallazgos.All(h => h.Id != "DISP-CARPETA-RARA"), "una app de la Tienda no tiene ruta: no se evalua la carpeta");
            HallazgoDeSistema rara = AnalizadorDeDispositivos.Analizar(Disp(Reg("webcam", @"C:#Users#ana#Downloads#instalador.exe", inicio: Ft(AhoraDisp.AddDays(-3)), fin: Ft(AhoraDisp.AddDays(-3)))), AhoraDisp).Hallazgos.First(h => h.Id == "DISP-CARPETA-RARA");
            Check(rara.Detalle.Contains("no prueba que sea malicioso") && rara.Recomendacion.Contains("analízalo con Nexo"), "la alerta de carpeta rara dice que NO prueba nada malicioso y que se puede analizar");

            // Fechas raras: no rompen y no se inventan.
            foreach (long mala in new[] { -1L, 0L, long.MaxValue, 2_650_467_744_000_000_000L })
                Check(AnalizadorDeDispositivos.Fecha(mala) is null, "un FILETIME imposible («" + mala + "») no es una fecha");
            ResultadoDeAnalisis futuro = AnalizadorDeDispositivos.Analizar(Disp(Reg("webcam", @"C:#Users#ana#Downloads#x.exe", inicio: Ft(AhoraDisp.AddDays(5)), fin: Ft(AhoraDisp.AddDays(5)))), AhoraDisp);
            Check(futuro.Hallazgos.Count == 0, "un uso «en el futuro» (reloj raro) no cuenta ni como reciente ni como alarma");
            Check(AnalizadorDeDispositivos.Analizar(Disp(Reg("webcam", @"C:#x#a.exe", inicio: long.MaxValue, fin: long.MaxValue)), AhoraDisp).Hallazgos.Count == 0, "valores enormes: se ignoran sin caerse");

            // Lo que no se pudo leer.
            foreach (EstadoDeLecturaDispositivos e in new[] { EstadoDeLecturaDispositivos.SinAlmacen, EstadoDeLecturaDispositivos.Error })
            {
                ResultadoDeAnalisis n = AnalizadorDeDispositivos.Analizar(new InstantaneaDeDispositivos(e, null, null, Array.Empty<RegistroDeDispositivo>(), 0), AhoraDisp);
                Check(!n.Completo && n.Hallazgos.Count == 0 && n.NoEvaluado.Single().Contains("no se pudo saber"), "«" + e + "»: no evaluado y lo dice (NO «nadie la uso»)", string.Join("|", n.NoEvaluado));
            }
            ResultadoDeAnalisis il = AnalizadorDeDispositivos.Analizar(new InstantaneaDeDispositivos(EstadoDeLecturaDispositivos.Correcta, "Allow", "Allow", Array.Empty<RegistroDeDispositivo>(), 3), AhoraDisp);
            Check(!il.Completo && il.NoEvaluado.Single().Contains("3 entrada(s)") && il.NoEvaluado.Single().Contains("puede faltar"), "entradas ilegibles: revision incompleta, con cuantas");

            // Permiso global.
            ResultadoDeAnalisis den = AnalizadorDeDispositivos.Analizar(new InstantaneaDeDispositivos(EstadoDeLecturaDispositivos.Correcta, "Deny", "allow", Array.Empty<RegistroDeDispositivo>(), 0), AhoraDisp);
            Check(den.Hallazgos.Single().Id == "DISP-BLOQUEADO" && den.Hallazgos[0].Titulo.Contains("cámara") && den.Hallazgos[0].Severidad == Severidad.Info, "cámara desactivada en Windows: una nota Info");
            Check(AnalizadorDeDispositivos.Analizar(new InstantaneaDeDispositivos(EstadoDeLecturaDispositivos.Correcta, "Deny", "DENY", Array.Empty<RegistroDeDispositivo>(), 0), AhoraDisp).Hallazgos.Count == 2, "las dos desactivadas: dos notas (sin distinguir mayúsculas)");

            // Orden: lo mas grave primero.
            ResultadoDeAnalisis orden = AnalizadorDeDispositivos.Analizar(Disp(
                Reg("webcam", @"C:#Program Files#Zoom#Zoom.exe", inicio: Ft(AhoraDisp.AddDays(-1)), fin: Ft(AhoraDisp.AddDays(-1))),
                Reg("webcam", @"C:#Users#ana#Downloads#x.exe", inicio: Ft(AhoraDisp.AddDays(-1)), fin: Ft(AhoraDisp.AddDays(-1)))), AhoraDisp);
            Check(orden.Hallazgos[0].Id == "DISP-CARPETA-RARA", "el hallazgo de carpeta rara va antes que los informativos");

            // Tildes y palabras de absolutos que no se deben afirmar.
            var textos = new List<string>();
            foreach (ResultadoDeAnalisis x in new[] { rr, ar, enUso, den, il, rara is null ? rr : AnalizadorDeDispositivos.Analizar(Disp(Reg("webcam", @"C:#Users#ana#Downloads#instalador.exe", inicio: Ft(AhoraDisp.AddDays(-3)), fin: 0)), AhoraDisp) })
                textos.AddRange(TextosDe(x));
            textos.AddRange(AnalizadorDeDispositivos.Analizar(new InstantaneaDeDispositivos(EstadoDeLecturaDispositivos.SinAlmacen, null, null, Array.Empty<RegistroDeDispositivo>(), 0), AhoraDisp).NoEvaluado);
            textos.AddRange(AnalizadorDeDispositivos.Analizar(new InstantaneaDeDispositivos(EstadoDeLecturaDispositivos.Error, null, null, Array.Empty<RegistroDeDispositivo>(), 0), AhoraDisp).NoEvaluado);
            var malos = new SortedSet<string>(StringComparer.Ordinal);
            foreach (string t in textos)
                foreach (Match m in Palabra.Matches(t))
                    if (Array.IndexOf(SinTilde, m.Value.ToLowerInvariant()) >= 0 && !(m.Value.Length > 1 && m.Value == m.Value.ToUpperInvariant()))
                        malos.Add(m.Value + "  →  «" + Resumen(t, m.Index) + "»");
            Check(textos.Count > 10 && malos.Count == 0, "ningún texto de cámara y micrófono lleva una palabra sin su tilde (" + textos.Count + " textos)", string.Join(" | ", malos.Take(6)));
            Check(!textos.Any(t => Regex.IsMatch(t, @"\bnadie\b|\bningún programa (usó|ha usado)\b|\bes seguro\b|\bestás a salvo\b", RegexOptions.IgnoreCase)), "ningún texto afirma «nadie la usó», «es seguro» ni «estás a salvo»");
        }
    }
}
