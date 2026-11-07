using System;
using System.Collections.Generic;
using System.Linq;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Vulnerabilidades
{
    public enum EstadoDeLecturaDispositivos
    {
        Correcta,
        /// <summary>No existe el almacen de permisos de Windows (versiones antiguas, o limpiado): NO es «nadie uso la camara».</summary>
        SinAlmacen,
        Error
    }

    /// <summary>
    /// Una fila del almacen de permisos de Windows (<c>CapabilityAccessManager\ConsentStore</c>) para la camara («webcam») o el microfono
    /// («microphone»). <see cref="Clave"/> es el nombre de la clave: en programas normales la ruta con «#» en vez de «\», y en aplicaciones
    /// de la Tienda el nombre de familia del paquete. Los tiempos son FILETIME crudos (100 ns desde 1601); fin = 0 con inicio &gt; 0 es
    /// «Windows lo marca en uso».
    /// </summary>
    public sealed record RegistroDeDispositivo(string Dispositivo, string Clave, bool Empaquetada, string? Permiso, long? InicioFiletime, long? FinFiletime);

    public sealed record InstantaneaDeDispositivos(
        EstadoDeLecturaDispositivos Estado, string? PermisoGlobalCamara, string? PermisoGlobalMicrofono,
        IReadOnlyList<RegistroDeDispositivo> Registros, int Ilegibles);

    /// <summary>
    /// Que programas usaron la camara y el microfono, segun lo que Windows apunta (solo LECTURA del registro del usuario actual).
    /// Reglas de honestidad: Windows apunta lo que el sistema ve; un programa que no pasa por ahi puede no figurar, asi que «nadie la
    /// uso» nunca se afirma; un almacen que no se pudo leer es «no evaluado»; «en uso ahora» es lo que Windows marca y puede ser un dato
    /// viejo si un programa se cerro mal. Nada de esto prueba que un acceso sea malicioso: se muestra y el usuario decide. Nexo no
    /// bloquea nada (cambiar permisos del dispositivo se hace en Configuracion de Windows).
    /// </summary>
    public static class AnalizadorDeDispositivos
    {
        public static readonly TimeSpan VentanaReciente = TimeSpan.FromDays(7);
        public static readonly TimeSpan VentanaRuta = TimeSpan.FromDays(30);

        /// <summary>Carpetas donde un programa legitimo instalado no suele vivir: temporales, descargas, papelera, carpeta publica.</summary>
        private static readonly string[] CarpetasPocoHabituales =
        {
            @"\appdata\local\temp\", @"\windows\temp\", @"\temp\", @"\downloads\", @"\descargas\", @"\$recycle.bin\", @"\users\public\"
        };

        // FILETIME valido: de 1 a 31/12/9999.
        private const long MaximoFiletime = 2_650_467_743_999_999_999L;

        public static string Nombre(string dispositivo) => dispositivo == "webcam" ? "cámara" : "micrófono";

        /// <summary>Con su articulo: «la cámara» (femenino) y «el micrófono» (masculino).</summary>
        public static string Con(string dispositivo) => dispositivo == "webcam" ? "la cámara" : "el micrófono";

        /// <summary>«a la cámara» / «al micrófono».</summary>
        private static string ALa(string dispositivo) => dispositivo == "webcam" ? "a la cámara" : "al micrófono";

        /// <summary>El pronombre para retomarlo: «usarla» / «usarlo».</summary>
        private static string Pron(string dispositivo) => dispositivo == "webcam" ? "la" : "lo";

        public static string RutaDe(RegistroDeDispositivo r) => r.Empaquetada ? r.Clave : r.Clave.Replace('#', '\\');

        public static string ProgramaDe(RegistroDeDispositivo r)
        {
            if (r.Empaquetada)
            {
                int i = r.Clave.IndexOf('_');
                return i > 0 ? r.Clave.Substring(0, i) : r.Clave;
            }
            string ruta = RutaDe(r);
            int b = ruta.LastIndexOf('\\');
            return b >= 0 && b + 1 < ruta.Length ? ruta.Substring(b + 1) : ruta;
        }

        public static DateTimeOffset? Fecha(long? filetime)
            => filetime is long f && f > 0 && f <= MaximoFiletime ? DateTimeOffset.FromFileTime(f).ToUniversalTime() : null;

        /// <summary>
        /// «En uso ahora» solo si Windows no cerro el uso (fin = 0) Y empezo en las ultimas 24 horas. Windows deja fin = 0 en versiones viejas de un
        /// programa que nunca cerro esa fila (comprobado en un equipo real: cuatro versiones de Discord de junio a octubre con el programa abierto),
        /// asi que un «sin fin» antiguo es un dato viejo, no un uso actual.
        /// </summary>
        public static bool EnUsoAhora(RegistroDeDispositivo r, DateTimeOffset ahora)
            => r.InicioFiletime is > 0 && r.FinFiletime == 0 && Fecha(r.InicioFiletime) is DateTimeOffset i && ahora - i <= LimiteEnUso && i <= ahora.AddMinutes(5);

        public static readonly TimeSpan LimiteEnUso = TimeSpan.FromHours(24);

        public static bool EnCarpetaPocoHabitual(RegistroDeDispositivo r)
        {
            if (r.Empaquetada) return false;
            string ruta = RutaDe(r).ToLowerInvariant();
            return CarpetasPocoHabituales.Any(c => ruta.Contains(c));
        }

        public static ResultadoDeAnalisis Analizar(InstantaneaDeDispositivos s, DateTimeOffset ahora)
        {
            if (s is null) throw new ArgumentNullException(nameof(s));
            var hallazgos = new List<HallazgoDeSistema>();
            var noEvaluado = new List<string>();

            if (s.Estado == EstadoDeLecturaDispositivos.SinAlmacen)
            {
                noEvaluado.Add("Windows no tiene el registro de uso de la cámara y el micrófono en este equipo: no se pudo saber qué programas los usaron.");
                return new ResultadoDeAnalisis(hallazgos, noEvaluado);
            }
            if (s.Estado == EstadoDeLecturaDispositivos.Error)
            {
                noEvaluado.Add("No se pudo leer el registro de uso de la cámara y el micrófono: no se pudo saber qué programas los usaron.");
                return new ResultadoDeAnalisis(hallazgos, noEvaluado);
            }
            if (s.Ilegibles > 0)
                noEvaluado.Add(s.Ilegibles + " entrada(s) del registro de uso no se pudieron leer: puede faltar algún programa en esta revisión.");

            foreach ((string clave, string permiso) in new[] { ("webcam", s.PermisoGlobalCamara ?? ""), ("microphone", s.PermisoGlobalMicrofono ?? "") })
                if (string.Equals(permiso, "Deny", StringComparison.OrdinalIgnoreCase))
                    hallazgos.Add(new HallazgoDeSistema("DISP-BLOQUEADO", Severidad.Info, "El acceso " + ALa(clave) + " está desactivado en Windows",
                        "Windows tiene apagado el acceso " + ALa(clave) + " para los programas. Es una configuración tuya: ningún programa debería poder usar" + Pron(clave) + " mientras siga así.",
                        "Nada que hacer. Se cambia en Configuración de Windows > Privacidad."));

            foreach (string disp in new[] { "webcam", "microphone" })
            {
                List<RegistroDeDispositivo> regs = s.Registros.Where(r => r.Dispositivo == disp).ToList();

                // Un aviso por PROGRAMA: varias versiones del mismo ejecutable (Discord app-1.0.9242, app-1.0.9243...) son un programa.
                foreach (RegistroDeDispositivo r in regs.Where(x => EnUsoAhora(x, ahora)).GroupBy(ProgramaDe, StringComparer.OrdinalIgnoreCase).Select(g => g.First()))
                    hallazgos.Add(new HallazgoDeSistema("DISP-EN-USO", Severidad.Info, "Windows marca " + Con(disp) + " en uso ahora",
                        ProgramaDe(r) + " figura usando " + Con(disp) + ". Es lo que Windows apunta: si el programa se cerró mal, el dato puede ser viejo.",
                        "Si no reconoces el programa, ciérralo y revisa quién lo instaló.", ProgramaDe(r)));

                foreach (RegistroDeDispositivo r in regs)
                {
                    DateTimeOffset? inicio = Fecha(r.InicioFiletime);
                    if (inicio is null || ahora - inicio.Value > VentanaRuta || inicio.Value > ahora.AddMinutes(5)) continue;
                    if (!EnCarpetaPocoHabitual(r)) continue;
                    hallazgos.Add(new HallazgoDeSistema("DISP-CARPETA-RARA", Severidad.Media, "Un programa en una carpeta poco habitual usó " + Con(disp),
                        ProgramaDe(r) + " usó " + Con(disp) + " y está en «" + RutaDe(r) + "», una carpeta de temporales o descargas, donde no suelen vivir los programas instalados. " +
                        "Esto no prueba que sea malicioso: puede ser un instalador o un programa portátil que abriste tú.",
                        "Si no lo reconoces, no lo abras más y analízalo con Nexo.", ProgramaDe(r)));
                }

                List<RegistroDeDispositivo> recientes = regs.Where(r => Fecha(r.InicioFiletime) is DateTimeOffset i && ahora - i <= VentanaReciente && i <= ahora.AddMinutes(5)).ToList();
                if (recientes.Count > 0)
                {
                    string nombres = string.Join(", ", recientes.Select(ProgramaDe).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).Take(12));
                    int distintos = recientes.Select(ProgramaDe).Distinct(StringComparer.OrdinalIgnoreCase).Count();
                    hallazgos.Add(new HallazgoDeSistema("DISP-RECIENTE", Severidad.Info,
                        distintos + (distintos == 1 ? " programa usó " : " programas usaron ") + Con(disp) + " en los últimos 7 días",
                        nombres + (distintos > 12 ? " y " + (distintos - 12) + " más" : "") + ". Según el registro de Windows; un programa que no pase por ahí puede no figurar.",
                        "Revisa que los reconozcas. Para quitar el permiso a uno: Configuración de Windows > Privacidad."));
                }
            }

            return new ResultadoDeAnalisis(
                hallazgos.OrderByDescending(h => h.Severidad).ThenBy(h => h.Id, StringComparer.Ordinal).ThenBy(h => h.Sujeto, StringComparer.Ordinal).ToList(),
                noEvaluado);
        }
    }
}
