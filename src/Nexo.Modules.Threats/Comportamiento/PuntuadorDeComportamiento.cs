using System;
using System.Collections.Generic;
using System.Linq;
using Nexo.Modules.Threats.Criptojacking;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Comportamiento
{
    // =====================================================================================================
    //  ANÁLISIS DE COMPORTAMIENTO (Salida 0, fila 1c). Núcleo portable: no abre ninguna sesión ETW, recibe «eventos».
    //
    //  Puntúa a cada proceso con señales que, SOLAS, son normales (un instalador firmado escribe en Inicio y crea servicios):
    //  sin firma, carpeta poco habitual, escribe en la carpeta Inicio, crea un servicio o una tarea programada, abre una conexión.
    //  Lo que alerta es la SUMA. Nunca da «Crítica»: es una sospecha post-hoc, no una prueba, y no detiene nada.
    //  Una firma desconocida (no se pudo comprobar) no suma ni resta: se dice como «no evaluado».
    // =====================================================================================================

    public enum TipoDeSenal { ProcesoIniciado, ArchivoEnInicio, ServicioCreado, TareaProgramada, ConexionSaliente, ProcesoTerminado }

    public enum EstadoDeFirma { Desconocida, Valida, Ausente, Invalida }

    public sealed record EventoDeComportamiento(TipoDeSenal Tipo, int Pid, string Nombre, string? Ruta = null, EstadoDeFirma Firma = EstadoDeFirma.Desconocida, string? Detalle = null);

    /// <summary>De dónde vienen los eventos de comportamiento (ETW en Windows; falsa en las pruebas). Iniciar devuelve null si quedó en marcha, o el motivo.</summary>
    public interface IFuenteDeComportamiento : IDisposable
    {
        string? Iniciar();
        bool Activa { get; }
        long Recibidos { get; }
        long Descartados { get; }
    }

    /// <summary>Seguro entre hilos: lo escribe el hilo de ETW y lo lee el del pipe.</summary>
    public sealed class PuntuadorDeComportamiento
    {
        public const int PuntosParaMedia = 4;
        public const int PuntosParaAlta = 6;
        /// <summary>Tope de procesos que se siguen a la vez: pasado esto se olvida el más antiguo (memoria acotada).</summary>
        public const int MaximoDeProcesos = 2000;

        private sealed class Ficha
        {
            public string Nombre = "";
            public string? Ruta;
            public EstadoDeFirma Firma;
            public long Orden;
            public readonly HashSet<string> Senales = new();
            public Severidad Avisada = Severidad.Info;
        }

        private readonly Dictionary<string, Ficha> _fichas = new(StringComparer.OrdinalIgnoreCase);
        private long _contador;
        private readonly object _candado = new();

        private static string Clave(int pid, string nombre) => pid + "|" + nombre;

        /// <summary>Carpeta Inicio de un usuario o de todos (lo que arranca al iniciar sesión).</summary>
        public static bool EsCarpetaDeInicio(string? ruta)
            => !string.IsNullOrEmpty(ruta) && ruta.Replace('/', '\\').ToLowerInvariant().Contains(@"\start menu\programs\startup\");

        /// <summary>Carpeta donde Windows guarda las tareas programadas.</summary>
        public static bool EsCarpetaDeTareas(string? ruta)
            => !string.IsNullOrEmpty(ruta) && ruta.Replace('/', '\\').ToLowerInvariant().Contains(@"\windows\system32\tasks\");

        /// <summary>Incorpora un evento. Devuelve un hallazgo SOLO si el proceso acaba de subir de nivel (no repite el mismo aviso).</summary>
        public HallazgoDeSistema? Registrar(EventoDeComportamiento e)
        {
            if (e is null) throw new ArgumentNullException(nameof(e));
            lock (_candado) return RegistrarSinCandado(e);
        }

        private HallazgoDeSistema? RegistrarSinCandado(EventoDeComportamiento e)
        {
            string k = Clave(e.Pid, e.Nombre);
            if (e.Tipo == TipoDeSenal.ProcesoTerminado) { _fichas.Remove(k); return null; }

            if (!_fichas.TryGetValue(k, out Ficha? f))
            {
                if (_fichas.Count >= MaximoDeProcesos) _fichas.Remove(_fichas.MinBy(x => x.Value.Orden).Key);
                f = new Ficha { Nombre = e.Nombre, Orden = ++_contador };
                _fichas[k] = f;
            }
            if (e.Ruta is not null) f.Ruta = e.Ruta;
            if (e.Firma != EstadoDeFirma.Desconocida) f.Firma = e.Firma;

            switch (e.Tipo)
            {
                case TipoDeSenal.ArchivoEnInicio: if (EsCarpetaDeInicio(e.Detalle)) f.Senales.Add("inicio"); break;
                case TipoDeSenal.TareaProgramada: if (EsCarpetaDeTareas(e.Detalle)) f.Senales.Add("tarea"); break;
                case TipoDeSenal.ServicioCreado: f.Senales.Add("servicio"); break;
                case TipoDeSenal.ConexionSaliente: f.Senales.Add("red"); break;
            }

            Severidad ahora = Nivel(Puntos(f));
            if (ahora <= f.Avisada) return null;
            f.Avisada = ahora;
            return Hallazgo(f, ahora);
        }

        private static bool SinFirma(Ficha f) => f.Firma is EstadoDeFirma.Ausente or EstadoDeFirma.Invalida;

        private static int Puntos(Ficha f)
        {
            bool sin = SinFirma(f);
            int p = 0;
            if (sin) p += 2;
            if (VigilanteDeMineria.EnCarpetaPocoHabitual(f.Ruta)) p += 1;
            if (f.Senales.Contains("inicio")) p += sin ? 3 : 1;
            if (f.Senales.Contains("servicio")) p += sin ? 3 : 1;
            if (f.Senales.Contains("tarea")) p += sin ? 3 : 1;
            if (sin && f.Senales.Contains("red")) p += 1;
            return p;
        }

        private static Severidad Nivel(int puntos) => puntos >= PuntosParaAlta ? Severidad.Alta : puntos >= PuntosParaMedia ? Severidad.Media : Severidad.Info;

        private static HallazgoDeSistema Hallazgo(Ficha f, Severidad s)
        {
            var motivos = new List<string>();
            if (f.Firma == EstadoDeFirma.Ausente) motivos.Add("no tiene firma digital");
            if (f.Firma == EstadoDeFirma.Invalida) motivos.Add("su firma digital no es válida");
            if (VigilanteDeMineria.EnCarpetaPocoHabitual(f.Ruta)) motivos.Add("vive en una carpeta poco habitual (" + f.Ruta + ")");
            if (f.Senales.Contains("inicio")) motivos.Add("escribió en la carpeta Inicio");
            if (f.Senales.Contains("servicio")) motivos.Add("creó un servicio");
            if (f.Senales.Contains("tarea")) motivos.Add("creó una tarea programada");
            if (f.Senales.Contains("red")) motivos.Add("abrió una conexión de red");
            return new HallazgoDeSistema("COMPORTAMIENTO-SOSPECHOSO", s,
                "«" + f.Nombre + "» junta varias señales de comportamiento sospechoso",
                "«" + f.Nombre + "» " + string.Join(", ", motivos) + ". Cada señal por separado es normal (los instaladores también lo hacen); juntas merecen una mirada. No es una prueba de que sea malicioso.",
                "Si no reconoces el programa" + (f.Ruta is null ? "" : " (" + f.Ruta + ")") + ", analízalo con Nexo. Nexo no lo detiene por ti.", f.Nombre);
        }

        /// <summary>Todos los procesos que hoy están en Media o Alta, y lo que no se pudo comprobar.</summary>
        public ResultadoDeAnalisis Resumen()
        {
            lock (_candado) return ResumenSinCandado();
        }

        private ResultadoDeAnalisis ResumenSinCandado()
        {
            var hallazgos = new List<HallazgoDeSistema>();
            int sinSaber = 0;
            var nombresSinSaber = new List<string>();
            foreach (Ficha f in _fichas.Values.OrderBy(x => x.Orden))
            {
                if (f.Firma == EstadoDeFirma.Desconocida)
                {
                    sinSaber++;
                    if (nombresSinSaber.Count < 5 && !nombresSinSaber.Contains(f.Nombre)) nombresSinSaber.Add(f.Nombre);
                }
                Severidad s = Nivel(Puntos(f));
                if (s > Severidad.Info) hallazgos.Add(Hallazgo(f, s));
            }
            var no = new List<string>();
            if (sinSaber > 0) no.Add("firma digital: no se pudo comprobar en " + sinSaber + " proceso(s) (no suma ni resta puntos)"
                                  + (nombresSinSaber.Count > 0 ? "; por ejemplo: " + string.Join(", ", nombresSinSaber) : ""));
            return new ResultadoDeAnalisis(hallazgos, no);
        }

        public int ProcesosSeguidos { get { lock (_candado) return _fichas.Count; } }
    }
}
