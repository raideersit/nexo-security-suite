using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;

namespace Nexo.Modules.Threats.Apps
{
    // =====================================================================================================
    //  REVISION AL INSTALAR O ACTUALIZAR (Salida 7, 3.3). Portable: no sabe nada de Android.
    //
    //  La fuente de verdad es la COMPARACION de la lista completa de apps contra lo que se vio la vez anterior, no un aviso del sistema:
    //  Android ya no despierta a una app cerrada por «app instalada», y un aviso perdido no se recupera. Quien llama (un trabajo
    //  periodico, o un receptor mientras la app esta abierta) solo tiene que traer la lista actual.
    //
    //  Reglas:
    //   - La PRIMERA vez solo se anota lo que hay (linea base): no se alerta por apps que ya estaban.
    //   - Se alerta por una app NUEVA que sale «a revisar» o coincide con una huella conocida.
    //   - Una app ACTUALIZADA solo alerta si EMPEORO (mas puntos o nivel mas alto) o si ahora coincide con una huella: una app ya marcada
    //     que se actualiza sin cambiar no vuelve a gritar en cada version.
    //   - Nunca se avisa dos veces por la misma (paquete, version, fecha). Las apps del sistema no se vigilan.
    //   - «Confio en esta app» silencia sus avisos de riesgo, pero NO el de una coincidencia exacta con una huella conocida.
    // =====================================================================================================

    public sealed record InstantaneaDeApp(string Paquete, long VersionCode, long UltimaActualizacionMs, int Puntos, NivelDeRiesgo Nivel);

    /// <summary>Lo que Nexo recuerda entre revisiones. Un archivo danado se descarta con aviso y se vuelve a empezar desde una linea base nueva.</summary>
    public sealed class EstadoDeVigilancia
    {
        public Dictionary<string, InstantaneaDeApp> Conocidas { get; set; } = new(StringComparer.Ordinal);
        public HashSet<string> Avisadas { get; set; } = new(StringComparer.Ordinal);
        /// <summary>Cuando se hizo la ultima revision completa (ms desde 1970). null = nunca.</summary>
        public long? UltimaRevisionMs { get; set; }
        public int Version { get; set; } = 1;

        public static string Clave(string paquete, long versionCode, long ultimaActualizacionMs) => $"{paquete}|{versionCode}|{ultimaActualizacionMs}";

        private static readonly JsonSerializerOptions Opciones = new() { WriteIndented = false };

        public void Guardar(string ruta)
        {
            var carpeta = Path.GetDirectoryName(Path.GetFullPath(ruta));
            if (!string.IsNullOrEmpty(carpeta)) Directory.CreateDirectory(carpeta);
            var temporal = ruta + ".tmp";
            File.WriteAllText(temporal, JsonSerializer.Serialize(this, Opciones));
            File.Move(temporal, ruta, overwrite: true);
        }

        public static EstadoDeVigilancia Cargar(string ruta, out string? aviso)
        {
            aviso = null;
            if (!File.Exists(ruta)) return new EstadoDeVigilancia();
            try
            {
                var e = JsonSerializer.Deserialize<EstadoDeVigilancia>(File.ReadAllText(ruta), Opciones);
                if (e is null || e.Version != 1 || e.Conocidas is null || e.Avisadas is null)
                { aviso = "El estado de vigilancia tiene un formato desconocido: se empieza de nuevo."; return new EstadoDeVigilancia(); }
                return e;
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                aviso = "El estado de vigilancia estaba danado: se empieza de nuevo.";
                return new EstadoDeVigilancia();
            }
        }
    }

    public enum TipoDeCambio { Nueva, Actualizada }

    public sealed record AlertaDeInstalacion(string Paquete, string Nombre, TipoDeCambio Tipo, ResultadoDeApp Riesgo, IReadOnlyList<Coincidencia> Coincidencias, string Titulo, string Texto);

    public sealed record ResultadoDeRevision(
        bool EraLineaBase, IReadOnlyList<AlertaDeInstalacion> Alertas, int Nuevas, int Actualizadas, int Desinstaladas);

    public sealed class VigilanteDeInstalaciones
    {
        private readonly PuntuadorDeRiesgo _puntuador;

        public VigilanteDeInstalaciones(PuntuadorDeRiesgo puntuador) => _puntuador = puntuador;

        /// <summary>
        /// Compara <paramref name="actuales"/> con el estado y lo ACTUALIZA (quien llama decide cuando guardarlo en disco).
        /// <paramref name="huellas"/> trae las huellas ya calculadas por paquete; <paramref name="listas"/> las listas de huellas conocidas.
        /// </summary>
        public ResultadoDeRevision Revisar(
            IReadOnlyList<ModeloDeApp> actuales, EstadoDeVigilancia estado, long ahoraMs,
            IReadOnlyDictionary<string, HuellaDeApp>? huellas = null, IReadOnlyList<ListaDeHuellas>? listas = null,
            IReadOnlySet<string>? confiadas = null)
        {
            var deUsuario = actuales.Where(a => !a.EsDeSistema).ToList();
            bool lineaBase = estado.UltimaRevisionMs is null && estado.Conocidas.Count == 0;
            var alertas = new List<AlertaDeInstalacion>();
            int nuevas = 0, actualizadas = 0;
            var instantaneas = new Dictionary<string, InstantaneaDeApp>(StringComparer.Ordinal);

            foreach (var app in deUsuario)
            {
                var riesgo = _puntuador.Evaluar(app, confiadas);
                instantaneas[app.Paquete] = new InstantaneaDeApp(app.Paquete, app.VersionCode, app.UltimaActualizacionMs, riesgo.Puntos, riesgo.Nivel);
                if (lineaBase) continue;

                var previa = estado.Conocidas.GetValueOrDefault(app.Paquete);
                bool esNueva = previa is null;
                bool cambio = !esNueva && (previa!.VersionCode != app.VersionCode || previa.UltimaActualizacionMs != app.UltimaActualizacionMs);
                if (!esNueva && !cambio) continue;
                if (esNueva) nuevas++; else actualizadas++;

                var clave = EstadoDeVigilancia.Clave(app.Paquete, app.VersionCode, app.UltimaActualizacionMs);
                if (estado.Avisadas.Contains(clave)) continue;

                var coincidencias = huellas != null && listas != null && huellas.TryGetValue(app.Paquete, out var h)
                    ? BuscadorDeCoincidencias.Buscar(new[] { h }, listas) : (IReadOnlyList<Coincidencia>)Array.Empty<Coincidencia>();
                bool marcada = riesgo.Nivel is NivelDeRiesgo.ARevisar or NivelDeRiesgo.Prioritaria;
                bool empeoro = !esNueva && marcada && (riesgo.Puntos > previa!.Puntos || Peso(riesgo.Nivel) > Peso(previa.Nivel));
                bool avisar = coincidencias.Count > 0 || (esNueva && marcada) || empeoro;
                if (!avisar) continue;

                estado.Avisadas.Add(clave);
                alertas.Add(Componer(app, esNueva ? TipoDeCambio.Nueva : TipoDeCambio.Actualizada, riesgo, coincidencias));
            }

            int desinstaladas = lineaBase ? 0 : estado.Conocidas.Keys.Count(k => !instantaneas.ContainsKey(k));
            estado.Conocidas = instantaneas;
            estado.Avisadas.RemoveWhere(k => !instantaneas.ContainsKey(k.Split('|')[0]));
            estado.UltimaRevisionMs = ahoraMs;
            return new ResultadoDeRevision(lineaBase, alertas, nuevas, actualizadas, desinstaladas);
        }

        /// <summary>true si la ultima revision es mas vieja que el umbral: señal de que el fabricante esta matando las tareas en segundo plano.</summary>
        public static bool EstaAtrasada(long? ultimaRevisionMs, long activadaDesdeMs, long ahoraMs, TimeSpan umbral)
        {
            var referencia = Math.Max(ultimaRevisionMs ?? 0, activadaDesdeMs);
            return ahoraMs - referencia > (long)umbral.TotalMilliseconds;
        }

        private static int Peso(NivelDeRiesgo n) => n switch { NivelDeRiesgo.Prioritaria => 2, NivelDeRiesgo.ARevisar => 1, _ => 0 };

        private static AlertaDeInstalacion Componer(ModeloDeApp app, TipoDeCambio tipo, ResultadoDeApp riesgo, IReadOnlyList<Coincidencia> coincidencias)
        {
            var nombre = string.IsNullOrEmpty(app.Nombre) ? app.Paquete : app.Nombre;
            var verbo = tipo == TipoDeCambio.Nueva ? "se instaló" : "se actualizó";
            string titulo, texto;
            if (coincidencias.Count > 0)
            {
                titulo = $"«{nombre}» {verbo} y coincide con una huella conocida";
                texto = $"Es idéntica, byte a byte, a una huella de la lista «{coincidencias[0].Lista}». Es una coincidencia exacta, no un análisis.";
            }
            else
            {
                titulo = $"«{nombre}» {verbo} y conviene revisarla";
                texto = riesgo.Motivos.Count > 0 ? riesgo.Motivos[0] : "Tiene señales que conviene revisar.";
            }
            return new AlertaDeInstalacion(app.Paquete, nombre, tipo, riesgo, coincidencias, titulo, texto);
        }
    }
}
