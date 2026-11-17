using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Nexo.Modules.Threats.Apps
{
    // =====================================================================================================
    //  NOTIFICACIONES GENERALES (Salida 7, fase 1): «el chequeo del equipo empeoro» y «resumen semanal». Portable: recibe
    //  el chequeo ya evaluado y un estado, y decide QUE avisar. Mostrarlo y programar la revision es cosa de la app.
    //
    //  Reglas del chequeo:
    //  - La primera vez solo se anota (linea base): lo que ya estaba mal se ve en la pantalla «Estado», no llega como aviso.
    //  - Avisa cuando una fila PASA a «Aviso». Mientras siga en «Aviso» no se repite.
    //  - Solo «Bien» la rearma. «Info» (no se pudo leer, sin Wi-Fi...) no cambia nada: un dato ilegible no es «bien».
    //    Ejemplo: una Wi-Fi abierta avisa una vez; desconectarse no la rearma, conectarse a una red cifrada si.
    // =====================================================================================================

    public sealed record AvisoDelEquipo(string Fila, string Titulo, string Texto);

    public sealed class EstadoDelEquipo
    {
        /// <summary>Filas del chequeo que estan en «Aviso» y ya se avisaron.</summary>
        public HashSet<string> EnAviso { get; set; } = new(StringComparer.Ordinal);
        /// <summary>null = nunca se reviso: la proxima revision es la linea base.</summary>
        public long? UltimaRevisionMs { get; set; }
        /// <summary>Cuando se mostro el ultimo resumen semanal, o cuando se activo (para no mostrar uno al instante). null = nunca.</summary>
        public long? UltimoResumenMs { get; set; }
        public int Version { get; set; } = 1;

        private static readonly JsonSerializerOptions Opciones = new() { WriteIndented = false };

        public void Guardar(string ruta)
        {
            var carpeta = Path.GetDirectoryName(Path.GetFullPath(ruta));
            if (!string.IsNullOrEmpty(carpeta)) Directory.CreateDirectory(carpeta);
            var temporal = ruta + ".tmp";
            File.WriteAllText(temporal, JsonSerializer.Serialize(this, Opciones));
            File.Move(temporal, ruta, overwrite: true);
        }

        public static EstadoDelEquipo Cargar(string ruta, out string? aviso)
        {
            aviso = null;
            if (!File.Exists(ruta)) return new EstadoDelEquipo();
            try
            {
                var e = JsonSerializer.Deserialize<EstadoDelEquipo>(File.ReadAllText(ruta), Opciones);
                if (e is null || e.Version != 1 || e.EnAviso is null)
                { aviso = "El estado del equipo tiene un formato desconocido: se empieza de nuevo."; return new EstadoDelEquipo(); }
                return e;
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                aviso = "El estado del equipo estaba dañado: se empieza de nuevo.";
                return new EstadoDelEquipo();
            }
        }
    }

    public static class VigilanteDelEquipo
    {
        public static readonly TimeSpan Semana = TimeSpan.FromDays(7);

        /// <summary>Compara el chequeo con lo anterior y ACTUALIZA el estado (quien llama lo guarda). Devuelve los avisos nuevos.</summary>
        public static IReadOnlyList<AvisoDelEquipo> Revisar(IReadOnlyList<Comprobacion> chequeo, EstadoDelEquipo estado, long ahoraMs)
        {
            bool lineaBase = estado.UltimaRevisionMs is null;
            var avisos = new List<AvisoDelEquipo>();
            foreach (var c in chequeo)
            {
                switch (c.Nivel)
                {
                    case NivelDeComprobacion.Aviso:
                        if (estado.EnAviso.Add(c.Nombre) && !lineaBase)
                            avisos.Add(new AvisoDelEquipo(c.Nombre, "Cambió algo en tu teléfono: " + c.Nombre, c.Detalle));
                        break;
                    case NivelDeComprobacion.Bien:
                        estado.EnAviso.Remove(c.Nombre);
                        break;
                    // Info: sin cambios, a proposito.
                }
            }
            estado.UltimaRevisionMs = ahoraMs;
            return avisos;
        }

        /// <summary>
        /// ¿Toca el resumen? La primera vez solo anota la fecha (activar el resumen no muestra uno al instante).
        /// Si el reloj retrocede (fecha en el futuro), se reanota: mejor un resumen tarde que uno cada 15 minutos.
        /// </summary>
        public static bool TocaResumen(EstadoDelEquipo estado, long ahoraMs)
        {
            if (estado.UltimoResumenMs is not { } ultimo || ultimo > ahoraMs) { estado.UltimoResumenMs = ahoraMs; return false; }
            return ahoraMs - ultimo >= (long)Semana.TotalMilliseconds;
        }

        public static void ResumenMostrado(EstadoDelEquipo estado, long ahoraMs) => estado.UltimoResumenMs = ahoraMs;

        /// <summary>Texto del resumen. Solo cantidades: ningun nombre de app (la notificacion se ve en la pantalla bloqueada).</summary>
        public static (string Titulo, string Texto) ComponerResumen(int appsDeUsuario, int aRevisar, int deConfianza, IReadOnlyList<Comprobacion> chequeo)
        {
            int avisosEquipo = ChequeoDelEquipo.Avisos(chequeo);
            bool todoBien = aRevisar == 0 && avisosEquipo == 0;
            var titulo = todoBien ? "Resumen semanal: todo en orden" : "Resumen semanal: hay cosas que mirar";
            var partes = new List<string>
            {
                $"{appsDeUsuario} apps instaladas por ti" + (deConfianza > 0 ? $" ({deConfianza} de confianza)" : "") + ".",
                aRevisar == 0 ? "Ninguna app a revisar." : aRevisar == 1 ? "1 app a revisar." : $"{aRevisar} apps a revisar.",
                avisosEquipo == 0 ? "El equipo, sin avisos." : avisosEquipo == 1 ? "1 aviso en el equipo." : $"{avisosEquipo} avisos en el equipo.",
            };
            return (titulo, string.Join(" ", partes));
        }
    }
}
