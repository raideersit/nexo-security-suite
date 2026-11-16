using System.Collections.Generic;
using System.Linq;
using System.Text;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Apps
{
    /// <summary>
    /// Eventos de Android para el vault de Obsidian (Salida 7, 3.9).
    ///
    /// PRIVACIDAD: la lista de apps instaladas es informacion personal. Estos eventos NUNCA llevan la lista completa: solo las apps que
    /// salieron «a revisar» o coincidieron con una huella, y del chequeo del equipo solo el estado de cada fila, sin nombres de apps ni
    /// de redes. Los textos son los mismos de la pantalla: «a revisar», nunca «malware».
    /// </summary>
    public static class EventosDeApps
    {
        /// <summary>Un aviso de §3.3: una app se instalo o actualizo y conviene revisarla, o coincide con una huella conocida.</summary>
        public static NexoEvent DeAlerta(AlertaDeInstalacion a)
        {
            bool huella = a.Coincidencias.Count > 0;
            var e = new NexoEvent(ModuloOrigen.Amenazas, huella ? TipoEvento.HuellaCoincidente : TipoEvento.AppInstalada, a.Titulo)
            {
                Severidad = huella || a.Riesgo.Nivel == NivelDeRiesgo.Prioritaria ? Severidad.Alta : Severidad.Media,
                Accion = Accion.Registrada,
                Cuerpo = CuerpoDeApp(a.Riesgo, a.Coincidencias, a.Texto),
            };
            e.Campos["paquete"] = a.Paquete;
            e.Campos["cambio"] = a.Tipo == TipoDeCambio.Nueva ? "nueva" : "actualizada";
            e.Campos["puntos"] = a.Riesgo.Puntos;
            e.Campos["nivel"] = a.Riesgo.Nivel.ToString();
            e.Campos["coincidencias"] = a.Coincidencias.Count;
            e.EnlazaA(EntidadRef.Aplicacion(a.Nombre, a.Paquete));
            return e;
        }

        /// <summary>
        /// Resultado de una revision completa: SOLO las apps «a revisar» o «prioritarias». Si no hay ninguna, el evento lo dice sin
        /// listar nada (no se escribe cuantas apps tiene el telefono ni cuales).
        /// </summary>
        public static NexoEvent RevisionDeApps(IReadOnlyList<ResultadoDeApp> resultados)
        {
            var marcadas = resultados.Where(r => r.Nivel is NivelDeRiesgo.ARevisar or NivelDeRiesgo.Prioritaria).ToList();
            int prioritarias = marcadas.Count(r => r.Nivel == NivelDeRiesgo.Prioritaria);
            var sb = new StringBuilder();
            if (marcadas.Count == 0) sb.AppendLine("Ninguna app tiene señales que revisar.");
            else
            {
                sb.AppendLine("| Prioridad | App | Puntos | Motivo principal |");
                sb.AppendLine("|---|---|---|---|");
                foreach (var r in marcadas)
                    sb.AppendLine("| " + (r.Nivel == NivelDeRiesgo.Prioritaria ? "Prioritaria" : "A revisar") + " | " + Celda(string.IsNullOrEmpty(r.Nombre) ? r.Paquete : r.Nombre)
                                  + " (`" + r.Paquete + "`) | " + r.Puntos + " | " + Celda(r.Motivos.Count > 0 ? r.Motivos[0] : "") + " |");
                sb.AppendLine();
                sb.AppendLine("Es una puntuación, no un veredicto: ninguna de estas apps está confirmada como dañina.");
            }
            var e = new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.AppARevisar,
                marcadas.Count == 0 ? "Revisión de apps: nada que revisar" : $"Revisión de apps: {marcadas.Count} a revisar")
            {
                Severidad = prioritarias > 0 ? Severidad.Alta : marcadas.Count > 0 ? Severidad.Media : Severidad.Info,
                Accion = Accion.Registrada,
                Cuerpo = sb.ToString(),
            };
            e.Campos["a_revisar"] = marcadas.Count;
            e.Campos["prioritarias"] = prioritarias;
            foreach (var r in marcadas) e.EnlazaA(EntidadRef.Aplicacion(string.IsNullOrEmpty(r.Nombre) ? r.Paquete : r.Nombre, r.Paquete));
            return e;
        }

        /// <summary>El chequeo del equipo: una fila por comprobacion. Un dato sin evaluar se escribe como tal, no como «bien».</summary>
        public static NexoEvent DelChequeo(IReadOnlyList<Comprobacion> filas)
        {
            int avisos = ChequeoDelEquipo.Avisos(filas);
            var sb = new StringBuilder();
            sb.AppendLine("| Estado | Comprobación | Detalle |");
            sb.AppendLine("|---|---|---|");
            foreach (var f in filas)
                sb.AppendLine("| " + (f.Nivel == NivelDeComprobacion.Bien ? "Bien" : f.Nivel == NivelDeComprobacion.Aviso ? "Aviso" : "Sin evaluar") + " | " + Celda(f.Nombre) + " | " + Celda(f.DetalleParaReporte ?? f.Detalle) + " |");
            var e = new NexoEvent(ModuloOrigen.Sistema, TipoEvento.ChequeoDelEquipo, avisos == 0 ? "Chequeo del equipo: sin avisos" : $"Chequeo del equipo: {avisos} aviso(s)")
            {
                Severidad = avisos > 0 ? Severidad.Media : Severidad.Info,
                Accion = Accion.Registrada,
                Cuerpo = sb.ToString(),
            };
            e.Campos["avisos"] = avisos;
            e.Campos["sin_evaluar"] = filas.Count(f => f.Nivel == NivelDeComprobacion.Info);
            return e;
        }

        private static string CuerpoDeApp(ResultadoDeApp r, IReadOnlyList<Coincidencia> coincidencias, string textoPrincipal)
        {
            var sb = new StringBuilder();
            sb.AppendLine(textoPrincipal);
            if (r.Motivos.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Motivos de la puntuación (" + r.Puntos + " puntos):");
                foreach (var m in r.Motivos) sb.AppendLine("- " + m);
            }
            foreach (var c in coincidencias)
                sb.AppendLine().AppendLine("Coincidencia exacta: el archivo `" + c.Archivo + "` es idéntico a una huella de la lista «" + c.Lista + "».");
            sb.AppendLine().AppendLine("Es una puntuación y una coincidencia con una lista, no un análisis de la app.");
            return sb.ToString();
        }

        private static string Celda(string s) => (s ?? "").Replace("|", "\\|").Replace("\r", " ").Replace("\n", " ");
    }
}
