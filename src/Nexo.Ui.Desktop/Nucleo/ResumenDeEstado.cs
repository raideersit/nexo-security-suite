using System.Collections.Generic;
using Nexo.Ui.Tray.Nucleo;

namespace Nexo.Ui.Desktop.Nucleo
{
    /// <summary>El cuadradito de color de cada fila. El texto de al lado dice lo mismo: el color nunca va solo.</summary>
    public enum Indicador
    {
        Correcto,
        Atencion,
        Alerta,
        SinDatos
    }

    public sealed record FilaDeModulo(string Modulo, Indicador Indicador, string Estado, string Detalle);

    /// <summary>Todo lo que muestra la pestaña «Estado», sin interfaz (se prueba en tools/Nexo.Desktop.Demo).</summary>
    public sealed record ResumenDeEstado(
        EstadoDeBandeja Estado,
        Indicador Indicador,
        string Titulo,
        string Detalle,
        IReadOnlyList<FilaDeModulo> Modulos,
        string BarraServicio,
        string BarraTiempoReal,
        string BarraMotor);

    /// <summary>
    /// Traduce el estado de <see cref="ModeloDeBandeja"/> (la misma maquina de estados que la bandeja) a lo que se ve en la
    /// ventana. Reglas: nunca «todo en orden» si no se sabe, y un modulo que la ventana aun no consulta se muestra como
    /// «sin consultar», no como correcto.
    /// </summary>
    public static class Resumir
    {
        public const string Complemento = "Microsoft Defender sigue siendo su protección principal.";

        // Los modulos que la ventana todavia no consulta al servicio. Se listan igual, para que se vea que faltan.
        private static readonly string[] SinConsultar = { "Escaneo bajo demanda", "Firewall", "Salud del disco", "Cuarentena", "Limpieza" };

        public static ResumenDeEstado Desde(ModeloDeBandeja m)
        {
            InstantaneaDelServicio i = m.Ultima;
            var filas = new List<FilaDeModulo> { FilaDeTiempoReal(i) };
            foreach (string nombre in SinConsultar)
                filas.Add(i.Conectado
                    ? new FilaDeModulo(nombre, Indicador.SinDatos, "Sin consultar", "Esta ventana todavía no consulta este módulo.")
                    : new FilaDeModulo(nombre, Indicador.SinDatos, "Sin datos", "Sin conexión con el servicio."));

            (Indicador ind, string titulo, string detalle) = Cabecera(m);

            return new ResumenDeEstado(
                m.Estado, ind, titulo, detalle, filas,
                BarraServicio: i.Conectado
                    ? "Servicio: conectado" + (string.IsNullOrEmpty(i.Version) ? "" : " (versión " + i.Version + ")")
                    : "Servicio: sin conexión",
                BarraTiempoReal: !i.Conectado ? "Tiempo real: sin datos"
                    : i.TiempoRealActivo ? "Tiempo real: activo" : "Tiempo real: apagado",
                // Si el tiempo real esta apagado nadie usa el motor: no se sabe si responde.
                BarraMotor: !i.Conectado || !i.TiempoRealActivo ? "Motor clamd: sin datos"
                    : i.MotorCaido ? "Motor clamd: no responde" : "Motor clamd: listo");
        }

        private static (Indicador, string, string) Cabecera(ModeloDeBandeja m)
        {
            InstantaneaDelServicio i = m.Ultima;
            switch (m.Estado)
            {
                case EstadoDeBandeja.Desconectado:
                    return (Indicador.SinDatos, "Sin conexión con el servicio de Nexo.",
                        "No se conoce el estado del equipo. Motivo: " + (i.Error ?? "desconocido") + ".");

                case EstadoDeBandeja.Alerta:
                    int n = m.SinRevisar.Count;
                    return (Indicador.Alerta,
                        n == 1 ? "Hay 1 detección sin revisar." : "Hay " + n + " detecciones sin revisar.",
                        "El análisis en tiempo real encontró archivos sospechosos. Revíselos y decida si van a cuarentena.");

                case EstadoDeBandeja.Atencion:
                    if (!i.TiempoRealActivo)
                        return (Indicador.Atencion, "Requiere atención: el análisis en tiempo real está apagado.",
                            "Nexo detecta y avisa después de que un archivo se escribe; no lo bloquea. " + Complemento);
                    if (i.MotorCaido)
                        return (Indicador.Atencion, "Requiere atención: el motor de análisis no responde.",
                            "Los archivos nuevos quedan sin analizar hasta que clamd vuelva. Nexo lo vuelve a intentar solo.");
                    if (!i.CoberturaCompleta)
                    {
                        int c = i.CarpetasPorRevisar.Count;
                        return (Indicador.Atencion, "Requiere atención: cobertura incompleta.",
                            c == 0 ? "Hubo cambios que el tiempo real no alcanzó a ver."
                                   : "Hubo cambios que el tiempo real no alcanzó a ver: " + c
                                     + (c == 1 ? " carpeta queda" : " carpetas quedan") + " por revisar.");
                    }
                    return (Indicador.Atencion, "Hay detecciones revisadas sin resolver.",
                        "Siguen en su lugar hasta que las ponga en cuarentena.");

                default:
                    // Solo habla de lo que se consulto: el tiempo real. El resto figura «sin consultar» en la tabla.
                    return (Indicador.Correcto, "Tiempo real activo, sin detecciones pendientes.",
                        "Nexo complementa a Microsoft Defender; no lo reemplaza.");
            }
        }

        private static FilaDeModulo FilaDeTiempoReal(InstantaneaDelServicio i)
        {
            const string nombre = "Tiempo real";
            if (!i.Conectado) return new FilaDeModulo(nombre, Indicador.SinDatos, "Sin datos", "Sin conexión con el servicio.");
            if (!i.TiempoRealActivo) return new FilaDeModulo(nombre, Indicador.Atencion, "Apagado", "No se vigila ninguna carpeta.");
            if (i.Detecciones.Count > 0)
                return new FilaDeModulo(nombre, Indicador.Alerta, i.Detecciones.Count == 1 ? "1 detección" : i.Detecciones.Count + " detecciones",
                    "Última: " + i.Detecciones[i.Detecciones.Count - 1].Firma);
            if (i.MotorCaido) return new FilaDeModulo(nombre, Indicador.Atencion, "Motor caído", "clamd no responde.");
            if (!i.CoberturaCompleta)
                return new FilaDeModulo(nombre, Indicador.Atencion, "Incompleto",
                    i.CarpetasPorRevisar.Count == 0 ? "Hubo cambios sin ver." : i.CarpetasPorRevisar.Count + " carpetas por revisar.");
            return new FilaDeModulo(nombre, Indicador.Correcto, "Activo", "Vigilando, cobertura completa.");
        }
    }
}
