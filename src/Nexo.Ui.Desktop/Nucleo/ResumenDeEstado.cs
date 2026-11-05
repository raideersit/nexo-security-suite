using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
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
    /// Traduce el estado a lo que se ve en la ventana. La parte del tiempo real pasa por <see cref="ModeloDeBandeja"/> (la misma
    /// maquina de estados que la bandeja). Reglas:
    /// - nunca «todo en orden» si no se sabe; un modulo que no se pudo consultar es «sin datos», no correcto;
    /// - la cabecera muestra lo mas grave: si el tiempo real esta bien pero otro modulo tiene un problema, manda el problema.
    /// </summary>
    public static class Resumir
    {
        public const string Complemento = "Microsoft Defender sigue siendo su protección principal.";

        public const string TiempoReal = "Tiempo real";
        public const string Motor = "Motor de análisis";
        public const string Programado = "Escaneo programado";
        public const string Firewall = "Firewall";
        public const string Cuarentena = "Cuarentena";
        public const string Disco = "Salud del disco";
        public const string Limpieza = "Limpieza";

        /// <summary>Como se muestran las fechas (hora local del equipo).</summary>
        public static string Fecha(DateTimeOffset f) => f.ToLocalTime().ToString("dd/MM HH:mm", CultureInfo.InvariantCulture);

        public static ResumenDeEstado Desde(ModeloDeBandeja m, EstadoCompleto e)
        {
            InstantaneaDelServicio i = m.Ultima;
            var filas = new List<FilaDeModulo>
            {
                FilaDeTiempoReal(i),
                i.Conectado ? FilaDelMotor(e.Motor) : SinConexion(Motor),
                i.Conectado ? FilaDelProgramado(e.Programado) : SinConexion(Programado),
                i.Conectado ? FilaDelFirewall(e.Firewall) : SinConexion(Firewall),
                i.Conectado ? FilaDeLaCuarentena(e.Cuarentena) : SinConexion(Cuarentena),
                i.Conectado
                    ? new FilaDeModulo(Disco, Indicador.SinDatos, "Sin consultar", "El servicio todavía no informa la salud del disco.")
                    : SinConexion(Disco),
                i.Conectado
                    ? new FilaDeModulo(Limpieza, Indicador.SinDatos, "A pedido", "No tiene estado: se usa desde la bandeja o con nexo-cleanup.")
                    : SinConexion(Limpieza)
            };

            (Indicador ind, string titulo, string detalle) = Cabecera(m);

            // Lo mas grave de los otros modulos (el tiempo real ya esta en la cabecera).
            if (m.Estado != EstadoDeBandeja.Desconectado)
            {
                FilaDeModulo? peor = filas.Skip(1).Where(f => Gravedad(f.Indicador) > 0).OrderByDescending(f => Gravedad(f.Indicador)).FirstOrDefault();
                if (peor is not null && Gravedad(peor.Indicador) > Gravedad(ind))
                {
                    ind = peor.Indicador;
                    titulo = (peor.Indicador == Indicador.Alerta ? "Alerta en " : "Requiere atención: ") + peor.Modulo + ": "
                             + peor.Estado.ToLowerInvariant() + ".";
                    detalle = peor.Detalle;
                }
            }

            EstadoDelMotor? motor = i.Conectado ? e.Motor.Valor : null;
            return new ResumenDeEstado(
                m.Estado, ind, titulo, detalle, filas,
                BarraServicio: i.Conectado
                    ? "Servicio: conectado" + (string.IsNullOrEmpty(i.Version) ? "" : " (versión " + i.Version + ")")
                    : "Servicio: sin conexión",
                BarraTiempoReal: !i.Conectado ? "Tiempo real: sin datos"
                    : i.TiempoRealActivo ? "Tiempo real: activo" : "Tiempo real: apagado",
                BarraMotor: motor is not null ? (motor.Disponible ? "Motor clamd: listo" : "Motor clamd: no responde")
                    // Sin la consulta del motor, solo el tiempo real sabe algo (y solo si esta activo).
                    : !i.Conectado || !i.TiempoRealActivo ? "Motor clamd: sin datos"
                    : i.MotorCaido ? "Motor clamd: no responde" : "Motor clamd: sin datos");
        }

        private static int Gravedad(Indicador i) => i == Indicador.Alerta ? 2 : i == Indicador.Atencion ? 1 : 0;

        private static FilaDeModulo SinConexion(string modulo) => new FilaDeModulo(modulo, Indicador.SinDatos, "Sin datos", "Sin conexión con el servicio.");

        private static FilaDeModulo NoSePudo(string modulo, string? error)
            => new FilaDeModulo(modulo, Indicador.SinDatos, "Sin datos", "No se pudo consultar: " + (error ?? "motivo desconocido") + ".");

        // ------------------------------------------------------------
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
                    // No dice «todo en orden»: lo que no se pudo consultar figura «sin datos» en la tabla.
                    return (Indicador.Correcto, "Sin problemas en lo que se pudo consultar.",
                        "Nexo complementa a Microsoft Defender; no lo reemplaza.");
            }
        }

        private static FilaDeModulo FilaDeTiempoReal(InstantaneaDelServicio i)
        {
            if (!i.Conectado) return SinConexion(TiempoReal);
            if (!i.TiempoRealActivo) return new FilaDeModulo(TiempoReal, Indicador.Atencion, "Apagado", "No se vigila ninguna carpeta.");
            if (i.Detecciones.Count > 0)
                return new FilaDeModulo(TiempoReal, Indicador.Alerta, i.Detecciones.Count == 1 ? "1 detección" : i.Detecciones.Count + " detecciones",
                    "Última: " + i.Detecciones[i.Detecciones.Count - 1].Firma);
            if (i.MotorCaido) return new FilaDeModulo(TiempoReal, Indicador.Atencion, "Motor caído", "clamd no responde.");
            if (!i.CoberturaCompleta)
                return new FilaDeModulo(TiempoReal, Indicador.Atencion, "Incompleto",
                    i.CarpetasPorRevisar.Count == 0 ? "Hubo cambios sin ver." : i.CarpetasPorRevisar.Count + " carpetas por revisar.");
            return new FilaDeModulo(TiempoReal, Indicador.Correcto, "Activo", "Vigilando, cobertura completa.");
        }

        private static FilaDeModulo FilaDelMotor(Consulta<EstadoDelMotor> c)
        {
            if (c.Valor is not EstadoDelMotor m) return NoSePudo(Motor, c.Error);
            return m.Disponible
                ? new FilaDeModulo(Motor, Indicador.Correcto, "Listo", m.Version ?? m.Motor ?? "clamd")
                : new FilaDeModulo(Motor, Indicador.Atencion, "No responde", "clamd no contesta: los escaneos no pueden analizar nada.");
        }

        private static FilaDeModulo FilaDelProgramado(Consulta<EstadoDeEscaneoProgramado> c)
        {
            if (c.Valor is not EstadoDeEscaneoProgramado p) return NoSePudo(Programado, c.Error);
            if (!p.Activo) return new FilaDeModulo(Programado, Indicador.SinDatos, "Apagado", "No está activado (se activa en appsettings.json).");

            string completo = p.UltimoCompleto is DateTimeOffset f ? "Último completo: " + Fecha(f) : "Nunca terminó uno completo";

            if (p.UltimoResultado == "con_detecciones" && p.Detecciones > 0)
                return new FilaDeModulo(Programado, Indicador.Alerta, p.Detecciones == 1 ? "1 detección" : p.Detecciones + " detecciones",
                    "En el último escaneo completo" + (p.UltimoCompleto is DateTimeOffset g ? " (" + Fecha(g) + ")" : "") + ".");

            string? intento = p.UltimoResultado switch
            {
                "fallido" => "El último intento falló",
                "incompleto" => "El último intento quedó incompleto",
                _ => null
            };
            if (intento is not null && p.Motivo is not null) intento += ": " + p.Motivo;

            if (p.Vencido)
                return new FilaDeModulo(Programado, Indicador.Atencion, p.Corriendo ? "Escaneando (vencido)" : "Vencido",
                    (intento is not null ? intento + ". " : "") + completo + ".");
            if (intento is not null)
                return new FilaDeModulo(Programado, Indicador.Atencion, p.UltimoResultado == "fallido" ? "Falló" : "Incompleto",
                    intento + ". " + completo + ".");
            if (p.UltimoResultado == "limpio")
                return new FilaDeModulo(Programado, Indicador.Correcto, p.Corriendo ? "Escaneando ahora" : "Al día",
                    completo + ", sin detecciones.");
            return new FilaDeModulo(Programado, Indicador.SinDatos, "Resultado desconocido",
                completo + ", pero el servicio no recuerda su resultado.");
        }

        private static FilaDeModulo FilaDelFirewall(Consulta<EstadoDeFirewall> c)
        {
            if (c.Valor is not EstadoDeFirewall f) return NoSePudo(Firewall, c.Error);
            if (f.Perfiles.Count == 0) return new FilaDeModulo(Firewall, Indicador.SinDatos, "Sin datos", "El servicio no informó los perfiles.");

            List<string> apagados = f.Perfiles.Where(p => !p.Activo).Select(p => NombreDePerfil(p.Perfil)).ToList();
            if (apagados.Count > 0)
                return new FilaDeModulo(Firewall, Indicador.Atencion,
                    apagados.Count == f.Perfiles.Count ? "Desactivado" : "Desactivado en parte",
                    "Apagado en el perfil " + string.Join(", ", apagados) + ". Nexo no lo enciende: solo avisa.");

            return new FilaDeModulo(Firewall, Indicador.Correcto, "Activo",
                (f.ReglasDeNexo == 1 ? "1 regla de Nexo" : f.ReglasDeNexo + " reglas de Nexo")
                + " · modo sigiloso " + (f.Sigiloso ? "activado" : "desactivado") + ".");
        }

        private static FilaDeModulo FilaDeLaCuarentena(Consulta<EstadoDeCuarentena> c)
        {
            if (c.Valor is not EstadoDeCuarentena q) return NoSePudo(Cuarentena, c.Error);
            if (q.Elementos == 0) return new FilaDeModulo(Cuarentena, Indicador.Correcto, "Vacía", "No hay archivos en cuarentena.");
            return new FilaDeModulo(Cuarentena, Indicador.Correcto, q.Elementos == 1 ? "1 elemento" : q.Elementos + " elementos",
                q.ProximoVencimiento is DateTimeOffset v ? "El próximo se elimina el " + Fecha(v) + "." : "Guardados cifrados.");
        }

        private static string NombreDePerfil(string p) => p switch
        {
            "Dominio" => "dominio",
            "Privado" => "privado",
            "Publico" => "público",
            _ => p
        };
    }
}
