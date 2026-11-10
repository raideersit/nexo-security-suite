using System;
using System.Collections.Generic;

namespace Nexo.Modules.Threats.Ransomware
{
    /// <summary>Lo minimo de Defender para decidir un cambio: el modo del CFA (0-4, o null), el tiempo real y el modo del motor.</summary>
    public sealed record EstadoDeDefenderCfa(int? Modo, bool? TiempoReal, string? Motor);

    public interface ILectorDeEstadoDeCfa
    {
        EstadoDeDefenderCfa Leer();
    }

    /// <summary>Quien cambia el ajuste de verdad (en Windows, como SYSTEM en el servicio). Se abstrae para probar sin tocar Defender.</summary>
    public interface IEjecutorDeCfa
    {
        /// <returns>null si Windows acepto la orden; si no, el motivo. Que la aceptara NO prueba que se aplicara: se vuelve a leer.</returns>
        string? Fijar(ModoDeCarpetasProtegidas modo);
    }

    public sealed record PlanDeCarpetasProtegidas(ModoDeCarpetasProtegidas Destino, int? ModoAnterior, bool HayCambios, string Motivo, IReadOnlyList<string> Advertencias)
    {
        public string Describir() => Motivo;
    }

    public sealed record ResultadoDeCfa(bool Exito, string Mensaje, int? ModoFinal);

    /// <summary>
    /// Reglas para cambiar el acceso controlado a carpetas desde Nexo. Regla del proyecto: Nexo NO desactiva ni debilita Defender. Por eso
    /// solo hay dos cambios posibles: activarlo (desde cualquier otro modo) o ponerlo en auditoria (solo si esta APAGADO: desde cualquier otro
    /// modo seria quitar proteccion). Apagarlo o dar permiso a un programa se hace en Seguridad de Windows.
    /// Tras aplicar se vuelve a leer: Windows puede aceptar la orden y no aplicarla (directiva de la organizacion, proteccion contra
    /// alteraciones), y entonces se dice que no se cambio, nunca «activado».
    /// </summary>
    public static class PlanificadorDeCarpetasProtegidas
    {
        public const string DondeEnWindows = "Seguridad de Windows > Protección antivirus y contra amenazas > Protección contra ransomware";

        public static PlanDeCarpetasProtegidas Preparar(ModoDeCarpetasProtegidas destino, EstadoDeDefenderCfa e)
        {
            if (e is null) throw new ArgumentNullException(nameof(e));
            PlanDeCarpetasProtegidas No(string motivo) => new(destino, e.Modo, false, motivo, Array.Empty<string>());

            if (destino is not (ModoDeCarpetasProtegidas.Activado or ModoDeCarpetasProtegidas.Auditoria))
                return No("Nexo solo activa esta protección; no la apaga ni la debilita. Para cambiarla de otra forma: " + DondeEnWindows + ".");
            if (e.Motor is null)
                return No("No se pudo saber si Microsoft Defender está activo, así que no se toca nada.");
            if (!string.Equals(e.Motor.Trim(), "Normal", StringComparison.OrdinalIgnoreCase))
                return No("Microsoft Defender no es el antivirus activo (modo «" + e.Motor.Trim() + "»): sus carpetas protegidas no funcionarían. Revisa la protección contra ransomware de tu otro antivirus.");
            if (e.TiempoReal != true)
                return No(e.TiempoReal is null
                    ? "No se pudo saber si la protección en tiempo real de Defender está encendida, así que no se toca nada."
                    : "La protección en tiempo real de Defender está apagada: sin ella las carpetas protegidas no bloquean nada. Enciéndela primero en Seguridad de Windows (Nexo no la toca).");
            if (e.Modo is not int actual)
                return No("No se pudo leer cómo está ahora el acceso controlado a carpetas, así que no se toca nada.");
            if (!Enum.IsDefined(typeof(ModoDeCarpetasProtegidas), actual))
                return No("El acceso controlado a carpetas tiene un valor desconocido (" + actual + "): Nexo no lo toca.");
            var antes = (ModoDeCarpetasProtegidas)actual;
            if (antes == destino)
                return No("Ya está en «" + AnalizadorDeCarpetasProtegidas.Nombre(destino) + "»: no hay nada que cambiar.");
            if (destino == ModoDeCarpetasProtegidas.Auditoria && antes != ModoDeCarpetasProtegidas.Desactivado)
                return No("El modo auditoría solo se ofrece cuando la protección está apagada: pasar de «" + AnalizadorDeCarpetasProtegidas.Nombre(antes) + "» a auditoría quitaría protección.");

            string motivo = "Cambiar el acceso controlado a carpetas de Microsoft Defender de «" + AnalizadorDeCarpetasProtegidas.Nombre(antes) + "» a «" +
                            AnalizadorDeCarpetasProtegidas.Nombre(destino) + "».\n\n" +
                            (destino == ModoDeCarpetasProtegidas.Activado
                                ? "Windows impedirá que programas desconocidos cambien tus Documentos, Imágenes, Vídeos, Música, Escritorio y Favoritos (y las carpetas que hayas añadido), que es lo que hace un ransomware al cifrarlos."
                                : "Windows no bloqueará nada: solo anotará qué programas habría bloqueado. Lo verás en esta sección de Nexo. Sirve para probar antes de activarlo.");
            var avisos = new List<string>();
            if (destino == ModoDeCarpetasProtegidas.Activado)
                avisos.Add("Puede bloquear a programas tuyos que guardan en esas carpetas (juegos, editores, programas de copias). Windows avisa con una notificación y se les da permiso en " + DondeEnWindows + " > Permitir una aplicación.");
            avisos.Add("Nexo no apaga protecciones: para desactivarlo después, " + DondeEnWindows + ".");
            avisos.Add("Si una directiva de la organización o Windows impiden el cambio, Nexo lo comprobará al terminar y lo dirá.");
            return new PlanDeCarpetasProtegidas(destino, actual, true, motivo, avisos);
        }

        public static ResultadoDeCfa Aplicar(PlanDeCarpetasProtegidas plan, ILectorDeEstadoDeCfa lector, IEjecutorDeCfa ejecutor)
        {
            if (plan is null) throw new ArgumentNullException(nameof(plan));
            if (!plan.HayCambios) return new ResultadoDeCfa(false, "No hay nada que aplicar.", plan.ModoAnterior);

            // Se vuelve a mirar: si algo cambio desde la vista previa, el plan ya no describe lo que pasaria.
            EstadoDeDefenderCfa ahora = lector.Leer();
            PlanDeCarpetasProtegidas otraVez = Preparar(plan.Destino, ahora);
            if (!otraVez.HayCambios || ahora.Modo != plan.ModoAnterior)
                return new ResultadoDeCfa(false, "El estado cambió desde la vista previa, así que no se tocó nada. " + otraVez.Motivo, ahora.Modo);

            string? error = ejecutor.Fijar(plan.Destino);
            EstadoDeDefenderCfa despues = lector.Leer();
            if (error is not null)
                return new ResultadoDeCfa(false, "Windows rechazó el cambio (" + error + "). " + Queda(despues), despues.Modo);
            if (despues.Modo is null)
                return new ResultadoDeCfa(false, "Windows aceptó la orden, pero no se pudo comprobar si quedó aplicada: míralo en " + DondeEnWindows + ".", null);
            if (despues.Modo != (int)plan.Destino)
                return new ResultadoDeCfa(false, "Windows aceptó la orden, pero el ajuste no cambió. Puede impedirlo una directiva de la organización o la protección contra alteraciones de Windows. " + Queda(despues), despues.Modo);
            return new ResultadoDeCfa(true, plan.Destino == ModoDeCarpetasProtegidas.Activado
                ? "Listo: las carpetas protegidas contra ransomware están activadas (comprobado leyendo de nuevo la configuración de Windows)."
                : "Listo: las carpetas protegidas están en modo auditoría (comprobado leyendo de nuevo la configuración de Windows). Windows anotará sin bloquear.", despues.Modo);
        }

        private static string Queda(EstadoDeDefenderCfa e)
            => e.Modo is int m && Enum.IsDefined(typeof(ModoDeCarpetasProtegidas), m)
                ? "Sigue en «" + AnalizadorDeCarpetasProtegidas.Nombre((ModoDeCarpetasProtegidas)m) + "»."
                : "No se pudo leer cómo quedó.";
    }
}
