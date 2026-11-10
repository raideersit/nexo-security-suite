using System;
using System.Collections.Generic;
using System.Linq;
using Nexo.Modules.Threats.Ransomware;

namespace Nexo.Vuln.Demo
{
    internal static partial class Program
    {
        private sealed class LectorCfaFalso : ILectorDeEstadoDeCfa
        {
            public EstadoDeDefenderCfa Valor = new(0, true, "Normal");
            public int Lecturas;
            public EstadoDeDefenderCfa Leer() { Lecturas++; return Valor; }
        }

        private sealed class EjecutorCfaFalso : IEjecutorDeCfa
        {
            public readonly List<ModoDeCarpetasProtegidas> Llamadas = new();
            public string? Error;
            /// <summary>Lo que hace Windows con la orden: por omision, la aplica de verdad (cambia lo que lee el lector).</summary>
            public Action<ModoDeCarpetasProtegidas>? AlFijar;
            public string? Fijar(ModoDeCarpetasProtegidas modo) { Llamadas.Add(modo); if (Error is null) AlFijar?.Invoke(modo); return Error; }
        }

        private static readonly EstadoDeDefenderCfa Apagado = new(0, true, "Normal");

        private static PlanDeCarpetasProtegidas Prep(ModoDeCarpetasProtegidas d, EstadoDeDefenderCfa e) => PlanificadorDeCarpetasProtegidas.Preparar(d, e);

        public static void ProbarPlanDeRansomware()
        {
            Console.WriteLine("25. Activar las carpetas protegidas: el plan y la comprobación posterior");
            const ModoDeCarpetasProtegidas Act = ModoDeCarpetasProtegidas.Activado, Aud = ModoDeCarpetasProtegidas.Auditoria;

            PlanDeCarpetasProtegidas p = Prep(Act, Apagado);
            Check(p.HayCambios && p.ModoAnterior == 0 && p.Describir().Contains("de «desactivado» a «activado»") && p.Describir().Contains("Documentos"),
                "apagado -> activar: hay cambios y dice de qué a qué y qué protege", p.Describir());
            Check(p.Advertencias.Any(a => a.Contains("Permitir una aplicación")) && p.Advertencias.Any(a => a.Contains("Nexo no apaga")) && p.Advertencias.Any(a => a.Contains("lo comprobará")),
                "avisa: puede bloquear programas tuyos (y dónde permitirlos), Nexo no lo apaga, y se comprueba al terminar");

            // Nexo nunca apaga ni debilita.
            foreach (ModoDeCarpetasProtegidas d in new[] { ModoDeCarpetasProtegidas.Desactivado, ModoDeCarpetasProtegidas.SoloDiscos, ModoDeCarpetasProtegidas.AuditoriaSoloDiscos })
                Check(!Prep(d, new EstadoDeDefenderCfa(1, true, "Normal")).HayCambios && Prep(d, Apagado).Describir().Contains("no la apaga ni la debilita"), "pedir «" + d + "»: no se ofrece nunca");
            Check(Prep(Aud, Apagado).HayCambios, "apagado -> auditoría: sí (no quita nada)");
            Check(!Prep(Aud, new EstadoDeDefenderCfa(1, true, "Normal")).HayCambios && Prep(Aud, new EstadoDeDefenderCfa(1, true, "Normal")).Describir().Contains("quitaría protección"), "activado -> auditoría: NO (quitaría protección)");
            Check(!Prep(Aud, new EstadoDeDefenderCfa(3, true, "Normal")).HayCambios, "solo discos -> auditoría: NO (quitaría la protección del disco)");
            Check(Prep(Act, new EstadoDeDefenderCfa(2, true, "Normal")).HayCambios && Prep(Act, new EstadoDeDefenderCfa(3, true, "Normal")).HayCambios && Prep(Act, new EstadoDeDefenderCfa(4, true, "Normal")).HayCambios,
                "auditoría o solo discos -> activar: sí");
            Check(!Prep(Act, new EstadoDeDefenderCfa(1, true, "Normal")).HayCambios && Prep(Act, new EstadoDeDefenderCfa(1, true, "Normal")).Describir().StartsWith("Ya está"), "ya activado: nada que hacer");

            // Sin saber, nada.
            Check(!Prep(Act, Apagado with { Motor = null }).HayCambios, "sin saber si Defender está activo: nada");
            Check(!Prep(Act, Apagado with { Motor = "Passive Mode" }).HayCambios && Prep(Act, Apagado with { Motor = "Passive Mode" }).Describir().Contains("otro antivirus"), "Defender pasivo: nada (no funcionaría)");
            Check(!Prep(Act, Apagado with { TiempoReal = false }).HayCambios && Prep(Act, Apagado with { TiempoReal = false }).Describir().Contains("Nexo no la toca"), "tiempo real apagado: nada, y Nexo no lo enciende");
            Check(!Prep(Act, Apagado with { TiempoReal = null }).HayCambios, "sin saber el tiempo real: nada");
            Check(!Prep(Act, Apagado with { Modo = null }).HayCambios, "sin saber el modo actual: nada");
            Check(!Prep(Act, Apagado with { Modo = 9 }).HayCambios && Prep(Act, Apagado with { Modo = 9 }).Describir().Contains("(9)"), "modo desconocido: no se toca");

            // ---- Aplicar ----
            var l = new LectorCfaFalso { Valor = Apagado };
            var ej = new EjecutorCfaFalso();
            ej.AlFijar = m => l.Valor = l.Valor with { Modo = (int)m };
            ResultadoDeCfa ok = PlanificadorDeCarpetasProtegidas.Aplicar(p, l, ej);
            Check(ok.Exito && ok.ModoFinal == 1 && ej.Llamadas.SequenceEqual(new[] { Act }) && ok.Mensaje.Contains("comprobado"), "aplicar: una orden, y el éxito se confirma LEYENDO de nuevo", ok.Mensaje);
            Check(l.Lecturas == 2, "se lee antes (por si cambió) y después (para comprobar)");

            l.Valor = new EstadoDeDefenderCfa(1, true, "Normal"); ej.Llamadas.Clear();
            ResultadoDeCfa yaEsta = PlanificadorDeCarpetasProtegidas.Aplicar(p, l, ej);
            Check(!yaEsta.Exito && ej.Llamadas.Count == 0 && yaEsta.Mensaje.Contains("cambió desde la vista previa"), "si mientras tanto alguien lo activó: no se toca nada y se dice", yaEsta.Mensaje);
            l.Valor = new EstadoDeDefenderCfa(2, true, "Normal");
            Check(!PlanificadorDeCarpetasProtegidas.Aplicar(p, l, ej).Exito && ej.Llamadas.Count == 0, "si cambió a otro modo (aunque se pudiera activar igual): no se toca, el plan describía otra cosa");
            l.Valor = Apagado with { TiempoReal = false };
            Check(!PlanificadorDeCarpetasProtegidas.Aplicar(p, l, ej).Exito && ej.Llamadas.Count == 0, "si apagaron el tiempo real entre medias: no se toca");

            l.Valor = Apagado; ej.Error = "ManagementException AccessDenied";
            ResultadoDeCfa rech = PlanificadorDeCarpetasProtegidas.Aplicar(p, l, ej);
            Check(!rech.Exito && rech.Mensaje.Contains("rechazó") && rech.Mensaje.Contains("Sigue en «desactivado»"), "Windows rechaza la orden: fallo, con el motivo y cómo quedó", rech.Mensaje);

            ej.Error = null; ej.AlFijar = null; l.Valor = Apagado;
            ResultadoDeCfa ignorado = PlanificadorDeCarpetasProtegidas.Aplicar(p, l, ej);
            Check(!ignorado.Exito && ignorado.Mensaje.Contains("no cambió") && ignorado.Mensaje.Contains("directiva") && ignorado.ModoFinal == 0,
                "Windows ACEPTA la orden pero no la aplica (directiva, protección contra alteraciones): NUNCA «activado»", ignorado.Mensaje);

            ej.AlFijar = _ => l.Valor = l.Valor with { Modo = null }; l.Valor = Apagado;
            ResultadoDeCfa sinComprobar = PlanificadorDeCarpetasProtegidas.Aplicar(p, l, ej);
            Check(!sinComprobar.Exito && sinComprobar.Mensaje.Contains("no se pudo comprobar"), "si después no se puede leer: no se afirma que quedó", sinComprobar.Mensaje);

            // Un plan FABRICADO para apagar (no sale de Preparar) tampoco pasa: Aplicar vuelve a preparar con las mismas reglas.
            ej.Llamadas.Clear(); ej.AlFijar = m => l.Valor = l.Valor with { Modo = (int)m }; l.Valor = new EstadoDeDefenderCfa(1, true, "Normal");
            var falso = new PlanDeCarpetasProtegidas(ModoDeCarpetasProtegidas.Desactivado, 1, true, "apagar", Array.Empty<string>());
            Check(!PlanificadorDeCarpetasProtegidas.Aplicar(falso, l, ej).Exito && ej.Llamadas.Count == 0 && l.Valor.Modo == 1, "un plan fabricado para APAGAR se rechaza al aplicar: Defender no se toca");
            Check(!PlanificadorDeCarpetasProtegidas.Aplicar(Prep(Act, new EstadoDeDefenderCfa(1, true, "Normal")), l, ej).Exito && ej.Llamadas.Count == 0, "un plan sin cambios no ejecuta nada");
        }
    }
}
