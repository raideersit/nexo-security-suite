using System;
using System.Diagnostics;
using System.Linq;
using Android.Content;
using Nexo.Modules.Threats.Apps;
using Nexo.Ui.Movil.Interfaz;

namespace Nexo.Ui.Movil.Vigilancia;

/// <summary>
/// Notificaciones generales: «el equipo empeoro» y «resumen semanal». Lo llama el trabajo periodico (junto a la revision de apps)
/// y cada interruptor al encenderse, para tomar la linea base. La decision vive en <see cref="VigilanteDelEquipo"/> (portable, probada en Linux).
/// </summary>
public static class EjecutorDelEquipo
{
    private static readonly object Candado = new();

    public sealed record Resultado(bool Ejecutada, bool LineaBase, int Avisos, int Mostrados, bool Resumen, long Ms);

    /// <param name="lineaBaseEquipo">Al encender «avisar si el equipo empeora»: se olvida lo anterior, y lo que ya esta mal no avisa.</param>
    /// <param name="reiniciarResumen">Al encender el resumen: la semana empieza a contar ahora.</param>
    public static Resultado Ejecutar(Context contexto, string origen, bool lineaBaseEquipo = false, bool reiniciarResumen = false)
    {
        bool equipo = ConfiguracionDeVigilancia.EquipoActivado(contexto), resumen = ConfiguracionDeVigilancia.ResumenActivado(contexto);
        if (!equipo && !resumen) return new Resultado(false, false, 0, 0, false, 0);
        lock (Candado)
        {
            var reloj = Stopwatch.StartNew();
            var ruta = RutasDeNexo.Equipo(contexto);
            var estado = EstadoDelEquipo.Cargar(ruta, out var aviso);
            if (aviso != null) Android.Util.Log.Warn("NEXO", aviso);
            if (lineaBaseEquipo) { estado.UltimaRevisionMs = null; estado.EnAviso.Clear(); }
            if (reiniciarResumen) estado.UltimoResumenMs = null;

            // El chequeo completo, igual que la pantalla «Estado»: datos del equipo + las apps que pueden instalar otras apps.
            var apps = EquipoAhora.LeerApps();
            var datos = EquipoAhora.Leer() with { AppsQueInstalan = apps.Instalan };
            var chequeo = EquipoAhora.Evaluar(datos);
            var ahora = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            bool puede = Notificador.PuedeNotificar(contexto);

            bool eraLineaBase = false;
            int avisos = 0, mostrados = 0;
            if (equipo)
            {
                eraLineaBase = estado.UltimaRevisionMs is null;
                var nuevos = VigilanteDelEquipo.Revisar(chequeo, estado, ahora);
                avisos = nuevos.Count;
                foreach (var a in nuevos)
                {
                    if (puede) { Notificador.MostrarEquipo(contexto, a); mostrados++; }
                    // Sin permiso NO se da por avisado: el proximo intento (con permiso) lo muestra.
                    else estado.EnAviso.Remove(a.Fila);
                }
                if (avisos > 0 && !puede) Android.Util.Log.Warn("NEXO", $"EQUIPO {avisos} aviso(s) sin mostrar: falta el permiso de notificaciones");
            }

            bool resumenMostrado = false;
            if (resumen && VigilanteDelEquipo.TocaResumen(estado, ahora))
            {
                if (puede)
                {
                    var (titulo, texto) = VigilanteDelEquipo.ComponerResumen(apps.Usuario, apps.Prioritarias + apps.ARevisar, apps.DeConfianza, chequeo);
                    Notificador.MostrarResumen(contexto, titulo, texto);
                    VigilanteDelEquipo.ResumenMostrado(estado, ahora);
                    resumenMostrado = true;
                }
                else Android.Util.Log.Warn("NEXO", "RESUMEN sin mostrar: falta el permiso de notificaciones");
            }

            estado.Guardar(ruta);
            var r = new Resultado(true, eraLineaBase, avisos, mostrados, resumenMostrado, reloj.ElapsedMilliseconds);
            Android.Util.Log.Info("NEXO", $"EQUIPO-REVISION origen={origen} equipo={equipo} resumen={resumen} lineaBase={r.LineaBase} avisos={r.Avisos} mostrados={r.Mostrados} resumenMostrado={r.Resumen} enAviso={estado.EnAviso.Count} ms={r.Ms}"
                + string.Concat(estado.EnAviso.Select(f => " EN_AVISO=" + f.Replace(' ', '_'))));
            return r;
        }
    }
}
