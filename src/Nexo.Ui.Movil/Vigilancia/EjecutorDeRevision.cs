using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Android.Content;
using Nexo.Modules.Threats.Apps;
using Nexo.Modules.Threats.Movil;

namespace Nexo.Ui.Movil.Vigilancia;

/// <summary>
/// Una revision completa: lee las apps, calcula huellas (con cache), compara con lo que se vio la vez anterior y avisa.
/// Lo usan dos caminos: el trabajo periodico y el receptor mientras la app esta abierta. Nunca corren a la vez.
/// </summary>
public static class EjecutorDeRevision
{
    private static readonly object Candado = new();
    private static readonly Lazy<VigilanteDeInstalaciones> Vigilante = new(() => new VigilanteDeInstalaciones(new PuntuadorDeRiesgo(CatalogoDeSenales.Embebido())));

    public sealed record Resultado(bool Ejecutada, bool LineaBase, int Alertas, int Mostradas, int Nuevas, int Actualizadas, int Desinstaladas, long Ms);

    public static Resultado Ejecutar(Context contexto, string origen, bool ignorarInterruptor = false)
    {
        if (!ignorarInterruptor && !ConfiguracionDeVigilancia.Activada(contexto))
        {
            Android.Util.Log.Info("NEXO", $"REVISION origen={origen} omitida: el aviso al instalar esta apagado");
            return new Resultado(false, false, 0, 0, 0, 0, 0, 0);
        }
        lock (Candado)
        {
            var reloj = Stopwatch.StartNew();
            var apps = new LectorDeAppsAndroid(contexto).Leer();

            var cache = CacheDeHuellas.Cargar(RutasDeNexo.Cache(contexto), out _);
            ResultadoDeHuellas huellas;
            try { huellas = new CalculadorDeHuellas(new OrigenDeApksEnDisco(), cache).Calcular(apps); }
            finally { cache.Guardar(RutasDeNexo.Cache(contexto)); }

            var listas = new List<ListaDeHuellas>();
            var carpeta = RutasDeNexo.CarpetaDeListas(contexto);
            if (Directory.Exists(carpeta))
                foreach (var f in Directory.EnumerateFiles(carpeta).Where(f => f.EndsWith(".txt") || f.EndsWith(".csv")))
                {
                    try { listas.Add(ListaDeHuellas.DesdeArchivo(f)); }
                    catch (Exception ex) when (ex is InvalidDataException or IOException) { Android.Util.Log.Warn("NEXO", "lista ignorada " + Path.GetFileName(f) + ": " + ex.Message); }
                }

            var estado = EstadoDeVigilancia.Cargar(RutasDeNexo.Vigilancia(contexto), out var aviso);
            if (aviso != null) Android.Util.Log.Warn("NEXO", aviso);
            var ahora = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var r = Vigilante.Value.Revisar(apps, estado, ahora, huellas.Huellas, listas);

            int mostradas = 0;
            if (r.Alertas.Count > 0)
            {
                if (Notificador.PuedeNotificar(contexto))
                {
                    foreach (var a in r.Alertas) { Notificador.Mostrar(contexto, a); mostradas++; }
                }
                else
                {
                    // Sin permiso para avisar: NO se da por avisado, asi el proximo intento (con permiso) lo muestra.
                    foreach (var a in r.Alertas)
                        estado.Avisadas.Remove(EstadoDeVigilancia.Clave(a.Paquete, apps.First(x => x.Paquete == a.Paquete).VersionCode, apps.First(x => x.Paquete == a.Paquete).UltimaActualizacionMs));
                    Android.Util.Log.Warn("NEXO", $"REVISION {r.Alertas.Count} aviso(s) sin mostrar: falta el permiso de notificaciones");
                }
            }
            estado.Guardar(RutasDeNexo.Vigilancia(contexto));
            var res = new Resultado(true, r.EraLineaBase, r.Alertas.Count, mostradas, r.Nuevas, r.Actualizadas, r.Desinstaladas, reloj.ElapsedMilliseconds);
            Android.Util.Log.Info("NEXO", $"REVISION origen={origen} lineaBase={res.LineaBase} nuevas={res.Nuevas} actualizadas={res.Actualizadas} desinstaladas={res.Desinstaladas} alertas={res.Alertas} mostradas={res.Mostradas} ms={res.Ms}"
                + string.Concat(r.Alertas.Select(a => " ALERTA=" + a.Paquete)));
            return res;
        }
    }
}
