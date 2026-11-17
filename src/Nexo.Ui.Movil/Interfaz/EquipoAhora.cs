using System;
using System.Collections.Generic;
using System.Linq;
using Nexo.Modules.Threats.Apps;
using Nexo.Modules.Threats.Movil;

namespace Nexo.Ui.Movil.Interfaz;

/// <summary>Lee el equipo y evalua el chequeo. Lo comparten el inicio y la pantalla de detalle.</summary>
public static class EquipoAhora
{
    public static readonly Lazy<CatalogoDeSenales> Catalogo = new(CatalogoDeSenales.Embebido);

    public static DatosDelEquipo Leer()
    {
        var lector = new LectorDelEquipoAndroid(Android.App.Application.Context);
        var d = lector.Leer();
        Android.Util.Log.Info("NEXO", "EQUIPO wifi=" + d.Wifi + " (" + lector.DiagnosticoDeWifi + ")");
        return d;
    }

    public static IReadOnlyList<Comprobacion> Evaluar(DatosDelEquipo d) => ChequeoDelEquipo.Evaluar(d, DateTime.Today, Catalogo.Value);

    /// <summary>Lo que necesita leer TODAS las apps (0,9 s en un S20 FE): apps que instalan otras apps y el resumen del riesgo. Corre fuera del hilo de la pantalla.</summary>
    public sealed record DeLasApps(IReadOnlyList<AppQueInstala> Instalan, int Prioritarias, int ARevisar, int DeConfianza, int Usuario);

    public static DeLasApps LeerApps()
    {
        var contexto = Android.App.Application.Context;
        var apps = new LectorDeAppsAndroid(contexto).Leer();
        var almacen = AlmacenDeConfianza.Cargar(Vigilancia.RutasDeNexo.Confiadas(contexto), out _);
        var resultados = new PuntuadorDeRiesgo(Catalogo.Value).EvaluarTodas(apps, almacen.Vigentes(apps));
        var porPaquete = resultados.ToDictionary(r => r.Paquete);
        var instalan = apps.Where(a => !a.EsDeSistema && a.InstalaAppsConcedido)
            .Select(a => new AppQueInstala(a.Nombre, a.Paquete, porPaquete[a.Paquete].Nivel)).ToList();
        var usuario = resultados.Where(r => r.Nivel != NivelDeRiesgo.NoEvaluada).ToList();
        return new DeLasApps(instalan, usuario.Count(r => r.Nivel == NivelDeRiesgo.Prioritaria), usuario.Count(r => r.Nivel == NivelDeRiesgo.ARevisar),
            usuario.Count(r => r.Nivel == NivelDeRiesgo.Confiada), usuario.Count);
    }
}
