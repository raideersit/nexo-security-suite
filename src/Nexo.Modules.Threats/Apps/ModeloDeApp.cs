using System.Collections.Generic;

namespace Nexo.Modules.Threats.Apps
{
    // =====================================================================================================
    //  INVENTARIO Y RIESGO DE APPS (Salida 7, 3.1). Modelo portable: no sabe nada de Android.
    //  Quien lee el telefono (Nexo.Ui.Movil / Nexo.Modules.Threats.Android) llena un ModeloDeApp por cada app;
    //  el puntuador solo ve este registro, asi se prueba en Linux con apps inventadas.
    // =====================================================================================================

    public enum OrigenDeInstalacion { Desconocido, TiendaOficial, TiendaConocida, OtraTienda, Navegador, ArchivoOAdb }

    public sealed record ModeloDeApp
    {
        public required string Paquete { get; init; }
        public string Nombre { get; init; } = "";
        public bool EsDeSistema { get; init; }
        /// <summary>Paquete que la instalo (puede ser null: archivo suelto, adb o dato no disponible).</summary>
        public string? InstaladoPor { get; init; }
        /// <summary>Permisos que la app declara (no implica que esten concedidos).</summary>
        public IReadOnlySet<string> PermisosPedidos { get; init; } = new HashSet<string>();
        /// <summary>Permisos peligrosos con la concesion hecha. Es lo que importa.</summary>
        public IReadOnlySet<string> PermisosConcedidos { get; init; } = new HashSet<string>();
        public bool AccesibilidadActiva { get; init; }
        public bool AdministradorActivo { get; init; }
        public bool SuperposicionConcedida { get; init; }
        public bool OyenteDeNotificacionesActivo { get; init; }
        public bool InstalaAppsConcedido { get; init; }
        public bool SinIconoEnLanzador { get; init; }
        public bool FirmaDeDepuracion { get; init; }
        /// <summary>Rutas de los APK instalados (el base y los «split»). Para la huella (3.2).</summary>
        public IReadOnlyList<string> Apks { get; init; } = System.Array.Empty<string>();
        public long VersionCode { get; init; }
        public long UltimaActualizacionMs { get; init; }
    }

    public enum NivelDeRiesgo
    {
        /// <summary>No se evalua (apps del sistema).</summary>
        NoEvaluada,
        Normal,
        ARevisar,
        /// <summary>«A revisar» con prioridad. Sigue sin ser un veredicto de malware.</summary>
        Prioritaria,
        /// <summary>Tiene puntos pero el usuario dijo «confio en esta app».</summary>
        Confiada,
    }

    public sealed record ResultadoDeApp(string Paquete, string Nombre, NivelDeRiesgo Nivel, int Puntos, IReadOnlyList<string> Motivos, IReadOnlyList<string> SenalesActivas, OrigenDeInstalacion Origen);
}
