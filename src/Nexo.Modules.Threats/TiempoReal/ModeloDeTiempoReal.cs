using System;
using System.Collections.Generic;

namespace Nexo.Modules.Threats.TiempoReal
{
    public enum MotivoDeCambio
    {
        Creado,
        Modificado,
        Renombrado
    }

    /// <summary>Un archivo que cambio, segun la fuente (FileSystemWatcher o diario USN).</summary>
    public sealed record CambioDeArchivo(string Ruta, MotivoDeCambio Motivo);

    /// <summary>
    /// De donde vienen los cambios. Se abstrae para que el vigilante se pruebe sin tocar el
    /// disco y para poder cambiar de FileSystemWatcher (sin administrador, puede perder
    /// eventos) al diario USN (necesita administrador, no pierde nada) sin tocar la logica.
    /// </summary>
    public interface IFuenteDeCambios : IDisposable
    {
        /// <param name="alCambiar">Se llama por cada cambio, desde cualquier hilo. Debe ser rapida.</param>
        /// <param name="alPerder">
        /// La fuente sabe que se le escaparon eventos (p. ej. desbordo el buffer del
        /// FileSystemWatcher). NUNCA se debe silenciar: el vigilante lo cuenta y lo informa,
        /// porque «no vi el cambio» no equivale a «no hubo nada».
        /// </param>
        void Iniciar(Action<CambioDeArchivo> alCambiar, Action<string> alPerder);
    }

    /// <summary>Una fuente que sabe decir que partes NO esta vigilando (y por que). Nunca se oculta.</summary>
    public interface IFuenteConCobertura
    {
        IReadOnlyList<string> NoVigiladas { get; }
    }

    public sealed class OpcionesDeTiempoReal
    {
        /// <summary>Extensiones que se analizan: ejecutables, scripts, instaladores y documentos con macros.</summary>
        public IReadOnlyCollection<string> Extensiones { get; init; } = new[]
        {
            ".exe", ".dll", ".scr", ".sys", ".com", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
            ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar", ".cpl", ".reg", ".docm", ".xlsm", ".pptm", ".iso", ".img"
        };

        /// <summary>Carpetas que no se miran (la cuarentena, el vault de Nexo...). Evita que Nexo se analice a si mismo en bucle.</summary>
        public IReadOnlyList<string> Excluir { get; init; } = Array.Empty<string>();

        /// <summary>Mas grande que esto no se envia al motor (limite de clamd): queda como NO analizado.</summary>
        public long MaxBytes { get; init; } = 25L * 1024 * 1024;

        /// <summary>
        /// Tiempo sin nuevos cambios antes de analizar un archivo: una descarga o una copia emite
        /// decenas de eventos y analizarlo a medias solo da falsos «limpio».
        /// </summary>
        public TimeSpan Estabilizacion { get; init; } = TimeSpan.FromMilliseconds(1500);

        /// <summary>Si el archivo sigue bloqueado, cuantas veces se reintenta antes de darlo por no analizado.</summary>
        public int MaxReintentos { get; init; } = 4;

        public int Trabajadores { get; init; } = 2;

        /// <summary>Archivos distintos pendientes a la vez. Pasado esto se descartan (y se CUENTAN como perdidos).</summary>
        public int MaxPendientes { get; init; } = 5000;

        /// <summary>Tras tantos fallos seguidos del motor se declara «motor caido» (la cobertura es nula, y se dice).</summary>
        public int MaxErroresSeguidos { get; init; } = 5;

        public TimeSpan Sondeo { get; init; } = TimeSpan.FromMilliseconds(100);

        /// <summary>
        /// Con el motor caido, cada cuanto se le pregunta si volvio. Sin esto «motor caido» solo se borraba al llegar el
        /// siguiente archivo: con el equipo quieto se seguia avisando de un motor que ya funcionaba.
        /// </summary>
        public TimeSpan ComprobarMotorCada { get; init; } = TimeSpan.FromSeconds(30);
    }

    /// <summary>
    /// Contadores del vigilante. «Perdidos» y «no analizados» son tan importantes como «analizados».
    /// <c>Perdidos</c> son ARCHIVOS distintos descartados por exceso de pendientes y no analizados despues (un minimo si <c>PerdidosEsMinimo</c>);
    /// <c>DesbordesDeFuente</c>, las veces que la fuente perdio eventos sin decir cuales (no hay numero de archivos).
    /// </summary>
    public sealed record EstadoDeTiempoReal(
        bool Activo,
        long CambiosVistos,
        long Descartados,
        long Analizados,
        long NoAnalizados,
        long Perdidos,
        int Pendientes,
        bool MotorCaido,
        int Detecciones,
        string? UltimoAviso,
        long DesbordesDeFuente = 0,
        int CarpetasPorRevisar = 0,
        bool RevisarTodo = false,
        bool PerdidosEsMinimo = false);

    /// <summary>Lo que hay que volver a mirar con un escaneo bajo demanda. <c>Todo</c>: todas las raices vigiladas.</summary>
    public sealed record PorRevisar(IReadOnlyList<string> Carpetas, bool Todo)
    {
        public bool Vacio => Carpetas.Count == 0 && !Todo;
    }
}
