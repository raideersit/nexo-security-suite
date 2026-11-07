using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Vulnerabilidades;
#if WINDOWS
using Nexo.Modules.Threats.Windows;
#endif

namespace Nexo.Ui.Desktop.Nucleo
{
    public enum SeccionDeSeguridad
    {
        Cuentas,
        Wifi,
        Aplicaciones
    }

    /// <summary>
    /// Una revision ya hecha. <see cref="Nota"/> es un hecho que no es un hallazgo ni un fallo (por ejemplo «este equipo no tiene
    /// adaptador Wi-Fi»). Un analisis incompleto (<c>Analisis.Completo == false</c>) NUNCA se presenta como «sin problemas».
    /// </summary>
    public sealed record RevisionDeSeccion(SeccionDeSeguridad Seccion, ResultadoDeAnalisis Analisis, DateTimeOffset Fecha, string? Nota = null, int? Elementos = null);

    /// <summary>
    /// De donde salen las revisiones de seguridad. Todo es SOLO LECTURA: ningun metodo cambia nada en el equipo. Corre en el proceso
    /// de la ventana (con el usuario), no en el servicio.
    /// </summary>
    public interface IServicioDeSeguridad
    {
        Task<Consulta<RevisionDeSeccion>> RevisarAsync(SeccionDeSeguridad seccion, CancellationToken ct);
    }

    public sealed class ServicioDeSeguridadNoDisponible : IServicioDeSeguridad
    {
        private readonly string _motivo;

        public ServicioDeSeguridadNoDisponible(string motivo) => _motivo = motivo;

        public Task<Consulta<RevisionDeSeccion>> RevisarAsync(SeccionDeSeguridad seccion, CancellationToken ct)
            => Task.FromResult(Consulta<RevisionDeSeccion>.Mal(_motivo));
    }

#if WINDOWS
    /// <summary>
    /// Las revisiones reales de Windows, en el propio proceso. Cuentas y Wi-Fi leen metadatos con APIs del sistema (sin red ni
    /// administrador); Aplicaciones ejecuta <c>winget upgrade</c>, que CONSULTA Internet: por eso solo corre cuando el usuario lo pide.
    /// </summary>
    public sealed class ServicioDeSeguridadLocal : IServicioDeSeguridad
    {
        private readonly Func<DateTimeOffset> _reloj;

        public ServicioDeSeguridadLocal(Func<DateTimeOffset>? reloj = null) => _reloj = reloj ?? (() => DateTimeOffset.Now);

        public async Task<Consulta<RevisionDeSeccion>> RevisarAsync(SeccionDeSeguridad seccion, CancellationToken ct)
        {
            try
            {
                switch (seccion)
                {
                    case SeccionDeSeguridad.Cuentas:
                    {
                        InstantaneaDeCuentas s = await Task.Run(() => LectorDeCuentasWindows.Leer(), ct).ConfigureAwait(false);
                        return Consulta<RevisionDeSeccion>.Bien(new RevisionDeSeccion(seccion, AnalizadorDeCuentas.Analizar(s), _reloj(), Elementos: s.Cuentas?.Count));
                    }
                    case SeccionDeSeguridad.Wifi:
                    {
                        InstantaneaDeWifi s = await Task.Run(() => LectorDeWifiWindows.Leer(), ct).ConfigureAwait(false);
                        string? nota = s.Estado == EstadoDeLecturaWifi.SinAdaptador ? "Este equipo no tiene adaptador Wi-Fi: no hay redes que revisar." : null;
                        return Consulta<RevisionDeSeccion>.Bien(new RevisionDeSeccion(seccion, AnalizadorDeWifi.Analizar(s), _reloj(), nota,
                            s.Adaptadores.Sum(a => a.Perfiles.Count)));
                    }
                    default:
                    {
                        SalidaDeWinget w = await LectorDeWingetWindows.LeerAsync(ct: ct).ConfigureAwait(false);
                        ResultadoDeAplicaciones r = AnalizadorDeAplicaciones.Analizar(w);
                        return Consulta<RevisionDeSeccion>.Bien(new RevisionDeSeccion(seccion, r.Analisis, _reloj(), Elementos: r.Aplicaciones.Count));
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Lo que no se pudo revisar se dice; nunca se devuelve un resultado a medias.
                return Consulta<RevisionDeSeccion>.Mal("error inesperado al revisar (" + ex.GetType().Name + ")");
            }
        }
    }
#endif
}
