using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Ipc;
using Nexo.Modules.Cleanup.Perfiles;

namespace Nexo.Service
{
    /// <summary>
    /// Perfiles de actividad (§2ay-§2az del traspaso): cada pocos segundos lee energía y pantalla completa, elige un perfil con histéresis y
    /// se lo da a la <see cref="PuertaDeTareasPesadas"/>, que consultan el escaneo programado y la copia automática antes de arrancar.
    ///
    /// APAGADO por omisión (Nexo:Perfiles:Activo): cambia CUÁNDO corren las tareas automáticas. Solo posterga su arranque (con un máximo de
    /// espera) y no toca el plan de energía, la prioridad de otros programas ni la protección en tiempo real. Por el pipe: solo
    /// <c>perfil.estado</c> (lectura); no hay métodos para cambiar el perfil a mano.
    /// </summary>
    public sealed class ModuloPerfil : IModuloDelServicio, IAsyncDisposable
    {
        public static readonly TimeSpan IntervaloPorDefecto = TimeSpan.FromSeconds(10);
        public static readonly TimeSpan IntervaloMinimo = TimeSpan.FromSeconds(2);

        private readonly Func<SenalesDeActividad> _leer;
        private readonly TimeSpan _intervalo;
        private readonly Func<DateTimeOffset> _reloj;
        private readonly Func<TimeSpan, CancellationToken, Task> _esperar;
        private readonly SelectorDePerfil _selector = new SelectorDePerfil();
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly object _candado = new object();
        private Task? _bucle;
        private DateTimeOffset? _ultimaLectura;
        private DateTimeOffset? _desdeElPerfil;
        private Perfil? _perfilAnterior;
        private string? _fallo;

        /// <summary>Cada cuánto se vuelve a mirar el Wi-Fi (es una consulta más cara que la energía y la pantalla, y cambia poco).</summary>
        public static readonly TimeSpan WifiCadaPorDefecto = TimeSpan.FromSeconds(60);

        private readonly Func<bool?>? _wifiAbierto;
        private readonly TimeSpan _wifiCada;
        private DateTimeOffset? _wifiLeidoEn;
        private bool? _wifi;

        /// <param name="wifiAbierto">
        /// Si estás conectado a una red Wi-Fi sin cifrado: true/false, o null si no se pudo saber. Se llama como mucho una vez por
        /// <paramref name="wifiCada"/>. Sin esta función el aviso de Wi-Fi abierto no existe (nunca se inventa).
        /// </param>
        public ModuloPerfil(Func<SenalesDeActividad> leer, TimeSpan? maximoDeEspera = null, TimeSpan? intervalo = null,
                            Func<DateTimeOffset>? reloj = null, Func<TimeSpan, CancellationToken, Task>? esperar = null,
                            Func<bool?>? wifiAbierto = null, TimeSpan? wifiCada = null)
        {
            _leer = leer;
            _wifiAbierto = wifiAbierto;
            _wifiCada = wifiCada ?? WifiCadaPorDefecto;
            TimeSpan i = intervalo ?? IntervaloPorDefecto;
            _intervalo = i < IntervaloMinimo ? IntervaloMinimo : i;
            _reloj = reloj ?? (() => DateTimeOffset.Now);
            _esperar = esperar ?? ((t, ct) => Task.Delay(t, ct));
            Puerta = new PuertaDeTareasPesadas(() => { lock (_candado) return _ultimaLectura is null || _fallo is not null ? null : _selector.Actual; },
                                               maximoDeEspera ?? PuertaDeTareasPesadas.MaximoPorOmision);
        }

        /// <summary>La puerta que consultan las tareas automáticas. Si no se pudo leer nunca (o la última lectura falló), está abierta.</summary>
        public PuertaDeTareasPesadas Puerta { get; }

        public TimeSpan Intervalo => _intervalo;

        public IReadOnlyList<string> Metodos { get; } = new[] { "perfil.estado" };

        public void Iniciar()
        {
            if (_bucle is not null) return;
            _bucle = Task.Run(() => BucleAsync(_cts.Token));
        }

        private async Task BucleAsync(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    UnaVuelta();
                    await _esperar(_intervalo, ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
        }

        /// <summary>Una lectura y su decisión. Interno: lo usan el bucle y las pruebas.</summary>
        internal void UnaVuelta()
        {
            try
            {
                SenalesDeActividad s = _leer();
                bool? wifi = LeerWifi();
                if (wifi is not null || _wifiAbierto is not null) s = s with { WifiAbierto = wifi };
                lock (_candado)
                {
                    DecisionDePerfil d = _selector.Actualizar(s);
                    DateTimeOffset ahora = _reloj();
                    if (_perfilAnterior != d.Perfil) { _perfilAnterior = d.Perfil; _desdeElPerfil = ahora; }
                    _ultimaLectura = ahora;
                    _fallo = null;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Una lectura que falla no deja tareas paradas (la puerta se abre) y se dice.
                lock (_candado) _fallo = "la última lectura falló (" + ex.GetType().Name + "): no se pospone nada";
            }
        }

        /// <summary>El Wi-Fi, como mucho una vez por <c>_wifiCada</c>; entre una y otra se repite lo último. Una lectura que falla es «no se sabe» (null).</summary>
        private bool? LeerWifi()
        {
            if (_wifiAbierto is null) return null;
            DateTimeOffset ahora = _reloj();
            if (_wifiLeidoEn is { } ult && ahora - ult < _wifiCada) return _wifi;
            bool? v;
            try { v = _wifiAbierto(); }
            catch (Exception ex) when (ex is not OperationCanceledException) { v = null; }
            lock (_candado) { _wifi = v; _wifiLeidoEn = ahora; }
            return v;
        }

        public Task<object?> ManejarAsync(string metodo, JsonElement? p, CancellationToken ct)
        {
            if (metodo != "perfil.estado") throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
            return Task.FromResult<object?>(Estado());
        }

        private object Estado()
        {
            DecisionDePerfil d; DateTimeOffset? lectura, desde; string? fallo; bool wifiConocido;
            lock (_candado) { d = _selector.Actual; lectura = _ultimaLectura; desde = _desdeElPerfil; fallo = _fallo; wifiConocido = _wifi is not null; }
            DateTimeOffset ahora = _reloj();
            bool pospone = lectura is not null && fallo is null && d.PosponerTareasPesadas;

            return new
            {
                activo = true,
                intervalo_segundos = (int)_intervalo.TotalSeconds,
                ultima_lectura = lectura,
                perfil = lectura is null ? null : d.Perfil.ToString(),
                desde,
                pospone_tareas_pesadas = pospone,
                maximo_espera_horas = Math.Round(Puerta.MaximoDeEspera.TotalHours, 2),
                // true: conectado a un Wi-Fi sin cifrado. false: no lo está, o no se pudo saber (ver wifi_leido).
                wifi_abierto = lectura is not null && d.AvisarWifiAbierto,
                wifi_leido = _wifiAbierto is not null && lectura is not null && wifiConocido,
                motivos = lectura is null ? Array.Empty<string>() : d.Motivos.ToArray(),
                no_evaluado = lectura is null ? Array.Empty<string>() : d.NoEvaluado.ToArray(),
                pospuestas = Puerta.Pospuestas(ahora).Select(t => new { tarea = t.Tarea, desde = t.Desde, forzada = t.Forzada }).ToList(),
                aviso = fallo,
                nota = "Solo cambia CUÁNDO empiezan el escaneo programado y la copia automática; no toca el plan de energía, la prioridad de otros programas ni la protección en tiempo real."
            };
        }

        public async ValueTask DisposeAsync()
        {
            _cts.Cancel();
            if (_bucle is not null)
            {
                try { await _bucle.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false); }
                catch (TimeoutException) { }
            }
            _cts.Dispose();
        }
    }

    /// <summary>Lo que contesta el servicio con los perfiles apagados.</summary>
    public sealed class ModuloPerfilApagado : IModuloDelServicio
    {
        public IReadOnlyList<string> Metodos { get; } = new[] { "perfil.estado" };

        public Task<object?> ManejarAsync(string metodo, JsonElement? parametros, CancellationToken ct)
            => metodo == "perfil.estado"
                ? Task.FromResult<object?>(new
                {
                    activo = false,
                    pospone_tareas_pesadas = false,
                    nota = "Los perfiles de actividad están apagados: el escaneo programado y la copia automática corren a su hora. Se activan en appsettings.json (Nexo:Perfiles:Activo)."
                })
                : throw new ErrorDeComando(CodigoDeError.MetodoDesconocido, "metodo desconocido");
    }
}
