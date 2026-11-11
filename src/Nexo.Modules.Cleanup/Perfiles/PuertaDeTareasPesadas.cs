using System;
using System.Collections.Generic;
using System.Linq;

namespace Nexo.Modules.Cleanup.Perfiles
{
    /// <summary>Una tarea pesada de Nexo que está esperando por el perfil, y desde cuándo.</summary>
    public sealed record TareaPospuesta(string Tarea, DateTimeOffset Desde, bool Forzada);

    /// <summary>
    /// «¿Puedo empezar ahora una tarea pesada?» Las tareas automáticas de Nexo (escaneo programado, copia versionada) la consultan JUSTO
    /// antes de arrancar. Reglas:
    ///  - Con el perfil Normal (o sin perfil: <see cref="Abierta"/>) siempre se puede.
    ///  - En JuegoOVideo o Bateria se pospone, pero como MÁXIMO <see cref="MaximoDeEspera"/>: pasado ese tiempo la tarea corre aunque siga el
    ///    perfil (quien juega ocho horas al día no debe quedarse sin copia ni escaneo para siempre). Eso se dice: <c>Forzada</c>.
    ///  - Solo se pospone el ARRANQUE: una tarea que ya empezó no se interrumpe.
    ///  - El tiempo real y el resto de la protección no pasan por aquí: nunca se pospone.
    /// </summary>
    public sealed class PuertaDeTareasPesadas
    {
        public static readonly TimeSpan MaximoPorOmision = TimeSpan.FromHours(6);

        /// <summary>Sin perfiles: todo se puede siempre.</summary>
        public static readonly PuertaDeTareasPesadas Abierta = new(() => null, MaximoPorOmision);

        private readonly Func<DecisionDePerfil?> _perfil;
        private readonly object _candado = new object();
        private readonly Dictionary<string, DateTimeOffset> _desde = new(StringComparer.Ordinal);

        public PuertaDeTareasPesadas(Func<DecisionDePerfil?> perfil, TimeSpan maximoDeEspera)
        {
            _perfil = perfil;
            MaximoDeEspera = maximoDeEspera <= TimeSpan.Zero ? MaximoPorOmision : maximoDeEspera;
        }

        public TimeSpan MaximoDeEspera { get; }

        /// <summary>true si la tarea puede empezar ahora. Llamarla otra vez mientras espera no reinicia la cuenta.</summary>
        public bool Permite(string tarea, DateTimeOffset ahora)
        {
            DecisionDePerfil? d = _perfil();
            lock (_candado)
            {
                if (d is null || !d.PosponerTareasPesadas)
                {
                    _desde.Remove(tarea);
                    return true;
                }
                if (!_desde.TryGetValue(tarea, out DateTimeOffset desde)) { _desde[tarea] = ahora; return false; }
                return ahora - desde >= MaximoDeEspera;
            }
        }

        /// <summary>La tarea ya corrió (o se descartó): la próxima vez la cuenta de espera empieza de cero.</summary>
        public void Terminada(string tarea)
        {
            lock (_candado) _desde.Remove(tarea);
        }

        public IReadOnlyList<TareaPospuesta> Pospuestas(DateTimeOffset ahora)
        {
            // Con el perfil ya en Normal no hay nada pospuesto (una entrada vieja se limpia en la próxima consulta de la tarea).
            if (_perfil() is not { PosponerTareasPesadas: true }) return Array.Empty<TareaPospuesta>();
            lock (_candado) return _desde.Select(kv => new TareaPospuesta(kv.Key, kv.Value, ahora - kv.Value >= MaximoDeEspera)).OrderBy(t => t.Tarea, StringComparer.Ordinal).ToList();
        }
    }
}
