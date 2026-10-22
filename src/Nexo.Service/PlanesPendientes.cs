using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Nexo.Ipc;

namespace Nexo.Service
{
    /// <summary>
    /// Planes con vista previa que esperan confirmacion. El plan vive AQUI, en el servicio;
    /// el cliente solo recibe un token opaco para pedir que se aplique ESE plan. Asi la UI
    /// no puede cambiar lo que se aplica entre la vista previa y la confirmacion.
    ///
    /// - El token es aleatorio (256 bits), no adivinable.
    /// - Un solo uso: se consume al intentar aplicar, tenga o no exito. Reintentar exige
    ///   volver a previsualizar, y por tanto volver a mostrar al usuario lo que va a pasar.
    /// - Caduca, y hay un maximo de planes pendientes (el mas antiguo se descarta).
    ///
    /// LIMITE HONESTO: el token demuestra que quien aplica tiene el plan que se previsualizo;
    /// NO demuestra que una PERSONA lo aprobo. Un proceso malicioso que corra como el mismo
    /// usuario puede pedir la vista previa y despues aplicarla. Lo que lo acota es lo que el
    /// plan puede llegar a hacer (guardias de cada modulo, solo reglas del grupo de Nexo,
    /// todo reversible y registrado), no el token.
    /// </summary>
    public sealed class PlanesPendientes<T> where T : class
    {
        private sealed record Entrada(T Plan, DateTimeOffset Expira, ContextoDeLlamada? Dueno);

        private readonly Dictionary<string, Entrada> _planes = new Dictionary<string, Entrada>(StringComparer.Ordinal);
        private readonly TimeSpan _vigencia;
        private readonly int _maximo;
        private readonly Func<DateTimeOffset> _reloj;

        public PlanesPendientes(TimeSpan vigencia, int maximo = 32, Func<DateTimeOffset>? reloj = null)
        {
            _vigencia = vigencia;
            _maximo = maximo;
            _reloj = reloj ?? (() => DateTimeOffset.Now);
        }

        public int Pendientes { get { lock (_planes) return _planes.Count; } }

        /// <param name="dueno">Quien pidio la vista previa. Se guarda una copia de su identidad: si luego lo aprueba un administrador
        /// distinto (un usuario estandar cuyo UAC pide otras credenciales), el plan se ejecuta COMO el dueno, no como quien aprueba.</param>
        public (string Token, DateTimeOffset Expira) Guardar(T plan, ContextoDeLlamada? dueno = null)
        {
            string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
            DateTimeOffset ahora = _reloj();
            DateTimeOffset expira = ahora + _vigencia;
            ContextoDeLlamada? copia = dueno?.Duplicar();

            lock (_planes)
            {
                foreach (string k in _planes.Where(p => p.Value.Expira <= ahora).Select(p => p.Key).ToList())
                    Descartar(k);
                while (_planes.Count >= _maximo)
                    Descartar(_planes.OrderBy(p => p.Value.Expira).First().Key);
                _planes[token] = new Entrada(plan, expira, copia);
            }
            return (token, expira);
        }

        private void Descartar(string clave)
        {
            if (_planes.Remove(clave, out Entrada? e)) e.Dueno?.Dispose();
        }

        /// <summary>
        /// Saca el plan de ese token y lo borra. Null si no existe, ya se uso o caduco: el
        /// llamador no debe distinguir cual de las tres (no se le da pistas a quien adivina).
        /// </summary>
        public T? Tomar(string? token)
        {
            if (string.IsNullOrEmpty(token) || token.Length != 64) return null;
            lock (_planes)
            {
                if (!_planes.Remove(token, out Entrada? e)) return null;
                e.Dueno?.Dispose();
                return e.Expira > _reloj() ? e.Plan : null;
            }
        }

        /// <summary>
        /// Como <see cref="Tomar"/> pero decide CON QUE IDENTIDAD se ejecuta el plan. Si lo aplica quien lo pidio, con la suya. Si
        /// lo aplica otro usuario, solo vale cuando es un administrador con token elevado (alguien acepto el UAC) y entonces se
        /// ejecuta con la identidad del dueno: el administrador aprueba, pero no gana acceso a nada. Cualquier otro caso es el mismo
        /// "token invalido" que un token falso. Plan sin dueno (firewall, purga): se ejecuta con la identidad de quien aplica.
        /// </summary>
        public PlanTomado<T>? Tomar(string? token, ContextoDeLlamada? llamador)
        {
            if (string.IsNullOrEmpty(token) || token.Length != 64) return null;
            Entrada? e;
            lock (_planes)
            {
                if (!_planes.Remove(token, out e)) return null;
            }

            if (e.Expira <= _reloj()) { e.Dueno?.Dispose(); return null; }
            if (e.Dueno is null) return llamador is null ? null : new PlanTomado<T>(e.Plan, llamador, null);
            if (llamador is null) { e.Dueno.Dispose(); return null; }

            if (llamador.Usuario is not null && llamador.Usuario == e.Dueno.Usuario)
            {
                e.Dueno.Dispose();
                return new PlanTomado<T>(e.Plan, llamador, null);
            }
            if (llamador.EsAdministrador && e.Dueno.PuedeActuarComoElLlamador)
                return new PlanTomado<T>(e.Plan, e.Dueno, e.Dueno);

            e.Dueno.Dispose();
            return null;
        }
    }

    /// <summary>Un plan ya sacado de la lista y la identidad con la que debe ejecutarse. Libera la copia del dueno si la hay.</summary>
    public sealed class PlanTomado<T> : IDisposable where T : class
    {
        private readonly ContextoDeLlamada? _aLiberar;

        internal PlanTomado(T plan, ContextoDeLlamada contexto, ContextoDeLlamada? aLiberar)
        {
            Plan = plan;
            Contexto = contexto;
            _aLiberar = aLiberar;
        }

        public T Plan { get; }

        /// <summary>La identidad con la que se ejecuta: la de quien aplica, o la del dueno si aprobo otro administrador.</summary>
        public ContextoDeLlamada Contexto { get; }

        public bool AprobadoPorOtro => _aLiberar is not null;

        public void Dispose() => _aLiberar?.Dispose();
    }
}
