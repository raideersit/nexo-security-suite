using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

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
        private sealed record Entrada(T Plan, DateTimeOffset Expira);

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

        public (string Token, DateTimeOffset Expira) Guardar(T plan)
        {
            string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
            DateTimeOffset ahora = _reloj();
            DateTimeOffset expira = ahora + _vigencia;

            lock (_planes)
            {
                foreach (string k in _planes.Where(p => p.Value.Expira <= ahora).Select(p => p.Key).ToList())
                    _planes.Remove(k);
                while (_planes.Count >= _maximo)
                    _planes.Remove(_planes.OrderBy(p => p.Value.Expira).First().Key);
                _planes[token] = new Entrada(plan, expira);
            }
            return (token, expira);
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
                return e.Expira > _reloj() ? e.Plan : null;
            }
        }
    }
}
