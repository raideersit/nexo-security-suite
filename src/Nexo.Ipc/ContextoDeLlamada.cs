using System;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace Nexo.Ipc
{
    /// <summary>
    /// Quien esta al otro lado del pipe. El servicio corre como SYSTEM: si hiciera con SYSTEM lo que
    /// le pide un usuario, ese usuario obtendria permisos que no tiene (leer lo que no puede leer,
    /// borrar lo que no puede borrar). Con este contexto el servicio puede hacer cada operacion de
    /// archivos CON LA IDENTIDAD DEL LLAMADOR, de modo que nunca consiga mas de lo que ya tenia.
    ///
    /// Se captura una vez por conexion, tras leer el primer mensaje (Windows no permite suplantar a
    /// un cliente del pipe hasta que ha enviado datos). Solo sirve para actuar en su nombre si el
    /// cliente conecto con nivel de suplantacion <see cref="TokenImpersonationLevel.Impersonation"/>;
    /// con «Identification» el servicio solo puede SABER quien es, no usar sus permisos. En ese caso
    /// las operaciones que lo necesitan se RECHAZAN: nunca se recurre a SYSTEM como alternativa.
    /// </summary>
    public sealed class ContextoDeLlamada : IDisposable
    {
        private static readonly AsyncLocal<ContextoDeLlamada?> _actual = new AsyncLocal<ContextoDeLlamada?>();

        private readonly WindowsIdentity? _identidad;

        public ContextoDeLlamada(SecurityIdentifier? usuario, TokenImpersonationLevel nivel, WindowsIdentity? identidad,
                                 bool esAdministrador = false)
        {
            Usuario = usuario;
            Nivel = nivel;
            _identidad = identidad;
            EsAdministrador = esAdministrador;
        }

        /// <summary>El contexto de la peticion que se esta atendiendo (null fuera de una peticion).</summary>
        public static ContextoDeLlamada? Actual => _actual.Value;

        internal static void Establecer(ContextoDeLlamada? contexto) => _actual.Value = contexto;

        public SecurityIdentifier? Usuario { get; }

        /// <summary>
        /// Si el token del llamador es de administrador (un administrador con UAC y el token filtrado cuenta como
        /// NO administrador, igual que para el propio Windows). Lo usa quien decide que reglas necesitan permisos.
        /// </summary>
        public bool EsAdministrador { get; }
        public TokenImpersonationLevel Nivel { get; }

        /// <summary>True si se pueden usar los permisos del llamador (nivel Impersonation o Delegation y token valido).</summary>
        public bool PuedeActuarComoElLlamador
            => _identidad is not null && Nivel is TokenImpersonationLevel.Impersonation or TokenImpersonationLevel.Delegation;

        /// <summary>
        /// Ejecuta una operacion SINCRONA y breve con la identidad del llamador. La suplantacion va
        /// ligada al hilo y no cruza un <c>await</c>.
        /// </summary>
        /// <exception cref="InvalidOperationException">No se puede actuar como el llamador. NO se hace como SYSTEM.</exception>
        public T Ejecutar<T>(Func<T> operacion)
        {
            if (!PuedeActuarComoElLlamador || _identidad is null)
                throw new InvalidOperationException("No se puede actuar con la identidad del llamador.");
            return WindowsIdentity.RunImpersonated(_identidad.AccessToken, operacion);
        }

        /// <summary>
        /// Como <see cref="Ejecutar{T}"/> pero para una operacion ASINCRONA: la suplantacion se mantiene a traves de
        /// los <c>await</c> (RunImpersonatedAsync). Util para operaciones largas que mezclan archivos y esperas.
        /// </summary>
        public Task<T> EjecutarAsync<T>(Func<Task<T>> operacion)
        {
            if (!PuedeActuarComoElLlamador || _identidad is null)
                throw new InvalidOperationException("No se puede actuar con la identidad del llamador.");
            return WindowsIdentity.RunImpersonatedAsync(_identidad.AccessToken, operacion);
        }

        /// <summary>
        /// Ejecuta algo con la identidad del PROPIO SERVICIO aunque se este dentro de <see cref="EjecutarAsync{T}"/>.
        /// Para lo que es del servicio y no del usuario (escribir en el vault, que el usuario no puede tocar).
        /// </summary>
        public static Task<T> FueraDeSuplantacionAsync<T>(Func<Task<T>> operacion)
            => WindowsIdentity.RunImpersonatedAsync(Microsoft.Win32.SafeHandles.SafeAccessTokenHandle.InvalidHandle, operacion);

        /// <summary>
        /// Copia independiente, para un trabajo que sigue despues de que la peticion termine (un
        /// escaneo): el contexto original se libera al cerrarse la conexion.
        /// </summary>
        public ContextoDeLlamada Duplicar()
            => new ContextoDeLlamada(Usuario, Nivel,
                _identidad is null ? null : new WindowsIdentity(_identidad.AccessToken.DangerousGetHandle()), EsAdministrador);

        public void Dispose() => _identidad?.Dispose();
    }
}
