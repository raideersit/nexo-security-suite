using System;
using Nexo.Ipc;

namespace Nexo.Service
{
    /// <summary>
    /// Quien puede APLICAR un plan (no previsualizarlo). El token prueba que quien aplica tiene el plan
    /// previsualizado, no que una persona lo aprobo: un proceso malicioso del mismo usuario puede pedir la vista
    /// previa y aplicarla. Con el modo "elevada" aplicar exige que el llamador tenga un token ELEVADO, es
    /// decir, que alguien acepto el aviso de UAC, que se muestra en el escritorio seguro y un proceso normal del
    /// usuario no puede pulsar ni simular. Eso es la aprobacion "fuera de banda".
    ///
    /// Que lo aplique la bandeja elevada o una consola de administrador da igual: lo que cuenta es el token.
    /// Limites: solo protege frente a procesos NO elevados (uno ya elevado puede todo); y con un usuario estandar,
    /// UAC pide las credenciales de OTRO usuario, cuyo SID no es el del dueno del plan, asi que el plan se rechaza.
    /// </summary>
    public sealed class PoliticaDeAprobacion
    {
        public const int AprobacionRequerida = -32040;

        public static readonly PoliticaDeAprobacion Ninguna = new PoliticaDeAprobacion(false);
        public static readonly PoliticaDeAprobacion Elevada = new PoliticaDeAprobacion(true);

        private PoliticaDeAprobacion(bool exigeElevacion) => ExigeElevacion = exigeElevacion;

        public bool ExigeElevacion { get; }

        /// <summary>
        /// "elevada" (por omision: lo seguro) o "ninguna". Un valor que no se reconoce cuenta como "elevada": una errata
        /// en la configuracion no debe quitar la proteccion.
        /// </summary>
        public static PoliticaDeAprobacion Desde(string? modo, out string? aviso)
        {
            aviso = null;
            string m = (modo ?? "elevada").Trim().ToLowerInvariant();
            if (m == "ninguna") return Ninguna;
            if (m != "elevada" && m.Length > 0) aviso = "Nexo:Aprobacion:Modo '" + modo + "' no se reconoce: se usa 'elevada'.";
            return Elevada;
        }

        /// <summary>Rechaza si hace falta elevacion y el llamador no la tiene. Se llama ANTES de gastar el token.</summary>
        public void Exigir(ContextoDeLlamada? llamador)
        {
            if (ExigeElevacion && llamador?.EsAdministrador != true)
                throw new ErrorDeComando(AprobacionRequerida,
                    "esta accion necesita tu aprobacion: confirmala con permisos elevados (aviso de UAC). " +
                    "El plan sigue vigente.");
        }
    }
}
