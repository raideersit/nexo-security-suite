namespace Nexo.Reports.Model
{
    /// <summary>
    /// Tipos de evento como constantes de texto, no como enum.
    /// Razon: el valor viaja al front matter y los modulos futuros deben poder
    /// anadir tipos sin recompilar Nexo.Reports. Un enum obligaria a tocar esta
    /// libreria cada vez que un modulo inventa un evento nuevo.
    /// La subcarpeta del vault se decide por ModuloOrigen, no por este valor.
    /// </summary>
    public static class TipoEvento
    {
        // --- Modulo de amenazas (Prompt 1) ---
        public const string AmenazaDetectada = "amenaza-detectada";
        public const string ArchivoEnCuarentena = "archivo-en-cuarentena";
        public const string ArchivoRestaurado = "archivo-restaurado";
        public const string BloqueoFirewall = "bloqueo-firewall";
        public const string ResultadoEscaneo = "resultado-escaneo";
        public const string VulnerabilidadDetectada = "vulnerabilidad-detectada";

        // --- Modulo de privacidad (Prompt 2) ---
        public const string ConexionVpn = "conexion-vpn";
        public const string AccesoDispositivo = "acceso-dispositivo";
        public const string SitioBloqueado = "sitio-bloqueado";

        // --- Modulo de identidad (Prompt 3) ---
        public const string AlertaIdentidad = "alerta-identidad";
        public const string BrechaDetectada = "brecha-detectada";

        // --- Modulo de limpieza (Prompt 4) ---
        public const string SesionLimpieza = "sesion-limpieza";
        public const string DuplicadosDetectados = "duplicados-detectados";
        public const string SaludDisco = "salud-disco";
        public const string ArchivoTriturado = "archivo-triturado";
        public const string InicioModificado = "inicio-modificado";

        // --- Sistema ---
        public const string ResumenDiario = "resumen-diario";
        public const string ErrorModulo = "error-modulo";
    }
}
