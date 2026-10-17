using System;

namespace Nexo.Modules.Cleanup.Inicio
{
    /// <summary>De donde sale una entrada de inicio. Determina el permiso necesario.</summary>
    public enum OrigenDeInicio
    {
        /// <summary>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</summary>
        RunUsuario,
        /// <summary>HKLM\...\Run — requiere administrador para escribir.</summary>
        RunMaquina,
        /// <summary>HKLM\SOFTWARE\Wow6432Node\...\Run (32 bits) — requiere administrador.</summary>
        RunMaquina32,
        /// <summary>%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup</summary>
        CarpetaUsuario,
        /// <summary>%ProgramData%\...\Startup — requiere administrador.</summary>
        CarpetaComun
    }

    public enum EstadoDeInicio
    {
        Habilitada,
        Deshabilitada,
        /// <summary>El indicador tiene un valor que no reconocemos: no se toca a ciegas.</summary>
        Desconocida
    }

    public sealed class EntradaDeInicio
    {
        public EntradaDeInicio(string nombre, string? comando, OrigenDeInicio origen, EstadoDeInicio estado)
        {
            if (string.IsNullOrWhiteSpace(nombre))
                throw new ArgumentException("El nombre no puede ser vacio.", nameof(nombre));

            Nombre = nombre;
            Comando = comando;
            Origen = origen;
            Estado = estado;
        }

        /// <summary>Nombre del valor de registro o del archivo en la carpeta de inicio.</summary>
        public string Nombre { get; }

        /// <summary>Linea de comando o ruta del acceso directo. Solo informativa.</summary>
        public string? Comando { get; }

        public OrigenDeInicio Origen { get; }
        public EstadoDeInicio Estado { get; }

        public string Id => Origen + ":" + Nombre;

        public bool RequiereAdmin =>
            Origen == OrigenDeInicio.RunMaquina
            || Origen == OrigenDeInicio.RunMaquina32
            || Origen == OrigenDeInicio.CarpetaComun;
    }

    public sealed class ResultadoCambioInicio
    {
        private ResultadoCambioInicio(bool aplicado, string? motivo)
        {
            Aplicado = aplicado;
            Motivo = motivo;
        }

        public bool Aplicado { get; }

        /// <summary>Por que no se aplico, o null si se aplico.</summary>
        public string? Motivo { get; }

        public static ResultadoCambioInicio Ok() => new ResultadoCambioInicio(true, null);
        public static ResultadoCambioInicio No(string motivo) => new ResultadoCambioInicio(false, motivo);
    }
}
