using System;
using System.Globalization;
using System.IO;
using Nexo.Reports.Model;

namespace Nexo.Reports.Vault
{
    /// <summary>
    /// Unico lugar que sabe como se organizan las carpetas del vault.
    /// Si manana se reorganiza la estructura, se cambia aqui y nada mas.
    ///
    /// Estructura:
    ///   00 Panel/                      nota de entrada, indice manual
    ///   01 Diario/2026/2026-09/2026-09-28.md
    ///   02 Eventos/Amenazas/2026/2026-09/*.md
    ///   03 Entidades/Archivos/*.md
    ///   99 Sistema/                    esquema, advertencia de seguridad
    ///
    /// El prefijo numerico existe porque Obsidian ordena el explorador de archivos
    /// alfabeticamente y no permite ordenar carpetas a mano.
    /// </summary>
    public sealed class VaultLayout
    {
        private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        public VaultLayout(string rutaVault)
        {
            if (string.IsNullOrWhiteSpace(rutaVault))
                throw new ArgumentException("La ruta del vault es obligatoria.", nameof(rutaVault));

            Raiz = Path.GetFullPath(rutaVault);
        }

        public string Raiz { get; }

        public string Panel => Path.Combine(Raiz, "00 Panel");
        public string Diario => Path.Combine(Raiz, "01 Diario");
        public string Eventos => Path.Combine(Raiz, "02 Eventos");
        public string Entidades => Path.Combine(Raiz, "03 Entidades");
        public string Sistema => Path.Combine(Raiz, "99 Sistema");

        /// <summary>Carpeta destino de un evento: 02 Eventos/{Modulo}/{yyyy}/{yyyy-MM}.</summary>
        public string CarpetaDeEvento(ModuloOrigen modulo, DateTimeOffset fecha)
            => Path.Combine(
                Eventos,
                CarpetaDeModulo(modulo),
                fecha.ToString("yyyy", Inv),
                fecha.ToString("yyyy-MM", Inv));

        /// <summary>Carpeta de la nota diaria: 01 Diario/{yyyy}/{yyyy-MM}.</summary>
        public string CarpetaDeDiario(DateTimeOffset fecha)
            => Path.Combine(Diario, fecha.ToString("yyyy", Inv), fecha.ToString("yyyy-MM", Inv));

        /// <summary>Nombre de la nota diaria. Formato ISO para que ordene solo.</summary>
        public static string NombreNotaDiaria(DateTimeOffset fecha)
            => fecha.ToString("yyyy-MM-dd", Inv);

        public string RutaNotaDiaria(DateTimeOffset fecha)
            => Path.Combine(CarpetaDeDiario(fecha), NombreNotaDiaria(fecha) + ".md");

        public string CarpetaDeEntidad(TipoEntidad tipo)
            => Path.Combine(Entidades, CarpetaDeTipoEntidad(tipo));

        public static string CarpetaDeModulo(ModuloOrigen modulo) => modulo switch
        {
            ModuloOrigen.Amenazas => "Amenazas",
            ModuloOrigen.Privacidad => "Privacidad",
            ModuloOrigen.Identidad => "Identidad",
            ModuloOrigen.Limpieza => "Limpieza",
            ModuloOrigen.Sistema => "Sistema",
            _ => "Otros"
        };

        public static string CarpetaDeTipoEntidad(TipoEntidad tipo) => tipo switch
        {
            TipoEntidad.Archivo => "Archivos",
            TipoEntidad.Proceso => "Procesos",
            TipoEntidad.Aplicacion => "Aplicaciones",
            TipoEntidad.Dispositivo => "Dispositivos",
            TipoEntidad.Dominio => "Dominios",
            TipoEntidad.Cuenta => "Cuentas",
            _ => "Otras"
        };

        /// <summary>
        /// Prefijo del nombre de nota de entidad. Evita que un archivo llamado
        /// "2026-09-28" colisione con una nota diaria, y hace obvio en el grafo
        /// de que tipo es cada nodo.
        /// </summary>
        public static string PrefijoDeEntidad(TipoEntidad tipo) => tipo switch
        {
            TipoEntidad.Archivo => "Archivo",
            TipoEntidad.Proceso => "Proceso",
            TipoEntidad.Aplicacion => "App",
            TipoEntidad.Dispositivo => "Dispositivo",
            TipoEntidad.Dominio => "Dominio",
            TipoEntidad.Cuenta => "Cuenta",
            _ => "Entidad"
        };
    }
}
