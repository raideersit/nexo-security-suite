using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Runtime.Versioning;
using Nexo.Modules.Cleanup.Disco;

namespace Nexo.Modules.Cleanup.Windows
{
    /// <summary>
    /// Lee la salud de los discos por WMI. Solo lee; no escribe nada.
    ///
    /// Tres fuentes, tal como lista el diseno (Salida 4, §1.6):
    ///   - root\wmi MSStorageDriver_FailurePredictStatus / FailurePredictData:
    ///     la bandera y los atributos ATA. Exige administrador. No existe en NVMe.
    ///   - root\Microsoft\Windows\Storage MSFT_PhysicalDisk + contadores de
    ///     fiabilidad: temperatura, desgaste y horas. Mas fiable en NVMe.
    ///   - Win32_DiskDrive: modelo, serie y la ruta PNP que relaciona las anteriores.
    ///
    /// Cuando falta un dato se dice por que, en vez de omitirlo.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class FuenteSmartWmi : IFuenteSmart
    {
        private const string EspacioWmi = @"root\wmi";
        private const string EspacioStorage = @"root\Microsoft\Windows\Storage";

        public IReadOnlyList<LecturaDeDisco> Leer()
        {
            var limitacionesGlobales = new List<string>();

            var estados = LeerEstadoAta(limitacionesGlobales);
            var datos = LeerDatosAta(limitacionesGlobales);
            var fisicos = LeerDiscosFisicos();

            var lecturas = new List<LecturaDeDisco>();

            foreach (ManagementObject d in Consultar(@"root\cimv2", "SELECT Model, SerialNumber, PNPDeviceID, InterfaceType FROM Win32_DiskDrive"))
            {
                using (d)
                {
                    string modelo = (d["Model"] as string ?? "").Trim();
                    if (modelo.Length == 0) continue;

                    string serie = Normalizar(d["SerialNumber"] as string);
                    string pnp = d["PNPDeviceID"] as string ?? "";
                    string interfaz = d["InterfaceType"] as string ?? "";

                    FisicoWmi? fisico = BuscarFisico(fisicos, serie, modelo);

                    bool? prediccion = null;
                    IReadOnlyList<AtributoSmart> atributos = Array.Empty<AtributoSmart>();
                    var limitaciones = new List<string>();

                    string? clave = estados.Keys.FirstOrDefault(k => pnp.Length > 0 && k.StartsWith(pnp, StringComparison.OrdinalIgnoreCase));
                    if (clave is not null)
                    {
                        prediccion = estados[clave];
                        string? claveDatos = datos.Keys.FirstOrDefault(k => k.Equals(clave, StringComparison.OrdinalIgnoreCase));
                        if (claveDatos is not null && SmartParser.TryAnalizar(datos[claveDatos], out var lista))
                            atributos = lista;
                    }
                    else
                    {
                        limitaciones.AddRange(ExplicarAusencia(fisico, interfaz, limitacionesGlobales));
                    }

                    lecturas.Add(new LecturaDeDisco(modelo, Redactar(serie))
                    {
                        PrediccionDeFallo = prediccion,
                        Atributos = atributos,
                        TemperaturaC = fisico?.Temperatura,
                        DesgastePorcentaje = fisico?.Desgaste,
                        HorasEncendido = fisico?.Horas,
                        Limitaciones = limitaciones
                    });
                }
            }

            return lecturas;
        }

        // ------------------------------------------------------------------
        private sealed class FisicoWmi
        {
            public string Serie = "";
            public string Nombre = "";
            public string Bus = "";
            public int? Temperatura;
            public int? Desgaste;
            public long? Horas;
        }

        private static List<FisicoWmi> LeerDiscosFisicos()
        {
            var lista = new List<FisicoWmi>();
            foreach (ManagementObject p in Consultar(EspacioStorage, "SELECT * FROM MSFT_PhysicalDisk"))
            {
                using (p)
                {
                    var f = new FisicoWmi
                    {
                        Serie = Normalizar(p["SerialNumber"] as string),
                        Nombre = (p["FriendlyName"] as string ?? "").Trim(),
                        Bus = BusComoTexto(p["BusType"])
                    };

                    try
                    {
                        foreach (ManagementObject c in p.GetRelated("MSFT_StorageReliabilityCounter"))
                        {
                            using (c)
                            {
                                f.Temperatura = Entero(c["Temperature"]);
                                f.Desgaste = Entero(c["Wear"]);
                                f.Horas = Largo(c["PowerOnHours"]);
                            }
                            break;
                        }
                    }
                    catch (ManagementException) { }

                    lista.Add(f);
                }
            }
            return lista;
        }

        private static Dictionary<string, bool> LeerEstadoAta(List<string> limitaciones)
        {
            var d = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            foreach (ManagementObject o in Consultar(EspacioWmi, "SELECT InstanceName, PredictFailure FROM MSStorageDriver_FailurePredictStatus", limitaciones))
                using (o) d[o["InstanceName"] as string ?? ""] = o["PredictFailure"] is bool b && b;
            return d;
        }

        private static Dictionary<string, byte[]> LeerDatosAta(List<string> limitaciones)
        {
            var d = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            foreach (ManagementObject o in Consultar(EspacioWmi, "SELECT InstanceName, VendorSpecific FROM MSStorageDriver_FailurePredictData", limitaciones))
                using (o)
                    if (o["VendorSpecific"] is byte[] bytes) d[o["InstanceName"] as string ?? ""] = bytes;
            return d;
        }

        /// <summary>
        /// Ejecuta una consulta y devuelve sus objetos. Un acceso denegado o una clase
        /// que no existe no son errores: son una limitacion que se le dice al usuario.
        /// </summary>
        private static IEnumerable<ManagementObject> Consultar(string espacio, string consulta, List<string>? limitaciones = null)
        {
            var resultado = new List<ManagementObject>();
            try
            {
                using var buscador = new ManagementObjectSearcher(espacio, consulta);
                foreach (ManagementBaseObject o in buscador.Get())
                    resultado.Add((ManagementObject)o);
            }
            catch (ManagementException ex) when (ex.ErrorCode == ManagementStatus.AccessDenied)
            {
                limitaciones?.Add("Sin permisos de administrador: no se pudo leer " + espacio + ".");
            }
            catch (UnauthorizedAccessException)
            {
                limitaciones?.Add("Sin permisos de administrador: no se pudo leer " + espacio + ".");
            }
            catch (ManagementException)
            {
                // Clase inexistente (p. ej. MSFT_* en un Windows muy antiguo) o servicio detenido.
            }
            return resultado;
        }

        private static IEnumerable<string> ExplicarAusencia(FisicoWmi? fisico, string interfaz, List<string> globales)
        {
            var l = new List<string>(globales.Distinct());

            if (string.Equals(fisico?.Bus, "NVMe", StringComparison.OrdinalIgnoreCase))
                l.Add("NVMe: no expone atributos ATA; se usan los contadores de fiabilidad de Storage.");
            else if (string.Equals(interfaz, "USB", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(fisico?.Bus, "USB", StringComparison.OrdinalIgnoreCase))
                l.Add("Puente USB: normalmente no pasa los comandos S.M.A.R.T.");
            else if (globales.Count == 0)
                l.Add("El controlador no expone S.M.A.R.T. (RAID, Intel VMD u otro).");

            return l;
        }

        private static FisicoWmi? BuscarFisico(List<FisicoWmi> fisicos, string serie, string modelo)
        {
            if (serie.Length > 0)
            {
                FisicoWmi? porSerie = fisicos.FirstOrDefault(f => f.Serie == serie);
                if (porSerie is not null) return porSerie;
            }
            return fisicos.FirstOrDefault(f => string.Equals(f.Nombre, modelo, StringComparison.OrdinalIgnoreCase));
        }

        private static string Normalizar(string? serie)
            => (serie ?? "").Trim().TrimEnd('.').ToUpperInvariant();

        /// <summary>Los numeros de serie son datos identificativos: solo se conservan los 4 ultimos.</summary>
        private static string Redactar(string serie)
            => serie.Length == 0 ? "sin-serie" : "****" + serie[^Math.Min(4, serie.Length)..];

        private static string BusComoTexto(object? bus) => Entero(bus) switch
        {
            3 => "ATA", 7 => "USB", 8 => "RAID", 11 => "SATA", 17 => "NVMe", _ => "otro"
        };

        private static int? Entero(object? o) => o is null ? null : Convert.ToInt32(o, System.Globalization.CultureInfo.InvariantCulture);
        private static long? Largo(object? o) => o is null ? null : Convert.ToInt64(o, System.Globalization.CultureInfo.InvariantCulture);
    }
}
