using System;
using System.Collections.Generic;
using Nexo.Reports.Model;

namespace Nexo.Modules.Cleanup.Disco
{
    /// <summary>Un atributo S.M.A.R.T. tal como lo informa el disco: ninguna metrica se inventa.</summary>
    public sealed class AtributoSmart
    {
        public AtributoSmart(byte id, ushort flags, byte valor, byte peor, ulong crudo)
        {
            Id = id;
            Flags = flags;
            Valor = valor;
            Peor = peor;
            Crudo = crudo;
        }

        public byte Id { get; }
        public ushort Flags { get; }

        /// <summary>Valor normalizado actual (100–253 segun el fabricante; mas bajo = peor).</summary>
        public byte Valor { get; }
        public byte Peor { get; }

        /// <summary>
        /// Contador crudo de 48 bits. Para 5, 187, 197 y 198 es un conteo simple.
        /// Para 188 algunos fabricantes empaquetan tres contadores de 16 bits, asi que
        /// solo se usa para detectar crecimiento entre dos lecturas.
        /// </summary>
        public ulong Crudo { get; }
    }

    /// <summary>Lo que se pudo leer de un disco. Todo salvo el modelo es opcional a proposito.</summary>
    public sealed class LecturaDeDisco
    {
        public LecturaDeDisco(string modelo, string serieRedactada)
        {
            if (string.IsNullOrWhiteSpace(modelo)) throw new ArgumentException("Modelo vacio.", nameof(modelo));
            Modelo = modelo.Trim();
            SerieRedactada = serieRedactada;
        }

        public string Modelo { get; }
        public string SerieRedactada { get; }

        /// <summary>null = el disco no expone esa bandera (p. ej. NVMe, o sin permisos).</summary>
        public bool? PrediccionDeFallo { get; init; }

        public IReadOnlyList<AtributoSmart> Atributos { get; init; } = Array.Empty<AtributoSmart>();

        public int? TemperaturaC { get; init; }
        public int? DesgastePorcentaje { get; init; }
        public long? HorasEncendido { get; init; }

        /// <summary>
        /// Por que faltan datos, dicho al usuario en vez de escondido: puente USB que no
        /// pasa SMART, controladora RAID o Intel VMD, NVMe sin atributos ATA, etc.
        /// </summary>
        public IReadOnlyList<string> Limitaciones { get; init; } = Array.Empty<string>();

        /// <summary>
        /// True si se obtuvo al menos algo medible. Si es false, el disco NO esta
        /// "correcto": simplemente no se pudo evaluar.
        /// </summary>
        public bool TieneDatos =>
            PrediccionDeFallo is not null
            || Atributos.Count > 0
            || TemperaturaC is not null
            || DesgastePorcentaje is not null
            || HorasEncendido is not null;

        public AtributoSmart? Atributo(byte id)
        {
            foreach (AtributoSmart a in Atributos)
                if (a.Id == id) return a;
            return null;
        }
    }

    public sealed class EvaluacionDeSalud
    {
        public EvaluacionDeSalud(Severidad severidad, IReadOnlyList<string> alertas)
        {
            Severidad = severidad;
            Alertas = alertas;
        }

        public Severidad Severidad { get; }
        public IReadOnlyList<string> Alertas { get; }
    }

    /// <summary>De donde salen las lecturas. Se abstrae: la real usa WMI y exige administrador.</summary>
    public interface IFuenteSmart
    {
        IReadOnlyList<LecturaDeDisco> Leer();
    }
}
