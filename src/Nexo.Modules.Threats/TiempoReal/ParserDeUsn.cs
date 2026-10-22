using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace Nexo.Modules.Threats.TiempoReal
{
    /// <summary>Un registro USN_RECORD_V2 ya decodificado (solo lo que hace falta).</summary>
    public sealed record RegistroUsn(ulong Frn, ulong FrnPadre, long Usn, uint Razon, uint Atributos, string Nombre)
    {
        public const uint RazonDatosSobrescritos = 0x00000001;
        public const uint RazonDatosExtendidos = 0x00000002;
        public const uint RazonDatosTruncados = 0x00000004;
        public const uint RazonCreado = 0x00000100;
        public const uint RazonRenombradoNuevoNombre = 0x00002000;
        public const uint RazonCierre = 0x80000000;

        public const uint AtributoDirectorio = 0x10;

        public bool EsDirectorio => (Atributos & AtributoDirectorio) != 0;

        public MotivoDeCambio Motivo =>
            (Razon & RazonCreado) != 0 ? MotivoDeCambio.Creado
            : (Razon & RazonRenombradoNuevoNombre) != 0 ? MotivoDeCambio.Renombrado
            : MotivoDeCambio.Modificado;
    }

    public sealed record ResultadoDeAnalisisUsn(long Siguiente, IReadOnlyList<RegistroUsn> Registros, int Ignorados, bool Corrupto);

    /// <summary>
    /// Decodifica el buffer que devuelve FSCTL_READ_USN_JOURNAL: 8 bytes con el siguiente USN y
    /// despues una serie de USN_RECORD_V2. Es codigo PORTABLE y defensivo a proposito: el buffer
    /// viene de una llamada al sistema y un nombre de archivo lo controla cualquiera, asi que
    /// ninguna longitud ni desplazamiento se da por buena. Un registro que no cuadra detiene la
    /// lectura (<see cref="ResultadoDeAnalisisUsn.Corrupto"/>) en vez de seguir a ciegas.
    /// </summary>
    public static class ParserDeUsn
    {
        private const int CabeceraV2 = 60;          // bytes antes del nombre
        private const int MaxNombreBytes = 1024;    // 255 caracteres UTF-16 con margen

        public static ResultadoDeAnalisisUsn Analizar(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length < 8) return new ResultadoDeAnalisisUsn(0, Array.Empty<RegistroUsn>(), 0, buffer.Length != 0);

            long siguiente = BinaryPrimitives.ReadInt64LittleEndian(buffer);
            var registros = new List<RegistroUsn>();
            int ignorados = 0;
            int pos = 8;

            while (pos < buffer.Length)
            {
                ReadOnlySpan<byte> resto = buffer[pos..];
                if (resto.Length < 4) return Cortar();

                uint largo = BinaryPrimitives.ReadUInt32LittleEndian(resto);
                // 0 haria un bucle infinito; los registros van alineados a 8; y no pueden pasarse del buffer.
                if (largo < CabeceraV2 || largo > resto.Length || (largo & 7) != 0) return Cortar();

                ReadOnlySpan<byte> r = resto[..(int)largo];
                ushort mayor = BinaryPrimitives.ReadUInt16LittleEndian(r[4..]);

                if (mayor != 2)
                {
                    ignorados++;     // V3/V4 (FRN de 128 bits): no se decodifican; se salta el registro entero y se cuenta
                    pos += (int)largo;
                    continue;
                }

                ushort largoNombre = BinaryPrimitives.ReadUInt16LittleEndian(r[56..]);
                ushort desplazamiento = BinaryPrimitives.ReadUInt16LittleEndian(r[58..]);
                if (largoNombre > MaxNombreBytes || (largoNombre & 1) != 0
                    || desplazamiento < CabeceraV2 || desplazamiento + largoNombre > largo)
                    return Cortar();

                registros.Add(new RegistroUsn(
                    Frn: BinaryPrimitives.ReadUInt64LittleEndian(r[8..]),
                    FrnPadre: BinaryPrimitives.ReadUInt64LittleEndian(r[16..]),
                    Usn: BinaryPrimitives.ReadInt64LittleEndian(r[24..]),
                    Razon: BinaryPrimitives.ReadUInt32LittleEndian(r[40..]),
                    Atributos: BinaryPrimitives.ReadUInt32LittleEndian(r[52..]),
                    Nombre: Encoding.Unicode.GetString(r.Slice(desplazamiento, largoNombre))));

                pos += (int)largo;
            }

            return new ResultadoDeAnalisisUsn(siguiente, registros, ignorados, false);

            ResultadoDeAnalisisUsn Cortar() => new ResultadoDeAnalisisUsn(siguiente, registros, ignorados, true);
        }
    }
}
