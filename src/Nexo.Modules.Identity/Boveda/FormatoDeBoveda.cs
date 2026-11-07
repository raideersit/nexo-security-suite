using System;
using System.Buffers.Binary;

namespace Nexo.Modules.Identity.Boveda
{
    internal enum EstadoDeFormato { Correcto, Ilegible, VersionNoSoportada, ParametrosFueraDeRango }

    internal sealed record CabeceraDeBoveda(ParametrosDeClave Parametros, byte[] Sal, byte[] Nonce, byte[] Cifrado, byte[] Etiqueta, byte[] DatosAutenticados);

    /// <summary>
    /// Formato del archivo .nxv (todo little-endian):
    /// <code>
    ///   "NXV1" | version u8 | kdf u8 (1 = Argon2id) | memoriaKiB u32 | iteraciones u32 | paralelismo u32
    ///   | sal[16] | nonce[12] | longitudCifrado u32 | cifrado[longitudCifrado] | etiqueta[16]
    /// </code>
    /// Todo lo anterior al cifrado (la cabecera completa) va como datos autenticados de AES-GCM: cambiar un solo bit de los
    /// parametros, la sal o el nonce invalida la etiqueta. La lectura es defensiva: el archivo lo controla quien sea, asi
    /// que la longitud declarada se cruza con el tamano real y los parametros se acotan ANTES de gastar memoria o tiempo.
    /// </summary>
    internal static class FormatoDeBoveda
    {
        public const byte Version = 1, Argon2idId = 1;
        public const int TamSal = 16, TamNonce = 12, TamEtiqueta = 16;
        public const int TamCabecera = 4 + 1 + 1 + 4 + 4 + 4 + TamSal + TamNonce + 4;
        public const long MaximoDeArchivo = 64L * 1024 * 1024;

        private static readonly byte[] Magia = { (byte)'N', (byte)'X', (byte)'V', (byte)'1' };

        public static byte[] Escribir(ParametrosDeClave p, byte[] sal, byte[] nonce, byte[] cifrado, byte[] etiqueta)
        {
            if (sal.Length != TamSal || nonce.Length != TamNonce || etiqueta.Length != TamEtiqueta) throw new ArgumentException("Tamano de sal, nonce o etiqueta incorrecto.");
            byte[] r = new byte[TamCabecera + cifrado.Length + TamEtiqueta];
            Cabecera(p, sal, nonce, cifrado.Length).CopyTo(r, 0);
            cifrado.CopyTo(r, TamCabecera);
            etiqueta.CopyTo(r, TamCabecera + cifrado.Length);
            return r;
        }

        /// <summary>Los bytes de la cabecera: tambien son los datos autenticados al cifrar.</summary>
        public static byte[] Cabecera(ParametrosDeClave p, byte[] sal, byte[] nonce, int longitudCifrado)
        {
            byte[] h = new byte[TamCabecera];
            Magia.CopyTo(h, 0);
            h[4] = Version;
            h[5] = Argon2idId;
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(6), (uint)p.MemoriaKiB);
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(10), (uint)p.Iteraciones);
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(14), (uint)p.Paralelismo);
            sal.CopyTo(h, 18);
            nonce.CopyTo(h, 18 + TamSal);
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(18 + TamSal + TamNonce), (uint)longitudCifrado);
            return h;
        }

        public static EstadoDeFormato Leer(byte[] archivo, out CabeceraDeBoveda? c)
        {
            c = null;
            if (archivo.Length < TamCabecera + TamEtiqueta || archivo.Length > MaximoDeArchivo) return EstadoDeFormato.Ilegible;
            if (!archivo.AsSpan(0, 4).SequenceEqual(Magia)) return EstadoDeFormato.Ilegible;
            if (archivo[4] != Version || archivo[5] != Argon2idId) return EstadoDeFormato.VersionNoSoportada;

            uint mem = BinaryPrimitives.ReadUInt32LittleEndian(archivo.AsSpan(6));
            uint iter = BinaryPrimitives.ReadUInt32LittleEndian(archivo.AsSpan(10));
            uint par = BinaryPrimitives.ReadUInt32LittleEndian(archivo.AsSpan(14));
            // Se compara como uint ANTES de convertir a int: un valor enorme no debe dar la vuelta a un numero negativo.
            if (mem > int.MaxValue || iter > int.MaxValue || par > int.MaxValue) return EstadoDeFormato.ParametrosFueraDeRango;
            var p = new ParametrosDeClave((int)mem, (int)iter, (int)par);
            if (!p.EsLegible) return EstadoDeFormato.ParametrosFueraDeRango;

            uint largo = BinaryPrimitives.ReadUInt32LittleEndian(archivo.AsSpan(18 + TamSal + TamNonce));
            // La longitud declarada debe coincidir EXACTAMENTE con lo que hay: ni sobra ni falta.
            if ((long)TamCabecera + largo + TamEtiqueta != archivo.Length) return EstadoDeFormato.Ilegible;

            c = new CabeceraDeBoveda(
                p,
                archivo.AsSpan(18, TamSal).ToArray(),
                archivo.AsSpan(18 + TamSal, TamNonce).ToArray(),
                archivo.AsSpan(TamCabecera, (int)largo).ToArray(),
                archivo.AsSpan(TamCabecera + (int)largo, TamEtiqueta).ToArray(),
                archivo.AsSpan(0, TamCabecera).ToArray());
            return EstadoDeFormato.Correcto;
        }
    }
}
