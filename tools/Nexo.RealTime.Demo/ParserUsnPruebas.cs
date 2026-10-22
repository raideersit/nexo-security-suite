using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using Nexo.Modules.Threats.TiempoReal;

namespace Nexo.RealTime.Demo
{
    internal static partial class Program
    {
        /// <summary>Arma un USN_RECORD_V2 (con parametros para romperlo a proposito).</summary>
        private static byte[] RegistroV2(string nombre, ulong frn, ulong padre, long usn, uint razon, uint atributos = 0x20,
                                         ushort mayor = 2, int? largoForzado = null, int? offNombre = null, int? lenNombre = null)
        {
            byte[] n = Encoding.Unicode.GetBytes(nombre);
            int largo = (60 + n.Length + 7) & ~7;
            byte[] r = new byte[largo];
            BinaryPrimitives.WriteUInt32LittleEndian(r, (uint)(largoForzado ?? largo));
            BinaryPrimitives.WriteUInt16LittleEndian(r.AsSpan(4), mayor);
            BinaryPrimitives.WriteUInt64LittleEndian(r.AsSpan(8), frn);
            BinaryPrimitives.WriteUInt64LittleEndian(r.AsSpan(16), padre);
            BinaryPrimitives.WriteInt64LittleEndian(r.AsSpan(24), usn);
            BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(40), razon);
            BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(52), atributos);
            BinaryPrimitives.WriteUInt16LittleEndian(r.AsSpan(56), (ushort)(lenNombre ?? n.Length));
            BinaryPrimitives.WriteUInt16LittleEndian(r.AsSpan(58), (ushort)(offNombre ?? 60));
            n.CopyTo(r, 60);
            return r;
        }

        private static byte[] BufferUsn(long siguiente, params byte[][] registros)
        {
            var ms = new MemoryStream();
            ms.Write(BitConverter.GetBytes(siguiente));
            foreach (byte[] r in registros) ms.Write(r);
            return ms.ToArray();
        }

        private static void ProbarParserUsn()
        {
            Console.WriteLine("6. Parser del diario USN (buffers sinteticos, incluidos los malformados)");

            var ok = ParserDeUsn.Analizar(BufferUsn(5000,
                RegistroV2("setup.exe", 100, 5, 4000, RegistroUsn.RazonCreado | RegistroUsn.RazonCierre),
                RegistroV2("ñandú-ü.dll", 101, 5, 4100, RegistroUsn.RazonDatosExtendidos | RegistroUsn.RazonCierre),
                RegistroV2("carpeta", 102, 5, 4200, RegistroUsn.RazonCreado, atributos: 0x10)));
            Check(!ok.Corrupto && ok.Registros.Count == 3 && ok.Siguiente == 5000, "decodifica varios registros y el siguiente USN");
            Check(ok.Registros[0].Nombre == "setup.exe" && ok.Registros[0].Frn == 100 && ok.Registros[0].FrnPadre == 5 && ok.Registros[0].Usn == 4000,
                  "con nombre, FRN, FRN del padre y USN correctos");
            Check(ok.Registros[1].Nombre == "ñandú-ü.dll", "los nombres Unicode se decodifican");

            var renombrado = ParserDeUsn.Analizar(BufferUsn(1, RegistroV2("x.exe", 1, 1, 1, RegistroUsn.RazonRenombradoNuevoNombre)));
            Check(ok.Registros[0].Motivo == MotivoDeCambio.Creado && ok.Registros[1].Motivo == MotivoDeCambio.Modificado
                  && renombrado.Registros[0].Motivo == MotivoDeCambio.Renombrado,
                  "el motivo se deduce: creado, modificado, renombrado");
            Check(ok.Registros[2].EsDirectorio && !ok.Registros[0].EsDirectorio, "reconoce los directorios");

            Check(ParserDeUsn.Analizar(Array.Empty<byte>()) is { Corrupto: false, Registros.Count: 0 }, "un buffer vacio no es un error");
            Check(ParserDeUsn.Analizar(new byte[3]).Corrupto, "un buffer de 3 bytes es corrupto");
            var soloCabecera = ParserDeUsn.Analizar(BufferUsn(9));
            Check(soloCabecera.Registros.Count == 0 && soloCabecera.Siguiente == 9 && !soloCabecera.Corrupto,
                  "solo la cabecera: sin registros y con su siguiente USN");

            // Malformados: no deben colgarse, desbordar ni lanzar.
            var largoCero = ParserDeUsn.Analizar(BufferUsn(1, RegistroV2("a.exe", 1, 1, 1, 1, largoForzado: 0)));
            Check(largoCero.Corrupto && largoCero.Registros.Count == 0, "RecordLength = 0 (bucle infinito si se fiara) se detiene como corrupto");
            Check(ParserDeUsn.Analizar(BufferUsn(1, RegistroV2("a.exe", 1, 1, 1, 1, largoForzado: 100000))).Corrupto, "RecordLength mayor que el buffer: corrupto");
            Check(ParserDeUsn.Analizar(BufferUsn(1, RegistroV2("a.exe", 1, 1, 1, 1, largoForzado: 61))).Corrupto, "RecordLength no alineado a 8: corrupto");
            Check(ParserDeUsn.Analizar(BufferUsn(1, RegistroV2("a.exe", 1, 1, 1, 1, offNombre: 4000))).Corrupto, "FileNameOffset fuera del registro: corrupto");
            Check(ParserDeUsn.Analizar(BufferUsn(1, RegistroV2("a.exe", 1, 1, 1, 1, lenNombre: 5000))).Corrupto, "FileNameLength enorme: corrupto");
            Check(ParserDeUsn.Analizar(BufferUsn(1, RegistroV2("a.exe", 1, 1, 1, 1, lenNombre: 7))).Corrupto, "FileNameLength impar (no es UTF-16): corrupto");
            Check(ParserDeUsn.Analizar(BufferUsn(1, RegistroV2("a.exe", 1, 1, 1, 1, offNombre: 10))).Corrupto, "FileNameOffset dentro de la cabecera: corrupto");

            var mezcla = ParserDeUsn.Analizar(BufferUsn(7,
                RegistroV2("bueno.exe", 1, 1, 1, 1),
                RegistroV2("v3.exe", 2, 1, 2, 1, mayor: 3),
                RegistroV2("otro.exe", 3, 1, 3, 1)));
            Check(mezcla.Registros.Count == 2 && mezcla.Ignorados == 1 && !mezcla.Corrupto,
                  "un registro de version distinta se salta y se CUENTA como ignorado; los demas se leen");

            var corte = ParserDeUsn.Analizar(BufferUsn(7,
                RegistroV2("antes.exe", 1, 1, 1, 1),
                RegistroV2("roto.exe", 2, 1, 2, 1, largoForzado: 0),
                RegistroV2("despues.exe", 3, 1, 3, 1)));
            Check(corte.Corrupto && corte.Registros.Count == 1 && corte.Registros[0].Nombre == "antes.exe",
                  "tras un registro roto se detiene: lo anterior se conserva y no se sigue a ciegas");

            // Ruido aleatorio: nunca lanza.
            var azar = new Random(12345);
            bool lanzo = false;
            for (int i = 0; i < 2000; i++)
            {
                byte[] b = new byte[azar.Next(0, 400)];
                azar.NextBytes(b);
                try { ParserDeUsn.Analizar(b); } catch (Exception) { lanzo = true; }
            }
            Check(!lanzo, "2000 buffers aleatorios: el parser nunca lanza una excepcion");

            Console.WriteLine();
        }
    }
}
