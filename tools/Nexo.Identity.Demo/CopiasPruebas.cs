using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Nexo.Modules.Identity.Boveda;

namespace Nexo.Identity.Demo
{
    internal static partial class Program
    {
        private static string Huella(string ruta) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(ruta)));

        private static async Task ProbarCopias(string dir)
        {
            Console.WriteLine("16. Copia de seguridad");
            string d = Path.Combine(dir, "copias");
            Directory.CreateDirectory(d);

            using Boveda b = await NuevaAsync(d, "origen").ConfigureAwait(false);
            await b.AgregarAsync("banco.ejemplo.cl", "ana", "S3creto!Banco", "nota").ConfigureAwait(false);
            await b.AgregarAsync("correo.ejemplo.com", "ana@ejemplo.com", "otra-clave-larga-9").ConfigureAwait(false);
            await b.AgregarAsync("tienda.example", "luis", "tercera-clave-larga-3").ConfigureAwait(false);
            string origen = Ruta(d, "origen");

            // ---- exportar
            string copia = Path.Combine(d, "respaldo", "copia1.nxv");   // la carpeta no existe: se crea
            await b.ExportarCopiaAsync(copia).ConfigureAwait(false);
            Check(File.Exists(copia), "la copia se crea (y su carpeta, si no existia)");
            ResultadoDeApertura r = await Boveda.AbrirAsync(copia, Maestra).ConfigureAwait(false);
            Check(r.Abierta && r.Boveda!.Entradas.Count == 3 && r.Boveda.Entradas.Any(e => e.Contrasena == "S3creto!Banco"), "la copia abre con la MISMA contraseña maestra y trae las 3 entradas");
            r.Boveda?.Dispose();
            Check(Huella(copia) != Huella(origen), "la copia no es un archivo identico al original (lleva un nonce nuevo)");
            byte[] bytes = File.ReadAllBytes(copia);
            Check(bytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes("banco.ejemplo.cl")) < 0 && bytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes("S3creto!Banco")) < 0, "en la copia no hay nada en claro");
            Check(Directory.GetFiles(Path.GetDirectoryName(copia)!).Length == 1, "y no quedan temporales ni .bak junto a la copia", string.Join(",", Directory.GetFiles(Path.GetDirectoryName(copia)!).Select(Path.GetFileName)));

            // lo que se borra DESPUES sigue en la copia ya hecha (es su razon de ser, y la interfaz lo advierte)
            Guid id = b.Entradas.First(e => e.Sitio == "tienda.example").Id;
            await b.EliminarAsync(id).ConfigureAwait(false);
            ResultadoDeApertura despues = await Boveda.AbrirAsync(copia, Maestra).ConfigureAwait(false);
            Check(despues.Abierta && despues.Boveda!.Entradas.Any(e => e.Sitio == "tienda.example"), "lo que se borra despues de hacer una copia SIGUE en esa copia (documentado)");
            despues.Boveda?.Dispose();
            ResultadoDeApertura viva = await Boveda.AbrirAsync(origen, Maestra).ConfigureAwait(false);
            Check(viva.Abierta && viva.Boveda!.Entradas.Count == 2, "pero en la boveda de verdad esta borrada");
            viva.Boveda?.Dispose();

            // ---- exportar: negativas
            string antes = Huella(copia);
            bool existe = false;
            try { await b.ExportarCopiaAsync(copia).ConfigureAwait(false); } catch (IOException) { existe = true; }
            Check(existe && Huella(copia) == antes, "no sobrescribe una copia que ya existe, y la deja intacta");
            await b.ExportarCopiaAsync(copia, sobrescribir: true).ConfigureAwait(false);
            ResultadoDeApertura sob = await Boveda.AbrirAsync(copia, Maestra).ConfigureAwait(false);
            Check(sob.Abierta && sob.Boveda!.Entradas.Count == 2 && Huella(copia) != antes, "con permiso expreso si la sobrescribe, con el estado actual (2 entradas)");
            sob.Boveda?.Dispose();

            string antesOrigen = Huella(origen);
            bool mismo = false;
            try { await b.ExportarCopiaAsync(origen, sobrescribir: true).ConfigureAwait(false); } catch (ArgumentException) { mismo = true; }
            Check(mismo && Huella(origen) == antesOrigen, "JAMAS acepta como destino el propio archivo de la boveda (ni con permiso de sobrescribir)");
            bool relativa = false;
            try { await b.ExportarCopiaAsync("copia-relativa.nxv").ConfigureAwait(false); } catch (ArgumentException) { relativa = true; }
            Check(relativa, "una ruta relativa se rechaza");

            using Boveda cerrada = await NuevaAsync(d, "cerrada").ConfigureAwait(false);
            cerrada.Bloquear();
            string deCerrada = Path.Combine(d, "de-cerrada.nxv");
            bool bloqueada = false;
            try { await cerrada.ExportarCopiaAsync(deCerrada).ConfigureAwait(false); } catch (InvalidOperationException) { bloqueada = true; }
            Check(bloqueada && !File.Exists(deCerrada), "con la boveda bloqueada no se puede exportar y no se crea nada");

            using Boveda vacia = await NuevaAsync(d, "vacia").ConfigureAwait(false);
            string deVacia = Path.Combine(d, "de-vacia.nxv");
            await vacia.ExportarCopiaAsync(deVacia).ConfigureAwait(false);
            ResultadoDeApertura rv = await Boveda.AbrirAsync(deVacia, Maestra).ConfigureAwait(false);
            Check(rv.Abierta && rv.Boveda!.Entradas.Count == 0, "una boveda vacia tambien se copia");
            rv.Boveda?.Dispose();

            // exportar mientras se escribe: la copia siempre es un estado coherente
            using Boveda ocupada = await NuevaAsync(d, "ocupada").ConfigureAwait(false);
            var altas = Enumerable.Range(0, 10).Select(i => ocupada.AgregarAsync("s" + i, "u", "clave-numero-" + i + "-xyz")).ToList();
            string deOcupada = Path.Combine(d, "de-ocupada.nxv");
            Task exportar = ocupada.ExportarCopiaAsync(deOcupada);
            await Task.WhenAll(altas.Concat(new[] { exportar })).ConfigureAwait(false);
            ResultadoDeApertura ro = await Boveda.AbrirAsync(deOcupada, Maestra).ConfigureAwait(false);
            Check(ro.Abierta && ro.Boveda!.Entradas.Count is >= 0 and <= 10, "exportar mientras se agregan entradas: la copia abre y es un estado coherente (" + ro.Boveda?.Entradas.Count + " de 10)");
            ro.Boveda?.Dispose();
            string deOcupada2 = Path.Combine(d, "de-ocupada-2.nxv");
            await ocupada.ExportarCopiaAsync(deOcupada2).ConfigureAwait(false);
            ResultadoDeApertura ro2 = await Boveda.AbrirAsync(deOcupada2, Maestra).ConfigureAwait(false);
            Check(ro2.Abierta && ro2.Boveda!.Entradas.Count == 10, "y una copia hecha cuando las altas terminaron tiene exactamente las 10", ro2.Boveda?.Entradas.Count.ToString());
            ro2.Boveda?.Dispose();

            // ---- restaurar
            Console.WriteLine("17. Restaurar desde una copia");
            string destino = Path.Combine(d, "restaurada", "boveda.nxv");
            ResultadoDeRestauracion ok = await Boveda.RestaurarAsync(copia, Maestra, destino).ConfigureAwait(false);
            Check(ok.Restaurada && ok.ArchivoAnterior is null && File.Exists(destino), "restaurar en un destino vacio: Restaurada, sin archivo anterior");
            ResultadoDeApertura rr = await Boveda.AbrirAsync(destino, Maestra).ConfigureAwait(false);
            Check(rr.Abierta && rr.Boveda!.Entradas.Count == 2, "la restaurada abre con la contraseña de la copia y trae sus entradas");
            rr.Boveda?.Dispose();
            Check(Directory.GetFiles(Path.GetDirectoryName(destino)!).Length == 1, "sin temporales sobrantes");

            // sobre una boveda existente: se aparta, no se borra
            using (Boveda vieja = await Boveda.CrearAsync(Path.Combine(d, "otra", "boveda.nxv"), "maestra-vieja-distinta-1", null, Rapidos, true).ConfigureAwait(false))
                await vieja.AgregarAsync("sitio-viejo", "u", "clave-vieja-larga-1").ConfigureAwait(false);
            string existente = Path.Combine(d, "otra", "boveda.nxv");
            string huellaVieja = Huella(existente);
            ResultadoDeRestauracion encima = await Boveda.RestaurarAsync(copia, Maestra, existente).ConfigureAwait(false);
            Check(encima.Restaurada && encima.ArchivoAnterior is not null && File.Exists(encima.ArchivoAnterior), "restaurar sobre una boveda existente: la APARTA con fecha y hora, no la borra", encima.ArchivoAnterior);
            Check(Huella(encima.ArchivoAnterior!) == huellaVieja && Path.GetFileName(encima.ArchivoAnterior!).StartsWith("boveda.nxv.anterior-"), "y lo apartado es identico a lo que habia");
            ResultadoDeApertura nueva = await Boveda.AbrirAsync(existente, Maestra).ConfigureAwait(false);
            ResultadoDeApertura anterior = await Boveda.AbrirAsync(encima.ArchivoAnterior!, "maestra-vieja-distinta-1").ConfigureAwait(false);
            Check(nueva.Abierta && anterior.Abierta && anterior.Boveda!.Entradas.Single().Sitio == "sitio-viejo", "la nueva abre con la contraseña de la copia y la apartada sigue abriendo con la suya");
            nueva.Boveda?.Dispose(); anterior.Boveda?.Dispose();

            // dos restauraciones seguidas: los nombres apartados no chocan
            ResultadoDeRestauracion otra = await Boveda.RestaurarAsync(copia, Maestra, existente).ConfigureAwait(false);
            Check(otra.Restaurada && otra.ArchivoAnterior != encima.ArchivoAnterior && File.Exists(otra.ArchivoAnterior!) && File.Exists(encima.ArchivoAnterior!), "dos restauraciones seguidas dejan dos archivos apartados distintos (no se pisan)");

            // ---- restaurar: negativas (el destino NO se toca)
            string huellaDest = Huella(existente);
            int archivosAntes = Directory.GetFiles(Path.GetDirectoryName(existente)!).Length;
            async Task<EstadoDeRestauracion> Intenta(string c, string pass) => (await Boveda.RestaurarAsync(c, pass, existente).ConfigureAwait(false)).Estado;

            Check(await Intenta(copia, "esta-no-es-la-maestra") == EstadoDeRestauracion.ContrasenaIncorrectaOArchivoAlterado, "con la contraseña equivocada: rechazada");
            Check(await Intenta(Path.Combine(d, "no-existe.nxv"), Maestra) == EstadoDeRestauracion.CopiaNoExiste, "una copia que no existe: CopiaNoExiste");

            string trunc = Path.Combine(d, "trunca.nxv");
            File.WriteAllBytes(trunc, File.ReadAllBytes(copia).AsSpan(0, 40).ToArray());
            Check(await Intenta(trunc, Maestra) == EstadoDeRestauracion.CopiaIlegible, "una copia truncada: CopiaIlegible");

            string alterada = Path.Combine(d, "alterada.nxv");
            byte[] a = File.ReadAllBytes(copia); a[a.Length - 30] ^= 0x01;
            File.WriteAllBytes(alterada, a);
            Check(await Intenta(alterada, Maestra) == EstadoDeRestauracion.ContrasenaIncorrectaOArchivoAlterado, "una copia con un bit cambiado: rechazada");

            string hostil = Path.Combine(d, "hostil.nxv");
            byte[] h = File.ReadAllBytes(copia); BitConverter.GetBytes(0xFFFFFFFFu).CopyTo(h, 6);
            File.WriteAllBytes(hostil, h);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            Check(await Intenta(hostil, Maestra) == EstadoDeRestauracion.ParametrosFueraDeRango && sw.ElapsedMilliseconds < 3000, "una copia que pide 4 GiB: rechazada en milisegundos", sw.ElapsedMilliseconds + " ms");

            string futura = Path.Combine(d, "futura.nxv");
            byte[] fu = File.ReadAllBytes(copia); fu[4] = 9;
            File.WriteAllBytes(futura, fu);
            Check(await Intenta(futura, Maestra) == EstadoDeRestauracion.VersionNoSoportada, "una copia de version futura: VersionNoSoportada");

            Check(await Intenta(existente, Maestra) == EstadoDeRestauracion.DestinoEsLaCopia, "la copia y el destino son el mismo archivo: DestinoEsLaCopia");
            Check(Huella(existente) == huellaDest && Directory.GetFiles(Path.GetDirectoryName(existente)!).Length == archivosAntes, "tras TODOS esos rechazos el destino esta intacto y no quedo ningun archivo sobrante");

            // destino bloqueado por otro programa: no se pierde nada
            string bloqueadoPorOtro = Path.Combine(d, "enuso", "boveda.nxv");
            Directory.CreateDirectory(Path.GetDirectoryName(bloqueadoPorOtro)!);
            File.Copy(existente, bloqueadoPorOtro);
            string huellaEnUso = Huella(bloqueadoPorOtro);
            ResultadoDeRestauracion fallo;
            using (new FileStream(bloqueadoPorOtro, FileMode.Open, FileAccess.Read, FileShare.None))
                fallo = await Boveda.RestaurarAsync(copia, Maestra, bloqueadoPorOtro).ConfigureAwait(false);
            Check(fallo.Estado == EstadoDeRestauracion.ErrorDeEscritura && fallo.Detalle!.Contains("se dejó todo como estaba"), "si otro programa tiene el destino abierto: ErrorDeEscritura y lo dice", fallo.Estado + " " + fallo.Detalle);
            Check(Huella(bloqueadoPorOtro) == huellaEnUso && Directory.GetFiles(Path.GetDirectoryName(bloqueadoPorOtro)!).Length == 1, "y el destino sigue intacto, sin temporales ni archivos apartados");

            bool relativaR = false;
            try { await Boveda.RestaurarAsync("copia.nxv", Maestra, existente).ConfigureAwait(false); } catch (ArgumentException) { relativaR = true; }
            Check(relativaR, "una ruta relativa se rechaza");
        }
    }
}
