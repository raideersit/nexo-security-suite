using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats;
using Nexo.Modules.Threats.Cuarentena;
using Nexo.Modules.Threats.Escaner;

namespace Nexo.Scan.Demo
{
    public static partial class Program
    {
        /// <summary>Ejecuta las operaciones tal cual, pero las cuenta: prueba que TODO pasa por el acceso del llamador.</summary>
        private sealed class AccesoContador : IAccesoAArchivos
        {
            private int _n;
            public int Llamadas => Volatile.Read(ref _n);

            public T Ejecutar<T>(Func<T> operacion)
            {
                Interlocked.Increment(ref _n);
                return operacion();
            }
        }

        /// <summary>Simula «no se puede actuar como el llamador» (p. ej. cliente con nivel Identification).</summary>
        private sealed class AccesoQueFalla : IAccesoAArchivos
        {
            public int Llamadas;
            public T Ejecutar<T>(Func<T> operacion)
            {
                Interlocked.Increment(ref Llamadas);
                throw new InvalidOperationException("no se puede actuar con la identidad del llamador");
            }
        }

        /// <summary>Simula que Windows deniega el acceso al llamador en cada operacion.</summary>
        private sealed class AccesoQueNiega : IAccesoAArchivos
        {
            public int Llamadas;
            public T Ejecutar<T>(Func<T> operacion)
            {
                Interlocked.Increment(ref Llamadas);
                throw new UnauthorizedAccessException("denegado al llamador");
            }
        }

        private static async Task ProbarIdentidadAsync(string raiz)
        {
            Console.WriteLine("N. El servicio actua con la identidad del llamador, no como SYSTEM");

            string docs = Path.Combine(raiz, "docs");
            Directory.CreateDirectory(Path.Combine(docs, "sub"));
            File.WriteAllBytes(Path.Combine(docs, "a.txt"), Relleno(100));
            File.WriteAllBytes(Path.Combine(docs, "sub", "b.txt"), Relleno(100));
            string malo = Path.Combine(docs, "sub", "malo.exe");
            File.WriteAllBytes(malo, Bytes(Relleno(10), Marcador).ToArray());

            using var servidor = new ClamdFalso();
            var cliente = new ClamdClient("127.0.0.1", servidor.Puerto, timeout: TimeSpan.FromSeconds(5));

            // --- Escaneo: cada operacion de archivos pasa por el acceso del llamador ---
            var contador = new AccesoContador();
            ResultadoDeEscaneo r = await new EscanerBajoDemanda(cliente, new ReportesEnMemoria(), new OpcionesDeEscaneo { Acceso = contador })
                .EscanearAsync(new[] { docs }).ConfigureAwait(false);
            Check(r.Analizados == 3 && r.Detecciones.Count == 1, "con un acceso que solo cuenta, el escaneo da el mismo resultado");
            Check(contador.Llamadas >= 3 * 2 + 4, "y cada consulta, enumeracion y apertura paso por el acceso del llamador",
                  "llamadas: " + contador.Llamadas);

            // --- Fallo cerrado: si no se puede actuar como el llamador, NO se escanea (ni como el servicio) ---
            var falla = new AccesoQueFalla();
            int conexionesAntes = servidor.Conexiones;
            bool lanzo = false;
            try
            {
                await new EscanerBajoDemanda(cliente, new ReportesEnMemoria(), new OpcionesDeEscaneo { Acceso = falla })
                    .EscanearAsync(new[] { docs }).ConfigureAwait(false);
            }
            catch (InvalidOperationException) { lanzo = true; }
            Check(lanzo && falla.Llamadas >= 1, "si no se puede actuar como el llamador, el escaneo se aborta: no se recurre al servicio");
            Check(servidor.Conexiones - conexionesAntes <= 1, "y no se envia ningun contenido al motor (solo la consulta de version)",
                  "conexiones nuevas: " + (servidor.Conexiones - conexionesAntes));

            // --- Si Windows le deniega el acceso al llamador, queda NO ANALIZADO, no 'limpio' ---
            var niega = new AccesoQueNiega();
            ResultadoDeEscaneo rn = await new EscanerBajoDemanda(cliente, new ReportesEnMemoria(), new OpcionesDeEscaneo { Acceso = niega })
                .EscanearAsync(new[] { Path.Combine(docs, "a.txt") }).ConfigureAwait(false);
            Check(rn.Analizados == 0 && rn.Omitidos.Count == 1 && !rn.CompletamenteLimpio,
                  "un archivo que el llamador no puede abrir queda como no analizado, nunca como limpio",
                  $"analizados {rn.Analizados}, omitidos {rn.Omitidos.Count}");

            // --- Cuarentena: el original se lee y se retira como el llamador ---
            string q = Path.Combine(raiz, "q");
            var reportes = new ReportesEnMemoria();
            var almacen = new AlmacenDeCuarentena(q, reportes, new[] { Path.Combine(raiz, "sistema") });
            var det = r.Detecciones[0];

            VistaPreviaCuarentena v = almacen.Preparar(new[] { det });
            var deniega = new AccesoQueNiega();
            ResultadoCuarentena rq = await almacen.AplicarAsync(v, v.Token, acceso: deniega).ConfigureAwait(false);
            Check(rq.Movidos.Count == 0 && rq.Omitidos.Count == 1 && File.Exists(malo) && deniega.Llamadas >= 1,
                  "si el llamador no puede leer el original, NO se pone en cuarentena y el archivo sigue ahi",
                  string.Join("; ", rq.Omitidos));
            Check(!Directory.Exists(q) || Directory.GetFiles(q).Length == 0, "y no queda ninguna copia a medias en la cuarentena");

            var cuenta2 = new AccesoContador();
            v = almacen.Preparar(new[] { det });
            ResultadoCuarentena ok = await almacen.AplicarAsync(v, v.Token, acceso: cuenta2).ConfigureAwait(false);
            Check(ok.Movidos.Count == 1 && !File.Exists(malo) && cuenta2.Llamadas >= 2,
                  "con acceso, lee y retira el original pasando por el acceso del llamador", "llamadas: " + cuenta2.Llamadas);

            // --- Restaurar: se escribe en la ruta original como el llamador ---
            string id = ok.Movidos[0].Id;
            var niegaR = new AccesoQueNiega();
            ResultadoRestauracion rr = await almacen.RestaurarAsync(id, acceso: niegaR).ConfigureAwait(false);
            // Exists lanza UnauthorizedAccess dentro del acceso: no se escribe nada.
            Check(!rr.Exito && !File.Exists(malo) && almacen.Listar().Count == 1,
                  "si el llamador no puede escribir en la ruta original, no se restaura y la entrada se conserva", rr.Motivo);

            var cuentaR = new AccesoContador();
            ResultadoRestauracion rr2 = await almacen.RestaurarAsync(id, acceso: cuentaR).ConfigureAwait(false);
            Check(rr2.Exito && File.Exists(malo) && cuentaR.Llamadas >= 2, "con acceso, restaura pasando por el acceso del llamador");

            Console.WriteLine();
        }
    }
}
