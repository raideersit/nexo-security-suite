using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using Nexo.Reports;
using Nexo.Reports.Model;
using Nexo.Reports.Seguridad;
using Nexo.Reports.Vault;

namespace Nexo.Reports.Demo
{
    /// <summary>
    /// Genera un vault de prueba con eventos sinteticos de los cuatro modulos.
    ///
    /// Es el criterio de aceptacion del modulo de reportes: ejecutar esto, abrir
    /// la carpeta resultante como vault en Obsidian, y comprobar que el grafo,
    /// los backlinks, las etiquetas y la nota diaria funcionan SIN instalar
    /// ningun plugin.
    ///
    ///   dotnet run --project tools/Nexo.Reports.Demo -- ./vault-demo
    /// </summary>
    public static class Program
    {
        public static async Task<int> Main(string[] args)
        {
            Console.OutputEncoding = new System.Text.UTF8Encoding(false);
            string ruta = args.Length > 0
                ? args[0]
                : Path.Combine(Directory.GetCurrentDirectory(), "vault-demo");

            var opciones = new VaultOptions
            {
                RutaVault = ruta,
                Equipo = "NEXO-LAB",
                // Desarrollo: rutas completas para poder depurar. En un equipo con
                // datos reales se usa RedactionOptions.PorDefecto().
                Redaccion = RedactionOptions.PorDefecto(),
                RetencionDias = 90
            };

            using var writer = new ReportWriter(opciones);
            await writer.InicializarVaultAsync().ConfigureAwait(false);

            var reloj = Stopwatch.StartNew();
            int n = 0;

            // Tres dias de historial para que la navegacion entre notas diarias
            // tenga algo que mostrar.
            for (int dia = 2; dia >= 0; dia--)
            {
                DateTimeOffset ahora = DateTimeOffset.Now;
                DateTimeOffset baseDia = new DateTimeOffset(
                    ahora.AddDays(-dia).Date.AddHours(8), ahora.Offset);

                n += await EscribirDia(writer, baseDia, dia).ConfigureAwait(false);
            }

            reloj.Stop();

            Console.WriteLine($"Notas de evento escritas : {n}");
            Console.WriteLine($"Tiempo                   : {reloj.ElapsedMilliseconds} ms");
            Console.WriteLine($"Vault                    : {Path.GetFullPath(ruta)}");
            Console.WriteLine();

            // Demostracion del cortafuegos de secretos (riesgo L7).
            Console.WriteLine("Cortafuegos de campos secretos:");
            bool ok = true;
            ok &= await ProbarCampoProhibido(writer, "password").ConfigureAwait(false);
            ok &= await ProbarCampoProhibido(writer, "clave_maestra").ConfigureAwait(false);
            ok &= await ProbarCampoProhibido(writer, "session_id").ConfigureAwait(false);
            ok &= await ProbarCampoProhibido(writer, "cookie_sesion").ConfigureAwait(false);
            ok &= await ProbarCampoProhibido(writer, "hash_ntlm").ConfigureAwait(false);

            Console.WriteLine();
            Console.WriteLine("Casos borde de nombres y YAML:");
            ok &= await ProbarCasosBorde(writer, ruta).ConfigureAwait(false);

            Console.WriteLine();
            Console.WriteLine(ok ? "TODAS LAS VERIFICACIONES PASARON" : "HAY VERIFICACIONES FALLIDAS");
            return ok ? 0 : 1;
        }

        private static async Task<int> EscribirDia(ReportWriter w, DateTimeOffset b, int diasAtras)
        {
            int n = 0;

            // ---- Amenazas ----
            n += await E(w, Eventos.Amenazas.Escaneo(
                @"C:\Users\alvaro\Descargas", 12_483, diasAtras == 0 ? 2 : 0,
                TimeSpan.FromSeconds(97.4), "ClamAV 1.3 + YARA 4.5"), b.AddMinutes(5));

            if (diasAtras == 0)
            {
                n += await E(w, Eventos.Amenazas.Detectada(
                    "Win.Trojan.AgentTesla-9912", @"C:\Users\alvaro\Descargas\factura_pendiente.pdf.exe",
                    "ClamAV", Severidad.Critica, Accion.Cuarentena,
                    sha256: "3b1f0c9e8a7d6b5c4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d",
                    procesoOrigen: "chrome.exe"), b.AddMinutes(7));

                n += await E(w, Eventos.Amenazas.Cuarentena(
                    @"C:\Users\alvaro\Descargas\factura_pendiente.pdf.exe",
                    "q-20260928-0001", 482_304, b.AddDays(30),
                    "Win.Trojan.AgentTesla-9912"), b.AddMinutes(7).AddSeconds(3));
            }

            n += await E(w, Eventos.Amenazas.Firewall(
                @"C:\Program Files\ScreenConnect\sc.exe", "saliente",
                "185.220.101.47", 443, "TCP", "Nexo - bloqueo saliente no clasificado"),
                b.AddHours(1).AddMinutes(12));

            n += await E(w, Eventos.Amenazas.Firewall(
                @"C:\Windows\System32\svchost.exe", "entrante",
                "45.155.205.233", 3389, "TCP", "Nexo - modo sigiloso"),
                b.AddHours(2).AddMinutes(3));

            // ---- Privacidad ----
            n += await E(w, Eventos.Privacidad.Vpn(
                "cl-santiago-01", "Chile", conectado: true), b.AddHours(3));

            n += await E(w, Eventos.Privacidad.AccesoDispositivo(
                @"C:\Program Files\Zoom\bin\Zoom.exe", "camara", autorizado: true),
                b.AddHours(3).AddMinutes(20));

            if (diasAtras == 1)
            {
                n += await E(w, Eventos.Privacidad.AccesoDispositivo(
                    @"C:\Users\alvaro\AppData\Local\Temp\updater.exe", "microfono", autorizado: false),
                    b.AddHours(4));
            }

            n += await E(w, Eventos.Privacidad.Vpn(
                "cl-santiago-01", "Chile", conectado: false,
                duracion: TimeSpan.FromHours(2.5), bytesEnviados: 184_320_000, bytesRecibidos: 1_932_735_283),
                b.AddHours(5).AddMinutes(30));

            // ---- Identidad ----
            if (diasAtras == 2)
            {
                n += await E(w, Eventos.Identidad.Brecha(
                    "usuario.ejemplo@correo.cl", "Collection #1",
                    new DateTimeOffset(2019, 1, 7, 0, 0, 0, TimeSpan.Zero),
                    new[] { "correos", "contrasenas" }, 772_904_991), b.AddHours(6));
            }

            n += await E(w, Eventos.Identidad.Alerta(
                "Escritorio remoto habilitado", "rdp-habilitado",
                "Registro de eventos de Seguridad, id 4624 tipo 10", Severidad.Alta,
                "Se detecto un inicio de sesion por RDP. Si no fuiste tu, desconecta el equipo de la red."),
                b.AddHours(6).AddMinutes(45));

            // ---- Limpieza ----
            n += await E(w, Eventos.Limpieza.Sesion(
                new[] { "temporales", "cache-navegadores", "papelera", "logs-windows" },
                8_412, 4_294_967_296, confirmadoPorUsuario: true, enviadoAPapelera: false,
                TimeSpan.FromSeconds(42.8)), b.AddHours(7));

            n += await E(w, Eventos.Limpieza.Duplicados(
                137, 412, 12_884_901_888, "tamano -> primeros 8 KB -> BLAKE3 completo"),
                b.AddHours(7).AddMinutes(15));

            n += await E(w, Eventos.Limpieza.SaludDisco(
                "Samsung SSD 980 PRO 1TB", "S5GX****1234",
                prediccionDeFallo: diasAtras == 0, temperaturaC: 41,
                porcentajeDesgaste: 3, horasEncendido: 8_712), b.AddHours(7).AddMinutes(30));

            n += await E(w, Eventos.Limpieza.Triturado(
                @"C:\Users\alvaro\Documentos\respaldo-claves-viejas.txt", 4_096,
                pasadas: 1, esSsd: true), b.AddHours(8));

            return n;
        }

        /// <summary>Escribe el evento forzando su marca de tiempo.</summary>
        private static async Task<int> E(ReportWriter w, NexoEvent plantilla, DateTimeOffset cuando)
        {
            // NexoEvent.Fecha es init-only; se reconstruye con la fecha deseada.
            var ev = new NexoEvent(plantilla.Modulo, plantilla.Tipo, plantilla.Titulo)
            {
                Fecha = cuando,
                Severidad = plantilla.Severidad,
                Accion = plantilla.Accion,
                Cuerpo = plantilla.Cuerpo
            };
            foreach (var c in plantilla.Campos) ev.Campos[c.Key] = c.Value;
            foreach (var en in plantilla.Entidades) ev.Entidades.Add(en);

            await w.EscribirAsync(ev).ConfigureAwait(false);
            return 1;
        }

        private static async Task<bool> ProbarCampoProhibido(ReportWriter w, string campo)
        {
            int notasAntes = ContarNotas(w.Layout.Raiz);

            var ev = new NexoEvent(ModuloOrigen.Identidad, TipoEvento.AlertaIdentidad, "Prueba de cortafuegos")
                .Con(campo, "hunter2");
            try
            {
                await w.EscribirAsync(ev).ConfigureAwait(false);
                Console.WriteLine($"  [FALLO] '{campo}' se escribio al disco. El cortafuegos NO funciona.");
                return false;
            }
            catch (InvalidOperationException)
            {
                // No basta con que lance: la escritura debe ser atomica en su
                // conjunto. Si la nota diaria quedo con un enlace a una nota
                // inexistente, el rechazo dejo el vault inconsistente.
                int notasDespues = ContarNotas(w.Layout.Raiz);
                if (notasDespues != notasAntes)
                {
                    Console.WriteLine($"  [FALLO] '{campo}' fue rechazado pero dejo efectos en el vault.");
                    return false;
                }
                Console.WriteLine($"  [OK]    '{campo}' rechazado sin efectos en el vault.");
                return true;
            }
        }

        private static int ContarNotas(string raiz)
            => Directory.GetFiles(raiz, "*.md", SearchOption.AllDirectories).Length;

        /// <summary>
        /// Verifica los casos que rompen un vault: caracteres prohibidos en el
        /// titulo, nombres reservados de Windows, y escalares que YAML
        /// malinterpretaria si no se citan.
        /// </summary>
        private static async Task<bool> ProbarCasosBorde(ReportWriter w, string rutaVault)
        {
            bool ok = true;

            var casos = new (string Titulo, string Descripcion)[]
            {
                ("Malware [PUA] #cryptominer | ruta: C:\\x*?\\y<z>.exe", "caracteres prohibidos en NTFS y en wikilinks"),
                ("CON", "nombre reservado de MS-DOS"),
                ("aux.exe", "nombre reservado con extension"),
                ("   espacios    multiples   y punto final...", "espacios y puntos al final"),
                (new string('A', 300), "titulo mas largo que MAX_PATH")
            };

            foreach (var (titulo, descripcion) in casos)
            {
                var ev = new NexoEvent(ModuloOrigen.Sistema, TipoEvento.ErrorModulo, titulo)
                {
                    Severidad = Severidad.Baja
                };
                // Escalares que YAML 1.1 convertiria en booleano o numero si no se citan.
                ev.Con("valor_no", "no")
                  .Con("valor_on", "on")
                  .Con("hash_corto", "0123")
                  .Con("con_dos_puntos", "clave: valor")
                  .Con("con_almohadilla", "algo # comentario");

                NoteRef nota = await w.EscribirAsync(ev).ConfigureAwait(false);

                bool existe = File.Exists(nota.RutaAbsoluta);
                bool sinProhibidos = nota.NombreNota.IndexOfAny(
                    new[] { '[', ']', '#', '^', '|', '\\', '/', ':', '*', '?', '"', '<', '>' }) < 0;
                bool largoOk = Path.GetFileName(nota.RutaAbsoluta).Length <= 120;

                bool caso = existe && sinProhibidos && largoOk;
                ok &= caso;
                Console.WriteLine($"  [{(caso ? "OK" : "FALLO")}]    {descripcion}");
                if (!caso)
                {
                    Console.WriteLine($"          existe={existe} sinProhibidos={sinProhibidos} largoOk={largoOk}");
                    Console.WriteLine($"          -> {Path.GetFileName(nota.RutaAbsoluta)}");
                }
            }

            // El front matter de la ultima nota debe tener los escalares citados.
            string contenido = File.ReadAllText(
                Directory.GetFiles(Path.Combine(rutaVault, "02 Eventos", "Sistema"), "*.md",
                    SearchOption.AllDirectories)[0]);

            var esperados = new[] { "valor_no: \"no\"", "valor_on: \"on\"", "hash_corto: \"0123\"" };
            foreach (string esperado in esperados)
            {
                bool presente = contenido.Contains(esperado);
                ok &= presente;
                Console.WriteLine($"  [{(presente ? "OK" : "FALLO")}]    YAML cita correctamente  {esperado}");
            }

            return ok;
        }
    }
}
