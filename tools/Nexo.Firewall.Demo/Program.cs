using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Modules.Threats.Firewall;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Firewall.Demo
{
    /// <summary>
    /// Comprobaciones portables del firewall por aplicacion y del modo sigiloso.
    /// Todo contra un almacen en memoria: no toca el Firewall de Windows. Lo que
    /// si lo toca esta en Nexo.Firewall.Windows.Demo.
    /// </summary>
    public static class Program
    {
        private static int _fallos;

        private const string App = @"C:\Apps\navegador\navegador.exe";
        private const string OtraApp = @"C:\Otro\navegador.exe";

        public static async Task<int> Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);

            await ProbarGuardia().ConfigureAwait(false);
            await ProbarPlanes().ConfigureAwait(false);
            await ProbarAplicacion().ConfigureAwait(false);
            await ProbarAjenas().ConfigureAwait(false);
            await ProbarSigiloso().ConfigureAwait(false);

            Console.WriteLine();
            Console.WriteLine(_fallos == 0
                ? "TODAS LAS VERIFICACIONES PASARON"
                : _fallos + " VERIFICACIONES FALLIDAS");
            return _fallos == 0 ? 0 : 1;
        }

        private static void Check(bool condicion, string descripcion, string? detalle = null)
        {
            if (!condicion) _fallos++;
            Console.WriteLine($"  [{(condicion ? "OK" : "FALLO")}]    {descripcion}");
            if (!condicion && detalle is not null) Console.WriteLine("           " + detalle);
        }

        private static AdministradorDeFirewall Crear(
            out AlmacenEnMemoria almacen, out ReportesEnMemoria reportes,
            bool admin = true, IEnumerable<string>? existentes = null, Func<DateTimeOffset>? reloj = null)
        {
            almacen = new AlmacenEnMemoria();
            reportes = new ReportesEnMemoria();
            var presentes = new HashSet<string>(existentes ?? new[] { App, OtraApp }, StringComparer.OrdinalIgnoreCase);
            var guardia = new GuardiaDeReglas(existe: presentes.Contains);
            return new AdministradorDeFirewall(almacen, reportes, admin, guardia, reloj);
        }

        // ============================================================
        private static Task ProbarGuardia()
        {
            Console.WriteLine("1. Guardia de reglas: que rutas y que procesos se aceptan");

            var presentes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                App, @"C:\Windows\System32\svchost.exe", @"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
                @"C:\Nexo\nexo-service.exe", @"\\servidor\recurso\app.exe"
            };
            var g = new GuardiaDeReglas(existe: presentes.Contains);

            Check(g.Validar(App, AccionDeRegla.Bloquear).Aceptada, "acepta bloquear una aplicacion normal");
            Check(!g.Validar(@"navegador.exe", AccionDeRegla.Bloquear).Aceptada, "rechaza una ruta relativa");
            Check(!g.Validar(@"C:\Apps\..\Windows\evil.exe", AccionDeRegla.Bloquear).Aceptada, "rechaza segmentos '..'");
            Check(!g.Validar(@"C:\Apps\*.exe", AccionDeRegla.Bloquear).Aceptada, "rechaza comodines");
            Check(!g.Validar(@"C:\Apps\datos.txt", AccionDeRegla.Bloquear).Aceptada, "rechaza lo que no es .exe");
            Check(!g.Validar(@"C:\Apps\no-existe.exe", AccionDeRegla.Bloquear).Aceptada, "rechaza un archivo que no existe");
            Check(!g.Validar("", AccionDeRegla.Bloquear).Aceptada && !g.Validar(null, AccionDeRegla.Bloquear).Aceptada,
                  "rechaza ruta vacia o nula");
            Check(g.Validar(@"\\servidor\recurso\app.exe", AccionDeRegla.Bloquear).Aceptada, "acepta una ruta UNC");

            Check(!g.Validar(@"C:\Windows\System32\svchost.exe", AccionDeRegla.Bloquear).Aceptada,
                  "NO bloquea svchost.exe (de el depende medio Windows)");
            Check(!g.Validar(@"C:\Windows\System32\SVCHOST.EXE", AccionDeRegla.Bloquear).Aceptada,
                  "la proteccion no distingue mayusculas");
            Check(!g.Validar(@"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe", AccionDeRegla.Bloquear).Aceptada,
                  "NO bloquea Windows Defender (Nexo lo complementa, no lo desactiva)");
            Check(!g.Validar(@"C:\Nexo\nexo-service.exe", AccionDeRegla.Bloquear).Aceptada, "NO bloquea los ejecutables de Nexo");
            Check(g.Validar(@"C:\Windows\System32\svchost.exe", AccionDeRegla.Permitir).Aceptada,
                  "permitir un proceso protegido si se acepta (no rompe nada)");

            Console.WriteLine();
            return Task.CompletedTask;
        }

        // ============================================================
        private static Task ProbarPlanes()
        {
            Console.WriteLine("2. Vista previa: planear no cambia nada");

            var adm = Crear(out var almacen, out var reportes);
            VistaPreviaFirewall v = adm.PrepararRegla(App, AccionDeRegla.Bloquear);

            Check(v.Cambios.Count == 2, "bloquear sin direccion planea 2 reglas (saliente y entrante)",
                  "cambios: " + v.Cambios.Count);
            Check(almacen.Reglas.Count == 0, "preparar no escribio nada en el firewall");
            Check(reportes.Eventos.Count == 0, "preparar no emitio eventos");
            Check(v.Cambios.All(c => c.Regla.EsDeNexo), "todas las reglas planeadas son del grupo de Nexo");
            Check(v.Cambios.All(c => c.Regla.Perfiles == PerfilesDeRed.Todos), "las reglas cubren los tres perfiles");

            VistaPreviaFirewall solo = adm.PrepararRegla(App, AccionDeRegla.Bloquear, DireccionDeRegla.Saliente);
            Check(solo.Cambios.Count == 1 && solo.Cambios[0].Regla.Direccion == DireccionDeRegla.Saliente,
                  "con direccion saliente planea solo esa regla");

            VistaPreviaFirewall a = adm.PrepararRegla(App, AccionDeRegla.Bloquear, DireccionDeRegla.Saliente);
            VistaPreviaFirewall b = adm.PrepararRegla(OtraApp, AccionDeRegla.Bloquear, DireccionDeRegla.Saliente);
            Check(a.Cambios[0].Regla.Nombre != b.Cambios[0].Regla.Nombre,
                  "dos 'navegador.exe' de carpetas distintas no colisionan en el nombre");
            Check(a.Cambios[0].Regla.Nombre ==
                  adm.PrepararRegla(App, AccionDeRegla.Bloquear, DireccionDeRegla.Saliente).Cambios[0].Regla.Nombre,
                  "el nombre es determinista");

            VistaPreviaFirewall rech = adm.PrepararRegla(@"C:\Windows\System32\svchost.exe", AccionDeRegla.Bloquear);
            Check(!rech.HayCambios && rech.Rechazos.Count == 1, "un rechazo queda anotado, no se descarta en silencio",
                  string.Join("; ", rech.Rechazos));

            Console.WriteLine();
            return Task.CompletedTask;
        }

        // ============================================================
        private static async Task ProbarAplicacion()
        {
            Console.WriteLine("3. Aplicar: token, administrador y reverificacion");

            var adm = Crear(out var almacen, out var reportes);
            VistaPreviaFirewall v = adm.PrepararRegla(App, AccionDeRegla.Bloquear);

            // --- El token no es decorativo ---
            VistaPreviaFirewall otra = adm.PrepararRegla(OtraApp, AccionDeRegla.Bloquear);
            bool rechazado = false;
            try { await adm.AplicarAsync(v, otra.Token).ConfigureAwait(false); }
            catch (InvalidOperationException) { rechazado = true; }
            Check(rechazado, "rechaza aplicar con el token de OTRO plan");
            Check(almacen.Reglas.Count == 0, "el rechazo no dejo reglas a medias");

            DateTimeOffset ahora = DateTimeOffset.Now;
            var caducado = TokenDeCambio.Emitir(v.Cambios, ahora - TokenDeCambio.Vigencia - TimeSpan.FromMinutes(1));
            rechazado = false;
            try { await adm.AplicarAsync(v, caducado).ConfigureAwait(false); }
            catch (InvalidOperationException) { rechazado = true; }
            Check(rechazado, "rechaza aplicar con un token caducado");

            // --- Sin administrador no se finge ---
            var sinAdmin = Crear(out var almacenSA, out var reportesSA, admin: false);
            VistaPreviaFirewall vSA = sinAdmin.PrepararRegla(App, AccionDeRegla.Bloquear);
            ResultadoFirewall rSA = await sinAdmin.AplicarAsync(vSA, vSA.Token).ConfigureAwait(false);
            Check(rSA.Aplicados == 0 && rSA.Omitidos.Count == 2 && almacenSA.Reglas.Count == 0,
                  "sin administrador no aplica nada y lo dice (2 omitidos)", "aplicados: " + rSA.Aplicados);
            Check(reportesSA.Eventos.Count == 0, "y no emite eventos de cambios que no ocurrieron");

            // --- Camino feliz ---
            ResultadoFirewall r = await adm.AplicarAsync(v, v.Token).ConfigureAwait(false);
            Check(r.Aplicados == 2 && r.Omitidos.Count == 0, "aplica las 2 reglas", "aplicados: " + r.Aplicados);
            Check(almacen.Reglas.Count == 2, "las reglas existen en el almacen");
            Check(reportesSA.Eventos.Count == 0 && reportes.Eventos.Count == 2
                  && reportes.Eventos.All(e => e.Tipo == TipoEvento.ReglaFirewall),
                  "emite un evento por regla creada", "eventos: " + reportes.Eventos.Count);

            // --- Idempotencia ---
            VistaPreviaFirewall dup = adm.PrepararRegla(App, AccionDeRegla.Bloquear);
            Check(!dup.HayCambios && dup.Rechazos.Count == 2 && dup.Rechazos.All(x => x.Contains("ya existe")),
                  "pedir lo mismo otra vez no duplica: queda como 'ya existe'");

            // --- TOCTOU: la regla aparece entre la vista previa y la aplicacion ---
            var adm2 = Crear(out var almacen2, out _);
            VistaPreviaFirewall v2 = adm2.PrepararRegla(App, AccionDeRegla.Bloquear, DireccionDeRegla.Saliente);
            almacen2.Reglas.Add(v2.Cambios[0].Regla);   // alguien la creo entretanto
            ResultadoFirewall r2 = await adm2.AplicarAsync(v2, v2.Token).ConfigureAwait(false);
            Check(r2.Aplicados == 0 && r2.Omitidos.Count == 1 && almacen2.Reglas.Count == 1,
                  "si la regla aparecio despues de la vista previa, no la duplica");

            // --- Windows niega el acceso a mitad ---
            var adm3 = Crear(out var almacen3, out var reportes3);
            VistaPreviaFirewall v3 = adm3.PrepararRegla(App, AccionDeRegla.Bloquear);
            almacen3.FallarAgregar = true;
            ResultadoFirewall r3 = await adm3.AplicarAsync(v3, v3.Token).ConfigureAwait(false);
            Check(r3.Aplicados == 0 && r3.Omitidos.Count == 2 && reportes3.Eventos.Count == 0,
                  "si Windows deniega el acceso, lo informa y no emite eventos de lo que no ocurrio");

            // --- El ejecutable desaparece o pasa a estar protegido antes de aplicar ---
            var presentes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { App };
            var adm4 = new AdministradorDeFirewall(new AlmacenEnMemoria(), new ReportesEnMemoria(), true,
                                                   new GuardiaDeReglas(existe: presentes.Contains));
            VistaPreviaFirewall v4 = adm4.PrepararRegla(App, AccionDeRegla.Bloquear, DireccionDeRegla.Saliente);
            presentes.Clear();
            ResultadoFirewall r4 = await adm4.AplicarAsync(v4, v4.Token).ConfigureAwait(false);
            Check(r4.Aplicados == 0 && r4.Omitidos.Count == 1, "reverifica el ejecutable al aplicar (ya no existe)");

            // --- Quitar ---
            VistaPreviaFirewall q = adm.PrepararQuitar(v.Cambios[0].Regla.Nombre);
            ResultadoFirewall rq = await adm.AplicarAsync(q, q.Token).ConfigureAwait(false);
            Check(rq.Aplicados == 1 && almacen.Reglas.Count == 1, "quita una regla de Nexo");
            Check(reportes.Eventos.Last().Titulo.Contains("eliminada"), "y lo registra como 'eliminada'");

            Console.WriteLine();
        }

        // ============================================================
        private static async Task ProbarAjenas()
        {
            Console.WriteLine("4. Reglas ajenas: Nexo solo toca lo suyo");

            var adm = Crear(out var almacen, out _);
            var deWindows = new ReglaDeFirewall("Compartir archivos e impresoras (eco ICMPv4 de entrada)", null,
                DireccionDeRegla.Entrante, AccionDeRegla.Permitir, PerfilesDeRed.Privado, true, "Compartir archivos e impresoras");
            // Una regla ajena con un nombre que imita el prefijo de Nexo pero sin su grupo.
            var impostora = new ReglaDeFirewall("Nexo: Bloquear saliente falso.exe [000000]", @"C:\Apps\falso.exe",
                DireccionDeRegla.Saliente, AccionDeRegla.Bloquear, PerfilesDeRed.Todos, true, "Otro programa");
            almacen.Reglas.Add(deWindows);
            almacen.Reglas.Add(impostora);

            Check(!deWindows.EsDeNexo, "una regla de Windows no cuenta como de Nexo");
            Check(!impostora.EsDeNexo, "el prefijo 'Nexo:' solo, sin el grupo, no basta para ser de Nexo");
            Check(adm.ListarDeNexo().Count == 0, "ListarDeNexo no incluye reglas ajenas");

            VistaPreviaFirewall q = adm.PrepararQuitar(deWindows.Nombre);
            Check(!q.HayCambios && q.Rechazos.Count == 1, "se niega a quitar una regla de Windows");
            q = adm.PrepararQuitar(impostora.Nombre);
            Check(!q.HayCambios && q.Rechazos.Count == 1, "se niega a quitar una impostora con prefijo de Nexo");
            q = adm.PrepararQuitar("Nexo: no existe");
            Check(!q.HayCambios && q.Rechazos.Count == 1, "quitar algo inexistente se informa");

            // La regla de Nexo pasa a ser ajena entre la vista previa y la aplicacion.
            var propia = new ReglaDeFirewall("Nexo: Bloquear saliente x.exe [111111]", @"C:\Apps\x.exe",
                DireccionDeRegla.Saliente, AccionDeRegla.Bloquear, PerfilesDeRed.Todos, true, ReglaDeFirewall.GrupoNexo);
            almacen.Reglas.Add(propia);
            VistaPreviaFirewall qp = adm.PrepararQuitar(propia.Nombre);
            almacen.Reglas.Remove(propia);
            almacen.Reglas.Add(propia with { Grupo = "Otro programa" });
            ResultadoFirewall r = await adm.AplicarAsync(qp, qp.Token).ConfigureAwait(false);
            Check(r.Aplicados == 0 && almacen.Reglas.Any(x => x.Nombre == propia.Nombre),
                  "si la regla dejo de ser de Nexo antes de aplicar, no se borra (TOCTOU)");

            Console.WriteLine();
        }

        // ============================================================
        private static async Task ProbarSigiloso()
        {
            Console.WriteLine("5. Modo sigiloso: bloquear el ping entrante, sin driver");

            var adm = Crear(out var almacen, out var reportes);
            almacen.Politicas.Add(new PoliticaDePerfil(PerfilesDeRed.Publico, true, AccionDeRegla.Bloquear, AccionDeRegla.Permitir));

            Check(!adm.SigilosoActivo(), "empieza desactivado");

            VistaPreviaFirewall on = adm.PrepararSigiloso(true);
            Check(on.Cambios.Count == 2, "activarlo planea 2 reglas (ICMPv4 e ICMPv6)");
            Check(on.Cambios.All(c => c.Regla.Direccion == DireccionDeRegla.Entrante
                                      && c.Regla.Accion == AccionDeRegla.Bloquear
                                      && c.Regla.RutaApp is null),
                  "son reglas de BLOQUEO ENTRANTE, no de rechazo, y sin aplicacion");
            Check(on.Cambios.Any(c => c.Regla.Protocolo == 1 && c.Regla.TiposIcmp == "8:*")
                  && on.Cambios.Any(c => c.Regla.Protocolo == 58 && c.Regla.TiposIcmp == "128:*"),
                  "bloquean Echo Request: ICMPv4 tipo 8 e ICMPv6 tipo 128");
            Check(almacen.Reglas.Count == 0, "planear no cambia nada");

            ResultadoFirewall r = await adm.AplicarAsync(on, on.Token).ConfigureAwait(false);
            Check(r.Aplicados == 2 && adm.SigilosoActivo(), "activado: las 2 reglas existen");
            Check(reportes.Eventos.Count == 1 && reportes.Eventos[0].Tipo == TipoEvento.ModoSigiloso,
                  "emite UN evento de modo sigiloso (no uno por regla)", "eventos: " + reportes.Eventos.Count);

            VistaPreviaFirewall otra = adm.PrepararSigiloso(true);
            Check(!otra.HayCambios && otra.Advertencias.Any(a => a.Contains("ya estaba activo")),
                  "activarlo otra vez no duplica y avisa");

            // Reglas ajenas intactas al desactivar.
            var ajena = new ReglaDeFirewall("Mi regla", null, DireccionDeRegla.Entrante, AccionDeRegla.Permitir,
                PerfilesDeRed.Todos, true, "Otro");
            almacen.Reglas.Add(ajena);

            VistaPreviaFirewall off = adm.PrepararSigiloso(false);
            ResultadoFirewall roff = await adm.AplicarAsync(off, off.Token).ConfigureAwait(false);
            Check(roff.Aplicados == 2 && !adm.SigilosoActivo(), "desactivado: las 2 reglas se retiran");
            Check(almacen.Reglas.Contains(ajena) && almacen.Reglas.Count == 1, "y no se toca ninguna regla ajena");

            // Firewall apagado: se informa, no se enciende.
            var apagado = Crear(out var almacenA, out _);
            almacenA.Politicas.Add(new PoliticaDePerfil(PerfilesDeRed.Publico, false, AccionDeRegla.Bloquear, AccionDeRegla.Permitir));
            almacenA.Politicas.Add(new PoliticaDePerfil(PerfilesDeRed.Privado, true, AccionDeRegla.Permitir, AccionDeRegla.Permitir));
            VistaPreviaFirewall va = apagado.PrepararSigiloso(true);
            Check(va.Advertencias.Any(a => a.Contains("DESACTIVADO") && a.Contains("Publico")),
                  "avisa si el firewall esta apagado en un perfil (no lo enciende por su cuenta)");
            Check(va.Advertencias.Any(a => a.Contains("PERMITE el trafico entrante") && a.Contains("Privado")),
                  "avisa si un perfil permite la entrada por defecto (y no cambia esa politica)");

            // Una regla ajena con el nombre exacto de la de sigilo.
            var conflicto = Crear(out var almacenC, out _);
            almacenC.Reglas.Add(new ReglaDeFirewall(AdministradorDeFirewall.NombrePingV4, null, DireccionDeRegla.Entrante,
                AccionDeRegla.Permitir, PerfilesDeRed.Todos, true, "Otro"));
            VistaPreviaFirewall vc = conflicto.PrepararSigiloso(true);
            Check(vc.Rechazos.Count == 1 && vc.Cambios.Count == 1,
                  "si una regla ajena ya usa ese nombre, no la pisa: la informa y sigue con la otra");

            // Regla ajena sobre la misma aplicacion: se avisa, no se toca ni se impide crear la de Nexo.
            var equiv = Crear(out var almacenE, out _);
            var ajenaBloq = new ReglaDeFirewall("Bloqueo de otro programa", App, DireccionDeRegla.Saliente,
                AccionDeRegla.Bloquear, PerfilesDeRed.Todos, true, "Otro programa");
            almacenE.Reglas.Add(ajenaBloq);
            VistaPreviaFirewall ve = equiv.PrepararRegla(App, AccionDeRegla.Bloquear, DireccionDeRegla.Saliente);
            Check(ve.Cambios.Count == 1 && ve.Advertencias.Any(w => w.Contains("equivalente") && w.Contains("Bloqueo de otro programa")),
                  "bloquear avisa de una regla ajena equivalente, pero sigue siendo posible");
            VistaPreviaFirewall vp = equiv.PrepararRegla(App, AccionDeRegla.Permitir, DireccionDeRegla.Saliente);
            Check(vp.Advertencias.Any(w => w.Contains("BLOQUEA") && w.Contains("prioridad")),
                  "permitir avisa de que una regla ajena que bloquea tiene prioridad");
            VistaPreviaFirewall vd = equiv.PrepararRegla(App, AccionDeRegla.Bloquear, DireccionDeRegla.Entrante);
            Check(!vd.Advertencias.Any(w => w.Contains("Bloqueo de otro programa")),
                  "no avisa de reglas ajenas de otra direccion");
            almacenE.Reglas[0] = ajenaBloq with { Habilitada = false };
            Check(!equiv.PrepararRegla(App, AccionDeRegla.Bloquear, DireccionDeRegla.Saliente).Advertencias.Any(w => w.Contains("Bloqueo de otro programa")),
                  "no avisa de reglas ajenas deshabilitadas");
            Check(almacenE.Reglas.Count == 1, "avisar no modifica el almacen");

            Console.WriteLine();
        }
    }

    // ================================================================
    //  DOBLES DE PRUEBA
    // ================================================================
    internal sealed class AlmacenEnMemoria : IAlmacenDeFirewall
    {
        public List<ReglaDeFirewall> Reglas { get; } = new();
        public List<PoliticaDePerfil> Politicas { get; } = new();
        public bool FallarAgregar { get; set; }

        public IReadOnlyList<ReglaDeFirewall> Enumerar() => Reglas.ToList();

        public void Agregar(ReglaDeFirewall regla)
        {
            if (FallarAgregar) throw new UnauthorizedAccessException("denegado");
            Reglas.Add(regla);
        }

        public void Eliminar(string nombre) => Reglas.RemoveAll(r => r.Nombre == nombre);

        public void Habilitar(string nombre, bool habilitada)
        {
            int i = Reglas.FindIndex(r => r.Nombre == nombre);
            if (i >= 0) Reglas[i] = Reglas[i] with { Habilitada = habilitada };
        }

        public IReadOnlyList<PoliticaDePerfil> LeerPoliticas() => Politicas.ToList();
    }

    internal sealed class ReportesEnMemoria : IReportWriter
    {
        public List<NexoEvent> Eventos { get; } = new();

        public Task<NoteRef> EscribirAsync(NexoEvent evento, CancellationToken ct = default)
        {
            Eventos.Add(evento);
            return Task.FromResult<NoteRef>(null!);
        }

        public Task InicializarVaultAsync(CancellationToken ct = default) => Task.CompletedTask;
    }
}
