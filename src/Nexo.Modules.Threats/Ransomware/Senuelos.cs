using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Ransomware
{
    // =====================================================================================================
    //  SEÑUELOS (archivos canario) contra ransomware. Salida 0, fila 2: «archivos canario vigilados».
    //
    //  Nexo deja en las carpetas que un ransomware cifra primero (Documentos, Escritorio, Imágenes) dos archivos
    //  que nadie debería tocar: uno cuyo nombre se ordena al principio y otro al final (muchos programas de cifrado
    //  recorren las carpetas en orden). Si cambian, desaparecen o se renombran, avisa.
    //
    //  Lo que NO hace, y se dice: no impide nada (sin minifiltro no se puede bloquear; eso lo hace el acceso controlado
    //  a carpetas de Defender, §2ak) y no sabe QUÉ programa lo tocó (el diario USN no lo dice). Avisa después, hasta
    //  un intervalo de revisión más tarde.
    //
    //  Reglas:
    //   - Nexo nunca sobrescribe ni borra un archivo: si el nombre ya está ocupado, no pone el señuelo allí y lo dice.
    //     Un señuelo tocado se queda donde está (es la prueba); reponerlo pone uno NUEVO con plan, token y aprobación.
    //   - «No pude leer el señuelo» nunca es «está intacto»: queda como no comprobado, con el motivo.
    //   - Un señuelo tocado no se vuelve a poner solo: el aviso sigue hasta que alguien lo repone.
    // =====================================================================================================

    public enum TipoDeHallazgoDeSenuelo
    {
        /// <summary>Sigue en su sitio, pero el contenido ya no es el que puso Nexo.</summary>
        Modificado,
        /// <summary>Se renombró o se movió (se encontró por su número de archivo). Lo más típico de un ransomware: «x.docx» -> «x.docx.locked».</summary>
        Renombrado,
        /// <summary>Ya no existe (se buscó por su número de archivo y no está).</summary>
        Borrado,
        /// <summary>No está en su sitio y no se pudo buscar por su número de archivo: borrado o renombrado, no se sabe cuál.</summary>
        Desaparecido
    }

    public sealed record HallazgoDeSenuelo(TipoDeHallazgoDeSenuelo Tipo, string Detalle, DateTimeOffset Cuando, string? NuevaRuta = null);

    /// <summary>Un señuelo puesto por Nexo. <c>Ranura</c> 0 = el nombre que se ordena primero; 1 = el que se ordena al final.</summary>
    public sealed record Senuelo(string Carpeta, int Ranura, string Ruta, string Sha256, long Bytes, ulong? Id, DateTimeOffset Creado)
    {
        public HallazgoDeSenuelo? Hallazgo { get; init; }
        public bool Tocado => Hallazgo is not null;
    }

    public enum EstadoDeLectura { Leido, NoExiste, NoLeido }

    /// <summary>Lo que se sabe de un archivo al ir a comprobarlo. <c>Motivo</c> solo con <see cref="EstadoDeLectura.NoLeido"/>.</summary>
    public sealed record LecturaDeSenuelo(EstadoDeLectura Estado, long Bytes = 0, string? Sha256 = null, ulong? Id = null, string? Motivo = null)
    {
        public static LecturaDeSenuelo NoExiste { get; } = new(EstadoDeLectura.NoExiste);
        public static LecturaDeSenuelo NoLeido(string motivo) => new(EstadoDeLectura.NoLeido, Motivo: motivo);
    }

    public enum EstadoDeBusqueda { Encontrado, NoExiste, NoSePudo }

    /// <summary>Buscar un archivo por su número (el que NTFS mantiene aunque cambie de nombre).</summary>
    public sealed record BusquedaPorId(EstadoDeBusqueda Estado, string? Ruta = null, string? Motivo = null);

    public enum EstadoDeCreacion { Creado, Ocupado, Fallo }

    public sealed record CreacionDeSenuelo(EstadoDeCreacion Estado, ulong? Id = null, string? Motivo = null);

    /// <summary>El disco, abstraído para probar las reglas sin tocarlo. La versión de Windows está en Nexo.Modules.Threats.Windows.</summary>
    public interface IAccesoASenuelos
    {
        bool CarpetaExiste(string carpeta);
        /// <summary>Si <paramref name="ruta"/> existe (archivo o carpeta), sin abrirlo.</summary>
        bool Existe(string ruta);
        /// <summary>Crea el archivo SOLO si no existe (nunca sobrescribe) y lo deja oculto. Devuelve su número si se pudo leer.</summary>
        CreacionDeSenuelo Crear(string ruta, byte[] contenido);
        LecturaDeSenuelo Leer(string ruta);
        /// <summary>Dónde está ahora el archivo con ese número, buscando en el volumen de <paramref name="carpeta"/>.</summary>
        BusquedaPorId BuscarPorId(string carpeta, ulong id);
    }

    /// <summary>Dónde se guarda la lista de señuelos (con sus huellas). Es estado del servicio, no un log.</summary>
    public interface IAlmacenDeSenuelos
    {
        /// <summary>La lista guardada. Vacía la primera vez. <paramref name="problema"/>: si no se pudo leer o estaba dañada.</summary>
        IReadOnlyList<Senuelo> Cargar(out string? problema);
        /// <returns>null si se guardó; si no, el motivo.</returns>
        string? Guardar(IReadOnlyList<Senuelo> senuelos);
    }

    /// <summary>Una carpeta que no tiene señuelo (o le falta uno), y por qué. Nunca se esconde.</summary>
    public sealed record CarpetaSinSenuelo(string Carpeta, string Motivo);

    public sealed record EstadoDeSenuelos(
        IReadOnlyList<Senuelo> Senuelos,
        IReadOnlyList<CarpetaSinSenuelo> SinSenuelo,
        IReadOnlyDictionary<string, string> NoComprobados,
        DateTimeOffset? UltimaRevision,
        string? Aviso)
    {
        public int Tocados => Senuelos.Count(s => s.Tocado);
        public int Intactos => Senuelos.Count(s => !s.Tocado) - NoComprobados.Count;
    }

    /// <summary>Lo que se haría al reponer: por cada señuelo tocado, dónde queda el viejo y dónde se pone el nuevo.</summary>
    public sealed record ReposicionDeSenuelo(string RutaTocada, string? RutaActualDelTocado, string? RutaNueva, string? Motivo);

    public sealed record PlanDeReposicion(IReadOnlyList<ReposicionDeSenuelo> Pasos)
    {
        public bool HayCambios => Pasos.Any(p => p.RutaNueva is not null);

        public string Describir()
        {
            if (Pasos.Count == 0) return "No hay señuelos tocados: no hay nada que reponer.";
            var sb = new StringBuilder();
            sb.Append(Pasos.Count == 1 ? "Se repone 1 señuelo tocado." : "Se reponen " + Pasos.Count + " señuelos tocados.");
            foreach (ReposicionDeSenuelo p in Pasos)
            {
                sb.Append("\n- ");
                sb.Append(p.RutaNueva is not null ? "Nuevo señuelo en " + p.RutaNueva + "." : "No se puede poner uno nuevo junto a " + p.RutaTocada + ": " + p.Motivo + ".");
                if (p.RutaActualDelTocado is not null)
                    sb.Append(" El tocado se queda en " + p.RutaActualDelTocado + ": Nexo no lo borra (puedes borrarlo tú).");
            }
            sb.Append("\nEl aviso de esos señuelos se da por visto (sigue en el registro de Nexo).");
            return sb.ToString();
        }
    }

    public sealed record ResultadoDeReposicion(int Repuestos, IReadOnlyList<string> Problemas);

    /// <summary>
    /// Pone, vigila y repone los señuelos. Seguro entre hilos: el servicio revisa en segundo plano mientras el pipe consulta.
    /// </summary>
    public sealed class VigilanteDeSenuelos
    {
        /// <summary>Ranura 0 (el «!» se ordena antes que letras y cifras) y ranura 1 (se ordena al final).</summary>
        public static readonly IReadOnlyList<(string Base, string Extension)> Nombres = new[]
        {
            ("!nexo-señuelo", ".docx"),
            ("zz-nexo-señuelo", ".xlsx")
        };

        /// <summary>Hasta cuántos «(n)» se prueban si el nombre está ocupado al reponer.</summary>
        public const int MaxVariantes = 9;
        public const int BytesMinimos = 40 * 1024;
        public const int BytesMaximos = 96 * 1024;
        /// <summary>Dos señuelos tocados en este plazo: posible ransomware en marcha (Crítica).</summary>
        public static readonly TimeSpan VentanaDeRafaga = TimeSpan.FromMinutes(10);

        private readonly IAccesoASenuelos _acceso;
        private readonly IAlmacenDeSenuelos _almacen;
        private readonly IReportWriter _reportes;
        private readonly Func<DateTimeOffset> _reloj;
        private readonly Func<int, byte[]> _azar;
        private readonly SemaphoreSlim _paso = new SemaphoreSlim(1, 1);
        private readonly object _candado = new object();

        private List<Senuelo> _senuelos = new List<Senuelo>();
        private List<CarpetaSinSenuelo> _sinSenuelo = new List<CarpetaSinSenuelo>();
        private Dictionary<string, string> _noComprobados = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private DateTimeOffset? _ultimaRevision;
        private string? _aviso;
        private bool _cargado;

        public VigilanteDeSenuelos(IAccesoASenuelos acceso, IAlmacenDeSenuelos almacen, IReportWriter reportes,
                                   Func<DateTimeOffset>? reloj = null, Func<int, byte[]>? azar = null)
        {
            _acceso = acceso;
            _almacen = almacen;
            _reportes = reportes;
            _reloj = reloj ?? (() => DateTimeOffset.Now);
            _azar = azar ?? RandomNumberGenerator.GetBytes;
        }

        /// <summary>Se dispara con los señuelos que se acaban de encontrar tocados. No debe lanzar ni bloquear.</summary>
        public event Action<IReadOnlyList<Senuelo>>? Alarma;

        public static string NombreDe(int ranura, int variante)
            => Nombres[ranura].Base + (variante <= 1 ? "" : " (" + variante + ")") + Nombres[ranura].Extension;

        public EstadoDeSenuelos Estado()
        {
            lock (_candado)
                return new EstadoDeSenuelos(_senuelos.ToList(), _sinSenuelo.ToList(),
                    new Dictionary<string, string>(_noComprobados, StringComparer.OrdinalIgnoreCase), _ultimaRevision, _aviso);
        }

        // ============================================================
        //  PONER LOS QUE FALTEN
        // ============================================================

        /// <summary>
        /// Carga la lista guardada (la primera vez) y pone los señuelos que falten en <paramref name="carpetas"/>. Una ranura ya ocupada
        /// por un señuelo de Nexo (intacto O tocado) no se vuelve a poner. Se puede llamar a menudo: solo pone lo que falta.
        /// </summary>
        public async Task PrepararAsync(IReadOnlyList<string> carpetas, CancellationToken ct = default)
        {
            await _paso.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                CargarSiHaceFalta();
                var lista = Copia();
                var sin = new List<CarpetaSinSenuelo>();
                var puestos = new List<Senuelo>();

                foreach (string c in carpetas.Select(Normalizar).Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    if (!_acceso.CarpetaExiste(c)) { sin.Add(new CarpetaSinSenuelo(c, "la carpeta no existe")); continue; }
                    for (int ranura = 0; ranura < Nombres.Count; ranura++)
                    {
                        if (lista.Any(s => s.Ranura == ranura && Igual(s.Carpeta, c))) continue;
                        string ruta = Path.Combine(c, NombreDe(ranura, 1));
                        if (_acceso.Existe(ruta))
                        {
                            sin.Add(new CarpetaSinSenuelo(c, "ya hay un archivo «" + NombreDe(ranura, 1) + "» que no es de Nexo; no se toca"));
                            continue;
                        }
                        (Senuelo? s, string? problema) = Poner(c, ranura, ruta);
                        if (s is null) sin.Add(new CarpetaSinSenuelo(c, problema!));
                        else { lista.Add(s); puestos.Add(s); }
                    }
                }

                string? noGuardado = puestos.Count > 0 ? _almacen.Guardar(lista) : null;
                lock (_candado)
                {
                    _senuelos = lista;
                    _sinSenuelo = sin;
                    if (noGuardado is not null) _aviso = "no se pudo guardar la lista de señuelos (" + noGuardado + "): si el servicio se reinicia, los nuevos no se vigilarán";
                }

                if (puestos.Count > 0)
                {
                    var e = new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.SenuelosPuestos,
                        puestos.Count == 1 ? "Señuelo contra ransomware puesto" : puestos.Count + " señuelos contra ransomware puestos")
                    {
                        Severidad = Severidad.Info,
                        Accion = Accion.Registrada,
                        Cuerpo = "Archivos ocultos que nadie debería tocar; si cambian, Nexo avisa:\n" + string.Join("\n", puestos.Select(p => "- " + p.Ruta))
                                 + (sin.Count > 0 ? "\n\nSin señuelo:\n" + string.Join("\n", sin.Select(x => "- " + x.Carpeta + ": " + x.Motivo)) : "")
                    };
                    e.Campos["puestos"] = puestos.Count;
                    e.Campos["sin_senuelo"] = sin.Count;
                    await EscribirAsync(e, ct).ConfigureAwait(false);
                }
            }
            finally { _paso.Release(); }
        }

        private (Senuelo?, string?) Poner(string carpeta, int ranura, string ruta)
        {
            byte[] contenido = Contenido(Nombres[ranura].Extension);
            CreacionDeSenuelo r = _acceso.Crear(ruta, contenido);
            return r.Estado switch
            {
                EstadoDeCreacion.Creado => (new Senuelo(carpeta, ranura, ruta, Huella(contenido), contenido.Length, r.Id, _reloj()), null),
                EstadoDeCreacion.Ocupado => (null, "ya hay un archivo «" + Path.GetFileName(ruta) + "» que no es de Nexo; no se toca"),
                _ => (null, "no se pudo crear el señuelo: " + (r.Motivo ?? "motivo desconocido"))
            };
        }

        /// <summary>Contenido de relleno: parece el principio de un .docx/.xlsx (un ZIP) y el resto es azar, para que su huella sea única.</summary>
        private byte[] Contenido(string extension)
        {
            byte[] largo = _azar(4);
            int bytes = BytesMinimos + (int)(BitConverter.ToUInt32(largo, 0) % (uint)(BytesMaximos - BytesMinimos + 1));
            byte[] c = _azar(bytes);
            if (c.Length != bytes) throw new InvalidOperationException("el generador de azar devolvió otro tamaño");
            c[0] = (byte)'P'; c[1] = (byte)'K'; c[2] = 3; c[3] = 4;
            return c;
        }

        // ============================================================
        //  REVISAR
        // ============================================================

        /// <summary>Comprueba todos los señuelos no tocados. Devuelve los que se acaban de encontrar tocados.</summary>
        public async Task<IReadOnlyList<Senuelo>> RevisarAsync(CancellationToken ct = default)
        {
            await _paso.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                CargarSiHaceFalta();
                var lista = Copia();
                var noComprobados = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                var nuevos = new List<Senuelo>();
                DateTimeOffset ahora = _reloj();

                for (int i = 0; i < lista.Count; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    Senuelo s = lista[i];
                    if (s.Tocado) continue;

                    HallazgoDeSenuelo? h = Comprobar(s, ahora, out string? noComprobado);
                    if (noComprobado is not null) { noComprobados[s.Ruta] = noComprobado; continue; }
                    if (h is null) continue;
                    lista[i] = s with { Hallazgo = h };
                    nuevos.Add(lista[i]);
                }

                string? noGuardado = nuevos.Count > 0 ? _almacen.Guardar(lista) : null;
                lock (_candado)
                {
                    _senuelos = lista;
                    _noComprobados = noComprobados;
                    _ultimaRevision = ahora;
                    if (noGuardado is not null) _aviso = "no se pudo guardar la lista de señuelos (" + noGuardado + ")";
                }

                if (nuevos.Count > 0)
                {
                    foreach (Senuelo s in nuevos) await EscribirAsync(EventoDeTocado(s), ct).ConfigureAwait(false);

                    // Varios en poco tiempo: lo que hace un programa que cifra carpeta por carpeta.
                    int recientes = Recientes(lista, ahora);
                    if (recientes >= 2)
                    {
                        var e = new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.SenueloTocado,
                            "Varios señuelos tocados en poco tiempo: puede haber un ransomware cifrando tus archivos")
                        {
                            Severidad = Severidad.Critica,
                            Accion = Accion.Registrada,
                            Cuerpo = recientes + " señuelos tocados en los últimos " + (int)VentanaDeRafaga.TotalMinutes + " minutos. "
                                     + "Si no fuiste tú: desconecta el equipo de la red y de los discos externos, y no lo apagues sin antes "
                                     + "revisar qué programa está en marcha. Nexo no puede detenerlo ni sabe qué programa fue."
                        };
                        e.Campos["recientes"] = recientes;
                        e.Campos["rafaga"] = true;
                        await EscribirAsync(e, ct).ConfigureAwait(false);
                    }

                    try { Alarma?.Invoke(nuevos); }
                    catch (Exception) { /* un suscriptor roto no debe romper la vigilancia */ }
                }
                return nuevos;
            }
            finally { _paso.Release(); }
        }

        private HallazgoDeSenuelo? Comprobar(Senuelo s, DateTimeOffset ahora, out string? noComprobado)
        {
            noComprobado = null;
            LecturaDeSenuelo l = _acceso.Leer(s.Ruta);
            switch (l.Estado)
            {
                case EstadoDeLectura.NoLeido:
                    noComprobado = l.Motivo ?? "no se pudo leer";
                    return null;

                case EstadoDeLectura.Leido:
                    if (l.Bytes == s.Bytes && string.Equals(l.Sha256, s.Sha256, StringComparison.OrdinalIgnoreCase)) return null;
                    string otro = s.Id is { } id && l.Id is { } id2 && id != id2 ? " Ahora es otro archivo con el mismo nombre." : "";
                    return new HallazgoDeSenuelo(TipoDeHallazgoDeSenuelo.Modificado,
                        "Su contenido cambió (" + s.Bytes + " bytes antes, " + l.Bytes + " ahora)." + otro, ahora);

                default:   // no existe en su sitio
                    if (s.Id is not { } numero)
                        return new HallazgoDeSenuelo(TipoDeHallazgoDeSenuelo.Desaparecido,
                            "Ya no está en su sitio (no se sabe si se borró o se renombró: no se guardó su número de archivo).", ahora);

                    BusquedaPorId b = _acceso.BuscarPorId(s.Carpeta, numero);
                    switch (b.Estado)
                    {
                        case EstadoDeBusqueda.Encontrado when b.Ruta is not null && EnLaPapelera(b.Ruta):
                            // Borrar desde el Explorador lo MUEVE a la papelera: el número de archivo sigue vivo allí.
                            return new HallazgoDeSenuelo(TipoDeHallazgoDeSenuelo.Borrado, "Se envió a la papelera de reciclaje (" + b.Ruta + ").", ahora, b.Ruta);
                        case EstadoDeBusqueda.Encontrado when b.Ruta is not null:
                            string cambio = "";
                            LecturaDeSenuelo l2 = _acceso.Leer(b.Ruta);
                            if (l2.Estado == EstadoDeLectura.Leido)
                                cambio = l2.Bytes == s.Bytes && string.Equals(l2.Sha256, s.Sha256, StringComparison.OrdinalIgnoreCase)
                                    ? " Su contenido no cambió." : " Y su contenido cambió.";
                            else if (l2.Estado == EstadoDeLectura.NoLeido) cambio = " No se pudo leer su contenido.";
                            return new HallazgoDeSenuelo(TipoDeHallazgoDeSenuelo.Renombrado,
                                "Se renombró o se movió a " + b.Ruta + "." + cambio, ahora, b.Ruta);
                        case EstadoDeBusqueda.NoExiste:
                            return new HallazgoDeSenuelo(TipoDeHallazgoDeSenuelo.Borrado, "Se borró.", ahora);
                        default:
                            return new HallazgoDeSenuelo(TipoDeHallazgoDeSenuelo.Desaparecido,
                                "Ya no está en su sitio (no se pudo buscar si se renombró: " + (b.Motivo ?? "motivo desconocido") + ").", ahora);
                    }
            }
        }

        private static NexoEvent EventoDeTocado(Senuelo s)
        {
            HallazgoDeSenuelo h = s.Hallazgo!;
            string que = h.Tipo switch
            {
                TipoDeHallazgoDeSenuelo.Modificado => "modificado",
                TipoDeHallazgoDeSenuelo.Renombrado => "renombrado",
                TipoDeHallazgoDeSenuelo.Borrado => "borrado",
                _ => "desaparecido"
            };
            bool aMano = AMano(h);
            var e = new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.SenueloTocado, "Señuelo contra ransomware " + que + ": " + s.Carpeta)
            {
                Severidad = SeveridadDe(h),
                Accion = Accion.Registrada,
                Cuerpo = s.Ruta + "\n" + h.Detalle + "\n\nNadie debería tocar este archivo: lo puso Nexo como cebo. "
                         + (aMano
                             ? "Se envió a la papelera, cosa que un programa de cifrado no suele hacer: si lo borraste tú, repónlo desde Nexo."
                             : "Si no fuiste tú, puede ser un programa que está cifrando o borrando tus archivos. Nexo no sabe qué programa fue ni puede detenerlo.")
            };
            e.Campos["ruta"] = s.Ruta;
            e.Campos["hallazgo"] = que;
            if (h.NuevaRuta is not null) e.Campos["nueva_ruta"] = h.NuevaRuta;
            return e;
        }

        // ============================================================
        //  REPONER (con plan; lo ejecuta el servicio con token y aprobación)
        // ============================================================

        public PlanDeReposicion PrepararReposicion()
        {
            List<Senuelo> lista;
            lock (_candado) lista = _senuelos.ToList();
            return Planear(lista);
        }

        private PlanDeReposicion Planear(IReadOnlyList<Senuelo> lista)
        {
            var pasos = new List<ReposicionDeSenuelo>();
            var elegidas = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Senuelo s in lista.Where(x => x.Tocado))
            {
                HallazgoDeSenuelo h = s.Hallazgo!;
                string? actual = h.Tipo == TipoDeHallazgoDeSenuelo.Renombrado ? h.NuevaRuta
                               : h.Tipo == TipoDeHallazgoDeSenuelo.Modificado ? s.Ruta : null;
                if (!_acceso.CarpetaExiste(s.Carpeta)) { pasos.Add(new ReposicionDeSenuelo(s.Ruta, actual, null, "la carpeta ya no existe")); continue; }

                string? nueva = null;
                for (int v = 1; v <= MaxVariantes && nueva is null; v++)
                {
                    string candidata = Path.Combine(s.Carpeta, NombreDe(s.Ranura, v));
                    if (!elegidas.Contains(candidata) && !_acceso.Existe(candidata)) nueva = candidata;
                }
                if (nueva is not null) elegidas.Add(nueva);
                pasos.Add(new ReposicionDeSenuelo(s.Ruta, actual, nueva, nueva is null ? "todos los nombres posibles están ocupados" : null));
            }
            return new PlanDeReposicion(pasos);
        }

        /// <summary>
        /// Repone los señuelos tocados del plan. Se vuelve a planear con el estado de AHORA: solo se repone lo que sigue tocado y donde
        /// el nombre sigue libre (nunca se sobrescribe). El archivo tocado no se borra ni se mueve.
        /// </summary>
        public async Task<ResultadoDeReposicion> ReponerAsync(PlanDeReposicion plan, CancellationToken ct = default)
        {
            await _paso.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var lista = Copia();
                PlanDeReposicion ahora = Planear(lista);
                var problemas = new List<string>();
                int repuestos = 0;

                foreach (ReposicionDeSenuelo pedido in plan.Pasos)
                {
                    ReposicionDeSenuelo? vigente = ahora.Pasos.FirstOrDefault(p => Igual(p.RutaTocada, pedido.RutaTocada));
                    int i = lista.FindIndex(s => s.Tocado && Igual(s.Ruta, pedido.RutaTocada));
                    if (vigente is null || i < 0) { problemas.Add(pedido.RutaTocada + ": ya no está tocado o ya se repuso"); continue; }
                    if (vigente.RutaNueva is null) { problemas.Add(pedido.RutaTocada + ": " + vigente.Motivo); continue; }
                    if (pedido.RutaNueva is not null && !Igual(pedido.RutaNueva, vigente.RutaNueva))
                    {
                        problemas.Add(pedido.RutaTocada + ": el nombre previsto ya está ocupado; hay que volver a previsualizar");
                        continue;
                    }

                    Senuelo viejo = lista[i];
                    (Senuelo? nuevo, string? problema) = Poner(viejo.Carpeta, viejo.Ranura, vigente.RutaNueva);
                    if (nuevo is null) { problemas.Add(pedido.RutaTocada + ": " + problema); continue; }
                    lista[i] = nuevo;
                    repuestos++;
                }

                string? noGuardado = repuestos > 0 ? _almacen.Guardar(lista) : null;
                if (noGuardado is not null) problemas.Add("no se pudo guardar la lista de señuelos (" + noGuardado + ")");
                lock (_candado) _senuelos = lista;

                if (repuestos > 0 || problemas.Count > 0)
                {
                    var e = new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.SenuelosPuestos,
                        repuestos == 1 ? "Señuelo contra ransomware repuesto" : repuestos + " señuelos contra ransomware repuestos")
                    {
                        Severidad = problemas.Count > 0 ? Severidad.Media : Severidad.Info,
                        Accion = repuestos > 0 ? Accion.Registrada : Accion.Omitida,
                        Cuerpo = problemas.Count > 0 ? "Problemas:\n" + string.Join("\n", problemas.Select(p => "- " + p)) : null
                    };
                    e.Campos["repuestos"] = repuestos;
                    e.Campos["problemas"] = problemas.Count;
                    await EscribirAsync(e, ct).ConfigureAwait(false);
                }
                return new ResultadoDeReposicion(repuestos, problemas);
            }
            finally { _paso.Release(); }
        }

        // ============================================================
        private void CargarSiHaceFalta()
        {
            if (_cargado) return;
            IReadOnlyList<Senuelo> guardados = _almacen.Cargar(out string? problema);
            lock (_candado)
            {
                _senuelos = guardados.ToList();
                if (problema is not null) _aviso = problema;
            }
            _cargado = true;
        }

        private List<Senuelo> Copia() { lock (_candado) return _senuelos.ToList(); }

        private async Task EscribirAsync(NexoEvent e, CancellationToken ct)
        {
            try { await _reportes.EscribirAsync(e, ct).ConfigureAwait(false); }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
                lock (_candado) _aviso = "no se pudo escribir en el registro de Nexo (vault)";
            }
        }

        /// <summary>A la papelera: casi seguro una persona (Media). El resto: Alta.</summary>
        public static Severidad SeveridadDe(HallazgoDeSenuelo h) => AMano(h) ? Severidad.Media : Severidad.Alta;

        /// <summary>
        /// Señuelos tocados en los últimos <see cref="VentanaDeRafaga"/> antes de <paramref name="ahora"/>. Lo enviado a la papelera no cuenta:
        /// un programa de cifrado no usa la papelera, casi seguro fue alguien a mano. Dos o más = posible ransomware en marcha.
        /// </summary>
        public static int Recientes(IEnumerable<Senuelo> senuelos, DateTimeOffset ahora)
            => senuelos.Count(s => s.Hallazgo is { } h && ahora - h.Cuando <= VentanaDeRafaga && ahora >= h.Cuando && !AMano(h));

        private static bool AMano(HallazgoDeSenuelo h) => h.Tipo == TipoDeHallazgoDeSenuelo.Borrado && h.NuevaRuta is { } r && EnLaPapelera(r);

        public static bool EnLaPapelera(string ruta) => ruta.Contains(@"\$Recycle.Bin\", StringComparison.OrdinalIgnoreCase);

        public static string Huella(byte[] contenido) => Convert.ToHexString(SHA256.HashData(contenido)).ToLowerInvariant();

        private static string Normalizar(string c) => c.Trim().TrimEnd('\\', '/');

        private static bool Igual(string a, string b) => string.Equals(Normalizar(a), Normalizar(b), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// La lista de señuelos en un JSON (escritura atómica). Dañado: se aparta como «.corrupto» (no se borra) y se empieza de cero;
    /// los archivos que ya estaban NO se adoptan (no se sabe si su contenido es el original), así que esas ranuras quedan
    /// «ocupadas por un archivo que no es de Nexo», y se dice.
    /// </summary>
    public sealed class AlmacenDeSenuelosJson : IAlmacenDeSenuelos
    {
        private const int VersionActual = 1;
        private static readonly UTF8Encoding Utf8SinBom = new UTF8Encoding(false);
        private static readonly JsonSerializerOptions Opciones = new JsonSerializerOptions { WriteIndented = true };

        private sealed class Documento
        {
            public int Version { get; set; }
            public List<Senuelo> Senuelos { get; set; } = new List<Senuelo>();
        }

        private readonly string _ruta;
        public AlmacenDeSenuelosJson(string ruta) => _ruta = ruta;

        public IReadOnlyList<Senuelo> Cargar(out string? problema)
        {
            problema = null;
            if (!File.Exists(_ruta)) return Array.Empty<Senuelo>();
            try
            {
                Documento? d = JsonSerializer.Deserialize<Documento>(File.ReadAllText(_ruta, Utf8SinBom), Opciones);
                if (d is null || d.Version != VersionActual) throw new InvalidDataException("versión " + (d?.Version.ToString() ?? "desconocida"));
                if (d.Senuelos.Any(s => s is null || string.IsNullOrEmpty(s.Ruta) || string.IsNullOrEmpty(s.Carpeta) || string.IsNullOrEmpty(s.Sha256)
                                        || s.Ranura < 0 || s.Ranura >= VigilanteDeSenuelos.Nombres.Count))
                    throw new InvalidDataException("entrada incompleta");
                return d.Senuelos;
            }
            catch (Exception ex) when (ex is JsonException || ex is InvalidDataException || ex is NotSupportedException)
            {
                string apartado = _ruta + ".corrupto";
                try { File.Copy(_ruta, apartado, overwrite: true); File.Delete(_ruta); }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException) { }
                problema = "la lista de señuelos estaba dañada y se apartó como «" + Path.GetFileName(apartado) + "»: los señuelos anteriores ya no se vigilan";
                return Array.Empty<Senuelo>();
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                // No se aparta: puede ser un bloqueo pasajero. Pero no se finge que no había señuelos.
                problema = "no se pudo leer la lista de señuelos (" + ex.GetType().Name + "): los señuelos anteriores no se vigilan hasta que se pueda";
                return Array.Empty<Senuelo>();
            }
        }

        public string? Guardar(IReadOnlyList<Senuelo> senuelos)
        {
            try
            {
                string carpeta = Path.GetDirectoryName(Path.GetFullPath(_ruta)) ?? throw new IOException("ruta sin carpeta");
                Directory.CreateDirectory(carpeta);
                string temporal = Path.Combine(carpeta, "~" + Path.GetFileNameWithoutExtension(_ruta) + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp");
                string json = JsonSerializer.Serialize(new Documento { Version = VersionActual, Senuelos = senuelos.ToList() }, Opciones);
                try
                {
                    using (var fs = new FileStream(temporal, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    using (var sw = new StreamWriter(fs, Utf8SinBom))
                    {
                        sw.Write(json);
                        sw.Flush();
                        fs.Flush(flushToDisk: true);
                    }
                    if (File.Exists(_ruta)) File.Replace(temporal, _ruta, destinationBackupFileName: null);
                    else File.Move(temporal, _ruta);
                }
                finally
                {
                    try { if (File.Exists(temporal)) File.Delete(temporal); } catch (IOException) { } catch (UnauthorizedAccessException) { }
                }
                return null;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return ex.GetType().Name;
            }
        }
    }
}
