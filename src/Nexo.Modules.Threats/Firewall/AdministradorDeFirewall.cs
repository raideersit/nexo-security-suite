using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Nexo.Reports;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Firewall
{
    /// <summary>
    /// Firewall por aplicacion y modo sigiloso (funciones 3 y 3b de la Salida 0).
    ///
    /// Todo en modo usuario sobre el Firewall de Windows (INetFwPolicy2), SIN
    /// driver: el modo sigiloso no lo necesita, porque Windows ya descarta en
    /// silencio el trafico entrante no solicitado (no envia RST ni ICMP
    /// inalcanzable). Lo unico que se anade es bloquear el ping entrante.
    ///
    /// Reglas que gobiernan esta clase:
    ///   - Dos fases. Preparar* no cambia nada y devuelve un plan con token;
    ///     AplicarAsync solo ejecuta ese plan exacto.
    ///   - Solo se tocan reglas del grupo "Nexo Security Suite". Las de Windows y
    ///     las de otros programas no se editan ni se borran, aunque el nombre exista.
    ///   - Nunca se bloquean procesos del sistema ni Windows Defender.
    ///   - Lo que no se pudo hacer se informa; nunca se presenta como hecho.
    /// </summary>
    public sealed class AdministradorDeFirewall
    {
        public const string NombrePingV4 = "Nexo: Sigiloso - bloquear ping entrante (ICMPv4)";
        public const string NombrePingV6 = "Nexo: Sigiloso - bloquear ping entrante (ICMPv6)";

        private readonly IAlmacenDeFirewall _almacen;
        private readonly IReportWriter _reportes;
        private readonly bool _esAdministrador;
        private readonly GuardiaDeReglas _guardia;
        private readonly Func<DateTimeOffset> _reloj;

        public AdministradorDeFirewall(
            IAlmacenDeFirewall almacen,
            IReportWriter reportes,
            bool esAdministrador,
            GuardiaDeReglas? guardia = null,
            Func<DateTimeOffset>? reloj = null)
        {
            _almacen = almacen;
            _reportes = reportes;
            _esAdministrador = esAdministrador;
            _guardia = guardia ?? new GuardiaDeReglas();
            _reloj = reloj ?? (() => DateTimeOffset.Now);
        }

        // ============================================================
        //  LECTURA
        // ============================================================
        public IReadOnlyList<ReglaDeFirewall> ListarDeNexo()
            => _almacen.Enumerar().Where(r => r.EsDeNexo).OrderBy(r => r.Nombre, StringComparer.Ordinal).ToList();

        public IReadOnlyList<PoliticaDePerfil> LeerPoliticas() => _almacen.LeerPoliticas();

        /// <summary>True si las dos reglas de ping existen y estan habilitadas.</summary>
        public bool SigilosoActivo()
        {
            var nexo = ListarDeNexo();
            return ReglasDeSigilo().All(def => nexo.Any(r => r.Nombre == def.Nombre && r.Habilitada));
        }

        // ============================================================
        //  FASE 1: PLANES (no cambian nada)
        // ============================================================
        public VistaPreviaFirewall PrepararRegla(
            string rutaExe,
            AccionDeRegla accion,
            DireccionDeRegla? direccion = null)
        {
            var cambios = new List<CambioDeFirewall>();
            var rechazos = new List<string>();
            var advertencias = new List<string>();

            ResultadoDeRuta v = _guardia.Validar(rutaExe, accion);
            if (!v.Aceptada)
            {
                rechazos.Add((string.IsNullOrWhiteSpace(rutaExe) ? "(sin ruta)" : rutaExe.Trim()) + " — " + v.Motivo);
                return Plan("Regla por aplicacion", cambios, rechazos, advertencias);
            }

            var existentes = _almacen.Enumerar();
            DireccionDeRegla[] direcciones = direccion is null
                ? new[] { DireccionDeRegla.Saliente, DireccionDeRegla.Entrante }
                : new[] { direccion.Value };

            foreach (DireccionDeRegla d in direcciones)
            {
                string nombre = NombreDeRegla(accion, d, v.Ruta);

                if (existentes.Any(r => string.Equals(r.Nombre, nombre, StringComparison.OrdinalIgnoreCase)))
                {
                    rechazos.Add(nombre + " — ya existe");
                    continue;
                }

                cambios.Add(new CambioDeFirewall(TipoDeCambio.Agregar, new ReglaDeFirewall(
                    Nombre: nombre,
                    RutaApp: v.Ruta,
                    Direccion: d,
                    Accion: accion,
                    Perfiles: PerfilesDeRed.Todos,
                    Habilitada: true,
                    Grupo: ReglaDeFirewall.GrupoNexo,
                    Descripcion: "Creada por Nexo Security Suite el " +
                                 _reloj().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + ". Ruta: " + v.Ruta)));
            }

            if (accion == AccionDeRegla.Permitir)
            {
                string bloqueo = "Nexo: Bloquear";
                if (existentes.Any(r => r.EsDeNexo && r.RutaApp is not null
                                        && string.Equals(r.RutaApp, v.Ruta, StringComparison.OrdinalIgnoreCase)
                                        && r.Nombre.StartsWith(bloqueo, StringComparison.Ordinal)))
                    advertencias.Add("Nexo ya tiene una regla BLOQUEAR para esta aplicacion; en Windows el bloqueo " +
                                     "tiene prioridad sobre el permiso.");
            }

            AvisarPerfilesInactivos(advertencias);
            return Plan("Regla por aplicacion: " + GuardiaDeReglas.NombreDe(v.Ruta), cambios, rechazos, advertencias);
        }

        public VistaPreviaFirewall PrepararQuitar(string nombreRegla)
        {
            var cambios = new List<CambioDeFirewall>();
            var rechazos = new List<string>();

            var regla = _almacen.Enumerar()
                .FirstOrDefault(r => string.Equals(r.Nombre, nombreRegla, StringComparison.OrdinalIgnoreCase));

            if (regla is null)
                rechazos.Add(nombreRegla + " — no existe");
            else if (!regla.EsDeNexo)
                rechazos.Add(nombreRegla + " — no es una regla de Nexo; solo se quitan las que Nexo creo");
            else
                cambios.Add(new CambioDeFirewall(TipoDeCambio.Eliminar, regla));

            return Plan("Quitar regla", cambios, rechazos, new List<string>());
        }

        public VistaPreviaFirewall PrepararSigiloso(bool activar)
        {
            var cambios = new List<CambioDeFirewall>();
            var rechazos = new List<string>();
            var advertencias = new List<string>();

            var existentes = _almacen.Enumerar();

            foreach (ReglaDeFirewall def in ReglasDeSigilo())
            {
                ReglaDeFirewall? actual = existentes
                    .FirstOrDefault(r => string.Equals(r.Nombre, def.Nombre, StringComparison.OrdinalIgnoreCase));

                if (activar)
                {
                    if (actual is null) cambios.Add(new CambioDeFirewall(TipoDeCambio.Agregar, def));
                    else if (!actual.EsDeNexo)
                        rechazos.Add(def.Nombre + " — ya existe una regla con ese nombre que no es de Nexo");
                }
                else if (actual is not null)
                {
                    if (actual.EsDeNexo) cambios.Add(new CambioDeFirewall(TipoDeCambio.Eliminar, actual));
                    else rechazos.Add(def.Nombre + " — no es una regla de Nexo; no se toca");
                }
            }

            if (cambios.Count == 0 && rechazos.Count == 0)
                advertencias.Add(activar ? "El modo sigiloso ya estaba activo." : "El modo sigiloso ya estaba desactivado.");

            foreach (PoliticaDePerfil p in _almacen.LeerPoliticas())
            {
                if (!p.FirewallActivo)
                    advertencias.Add("El Firewall de Windows esta DESACTIVADO en el perfil " + p.Perfil +
                                     ": el modo sigiloso no tiene efecto alli. Nexo no lo activa por ti.");
                else if (activar && p.EntradaPorDefecto == AccionDeRegla.Permitir)
                    advertencias.Add("El perfil " + p.Perfil + " PERMITE el trafico entrante por defecto. " +
                                     "Nexo no cambia esa politica; se recomienda dejarla en Bloquear.");
            }

            return Plan(activar ? "Activar modo sigiloso" : "Desactivar modo sigiloso",
                        cambios, rechazos, advertencias, esSigiloso: true, activar: activar);
        }

        // ============================================================
        //  FASE 2: APLICAR
        // ============================================================
        public async Task<ResultadoFirewall> AplicarAsync(
            VistaPreviaFirewall vista,
            TokenDeCambio token,
            CancellationToken ct = default)
        {
            if (vista is null) throw new ArgumentNullException(nameof(vista));
            if (token is null) throw new ArgumentNullException(nameof(token));

            if (!token.EsValidoPara(vista.Cambios, _reloj()))
                throw new InvalidOperationException(
                    "El token no corresponde a este plan, o caduco. Hay que volver a previsualizar.");

            var omitidos = new List<string>();

            if (!_esAdministrador)
            {
                // No se presenta como hecho lo que no se pudo hacer.
                foreach (CambioDeFirewall c in vista.Cambios)
                    omitidos.Add(c.Regla.Nombre + " — requiere permisos de administrador");
                return new ResultadoFirewall(0, omitidos);
            }

            int aplicados = 0;
            foreach (CambioDeFirewall cambio in vista.Cambios)
            {
                ct.ThrowIfCancellationRequested();

                // El estado pudo cambiar entre la vista previa y ahora: se reverifica
                // cada cambio contra el firewall real, no contra lo que se vio.
                string? motivo = Reverificar(cambio);
                if (motivo is not null) { omitidos.Add(cambio.Regla.Nombre + " — " + motivo); continue; }

                try
                {
                    if (cambio.Tipo == TipoDeCambio.Agregar) _almacen.Agregar(cambio.Regla);
                    else _almacen.Eliminar(cambio.Regla.Nombre);
                }
                catch (UnauthorizedAccessException)
                {
                    omitidos.Add(cambio.Regla.Nombre + " — Windows denego el acceso");
                    continue;
                }
                catch (Exception ex) when (ex is InvalidOperationException || ex is IOException)
                {
                    omitidos.Add(cambio.Regla.Nombre + " — " + ex.GetType().Name + ": " + ex.Message);
                    continue;
                }

                aplicados++;

                if (!vista.EsModoSigiloso)
                {
                    await _reportes.EscribirAsync(Eventos.Amenazas.ReglaFirewall(
                        cambio.Tipo == TipoDeCambio.Agregar ? "creada" : "eliminada",
                        cambio.Regla.Nombre,
                        cambio.Regla.Accion == AccionDeRegla.Bloquear ? "bloquear" : "permitir",
                        cambio.Regla.Direccion == DireccionDeRegla.Entrante ? "entrante" : "saliente",
                        cambio.Regla.RutaApp), ct).ConfigureAwait(false);
                }
            }

            if (vista.EsModoSigiloso && aplicados > 0)
            {
                await _reportes.EscribirAsync(
                    Eventos.Amenazas.ModoSigiloso(vista.ActivarSigiloso, aplicados), ct).ConfigureAwait(false);
            }

            return new ResultadoFirewall(aplicados, omitidos);
        }

        private string? Reverificar(CambioDeFirewall cambio)
        {
            var actual = _almacen.Enumerar().FirstOrDefault(
                r => string.Equals(r.Nombre, cambio.Regla.Nombre, StringComparison.OrdinalIgnoreCase));

            if (cambio.Tipo == TipoDeCambio.Agregar)
            {
                if (actual is not null) return "ya existe";
                if (cambio.Regla.RutaApp is not null)
                {
                    ResultadoDeRuta v = _guardia.Validar(cambio.Regla.RutaApp, cambio.Regla.Accion);
                    if (!v.Aceptada) return v.Motivo;
                }
                return null;
            }

            if (actual is null) return "ya no existe";
            if (!actual.EsDeNexo) return "ya no es una regla de Nexo; no se toca";
            return null;
        }

        // ============================================================
        //  AUXILIARES
        // ============================================================
        private VistaPreviaFirewall Plan(
            string titulo,
            List<CambioDeFirewall> cambios,
            List<string> rechazos,
            List<string> advertencias,
            bool esSigiloso = false,
            bool activar = false)
            => new VistaPreviaFirewall(titulo, cambios, rechazos, advertencias,
                                       TokenDeCambio.Emitir(cambios, _reloj()), esSigiloso, activar);

        private void AvisarPerfilesInactivos(List<string> advertencias)
        {
            foreach (PoliticaDePerfil p in _almacen.LeerPoliticas().Where(p => !p.FirewallActivo))
                advertencias.Add("El Firewall de Windows esta DESACTIVADO en el perfil " + p.Perfil +
                                 ": la regla no tendra efecto alli.");
        }

        internal static IReadOnlyList<ReglaDeFirewall> ReglasDeSigilo() => new[]
        {
            new ReglaDeFirewall(NombrePingV4, null, DireccionDeRegla.Entrante, AccionDeRegla.Bloquear,
                PerfilesDeRed.Todos, true, ReglaDeFirewall.GrupoNexo,
                "Modo sigiloso de Nexo: descarta el ping (ICMPv4 Echo Request) entrante.",
                Protocolo: 1, TiposIcmp: "8:*"),
            new ReglaDeFirewall(NombrePingV6, null, DireccionDeRegla.Entrante, AccionDeRegla.Bloquear,
                PerfilesDeRed.Todos, true, ReglaDeFirewall.GrupoNexo,
                "Modo sigiloso de Nexo: descarta el ping (ICMPv6 Echo Request) entrante.",
                Protocolo: 58, TiposIcmp: "128:*")
        };

        /// <summary>
        /// Nombre determinista: el mismo ejecutable y la misma accion dan siempre el
        /// mismo nombre, asi que pedir dos veces lo mismo se detecta como duplicado.
        /// El sufijo evita que dos "chrome.exe" de carpetas distintas colisionen.
        /// </summary>
        internal static string NombreDeRegla(AccionDeRegla accion, DireccionDeRegla direccion, string ruta)
        {
            byte[] h = SHA256.HashData(Encoding.UTF8.GetBytes(ruta.ToLowerInvariant()));
            string sufijo = Convert.ToHexString(h, 0, 3).ToLowerInvariant();
            return ReglaDeFirewall.PrefijoNombre
                   + (accion == AccionDeRegla.Bloquear ? "Bloquear " : "Permitir ")
                   + (direccion == DireccionDeRegla.Entrante ? "entrante " : "saliente ")
                   + GuardiaDeReglas.NombreDe(ruta) + " [" + sufijo + "]";
        }
    }
}
