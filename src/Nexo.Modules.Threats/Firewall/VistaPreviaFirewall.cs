using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Nexo.Reports.Model;

namespace Nexo.Modules.Threats.Firewall
{
    public enum TipoDeCambio
    {
        Agregar,
        Eliminar
    }

    /// <summary>Un cambio concreto sobre una regla de Nexo.</summary>
    public sealed record CambioDeFirewall(TipoDeCambio Tipo, ReglaDeFirewall Regla)
    {
        /// <summary>Texto estable que entra en la huella del token.</summary>
        internal string Huella => string.Create(CultureInfo.InvariantCulture,
            $"{Tipo}|{Regla.Nombre}|{Regla.RutaApp}|{Regla.Direccion}|{Regla.Accion}|{(int)Regla.Perfiles}|{Regla.Protocolo}|{Regla.TiposIcmp}");

        public string Describir()
        {
            string accion = Regla.Accion == AccionDeRegla.Bloquear ? "BLOQUEAR" : "PERMITIR";
            string dir = Regla.Direccion == DireccionDeRegla.Entrante ? "entrante" : "saliente";
            string objetivo = Regla.RutaApp ?? (Regla.Protocolo is 1 ? "ICMPv4 Echo Request" : Regla.Protocolo is 58 ? "ICMPv6 Echo Request" : "(todo)");
            return (Tipo == TipoDeCambio.Agregar ? "+ " : "- ") + accion + " " + dir + "  " + TextoVisible.UnaLinea(objetivo)
                   + "   [" + TextoVisible.UnaLinea(Regla.Nombre) + "]";
        }
    }

    /// <summary>
    /// Prueba de que el usuario vio un plan de cambios concreto y lo aprobo. Misma
    /// idea que TokenConfirmacion del limpiador: no es un booleano, lleva la huella
    /// del plan exacto, caduca, y al aplicar se recalcula sobre el plan que llega.
    /// Un proceso que pida aplicar otro plan distinto no tiene un token valido.
    /// </summary>
    public sealed class TokenDeCambio
    {
        public static readonly TimeSpan Vigencia = TimeSpan.FromMinutes(10);

        private TokenDeCambio(string huella, DateTimeOffset expira)
        {
            Huella = huella;
            Expira = expira;
        }

        public string Huella { get; }
        public DateTimeOffset Expira { get; }

        public static TokenDeCambio Emitir(IEnumerable<CambioDeFirewall> plan, DateTimeOffset ahora)
            => Emitir(plan.Select(c => c.Huella), ahora);

        public bool EsValidoPara(IEnumerable<CambioDeFirewall> plan, DateTimeOffset ahora)
            => EsValidoPara(plan.Select(c => c.Huella), ahora);

        /// <summary>
        /// Token sobre un plan descrito como lineas de texto estables. Lo usan
        /// otras acciones con vista previa (p. ej. la cuarentena) para no
        /// duplicar la logica de huella y caducidad.
        /// </summary>
        public static TokenDeCambio Emitir(IEnumerable<string> lineas, DateTimeOffset ahora)
            => new TokenDeCambio(CalcularHuella(lineas), ahora + Vigencia);

        public bool EsValidoPara(IEnumerable<string> lineas, DateTimeOffset ahora)
            => ahora <= Expira
               && CryptographicOperations.FixedTimeEquals(
                      Encoding.ASCII.GetBytes(Huella),
                      Encoding.ASCII.GetBytes(CalcularHuella(lineas)));

        private static string CalcularHuella(IEnumerable<string> entrada)
        {
            // El orden se normaliza: la huella no depende de como se armo el plan.
            var lineas = entrada.ToList();
            lineas.Sort(StringComparer.Ordinal);
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", lineas)));
            return Convert.ToHexString(hash);
        }
    }

    /// <summary>Plan de cambios propuesto, todavia sin aplicar.</summary>
    public sealed class VistaPreviaFirewall
    {
        public VistaPreviaFirewall(
            string titulo,
            IReadOnlyList<CambioDeFirewall> cambios,
            IReadOnlyList<string> rechazos,
            IReadOnlyList<string> advertencias,
            TokenDeCambio token,
            bool esModoSigiloso = false,
            bool activarSigiloso = false)
        {
            Titulo = titulo;
            Cambios = cambios;
            Rechazos = rechazos;
            Advertencias = advertencias;
            Token = token;
            EsModoSigiloso = esModoSigiloso;
            ActivarSigiloso = activarSigiloso;
        }

        public string Titulo { get; }
        public IReadOnlyList<CambioDeFirewall> Cambios { get; }

        /// <summary>Lo que se pidio y NO se hara, con el motivo. Nunca se descarta en silencio.</summary>
        public IReadOnlyList<string> Rechazos { get; }

        /// <summary>Cosas que el usuario debe saber aunque no impidan aplicar el plan.</summary>
        public IReadOnlyList<string> Advertencias { get; }

        public TokenDeCambio Token { get; }

        internal bool EsModoSigiloso { get; }
        internal bool ActivarSigiloso { get; }

        public bool HayCambios => Cambios.Count > 0;

        public string Describir()
        {
            var sb = new StringBuilder();
            sb.Append(Titulo).Append('\n');
            if (Cambios.Count == 0) sb.Append("  (sin cambios)\n");
            foreach (CambioDeFirewall c in Cambios) sb.Append("  ").Append(c.Describir()).Append('\n');
            foreach (string r in Rechazos) sb.Append("  RECHAZADO: ").Append(TextoVisible.UnaLinea(r)).Append('\n');
            foreach (string a in Advertencias) sb.Append("  AVISO: ").Append(TextoVisible.UnaLinea(a)).Append('\n');
            return sb.ToString();
        }
    }

    public sealed class ResultadoFirewall
    {
        public ResultadoFirewall(int aplicados, IReadOnlyList<string> omitidos)
        {
            Aplicados = aplicados;
            Omitidos = omitidos;
        }

        public int Aplicados { get; }
        public IReadOnlyList<string> Omitidos { get; }
    }
}
