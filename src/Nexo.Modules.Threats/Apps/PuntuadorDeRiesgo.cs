using System;
using System.Collections.Generic;
using System.Linq;

namespace Nexo.Modules.Threats.Apps
{
    /// <summary>
    /// Puntua una app por la SUMA de senales y combinaciones del catalogo (Salida 7, 3.1). Puntuacion, no veredicto:
    /// el mejor resultado posible es «a revisar» con motivos en lenguaje simple; nunca «es malware».
    /// Las apps del sistema no se evaluan. Una app «conocida» (gestor de contrasenas, antivirus) tiene permitidas sus senales esperables, pero solo si la instalo la tienda oficial.
    /// </summary>
    public sealed class PuntuadorDeRiesgo
    {
        private static readonly string[] PermisosSms = { "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS", "android.permission.RECEIVE_MMS", "android.permission.RECEIVE_WAP_PUSH" };
        private static readonly string[] PermisosLlamadas = { "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG", "android.permission.PROCESS_OUTGOING_CALLS", "android.permission.ANSWER_PHONE_CALLS" };
        private static readonly string[] PermisosUbicacion = { "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION" };

        private readonly CatalogoDeSenales _catalogo;

        public PuntuadorDeRiesgo(CatalogoDeSenales catalogo) => _catalogo = catalogo;

        /// <param name="confiadas">Paquetes que el usuario marco con «confio en esta app»: conservan sus puntos y motivos, pero salen como «Confiada».</param>
        public ResultadoDeApp Evaluar(ModeloDeApp app, IReadOnlySet<string>? confiadas = null)
        {
            var origen = app.EsDeSistema ? OrigenDeInstalacion.Desconocido : _catalogo.ClasificarOrigen(app.InstaladoPor);
            if (app.EsDeSistema)
                return new ResultadoDeApp(app.Paquete, app.Nombre, NivelDeRiesgo.NoEvaluada, 0, Array.Empty<string>(), Array.Empty<string>(), origen);

            var activas = SenalesDe(app, origen);
            // La excepcion solo vale si viene de la tienda oficial: ahi un nombre de paquete no se puede falsificar. Un APK suelto con el
            // nombre de un antivirus famoso NO la recibe.
            if (origen == OrigenDeInstalacion.TiendaOficial && _catalogo.AppsConocidas.TryGetValue(app.Paquete, out var conocida))
                activas.RemoveAll(conocida.Permite.Contains);

            int puntos = 0;
            var motivos = new List<(int Peso, string Texto)>();
            foreach (var id in activas)
            {
                var s = _catalogo.Senales[id];
                puntos += s.Peso;
                if (s.Peso > 0) motivos.Add((s.Peso, s.Motivo));
            }
            foreach (var c in _catalogo.Combinaciones)
            {
                if (c.Requiere.All(activas.Contains)) { puntos += c.Peso; motivos.Add((c.Peso, c.Motivo)); }
            }

            var nivel = puntos >= _catalogo.UmbralPrioritaria ? NivelDeRiesgo.Prioritaria
                      : puntos >= _catalogo.UmbralARevisar ? NivelDeRiesgo.ARevisar
                      : NivelDeRiesgo.Normal;
            if (nivel != NivelDeRiesgo.Normal && confiadas?.Contains(app.Paquete) == true) nivel = NivelDeRiesgo.Confiada;

            return new ResultadoDeApp(app.Paquete, app.Nombre, nivel, puntos,
                motivos.OrderByDescending(m => m.Peso).Select(m => m.Texto).ToList(), activas, origen);
        }

        /// <summary>Evalua una lista y la ordena: lo mas urgente primero, y a igual nivel, mas puntos primero.</summary>
        public IReadOnlyList<ResultadoDeApp> EvaluarTodas(IEnumerable<ModeloDeApp> apps, IReadOnlySet<string>? confiadas = null) =>
            apps.Select(a => Evaluar(a, confiadas))
                .OrderByDescending(r => r.Nivel == NivelDeRiesgo.Prioritaria ? 2 : r.Nivel == NivelDeRiesgo.ARevisar ? 1 : 0)
                .ThenByDescending(r => r.Puntos)
                .ThenBy(r => r.Paquete, StringComparer.Ordinal)
                .ToList();

        private static List<string> SenalesDe(ModeloDeApp a, OrigenDeInstalacion origen)
        {
            var l = new List<string>();
            if (a.AccesibilidadActiva) l.Add("accesibilidad");
            if (a.AdministradorActivo) l.Add("administrador");
            if (a.SuperposicionConcedida) l.Add("superposicion");
            if (a.OyenteDeNotificacionesActivo) l.Add("oyente_notificaciones");
            if (a.InstalaAppsConcedido) l.Add("instala_apps");
            if (PermisosSms.Any(a.PermisosConcedidos.Contains)) l.Add("sms");
            if (PermisosLlamadas.Any(a.PermisosConcedidos.Contains)) l.Add("llamadas");
            if (a.PermisosConcedidos.Contains("android.permission.CAMERA")) l.Add("camara");
            if (a.PermisosConcedidos.Contains("android.permission.RECORD_AUDIO")) l.Add("microfono");
            if (PermisosUbicacion.Any(a.PermisosConcedidos.Contains)) l.Add("ubicacion");
            if (a.PermisosConcedidos.Contains("android.permission.READ_CONTACTS")) l.Add("contactos");
            switch (origen)
            {
                case OrigenDeInstalacion.Navegador: l.Add("origen_navegador"); break;
                case OrigenDeInstalacion.ArchivoOAdb: l.Add("origen_archivo"); break;
                case OrigenDeInstalacion.OtraTienda: l.Add("origen_otra_tienda"); break;
            }
            if (a.SinIconoEnLanzador) l.Add("sin_icono");
            if (a.FirmaDeDepuracion) l.Add("firma_depuracion");
            return l;
        }
    }
}
