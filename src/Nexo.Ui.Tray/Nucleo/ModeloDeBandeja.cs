using System;
using System.Collections.Generic;
using System.Linq;

namespace Nexo.Ui.Tray.Nucleo
{
    public enum EstadoDeBandeja
    {
        /// <summary>No se pudo hablar con el servicio: no se sabe nada, y se dice.</summary>
        Desconectado,
        /// <summary>Todo bien: tiempo real encendido y con cobertura completa, y nada sin revisar.</summary>
        Normal,
        /// <summary>Hay algo que atender, pero no una amenaza: tiempo real apagado, cobertura incompleta o motor caido.</summary>
        Atencion,
        /// <summary>Hay detecciones sin revisar, o un señuelo contra ransomware tocado.</summary>
        Alerta
    }

    /// <summary>
    /// Lo que muestra la bandeja, sin interfaz: que color, que texto y que avisos. Es una maquina de estados pura para poder
    /// probarla sin pantalla. NUNCA muestra «todo en orden» si no se sabe: sin conexion, tiempo real apagado, cobertura incompleta
    /// o motor caido NO son «Normal».
    /// </summary>
    public sealed class ModeloDeBandeja
    {
        private const int MaxTexto = 63;     // limite de NotifyIcon.Text

        private readonly HashSet<string> _notificadas = new HashSet<string>(StringComparer.Ordinal);
        private readonly HashSet<string> _revisadas = new HashSet<string>(StringComparer.Ordinal);
        private readonly HashSet<string> _senuelosAvisados = new HashSet<string>(StringComparer.Ordinal);
        private int _copiaAvisadas;      // cuántas copias sospechosas se avisaron ya con globo
        private InstantaneaDelServicio _ultima = InstantaneaDelServicio.SinConexion("sin consultar todavia");

        public EstadoDeBandeja Estado { get; private set; } = EstadoDeBandeja.Desconectado;
        public string Texto { get; private set; } = "Nexo: sin conexion con el servicio";

        /// <summary>Detecciones que el usuario aun no ha abierto para revisar.</summary>
        public IReadOnlyList<DeteccionVista> SinRevisar => _ultima.Detecciones.Where(d => !_revisadas.Contains(d.Clave)).ToList();

        public IReadOnlyList<DeteccionVista> Todas => _ultima.Detecciones;

        /// <summary>
        /// Señuelos que se tocaron desde la consulta anterior (para avisar con una notificación, una sola vez cada uno). Los tocados NO se
        /// marcan como revisados: la bandeja sigue en rojo hasta que se reponen, porque pueden ser la señal de un cifrado en marcha.
        /// </summary>
        public IReadOnlyList<SenueloTocadoVista> SenuelosNuevos { get; private set; } = Array.Empty<SenueloTocadoVista>();
        /// <summary>Hay una copia sospechosa guardada que todavía no se avisó con globo (una sola vez por cada una nueva).</summary>
        public bool CopiaSospechosaNueva { get; private set; }
        public InstantaneaDelServicio Ultima => _ultima;

        /// <summary>
        /// Incorpora una consulta nueva. Devuelve las detecciones que son NUEVAS (para avisar con una notificacion):
        /// cada una se avisa una sola vez, no en cada consulta.
        /// </summary>
        public IReadOnlyList<DeteccionVista> Actualizar(InstantaneaDelServicio i)
        {
            _ultima = i;

            var actuales = new HashSet<string>(i.Detecciones.Select(d => d.Clave), StringComparer.Ordinal);
            // Lo que ya no esta (se puso en cuarentena) se olvida: si reaparece, es una deteccion nueva.
            _notificadas.IntersectWith(actuales);
            _revisadas.IntersectWith(actuales);

            var nuevas = new List<DeteccionVista>();
            if (i.Conectado)
                foreach (DeteccionVista d in i.Detecciones)
                    if (_notificadas.Add(d.Clave)) nuevas.Add(d);

            // Señuelos: si no se pudo saber (SenuelosTocados null) se conserva lo avisado, para no repetir el aviso cuando vuelva.
            var senuelos = new List<SenueloTocadoVista>();
            if (i.Conectado && i.SenuelosTocados is { } tocados)
            {
                _senuelosAvisados.IntersectWith(tocados.Select(t => t.Clave));
                foreach (SenueloTocadoVista t in tocados)
                    if (_senuelosAvisados.Add(t.Clave)) senuelos.Add(t);
            }
            SenuelosNuevos = senuelos;
            // Copia de seguridad: si no se pudo hablar con el servicio se conserva lo avisado (no se repite el globo al volver).
            CopiaSospechosaNueva = false;
            if (i.Conectado)
            {
                CopiaSospechosaNueva = i.CopiaSospechosas > _copiaAvisadas;
                _copiaAvisadas = i.CopiaSospechosas;
            }

            Calcular();
            return nuevas;
        }

        /// <summary>El usuario abrio la revision: ya no cuentan como «sin revisar» (siguen listadas hasta que se resuelvan).</summary>
        public void MarcarRevisadas()
        {
            foreach (DeteccionVista d in _ultima.Detecciones) _revisadas.Add(d.Clave);
            Calcular();
        }

        private void Calcular()
        {
            InstantaneaDelServicio i = _ultima;
            int sinRevisar = SinRevisar.Count;

            if (!i.Conectado)
            {
                Estado = EstadoDeBandeja.Desconectado;
                Texto = Recortar("Nexo: sin conexion con el servicio");
            }
            else if (i.Tocados.Count > 0)
            {
                // Lo más urgente: puede ser un cifrado en marcha. Va antes que las detecciones.
                int n = i.Tocados.Count;
                Estado = EstadoDeBandeja.Alerta;
                Texto = Recortar(i.SenuelosEnRafaga ? "Nexo: POSIBLE RANSOMWARE (" + n + " señuelos tocados)"
                               : n == 1 ? "Nexo: señuelo contra ransomware tocado" : "Nexo: " + n + " señuelos contra ransomware tocados");
            }
            else if (i.CopiaSospechosas > 0)
            {
                // Muchos archivos cambiaron de golpe entre dos copias: puede ser un cifrado. Nexo conserva las versiones buenas.
                Estado = EstadoDeBandeja.Alerta;
                Texto = Recortar(i.CopiaSospechosas == 1 ? "Nexo: copia de seguridad sospechosa" : "Nexo: " + i.CopiaSospechosas + " copias sospechosas");
            }
            else if (sinRevisar > 0)
            {
                Estado = EstadoDeBandeja.Alerta;
                Texto = Recortar("Nexo: " + sinRevisar + (sinRevisar == 1 ? " deteccion sin revisar" : " detecciones sin revisar"));
            }
            else if (!i.TiempoRealActivo)
            {
                Estado = EstadoDeBandeja.Atencion;
                Texto = Recortar("Nexo: tiempo real apagado");
            }
            else if (i.MotorCaido)
            {
                Estado = EstadoDeBandeja.Atencion;
                Texto = Recortar("Nexo: el motor de analisis no responde");
            }
            else if (!i.CoberturaCompleta)
            {
                // Sin cifra de archivos: los contadores no la dan (un desborde de la fuente no dice cuantos fueron).
                Estado = EstadoDeBandeja.Atencion;
                int n = i.CarpetasPorRevisar.Count;
                Texto = Recortar(n == 0 ? "Nexo: cobertura incompleta"
                                        : "Nexo: cobertura incompleta (" + n + (n == 1 ? " carpeta" : " carpetas") + " por revisar)");
            }
            else if (i.CopiaFallida)
            {
                Estado = EstadoDeBandeja.Atencion;
                Texto = Recortar("Nexo: la última copia de seguridad falló");
            }
            else if (i.SenuelosError is not null)
            {
                // No poder leer los señuelos no es «ninguno tocado»: nunca verde sin saberlo.
                Estado = EstadoDeBandeja.Atencion;
                Texto = Recortar("Nexo: no se pudo leer el estado de los señuelos");
            }
            else if (i.Detecciones.Count > 0)
            {
                // Revisadas pero sin resolver: no es alarma, pero tampoco «todo en orden».
                Estado = EstadoDeBandeja.Atencion;
                Texto = Recortar("Nexo: " + i.Detecciones.Count + " detecciones sin resolver");
            }
            else
            {
                Estado = EstadoDeBandeja.Normal;
                Texto = Recortar("Nexo: todo en orden");
            }
        }

        private static string Recortar(string t) => t.Length <= MaxTexto ? t : t[..(MaxTexto - 1)] + "…";
    }
}
