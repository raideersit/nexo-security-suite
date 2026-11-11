using System;
using System.Collections.Generic;

namespace Nexo.Modules.Cleanup.Perfiles
{
    // =====================================================================================================
    //  PERFILES DE ACTIVIDAD (fila 18 de la Salida 0; §1.5 de la Salida 4)
    //
    //  Qué hace: mira señales REALES del equipo (corriente o batería, pantalla completa, presentación) y decide un perfil:
    //  Normal, JuegoOVideo o Bateria. En JuegoOVideo y Bateria, Nexo POSPONE SUS PROPIAS tareas pesadas (escaneo programado, copia,
    //  limpieza) para no estorbar. Además avisa si la red Wi-Fi es abierta (eso es de seguridad, no de rendimiento).
    //
    //  Qué NO hace (a propósito, y por qué):
    //   - No cambia el plan de energía de Windows: en portátiles con Modern Standby, pelearse con el gobernador de energía suele empeorar
    //     las cosas (Salida 4 §1.5).
    //   - No cambia la prioridad de otros programas ni los cierra.
    //   - No apaga nada de la PROTECCIÓN: lo único que se pospone son tareas pesadas y aplazables de Nexo. El tiempo real sigue activo.
    //   - Lo que no se pudo leer es «no evaluado», y NUNCA hace que se pospongan cosas (un fallo de lectura no debe dejar la copia o el
    //     escaneo parados para siempre).
    // =====================================================================================================

    public enum Perfil { Normal, JuegoOVideo, Bateria }

    public enum FuenteDeEnergia { Desconocida, Corriente, Bateria }

    /// <summary>Lo que dice Windows (SHQueryUserNotificationState) sobre si el usuario está ocupado con algo a pantalla completa.</summary>
    public enum EstadoDePantalla
    {
        Desconocido,
        /// <summary>Escritorio normal: se pueden mostrar avisos.</summary>
        Libre,
        /// <summary>Una aplicación a pantalla completa (vídeo, navegador en F11, una app de la Tienda...).</summary>
        PantallaCompleta,
        /// <summary>Pantalla bloqueada o protector de pantalla: la persona no está. Es buen momento para tareas pesadas, no mal momento.</summary>
        Ausente,
        /// <summary>Un juego Direct3D a pantalla completa exclusiva.</summary>
        JuegoD3D,
        /// <summary>Modo de presentación de Windows.</summary>
        Presentacion,
        /// <summary>No molestar o horas de silencio de Windows.</summary>
        NoMolestar
    }

    /// <summary>Lo que se leyó en un instante. «Desconocida/Desconocido/null» = no se pudo leer (no es «no»).</summary>
    public sealed record SenalesDeActividad(
        FuenteDeEnergia Energia,
        int? BateriaPorCiento,
        bool? AhorroDeBateriaActivo,
        EstadoDePantalla Pantalla,
        bool? WifiAbierto);

    /// <summary>El perfil elegido en un instante, y por qué.</summary>
    public sealed record DecisionDePerfil(Perfil Perfil, bool PosponerTareasPesadas, bool AvisarWifiAbierto,
                                          IReadOnlyList<string> Motivos, IReadOnlyList<string> NoEvaluado);

    public static class ReglasDePerfil
    {
        /// <summary>Con este porcentaje o menos, en batería, el motivo dice «batería baja».</summary>
        public const int BateriaBaja = 20;

        public static DecisionDePerfil Decidir(SenalesDeActividad s)
        {
            var motivos = new List<string>();
            var no = new List<string>();

            if (s.Energia == FuenteDeEnergia.Desconocida) no.Add("energía: no se pudo saber si está enchufado");
            if (s.Pantalla == EstadoDePantalla.Desconocido) no.Add("pantalla: no se pudo saber si hay un juego o vídeo a pantalla completa");

            bool juego = s.Pantalla is EstadoDePantalla.JuegoD3D or EstadoDePantalla.Presentacion or EstadoDePantalla.PantallaCompleta;
            if (s.Pantalla == EstadoDePantalla.JuegoD3D) motivos.Add("hay un juego a pantalla completa");
            else if (s.Pantalla == EstadoDePantalla.Presentacion) motivos.Add("Windows está en modo de presentación");
            else if (s.Pantalla == EstadoDePantalla.PantallaCompleta) motivos.Add("hay una aplicación a pantalla completa (por ejemplo un vídeo)");
            // «No molestar» es una preferencia del usuario sobre avisos, no una señal de que el equipo vaya justo: no cambia el perfil.

            bool bateria = s.Energia == FuenteDeEnergia.Bateria;
            if (bateria)
            {
                motivos.Add(s.BateriaPorCiento is int p && p <= BateriaBaja ? "funciona con batería y queda poca (" + p + " %)" : "funciona con batería");
                if (s.AhorroDeBateriaActivo == true) motivos.Add("el ahorro de batería de Windows está activado");
            }

            Perfil perfil = juego ? Perfil.JuegoOVideo : bateria ? Perfil.Bateria : Perfil.Normal;
            // Solo se pospone con una razón conocida. Con lecturas fallidas el perfil es Normal: no se deja nada parado por no saber.
            return new DecisionDePerfil(perfil, perfil != Perfil.Normal, s.WifiAbierto == true,
                                        motivos, no);
        }
    }

    /// <summary>
    /// Quien llama al perfil cada pocos segundos. Evita el «parpadeo»: se ENTRA a un perfil de inmediato (un juego empieza y Nexo debe
    /// apartarse), pero solo se VUELVE a Normal tras <see cref="LecturasParaSalir"/> lecturas seguidas en Normal (un alt-tab, una
    /// notificación o un cambio breve de pantalla no debe reanudar de golpe las tareas pesadas).
    /// </summary>
    public sealed class SelectorDePerfil
    {
        public const int LecturasParaSalir = 3;

        private int _normalesSeguidas;

        public DecisionDePerfil Actual { get; private set; } = new DecisionDePerfil(Perfil.Normal, false, false, Array.Empty<string>(), Array.Empty<string>());

        public DecisionDePerfil Actualizar(SenalesDeActividad s)
        {
            DecisionDePerfil nueva = ReglasDePerfil.Decidir(s);
            if (nueva.Perfil == Perfil.Normal && Actual.Perfil != Perfil.Normal)
            {
                _normalesSeguidas++;
                if (_normalesSeguidas < LecturasParaSalir)
                {
                    // Se mantiene el perfil anterior (con sus motivos), pero el aviso de Wi-Fi y lo no evaluado son de AHORA.
                    Actual = Actual with { AvisarWifiAbierto = nueva.AvisarWifiAbierto, NoEvaluado = nueva.NoEvaluado };
                    return Actual;
                }
            }
            _normalesSeguidas = 0;
            Actual = nueva;
            return Actual;
        }
    }
}
