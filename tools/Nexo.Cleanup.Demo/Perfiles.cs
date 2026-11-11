using System;
using System.Linq;
using Nexo.Modules.Cleanup.Perfiles;

namespace Nexo.Cleanup.Demo
{
    public static partial class Program
    {
        private static SenalesDeActividad Sen(FuenteDeEnergia e = FuenteDeEnergia.Corriente, EstadoDePantalla p = EstadoDePantalla.Libre,
                                              int? bat = null, bool? ahorro = null, bool? wifi = null)
            => new(e, bat, ahorro, p, wifi);

        private static void ProbarPerfiles()
        {
            Console.WriteLine("Perfiles de actividad (portable): reglas y histéresis");

            DecisionDePerfil d = ReglasDePerfil.Decidir(Sen());
            Check(d.Perfil == Perfil.Normal && !d.PosponerTareasPesadas && d.Motivos.Count == 0 && d.NoEvaluado.Count == 0, "enchufado y sin pantalla completa: Normal, no se pospone nada");

            d = ReglasDePerfil.Decidir(Sen(p: EstadoDePantalla.JuegoD3D));
            Check(d.Perfil == Perfil.JuegoOVideo && d.PosponerTareasPesadas && d.Motivos.Single().Contains("juego"), "un juego a pantalla completa: JuegoOVideo, se pospone, con motivo");
            Check(ReglasDePerfil.Decidir(Sen(p: EstadoDePantalla.Presentacion)).Perfil == Perfil.JuegoOVideo, "modo de presentación: JuegoOVideo");
            Check(ReglasDePerfil.Decidir(Sen(p: EstadoDePantalla.PantallaCompleta)).Perfil == Perfil.JuegoOVideo, "una aplicación a pantalla completa (vídeo): JuegoOVideo");

            d = ReglasDePerfil.Decidir(Sen(FuenteDeEnergia.Bateria, bat: 55));
            Check(d.Perfil == Perfil.Bateria && d.PosponerTareasPesadas && d.Motivos.Single() == "funciona con batería", "con batería: Bateria, se pospone");
            d = ReglasDePerfil.Decidir(Sen(FuenteDeEnergia.Bateria, bat: 15, ahorro: true));
            Check(d.Motivos.Any(m => m.Contains("queda poca (15 %)")) && d.Motivos.Any(m => m.Contains("ahorro de batería")), "batería baja y ahorro de Windows: lo dice");
            Check(!ReglasDePerfil.Decidir(Sen(FuenteDeEnergia.Bateria, bat: ReglasDePerfil.BateriaBaja + 1)).Motivos.Any(m => m.Contains("poca")), "21 %: todavía no es «poca»");
            Check(ReglasDePerfil.Decidir(Sen(FuenteDeEnergia.Bateria, bat: ReglasDePerfil.BateriaBaja)).Motivos.Any(m => m.Contains("poca")), "20 %: ya es «poca» (el límite incluido)");

            d = ReglasDePerfil.Decidir(Sen(FuenteDeEnergia.Bateria, EstadoDePantalla.JuegoD3D, 80));
            Check(d.Perfil == Perfil.JuegoOVideo && d.Motivos.Count == 2, "juego Y batería: manda JuegoOVideo y se dicen los dos motivos");

            // La pantalla bloqueada NO es un mal momento: es un buen momento para las tareas pesadas.
            d = ReglasDePerfil.Decidir(Sen(p: EstadoDePantalla.Ausente));
            Check(d.Perfil == Perfil.Normal && !d.PosponerTareasPesadas, "pantalla bloqueada o protector: Normal (buen momento para tareas pesadas)");
            Check(ReglasDePerfil.Decidir(Sen(p: EstadoDePantalla.NoMolestar)).Perfil == Perfil.Normal, "«No molestar» es una preferencia de avisos, no un perfil");

            // Lo desconocido: «no evaluado», y NUNCA deja cosas paradas.
            d = ReglasDePerfil.Decidir(Sen(FuenteDeEnergia.Desconocida, EstadoDePantalla.Desconocido));
            Check(d.Perfil == Perfil.Normal && !d.PosponerTareasPesadas && d.NoEvaluado.Count == 2, "no se pudo leer nada: Normal, NO se pospone, y se dice qué no se evaluó");

            // Wi-Fi abierto: aviso aparte, sin cambiar el perfil.
            d = ReglasDePerfil.Decidir(Sen(wifi: true));
            Check(d.AvisarWifiAbierto && d.Perfil == Perfil.Normal && !d.PosponerTareasPesadas, "Wi-Fi abierto: avisa, pero no es un perfil de rendimiento ni pospone nada");
            Check(!ReglasDePerfil.Decidir(Sen(wifi: false)).AvisarWifiAbierto && !ReglasDePerfil.Decidir(Sen(wifi: null)).AvisarWifiAbierto, "Wi-Fi cerrado o desconocido: sin aviso (no se inventa)");

            // Histéresis: entrar es inmediato; salir pide varias lecturas seguidas.
            var sel = new SelectorDePerfil();
            Check(sel.Actualizar(Sen()).Perfil == Perfil.Normal, "el selector empieza en Normal");
            Check(sel.Actualizar(Sen(p: EstadoDePantalla.JuegoD3D)).Perfil == Perfil.JuegoOVideo, "entrar a JuegoOVideo es inmediato");
            for (int i = 1; i < SelectorDePerfil.LecturasParaSalir; i++)
                Check(sel.Actualizar(Sen()).Perfil == Perfil.JuegoOVideo && sel.Actual.PosponerTareasPesadas, "lectura Normal " + i + " de " + SelectorDePerfil.LecturasParaSalir + ": se mantiene JuegoOVideo");
            Check(sel.Actualizar(Sen()).Perfil == Perfil.Normal && !sel.Actual.PosponerTareasPesadas, "a la tercera lectura Normal seguida, vuelve a Normal");

            // Un alt-tab breve no reanuda las tareas.
            sel.Actualizar(Sen(p: EstadoDePantalla.JuegoD3D));
            sel.Actualizar(Sen());
            sel.Actualizar(Sen());
            sel.Actualizar(Sen(p: EstadoDePantalla.JuegoD3D));
            sel.Actualizar(Sen());
            sel.Actualizar(Sen());
            Check(sel.Actual.Perfil == Perfil.JuegoOVideo, "dos Normales, un juego y dos Normales más: la racha se reinició, sigue JuegoOVideo");

            // Cambiar de un perfil a otro (no a Normal) es inmediato.
            Check(sel.Actualizar(Sen(FuenteDeEnergia.Bateria)).Perfil == Perfil.Bateria, "de JuegoOVideo a Bateria (sin pasar por Normal) es inmediato");

            // Al mantener el perfil, el aviso de Wi-Fi y lo no evaluado son de AHORA.
            var sel2 = new SelectorDePerfil();
            sel2.Actualizar(Sen(p: EstadoDePantalla.JuegoD3D));
            DecisionDePerfil mant = sel2.Actualizar(Sen(wifi: true));
            Check(mant.Perfil == Perfil.JuegoOVideo && mant.AvisarWifiAbierto, "manteniendo el perfil, el aviso de Wi-Fi abierto sale en el momento");
            mant = sel2.Actualizar(Sen(FuenteDeEnergia.Desconocida, EstadoDePantalla.Desconocido));
            Check(mant.Perfil == Perfil.JuegoOVideo && mant.NoEvaluado.Count == 2, "manteniendo el perfil, lo no evaluado se actualiza");

            // La puerta de tareas pesadas.
            var t0 = new DateTimeOffset(2026, 11, 11, 9, 0, 0, TimeSpan.Zero);
            Check(PuertaDeTareasPesadas.Abierta.Permite("x", t0) && PuertaDeTareasPesadas.Abierta.Pospuestas(t0).Count == 0, "sin perfiles (puerta abierta): siempre se puede");
            DecisionDePerfil? dec = new DecisionDePerfil(Perfil.Normal, false, false, Array.Empty<string>(), Array.Empty<string>());
            var puerta = new PuertaDeTareasPesadas(() => dec, TimeSpan.FromHours(1));
            Check(puerta.Permite("a", t0), "perfil Normal: se puede");
            dec = new DecisionDePerfil(Perfil.Bateria, true, false, new[] { "batería" }, Array.Empty<string>());
            Check(!puerta.Permite("a", t0) && !puerta.Permite("a", t0.AddMinutes(59)), "en batería se pospone, y volver a preguntar no reinicia la cuenta");
            Check(puerta.Permite("a", t0.AddMinutes(60)), "justo al cumplirse el máximo (60 min) ya corre");
            Check(!puerta.Permite("b", t0.AddMinutes(60)), "otra tarea tiene su propia cuenta (empieza ahora)");
            Check(puerta.Pospuestas(t0.AddMinutes(60)).Select(x => (x.Tarea, x.Forzada)).SequenceEqual(new[] { ("a", true), ("b", false) }), "lo pospuesto: «a» forzada, «b» no");
            puerta.Terminada("a");
            Check(!puerta.Permite("a", t0.AddMinutes(61)), "tras terminar, la espera de «a» empieza de cero");
            dec = new DecisionDePerfil(Perfil.Normal, false, false, Array.Empty<string>(), Array.Empty<string>());
            Check(puerta.Pospuestas(t0.AddMinutes(62)).Count == 0 && puerta.Permite("a", t0.AddMinutes(62)), "al volver a Normal no queda nada pospuesto y se puede");
            dec = new DecisionDePerfil(Perfil.Bateria, true, false, new[] { "batería" }, Array.Empty<string>());
            Check(!puerta.Permite("a", t0.AddMinutes(63)), "y si vuelve el perfil, la cuenta empieza de cero (la anterior se borró)");
            // Una espera vieja no se arrastra: tras pasar por Normal, volver horas después empieza de cero (no corre «forzada» de golpe).
            var p2 = new PuertaDeTareasPesadas(() => dec, TimeSpan.FromHours(1));
            Check(!p2.Permite("z", t0), "(z empieza a esperar en batería)");
            dec = new DecisionDePerfil(Perfil.Normal, false, false, Array.Empty<string>(), Array.Empty<string>());
            Check(p2.Permite("z", t0.AddMinutes(10)), "(z: perfil Normal, se puede)");
            dec = new DecisionDePerfil(Perfil.Bateria, true, false, new[] { "batería" }, Array.Empty<string>());
            Check(!p2.Permite("z", t0.AddHours(5)), "volver a batería 5 h después: espera desde cero, no corre por la espera de antes");
            Check(new PuertaDeTareasPesadas(() => dec, TimeSpan.Zero).MaximoDeEspera == PuertaDeTareasPesadas.MaximoPorOmision, "un máximo de 0 se cambia por el de por omisión (no hay «esperar para siempre» ni «no esperar»)");
        }
    }
}
