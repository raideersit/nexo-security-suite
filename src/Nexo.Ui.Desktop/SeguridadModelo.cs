using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Media;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Ui.Desktop
{
    public sealed record FilaDeHallazgoVista(string Gravedad, IBrush Color, string Titulo, string Sujeto, bool TieneSujeto, string Detalle, string Recomendacion);

    public sealed record FilaDeSeccion(
        SeccionDeSeguridad Seccion,
        string Nombre,
        string Estado,
        IBrush Color,
        string Resumen,
        IReadOnlyList<FilaDeHallazgoVista> Hallazgos,
        IReadOnlyList<string> NoEvaluado,
        bool HayNoEvaluado,
        bool Revisando,
        bool PuedeRevisar)
    {
        /// <summary>Para el XAML: Avalonia no convierte un entero en booleano al enlazar IsVisible.</summary>
        public bool HayHallazgos => Hallazgos.Count > 0;
    }

    /// <summary>
    /// La pestaña «Seguridad». Tres revisiones (cuentas y contraseñas del sistema, redes Wi-Fi, aplicaciones desactualizadas), todas de
    /// SOLO LECTURA y a peticion del usuario: la de aplicaciones consulta Internet (winget), asi que nunca corre sola. Reglas:
    ///  - Nunca se muestra un resultado anterior como si fuera el actual: al empezar una revision se borra el anterior, y si falla se
    ///    dice por que.
    ///  - Nunca verde si no se sabe: una revision incompleta, no hecha o fallida no es «sin problemas».
    ///  - El color nunca va solo: siempre hay un texto con el mismo significado.
    /// </summary>
    public sealed class SeguridadModelo : INotifyPropertyChanged
    {
        private static readonly SeccionDeSeguridad[] Orden = { SeccionDeSeguridad.Cuentas, SeccionDeSeguridad.Wifi, SeccionDeSeguridad.Aplicaciones };

        private readonly IServicioDeSeguridad _servicio;
        private readonly Dictionary<SeccionDeSeguridad, Consulta<RevisionDeSeccion>?> _ultimas = new();
        private readonly HashSet<SeccionDeSeguridad> _revisando = new();

        public SeguridadModelo(IServicioDeSeguridad servicio)
        {
            _servicio = servicio;
            foreach (SeccionDeSeguridad s in Orden) _ultimas[s] = null;
            Calcular();
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public string Titulo { get; private set; } = "";
        public string Explicacion { get; private set; } = "";
        public IBrush Color { get; private set; } = Colores.De(Indicador.SinDatos);
        public IReadOnlyList<FilaDeSeccion> Secciones { get; private set; } = Array.Empty<FilaDeSeccion>();
        public bool PuedeRevisarTodo { get; private set; }
        public Indicador Indicador { get; private set; } = Indicador.SinDatos;

        /// <summary>Revisa las tres, una tras otra (la de aplicaciones tarda mas y consulta Internet).</summary>
        public async Task RevisarTodoAsync(CancellationToken ct = default)
        {
            foreach (SeccionDeSeguridad s in Orden)
            {
                if (ct.IsCancellationRequested) break;
                await RevisarAsync(s, ct);
            }
        }

        public async Task RevisarAsync(SeccionDeSeguridad seccion, CancellationToken ct = default)
        {
            if (_revisando.Contains(seccion)) return;
            _revisando.Add(seccion);
            _ultimas[seccion] = null; // jamas queda a la vista el resultado anterior mientras se vuelve a mirar
            Calcular();
            try
            {
                Consulta<RevisionDeSeccion> r;
                try { r = await _servicio.RevisarAsync(seccion, ct); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    r = Consulta<RevisionDeSeccion>.Mal("error inesperado al revisar (" + ex.GetType().Name + ")");
                }
                _ultimas[seccion] = r;
            }
            finally
            {
                _revisando.Remove(seccion);
                Calcular();
            }
        }

        // ------------------------------------------------------------
        private void Calcular()
        {
            var filas = new List<FilaDeSeccion>();
            foreach (SeccionDeSeguridad s in Orden)
            {
                bool rev = _revisando.Contains(s);
                Consulta<RevisionDeSeccion>? c = _ultimas[s];
                (Indicador ind, string estado, string resumen) = ResumirSeguridad.Seccion(s, c, rev);
                RevisionDeSeccion? v = c?.Valor;
                IReadOnlyList<HallazgoDeSistema> hs = v?.Analisis.Hallazgos ?? Array.Empty<HallazgoDeSistema>();
                IReadOnlyList<string> no = v?.Analisis.NoEvaluado ?? Array.Empty<string>();
                filas.Add(new FilaDeSeccion(
                    s, ResumirSeguridad.Nombre(s), estado, Colores.De(ind), resumen,
                    hs.Select(h => new FilaDeHallazgoVista(
                        ResumirSeguridad.Gravedad(h.Severidad), Colores.De(ResumirSeguridad.IndicadorDe(h.Severidad)), h.Titulo,
                        h.Sujeto ?? "", h.Sujeto is not null, h.Detalle, h.Recomendacion)).ToList(),
                    no, no.Count > 0, rev, !rev));
            }
            Secciones = filas;

            (Indicador general, string titulo, string explicacion) = ResumirSeguridad.General(Orden.Select(s => (_ultimas[s], _revisando.Contains(s))).ToList());
            Indicador = general;
            Titulo = titulo;
            Explicacion = explicacion;
            Color = Colores.De(general);
            PuedeRevisarTodo = _revisando.Count == 0;

            foreach (string n in new[] { nameof(Secciones), nameof(Titulo), nameof(Explicacion), nameof(Color), nameof(Indicador), nameof(PuedeRevisarTodo) })
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
        }
    }

    /// <summary>Los textos y colores de la pestaña «Seguridad», sin interfaz (se prueban en tools/Nexo.Desktop.Demo).</summary>
    public static class ResumirSeguridad
    {
        public static string Nombre(SeccionDeSeguridad s) => s switch
        {
            SeccionDeSeguridad.Cuentas => "Cuentas y contraseñas del sistema",
            SeccionDeSeguridad.Wifi => "Redes Wi-Fi",
            _ => "Aplicaciones desactualizadas"
        };

        public static string Gravedad(Severidad s) => s switch
        {
            Severidad.Critica => "Crítica",
            Severidad.Alta => "Alta",
            Severidad.Media => "Media",
            Severidad.Baja => "Baja",
            _ => "Info"
        };

        /// <summary>Alta o critica = alerta; media o baja = atencion; info = una nota sin color de alarma (gris).</summary>
        public static Indicador IndicadorDe(Severidad s) => s switch
        {
            Severidad.Critica or Severidad.Alta => Indicador.Alerta,
            Severidad.Media or Severidad.Baja => Indicador.Atencion,
            _ => Indicador.SinDatos
        };

        public static (Indicador, string, string) Seccion(SeccionDeSeguridad s, Consulta<RevisionDeSeccion>? c, bool revisando)
        {
            if (revisando) return (Indicador.SinDatos, "Revisando...", s == SeccionDeSeguridad.Aplicaciones ? "Consultando winget (usa Internet); puede tardar unos segundos." : "");
            if (c is null) return (Indicador.SinDatos, "Sin revisar", "Pulsa «Revisar» para comprobarlo.");
            if (c.Valor is not RevisionDeSeccion v) return (Indicador.SinDatos, "No se pudo revisar", (c.Error ?? "motivo desconocido") + ".");

            ResultadoDeAnalisis a = v.Analisis;
            string cuando = "revisado a las " + v.Fecha.ToLocalTime().ToString("HH:mm", System.Globalization.CultureInfo.InvariantCulture);
            string alcance = Alcance(s, v);

            // Un hecho que no es hallazgo ni fallo (p. ej. no hay adaptador Wi-Fi): nada que revisar, y se dice.
            if (v.Nota is not null && a.Hallazgos.Count == 0 && a.Completo) return (Indicador.Correcto, "No aplica", v.Nota);

            var partes = new List<string>();
            if (a.Hallazgos.Count > 0) partes.Add(a.Hallazgos.Count + (a.Hallazgos.Count == 1 ? " hallazgo" : " hallazgos"));
            if (alcance.Length > 0) partes.Add(alcance);
            partes.Add(cuando);
            string resumen = string.Join(" · ", partes);

            Indicador peor = a.Hallazgos.Count == 0 ? Indicador.Correcto : a.Hallazgos.Select(h => IndicadorDe(h.Severidad)).Aggregate(Mas);
            // Solo notas informativas: se ve la nota, pero sigue siendo «sin problemas».
            if (a.Hallazgos.Count > 0 && a.Hallazgos.All(h => h.Severidad == Severidad.Info)) peor = Indicador.Correcto;

            if (!a.Completo)
            {
                // Incompleta: como minimo atencion; si ademas hay algo grave, manda lo grave.
                Indicador ind = Mas(peor, Indicador.Atencion);
                return (ind, a.Hallazgos.Count > 0 ? "Hallazgos, revisión incompleta" : "Revisión incompleta", resumen);
            }
            return peor switch
            {
                Indicador.Alerta => (Indicador.Alerta, "Hay hallazgos graves", resumen),
                Indicador.Atencion => (Indicador.Atencion, "Hay cosas que revisar", resumen),
                _ => (Indicador.Correcto, a.Hallazgos.Count == 0 ? "Sin hallazgos" : "Sin problemas (solo notas)", resumen)
            };
        }

        public static (Indicador, string, string) General(IReadOnlyList<(Consulta<RevisionDeSeccion>? Consulta, bool Revisando)> secciones)
        {
            bool algunaRevisando = secciones.Any(x => x.Revisando);
            var hechas = secciones.Where(x => !x.Revisando && x.Consulta is not null).ToList();
            if (hechas.Count == 0)
                return (Indicador.SinDatos, algunaRevisando ? "Revisando..." : "Sin revisar todavía",
                        "Pulsa «Revisar todo» para comprobar las cuentas, el Wi-Fi y las aplicaciones. Solo se lee: ninguna revisión cambia nada en el equipo. La de aplicaciones consulta Internet (winget).");

            Indicador peor = hechas.Select(x => x.Consulta!.Valor is RevisionDeSeccion v ? IndicadorSeccion(v) : Indicador.SinDatos).Aggregate(Mas);
            bool todas = hechas.Count == secciones.Count;

            // Solo es verde si se miraron TODAS y todas salieron bien: lo no revisado, en curso o fallido nunca cuenta como bien.
            if (peor == Indicador.Alerta) return (Indicador.Alerta, "Hay hallazgos graves", "Mira las secciones marcadas en rojo.");
            if (peor == Indicador.Atencion) return (Indicador.Atencion, "Hay cosas que revisar", "Mira las secciones marcadas en amarillo.");
            if (!todas || peor == Indicador.SinDatos)
                return (Indicador.SinDatos, algunaRevisando ? "Revisando..." : "Revisión parcial", "Faltan secciones por revisar o alguna no se pudo revisar: esto no significa que esté bien.");
            return (Indicador.Correcto, "Sin problemas en lo que se pudo revisar", "Las tres revisiones salieron sin hallazgos que pidan acción. Solo se miran las cosas descritas abajo: no es una garantía de seguridad.");
        }

        private static Indicador IndicadorSeccion(RevisionDeSeccion v)
        {
            Indicador peor = v.Analisis.Hallazgos.Count == 0 ? Indicador.Correcto : v.Analisis.Hallazgos.Select(h => IndicadorDe(h.Severidad)).Aggregate(Mas);
            if (v.Analisis.Hallazgos.Count > 0 && v.Analisis.Hallazgos.All(h => h.Severidad == Severidad.Info)) peor = Indicador.Correcto;
            return v.Analisis.Completo ? peor : Mas(peor, Indicador.Atencion);
        }

        /// <summary>El peor de dos: Alerta &gt; Atencion &gt; SinDatos (no se sabe) &gt; Correcto.</summary>
        public static Indicador Mas(Indicador a, Indicador b) => Rango(a) >= Rango(b) ? a : b;

        private static int Rango(Indicador i) => i switch { Indicador.Alerta => 3, Indicador.Atencion => 2, Indicador.SinDatos => 1, _ => 0 };

        private static string Alcance(SeccionDeSeguridad s, RevisionDeSeccion v) => v.Elementos is not int n ? "" : s switch
        {
            SeccionDeSeguridad.Cuentas => n + (n == 1 ? " cuenta local" : " cuentas locales"),
            SeccionDeSeguridad.Wifi => n + (n == 1 ? " red guardada" : " redes guardadas"),
            _ => n + (n == 1 ? " aplicación con versión nueva" : " aplicaciones con versión nueva")
        };
    }
}
