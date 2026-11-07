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
        bool PuedeRevisar,
        string Boton = "Revisar")
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
        /// <summary>Las revisiones locales que corre «Revisar todo». El cruce con NVD NO esta aqui: envia datos a Internet y solo corre con su boton.</summary>
        private static readonly SeccionDeSeguridad[] Orden = { SeccionDeSeguridad.Cuentas, SeccionDeSeguridad.Wifi, SeccionDeSeguridad.Aplicaciones, SeccionDeSeguridad.Dispositivos };
        private static readonly SeccionDeSeguridad[] Todas = { SeccionDeSeguridad.Cuentas, SeccionDeSeguridad.Wifi, SeccionDeSeguridad.Aplicaciones, SeccionDeSeguridad.FallosConocidos, SeccionDeSeguridad.Dispositivos };

        private readonly IServicioDeSeguridad _servicio;
        private readonly Dictionary<SeccionDeSeguridad, Consulta<RevisionDeSeccion>?> _ultimas = new();
        private readonly HashSet<SeccionDeSeguridad> _revisando = new();
        private string? _progreso;

        public SeguridadModelo(IServicioDeSeguridad servicio)
        {
            _servicio = servicio;
            foreach (SeccionDeSeguridad s in Todas) _ultimas[s] = null;
            Calcular();
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>Donde se avisa de cada revision terminada (solo conteos y gravedad maxima, jamas nombres). Sin servicio, no deja rastro.</summary>
        public IRastroDeVentana Rastro { get; set; } = RastroNulo.Instancia;

        private static string ClaveDeRastro(SeccionDeSeguridad s) => s switch
        {
            SeccionDeSeguridad.Cuentas => "seguridad.cuentas",
            SeccionDeSeguridad.Wifi => "seguridad.wifi",
            SeccionDeSeguridad.Aplicaciones => "seguridad.aplicaciones",
            SeccionDeSeguridad.Dispositivos => "seguridad.dispositivos",
            _ => "seguridad.fallos_conocidos"
        };

        /// <summary>Una revision que no se pudo hacer queda como «incompleta, sin hallazgos»: lo desconocido no es «bien».</summary>
        private void AvisarRevision(SeccionDeSeguridad s, Consulta<RevisionDeSeccion> r)
        {
            int n = r.Valor?.Analisis.Hallazgos.Count(h => h.Severidad != Severidad.Info) ?? 0;
            string maxima = n == 0 ? "Info" : r.Valor!.Analisis.Hallazgos.Where(h => h.Severidad != Severidad.Info).Max(h => h.Severidad).ToString();
            var campos = new Dictionary<string, object?>(StringComparer.Ordinal) { ["hallazgos"] = n, ["maxima"] = maxima, ["completa"] = r.Valor?.Analisis.Completo ?? false };
            try { Rastro.Avisar(ClaveDeRastro(s), campos); } catch (Exception) { /* el rastro nunca rompe la revision */ }
        }

        public string Titulo { get; private set; } = "";
        public string Explicacion { get; private set; } = "";
        public IBrush Color { get; private set; } = Colores.De(Indicador.SinDatos);
        public IReadOnlyList<FilaDeSeccion> Secciones { get; private set; } = Array.Empty<FilaDeSeccion>();
        public bool PuedeRevisarTodo { get; private set; }
        public Indicador Indicador { get; private set; } = Indicador.SinDatos;

        /// <summary>Revisa las locales (cuentas, Wi-Fi, aplicaciones, cámara y micrófono), una tras otra (la de aplicaciones tarda mas y consulta Internet).</summary>
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
            // Mientras se cruza con NVD no se vuelve a leer la lista de aplicaciones: el cruce acabaria mostrandose sobre otra lista.
            if (seccion == SeccionDeSeguridad.Aplicaciones && _revisando.Contains(SeccionDeSeguridad.FallosConocidos)) return;
            _revisando.Add(seccion);
            // Los fallos conocidos se calcularon con la lista de aplicaciones de ANTES: si esa lista se vuelve a leer, ese cruce ya no vale.
            IReadOnlyList<AplicacionDesactualizada>? apps = _ultimas[SeccionDeSeguridad.Aplicaciones]?.Valor?.Aplicaciones;
            _ultimas[seccion] = null; // jamas queda a la vista el resultado anterior mientras se vuelve a mirar
            if (seccion == SeccionDeSeguridad.Aplicaciones) _ultimas[SeccionDeSeguridad.FallosConocidos] = null;
            _progreso = null;
            Calcular();
            try
            {
                Consulta<RevisionDeSeccion> r;
                try
                {
                    if (seccion == SeccionDeSeguridad.FallosConocidos)
                    {
                        r = apps is null
                            ? Consulta<RevisionDeSeccion>.Mal("primero revisa las aplicaciones desactualizadas: de ahí salen los programas y versiones que se consultan")
                            : await _servicio.RevisarFallosConocidosAsync(apps, new Progress<string>(t =>
                              {
                                  _progreso = t; // solo se muestra mientras la seccion esta revisando; un aviso tardio no cambia un resultado ya mostrado
                                  Calcular();
                              }), ct);
                    }
                    else r = await _servicio.RevisarAsync(seccion, ct);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    r = Consulta<RevisionDeSeccion>.Mal("error inesperado al revisar (" + ex.GetType().Name + ")");
                }
                _ultimas[seccion] = r;
                AvisarRevision(seccion, r);
            }
            finally
            {
                _revisando.Remove(seccion);
                _progreso = null;
                Calcular();
            }
        }

        // ------------------------------------------------------------
        private void Calcular()
        {
            var filas = new List<FilaDeSeccion>();
            foreach (SeccionDeSeguridad s in Todas)
            {
                bool rev = _revisando.Contains(s);
                Consulta<RevisionDeSeccion>? c = _ultimas[s];
                (Indicador ind, string estado, string resumen) = ResumirSeguridad.Seccion(s, c, rev, s == SeccionDeSeguridad.FallosConocidos ? _progreso : null);
                RevisionDeSeccion? v = c?.Valor;
                IReadOnlyList<HallazgoDeSistema> hs = v?.Analisis.Hallazgos ?? Array.Empty<HallazgoDeSistema>();
                IReadOnlyList<string> no = v?.Analisis.NoEvaluado ?? Array.Empty<string>();
                filas.Add(new FilaDeSeccion(
                    s, ResumirSeguridad.Nombre(s), estado, Colores.De(ind), resumen,
                    hs.Select(h => new FilaDeHallazgoVista(
                        ResumirSeguridad.Gravedad(h.Severidad), Colores.De(ResumirSeguridad.IndicadorDe(h.Severidad)), h.Titulo,
                        h.Sujeto ?? "", h.Sujeto is not null, h.Detalle, h.Recomendacion)).ToList(),
                    no, no.Count > 0, rev, !rev, ResumirSeguridad.Boton(s)));
            }
            Secciones = filas;

            // El cruce con NVD cuenta para el resultado general solo si ya se hizo (o esta en marcha): nunca se hace sin que el usuario lo pida.
            var paraGeneral = Orden.ToList();
            if (_ultimas[SeccionDeSeguridad.FallosConocidos] is not null || _revisando.Contains(SeccionDeSeguridad.FallosConocidos)) paraGeneral.Add(SeccionDeSeguridad.FallosConocidos);
            (Indicador general, string titulo, string explicacion) = ResumirSeguridad.General(paraGeneral.Select(s => (_ultimas[s], _revisando.Contains(s))).ToList());
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
            SeccionDeSeguridad.Aplicaciones => "Aplicaciones desactualizadas",
            SeccionDeSeguridad.Dispositivos => "Cámara y micrófono",
            _ => "Fallos de seguridad conocidos en tus aplicaciones (NVD)"
        };

        public static string Boton(SeccionDeSeguridad s) => s == SeccionDeSeguridad.FallosConocidos ? "Consultar NVD" : "Revisar";

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

        public static (Indicador, string, string) Seccion(SeccionDeSeguridad s, Consulta<RevisionDeSeccion>? c, bool revisando, string? progreso = null)
        {
            if (revisando)
                return (Indicador.SinDatos, "Revisando...", s switch
                {
                    SeccionDeSeguridad.Aplicaciones => "Consultando winget (usa Internet); puede tardar unos segundos.",
                    SeccionDeSeguridad.FallosConocidos => (progreso ?? "Preparando la consulta a NVD") + " (usa Internet; unos 7 segundos por programa).",
                    _ => ""
                });
            if (c is null)
                return (Indicador.SinDatos, "Sin revisar", s == SeccionDeSeguridad.FallosConocidos
                    ? "Opcional. Primero revisa las aplicaciones; después pulsa «Consultar NVD». Solo se envía a Internet el nombre y la versión de cada programa, y antes te lo pregunta."
                    : "Pulsa «Revisar» para comprobarlo.");
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
                        "Pulsa «Revisar todo» para comprobar las cuentas, el Wi-Fi, las aplicaciones y qué programas usaron la cámara y el micrófono. Solo se lee: ninguna revisión cambia nada en el equipo. La de aplicaciones consulta Internet (winget).");

            Indicador peor = hechas.Select(x => x.Consulta!.Valor is RevisionDeSeccion v ? IndicadorSeccion(v) : Indicador.SinDatos).Aggregate(Mas);
            bool todas = hechas.Count == secciones.Count;

            // Solo es verde si se miraron TODAS y todas salieron bien: lo no revisado, en curso o fallido nunca cuenta como bien.
            if (peor == Indicador.Alerta) return (Indicador.Alerta, "Hay hallazgos graves", "Mira las secciones marcadas en rojo.");
            if (peor == Indicador.Atencion) return (Indicador.Atencion, "Hay cosas que revisar", "Mira las secciones marcadas en amarillo.");
            if (!todas || peor == Indicador.SinDatos)
                return (Indicador.SinDatos, algunaRevisando ? "Revisando..." : "Revisión parcial", "Faltan secciones por revisar o alguna no se pudo revisar: esto no significa que esté bien.");
            return (Indicador.Correcto, "Sin problemas en lo que se pudo revisar", "Las revisiones salieron sin hallazgos que pidan acción. Solo se miran las cosas descritas abajo: no es una garantía de seguridad.");
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
            SeccionDeSeguridad.FallosConocidos => n + (n == 1 ? " programa consultado" : " programas consultados"),
            SeccionDeSeguridad.Dispositivos => n + (n == 1 ? " programa en el registro" : " programas en el registro"),
            _ => n + (n == 1 ? " aplicación con versión nueva" : " aplicaciones con versión nueva")
        };
    }
}
