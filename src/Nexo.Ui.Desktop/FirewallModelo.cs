using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Media;
using Nexo.Ui.Desktop.Nucleo;

namespace Nexo.Ui.Desktop
{
    public sealed record FilaDePerfil(string Perfil, string Estado, string Entrada, IBrush Color);

    public sealed record FilaDeRegla(string Nombre, string Programa, string Accion, string Direccion, string Habilitada);

    /// <summary>
    /// La pestaña «Firewall». Lee firewall.estado; bloquear un programa, quitar una regla de Nexo y el modo sigiloso van con
    /// vista previa del servicio, confirmacion y token. Si no se pudo leer, no se muestra nada viejo ni se ofrecen acciones que
    /// dependen del estado (no se sabe si el sigiloso esta activado, asi que no se ofrece «activar» ni «desactivar»).
    /// </summary>
    public sealed class FirewallModelo : INotifyPropertyChanged
    {
        private readonly IServicioDeFirewall _servicio;
        private IReadOnlyList<FilaDePerfil> _perfiles = Array.Empty<FilaDePerfil>();
        private IReadOnlyList<FilaDeRegla> _reglas = Array.Empty<FilaDeRegla>();
        private FilaDeRegla? _seleccionada;
        private bool? _sigiloso;
        private bool _leido;
        private bool _ocupado;
        private string _resumen = "Sin consultar todavía.";
        private string _mensaje = "";
        private int _direccion;

        public FirewallModelo(IServicioDeFirewall servicio) => _servicio = servicio;

        public event PropertyChangedEventHandler? PropertyChanged;

        public IReadOnlyList<FilaDePerfil> Perfiles { get => _perfiles; private set { _perfiles = value; Avisar(); } }
        public IReadOnlyList<FilaDeRegla> Reglas { get => _reglas; private set { _reglas = value; Avisar(); } }
        public FilaDeRegla? Seleccionada { get => _seleccionada; set { if (_seleccionada == value) return; _seleccionada = value; Avisar(); Recalcular(); } }

        public bool Leido { get => _leido; private set { _leido = value; Avisar(); } }
        public string Resumen { get => _resumen; private set { _resumen = value; Avisar(); } }
        public string Mensaje { get => _mensaje; private set { if (_mensaje == value) return; _mensaje = value; Avisar(); } }

        /// <summary>null si no se sabe (no se pudo leer).</summary>
        public bool? Sigiloso => _sigiloso;
        public string TextoSigiloso { get; private set; } = "Sin datos.";
        public string TextoBotonSigiloso { get; private set; } = "Modo sigiloso...";

        public IReadOnlyList<string> OpcionesDeDireccion { get; } = new[] { "Entrante y saliente", "Solo saliente", "Solo entrante" };
        public int DireccionElegida { get => _direccion; set { if (_direccion == value) return; _direccion = value; Avisar(); } }
        public DireccionPedida Direccion => _direccion switch { 1 => DireccionPedida.Saliente, 2 => DireccionPedida.Entrante, _ => DireccionPedida.Ambas };

        public bool PuedeBloquear { get; private set; }
        public bool PuedeQuitar { get; private set; }
        public bool PuedeCambiarSigiloso { get; private set; }

        public async Task ActualizarAsync(CancellationToken ct = default)
        {
            if (_ocupado) return;
            _ocupado = true;
            Recalcular();
            try
            {
                Consulta<DetalleDeFirewall> c = await _servicio.EstadoAsync(ct);
                if (c.Valor is not DetalleDeFirewall d)
                {
                    Leido = false;
                    _sigiloso = null;
                    Perfiles = Array.Empty<FilaDePerfil>();
                    Reglas = Array.Empty<FilaDeRegla>();
                    Seleccionada = null;
                    Resumen = "No se pudo leer el firewall: " + c.Error + ".";
                    return;
                }

                Leido = true;
                _sigiloso = d.Sigiloso;
                Perfiles = d.Perfiles.Select(p => new FilaDePerfil(
                    LectorDeFirewall.NombreDePerfil(p.Perfil),
                    p.Activo ? "Activado" : "DESACTIVADO",
                    p.EntradaPorDefecto == "Bloquear" ? "bloquea lo entrante no pedido"
                        : p.EntradaPorDefecto == "Permitir" ? "PERMITE lo entrante por defecto" : p.EntradaPorDefecto,
                    Colores.De(!p.Activo || p.EntradaPorDefecto == "Permitir" ? Indicador.Atencion : Indicador.Correcto))).ToList();

                string? antes = _seleccionada?.Nombre;
                Reglas = d.Reglas.Select(r => new FilaDeRegla(
                    r.Nombre, r.Ruta ?? r.Nombre, r.Accion, r.Direccion, r.Habilitada ? "Sí" : "No")).ToList();
                Seleccionada = _reglas.FirstOrDefault(r => r.Nombre == antes);

                int apagados = d.Perfiles.Count(p => !p.Activo);
                Resumen = d.Perfiles.Count == 0 ? "El servicio no informó los perfiles del firewall."
                    : apagados > 0 ? "El firewall de Windows está DESACTIVADO en " + (apagados == 1 ? "1 perfil" : apagados + " perfiles")
                                     + ". Nexo no lo enciende: solo avisa."
                    : "El firewall de Windows está activado en todos los perfiles.";
            }
            finally
            {
                _ocupado = false;
                Recalcular();
            }
        }

        /// <summary>Paso 1 de bloquear un programa: que reglas crearia el servicio (o por que se niega). No cambia nada.</summary>
        public Task<Consulta<PlanDelServicio>> PrevisualizarBloqueoAsync(string? rutaDelPrograma, CancellationToken ct = default)
            => string.IsNullOrWhiteSpace(rutaDelPrograma)
                ? Task.FromResult(Consulta<PlanDelServicio>.Mal("elija el programa que quiere bloquear"))
                : _servicio.PrevisualizarBloqueoAsync(rutaDelPrograma.Trim(), Direccion, ct);

        /// <summary>Paso 1 de quitar la regla elegida. El servicio solo quita reglas de Nexo.</summary>
        public Task<Consulta<PlanDelServicio>> PrevisualizarQuitarAsync(CancellationToken ct = default)
            => _seleccionada is null
                ? Task.FromResult(Consulta<PlanDelServicio>.Mal("elija una regla de la lista"))
                : _servicio.PrevisualizarQuitarAsync(_seleccionada.Nombre, ct);

        /// <summary>Paso 1 de cambiar el modo sigiloso al contrario de como esta. Si no se sabe como esta, no se pide nada.</summary>
        public Task<Consulta<PlanDelServicio>> PrevisualizarSigilosoAsync(CancellationToken ct = default)
            => _sigiloso is bool actual
                ? _servicio.PrevisualizarSigilosoAsync(!actual, ct)
                : Task.FromResult(Consulta<PlanDelServicio>.Mal("no se sabe si el modo sigiloso está activado; actualice primero"));

        public async Task<ResultadoDeAccion> AplicarAsync(string token, CancellationToken ct = default)
        {
            ResultadoDeAccion r = await _servicio.AplicarAsync(token, ct);
            Mensaje = r.Mensaje;
            await ActualizarAsync(ct);
            return r;
        }

        // ------------------------------------------------------------
        private void Recalcular()
        {
            PuedeBloquear = !_ocupado && _leido;
            PuedeQuitar = !_ocupado && _leido && _seleccionada is not null;
            PuedeCambiarSigiloso = !_ocupado && _sigiloso is not null;
            TextoSigiloso = _sigiloso switch
            {
                true => "Activado: el equipo no contesta al ping (ICMPv4 e ICMPv6).",
                false => "Desactivado: el equipo contesta al ping.",
                _ => "Sin datos."
            };
            TextoBotonSigiloso = _sigiloso switch
            {
                true => "Desactivar modo sigiloso...",
                false => "Activar modo sigiloso...",
                _ => "Modo sigiloso..."
            };
            foreach (string p in new[] { nameof(PuedeBloquear), nameof(PuedeQuitar), nameof(PuedeCambiarSigiloso), nameof(Sigiloso),
                                         nameof(TextoSigiloso), nameof(TextoBotonSigiloso) })
                Avisar(p);
        }

        private void Avisar([CallerMemberName] string? nombre = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nombre));
    }
}
