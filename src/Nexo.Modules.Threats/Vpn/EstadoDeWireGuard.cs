using System;
using System.Collections.Generic;

namespace Nexo.Modules.Threats.Vpn
{
    public enum EstadoDeTunel
    {
        Activo,
        Detenido,
        Cambiando,
        Desconocido
    }

    /// <summary>Un tunel instalado como servicio de Windows (<c>WireGuardTunnel$nombre</c>).</summary>
    public sealed record TunelInstalado(string Nombre, EstadoDeTunel Estado);

    /// <summary>
    /// Lo que se sabe de WireGuard en este equipo. Leerlo es de solo lectura y no necesita administrador. «Activo» es lo que Windows dice del
    /// servicio del tunel: que el servidor responda (el «handshake») no se puede saber sin administrador (<c>wg show</c>), y no se afirma.
    /// </summary>
    public sealed record EstadoDeWireGuard(bool Instalado, string? Version, string? Ruta, IReadOnlyList<TunelInstalado> Tuneles, bool GestorEnMarcha, string? Error)
    {
        public static EstadoDeWireGuard NoSePudo(string error) => new(false, null, null, Array.Empty<TunelInstalado>(), false, error);
    }

    public interface ILectorDeWireGuard
    {
        EstadoDeWireGuard Leer();
    }
}
