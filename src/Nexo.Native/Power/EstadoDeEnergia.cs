using System;
using System.Runtime.InteropServices;

namespace Nexo.Native.Power
{
    /// <summary>Corriente o bateria segun GetSystemPowerStatus. <c>Desconocido</c> = Windows no lo sabe (ACLineStatus 255) o la llamada fallo.</summary>
    public enum LineaDeCorriente { Desconocida, Desconectada, Conectada }

    public readonly record struct LecturaDeEnergia(bool Correcta, LineaDeCorriente Corriente, int? BateriaPorCiento, bool? AhorroActivo, bool SinBateria);

    /// <summary>Estado de energia del equipo (GetSystemPowerStatus). Solo lectura, sin administrador. No lanza.</summary>
    public static class EstadoDeEnergia
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_POWER_STATUS
        {
            public byte ACLineStatus;
            public byte BatteryFlag;
            public byte BatteryLifePercent;
            public byte SystemStatusFlag;   // 1 = ahorro de bateria activado
            public uint BatteryLifeTime;
            public uint BatteryFullLifeTime;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS estado);

        public static LecturaDeEnergia Leer()
        {
            try
            {
                if (!GetSystemPowerStatus(out SYSTEM_POWER_STATUS s)) return new LecturaDeEnergia(false, LineaDeCorriente.Desconocida, null, null, false);
                return Interpretar(s.ACLineStatus, s.BatteryFlag, s.BatteryLifePercent, s.SystemStatusFlag);
            }
            catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException) { return new LecturaDeEnergia(false, LineaDeCorriente.Desconocida, null, null, false); }
        }

        /// <summary>La interpretacion de los bytes de Windows (separada para probarla con valores inventados).</summary>
        public static LecturaDeEnergia Interpretar(byte acLinea, byte banderaBateria, byte porciento, byte banderaSistema)
        {
            // BatteryFlag 128 = sin bateria (un equipo de escritorio): ACLineStatus suele ser 1. 255 = desconocido.
            bool sinBateria = banderaBateria == 128;
            LineaDeCorriente linea = acLinea switch { 0 => LineaDeCorriente.Desconectada, 1 => LineaDeCorriente.Conectada, _ => LineaDeCorriente.Desconocida };
            int? pct = porciento <= 100 ? porciento : null; // 255 = desconocido
            bool? ahorro = banderaSistema switch { 0 => false, 1 => true, _ => null };
            return new LecturaDeEnergia(true, linea, sinBateria ? null : pct, ahorro, sinBateria);
        }
    }
}
