namespace Nexo.Modules.Cleanup.Abstractions
{
    public enum MedioDeAlmacenamiento
    {
        /// <summary>No se pudo determinar (puente USB, RAID, volumen virtual…).</summary>
        Desconocido,
        Hdd,
        Ssd
    }

    /// <summary>
    /// Dice en que tipo de disco vive una ruta. Se abstrae porque la respuesta
    /// sale de una llamada a Windows (Nexo.Native) y porque las pruebas necesitan
    /// simular ambos casos.
    /// </summary>
    public interface IDetectorDeMedio
    {
        MedioDeAlmacenamiento Detectar(string ruta);
    }

    /// <summary>
    /// Valor por defecto: no sabe. Es el caso conservador, porque el triturador
    /// trata "desconocido" igual que SSD y avisa de que la garantia es parcial.
    /// </summary>
    public sealed class MedioDesconocido : IDetectorDeMedio
    {
        public MedioDeAlmacenamiento Detectar(string ruta) => MedioDeAlmacenamiento.Desconocido;
    }
}
