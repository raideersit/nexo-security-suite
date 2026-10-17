#if NETSTANDARD2_0
namespace System.Runtime.CompilerServices
{
    /// <summary>
    /// Polyfill necesario para usar propiedades 'init' al compilar contra
    /// netstandard2.0. En net8.0 el tipo ya existe en el framework.
    /// </summary>
    internal static class IsExternalInit { }
}
#endif
