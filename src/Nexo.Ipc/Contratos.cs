using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Nexo.Ipc
{
    /// <summary>Peticion al servicio. Estilo JSON-RPC 2.0, simplificado.</summary>
    public sealed class Solicitud
    {
        [JsonPropertyName("id")] public string? Id { get; set; }
        [JsonPropertyName("method")] public string? Metodo { get; set; }
        [JsonPropertyName("params")] public JsonElement? Parametros { get; set; }
    }

    public sealed class ErrorIpc
    {
        [JsonPropertyName("code")] public int Codigo { get; set; }
        [JsonPropertyName("message")] public string Mensaje { get; set; } = "";
    }

    public sealed class Respuesta
    {
        [JsonPropertyName("id")] public string? Id { get; set; }
        [JsonPropertyName("result")] public JsonElement? Resultado { get; set; }
        [JsonPropertyName("error")] public ErrorIpc? Error { get; set; }

        public bool Exito => Error is null;
    }

    /// <summary>Codigos de error (los negativos siguen a JSON-RPC 2.0).</summary>
    public static class CodigoDeError
    {
        public const int PeticionInvalida = -32600;
        public const int MetodoDesconocido = -32601;
        public const int ParametrosInvalidos = -32602;
        public const int ErrorInterno = -32603;
        public const int Tiempo = -32001;
    }

    /// <summary>Un fallo que el manejador quiere devolver al cliente con un codigo concreto.</summary>
    public sealed class ErrorDeComando : Exception
    {
        public ErrorDeComando(int codigo, string mensaje) : base(mensaje) => Codigo = codigo;
        public int Codigo { get; }
    }

    /// <summary>Quien atiende las peticiones. El servicio NO confia en el cliente: cada manejador valida.</summary>
    public interface IManejadorDeComandos
    {
        /// <returns>El resultado, que se serializa a JSON (o null).</returns>
        /// <exception cref="ErrorDeComando">Para devolver un error con codigo.</exception>
        System.Threading.Tasks.Task<object?> ManejarAsync(
            string metodo, JsonElement? parametros, System.Threading.CancellationToken ct);
    }
}
