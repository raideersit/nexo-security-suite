using System;

namespace Nexo.Reports.Model
{
    /// <summary>
    /// Envoltorio que marca un valor como sujeto a la politica de redaccion.
    ///
    /// Sin esto, el writer tendria que adivinar por el nombre del campo si un texto
    /// es una ruta o un correo. Con esto, el modulo declara la naturaleza del dato
    /// y la libreria decide cuanto de el llega al disco, segun la configuracion.
    ///
    ///   ev.Con("ruta", Redactable.Ruta(@"C:\Users\alvaro\Descargas\x.exe"))
    ///   // con NivelRuta.RelativaAlPerfil escribe: %USERPROFILE%\Descargas\x.exe
    /// </summary>
    public sealed class Redactable
    {
        public enum Clase
        {
            Ruta,
            Correo,
            TextoLibre
        }

        private Redactable(Clase tipo, string valor)
        {
            Tipo = tipo;
            Valor = valor ?? "";
        }

        public Clase Tipo { get; }
        public string Valor { get; }

        public static Redactable Ruta(string? valor) => new Redactable(Clase.Ruta, valor ?? "");
        public static Redactable Correo(string? valor) => new Redactable(Clase.Correo, valor ?? "");
        public static Redactable Texto(string? valor) => new Redactable(Clase.TextoLibre, valor ?? "");

        public override string ToString() => Valor;
    }
}
