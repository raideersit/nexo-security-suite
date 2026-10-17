using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Nexo.Reports.Seguridad
{
    /// <summary>
    /// Aplica la politica de redaccion antes de que cualquier dato llegue al disco.
    /// Todo lo que entra al vault pasa por aqui.
    /// </summary>
    public sealed class Redactor
    {
        /// <summary>
        /// Fragmentos que, si aparecen en el NOMBRE de un campo, indican que el
        /// modulo esta a punto de escribir un secreto en texto plano.
        /// La lista es deliberadamente amplia y bilingue: un falso positivo cuesta
        /// renombrar un campo, un falso negativo cuesta filtrar una credencial.
        /// </summary>
        private static readonly string[] FragmentosProhibidos =
        {
            "password", "passwd", "contrasena", "contraseña", "clave",
            "secret", "secreto", "token", "apikey", "api_key",
            "privatekey", "private_key", "llaveprivada",
            "ntlm", "lmhash", "nthash", "sam",
            "masterpass", "claveMaestra", "seed", "recoverycode",
            "cvv", "pin", "cookie", "sessionid", "session_id", "bearer"
        };

        private readonly RedactionOptions _opciones;
        private readonly string _perfilUsuario;

        public Redactor(RedactionOptions opciones)
        {
            _opciones = opciones ?? throw new ArgumentNullException(nameof(opciones));
            _perfilUsuario = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        }

        /// <summary>
        /// Cortafuegos de campos secretos. Se llama por cada clave del front matter.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// Si el nombre del campo parece un secreto. Es intencionalmente una
        /// excepcion y no un warning: queremos que reviente en la primera prueba
        /// del modulo, no que pase inadvertido hasta produccion.
        /// </exception>
        public void VerificarNombreDeCampo(string nombreCampo)
        {
            if (!_opciones.RechazarCamposSecretos) return;
            if (string.IsNullOrEmpty(nombreCampo)) return;

            string normalizado = nombreCampo.Replace("_", "").Replace("-", "").ToLowerInvariant();
            foreach (string fragmento in FragmentosProhibidos)
            {
                string f = fragmento.Replace("_", "").ToLowerInvariant();
                if (normalizado.IndexOf(f, StringComparison.Ordinal) >= 0)
                {
                    throw new InvalidOperationException(
                        "Nexo.Reports rechazo el campo '" + nombreCampo + "': su nombre indica que " +
                        "contiene un secreto y el vault se guarda en texto plano. " +
                        "Registra en su lugar un indicador (por ejemplo 'credencial_expuesta: true') " +
                        "o una referencia a la entrada de la boveda, nunca el valor.");
                }
            }
        }

        /// <summary>Aplica el nivel de ruta configurado.</summary>
        public string Ruta(string? rutaOriginal)
        {
            if (string.IsNullOrWhiteSpace(rutaOriginal)) return "";
            string ruta = rutaOriginal!;

            switch (_opciones.Rutas)
            {
                case NivelRuta.SoloNombre:
                    return SafeFileName(ruta);

                case NivelRuta.RelativaAlPerfil:
                    if (!string.IsNullOrEmpty(_perfilUsuario) &&
                        ruta.StartsWith(_perfilUsuario, StringComparison.OrdinalIgnoreCase))
                    {
                        return "%USERPROFILE%" + ruta.Substring(_perfilUsuario.Length);
                    }
                    return ruta;

                case NivelRuta.Completa:
                default:
                    return ruta;
            }
        }

        private static string SafeFileName(string ruta)
        {
            try { return Path.GetFileName(ruta); }
            catch (ArgumentException) { return ruta; }
        }

        /// <summary>
        /// usuario.ejemplo@correo.cl -> usu***plo@correo.cl
        /// Se conserva el dominio completo: es lo que hace accionable la alerta
        /// ("tu cuenta de Gmail aparece en una brecha") sin exponer el buzon entero.
        /// </summary>
        public string Correo(string? correo)
        {
            if (string.IsNullOrWhiteSpace(correo)) return "";
            if (!_opciones.EnmascararCorreos) return correo!;

            int arroba = correo!.IndexOf('@');
            if (arroba <= 0) return "***";

            string local = correo.Substring(0, arroba);
            string dominio = correo.Substring(arroba);

            if (local.Length <= 2) return new string('*', local.Length) + dominio;
            if (local.Length <= 5) return local.Substring(0, 1) + new string('*', local.Length - 1) + dominio;

            return local.Substring(0, 3) + "***" + local.Substring(local.Length - 3) + dominio;
        }

        /// <summary>
        /// Recorta un texto libre que podria arrastrar datos sensibles hacia el
        /// cuerpo de la nota (por ejemplo, la linea de comandos de un proceso).
        /// </summary>
        public string TextoLibre(string? texto, int maxLargo = 500)
        {
            if (string.IsNullOrEmpty(texto)) return "";
            string t = texto!.Replace("\r\n", " ").Replace('\n', ' ').Replace('\r', ' ');
            return t.Length <= maxLargo ? t : t.Substring(0, maxLargo) + " […]";
        }

        /// <summary>
        /// Resuelve un valor marcado como <see cref="Model.Redactable"/> aplicando la
        /// politica. Los valores no marcados pasan intactos.
        /// </summary>
        public object? Resolver(object? valor) => valor switch
        {
            Model.Redactable r when r.Tipo == Model.Redactable.Clase.Ruta => Ruta(r.Valor),
            Model.Redactable r when r.Tipo == Model.Redactable.Clase.Correo => Correo(r.Valor),
            Model.Redactable r => TextoLibre(r.Valor),
            _ => valor
        };

        /// <summary>
        /// Verifica los nombres y aplica la redaccion a los valores de una coleccion
        /// de campos. Es el unico camino por el que los datos de un modulo llegan al
        /// front matter.
        /// </summary>
        public IEnumerable<KeyValuePair<string, object?>> Campos(IEnumerable<KeyValuePair<string, object?>> campos)
        {
            foreach (var par in campos)
            {
                VerificarNombreDeCampo(par.Key);
                yield return new KeyValuePair<string, object?>(par.Key, Resolver(par.Value));
            }
        }

        /// <summary>Texto de la advertencia que se escribe en el propio vault.</summary>
        public string DescribirPolitica()
        {
            var sb = new StringBuilder();
            sb.Append("- Rutas: **").Append(_opciones.Rutas).Append("**\n");
            sb.Append("- Correos enmascarados: **").Append(_opciones.EnmascararCorreos ? "si" : "no").Append("**\n");
            sb.Append("- Campos con nombre de secreto: **")
              .Append(_opciones.RechazarCamposSecretos ? "rechazados por la libreria" : "PERMITIDOS (inseguro)")
              .Append("**\n");
            return sb.ToString();
        }
    }
}
