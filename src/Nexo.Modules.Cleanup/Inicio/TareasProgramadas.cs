using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml;

namespace Nexo.Modules.Cleanup.Inicio
{
    /// <summary>Cuando arranca una tarea programada, de lo que importa para el inicio del equipo.</summary>
    public enum DisparadorDeInicio
    {
        /// <summary>LogonTrigger: al iniciar sesion.</summary>
        InicioDeSesion,
        /// <summary>BootTrigger: al arrancar el equipo, antes de que nadie inicie sesion.</summary>
        Arranque
    }

    /// <summary>Una tarea programada que se ejecuta al arrancar o al iniciar sesion.</summary>
    /// <param name="Ruta">Ruta dentro del Programador de tareas (\Carpeta\Nombre), sacada del archivo, no del XML.</param>
    /// <param name="Comandos">Ejecutable y argumentos de cada accion Exec, tal cual.</param>
    /// <param name="TieneAccionCom">Tiene acciones COM (ComHandler): ejecutan codigo que no aparece como un comando.</param>
    /// <param name="Usuario">Usuario o SID con el que corre, si el XML lo dice.</param>
    /// <param name="Retraso">El menor retraso de sus disparadores de inicio, si tiene.</param>
    public sealed record TareaDeInicio(
        string Ruta,
        IReadOnlyList<DisparadorDeInicio> Disparadores,
        IReadOnlyList<string> Comandos,
        bool TieneAccionCom,
        bool Habilitada,
        bool Oculta,
        string? Usuario,
        bool MaximosPrivilegios,
        TimeSpan? Retraso,
        string? Autor)
    {
        /// <summary>
        /// Esta bajo \Microsoft\. Es una CATEGORIA, no una garantia: cualquier administrador (o un malware con
        /// permisos) puede crear tareas ahi para pasar desapercibido.
        /// </summary>
        public bool EnCarpetaDeMicrosoft => Ruta.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Interpreta el XML de una tarea del Programador de tareas (el formato de C:\Windows\System32\Tasks y de
    /// <c>schtasks /query /xml</c>). Es portable: recibe texto.
    ///
    /// Defensivo como los analizadores de eventos: sin DTD ni entidades, tamano acotado, y un comando con
    /// caracteres de control rechaza la tarea entera (acabaria en la consola o en una nota). Lo que el esquema
    /// da por omitido se respeta: una tarea o un disparador sin &lt;Enabled&gt; estan habilitados.
    /// </summary>
    public static class ParserDeTareaProgramada
    {
        public const int MaximoCaracteres = 256 * 1024;
        private const string EspacioDeNombres = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        private const int MaximoAcciones = 32;

        /// <summary>
        /// Lee una tarea. Devuelve true tambien si la tarea NO es de inicio: en ese caso <paramref name="tarea"/>
        /// es null y <paramref name="motivo"/> tambien (se entendio, simplemente no interesa).
        /// </summary>
        public static bool TryParse(string? xml, string ruta, out TareaDeInicio? tarea, out string? motivo)
        {
            tarea = null;
            motivo = null;
            if (string.IsNullOrWhiteSpace(xml)) { motivo = "XML vacio"; return false; }
            if (xml.Length > MaximoCaracteres) { motivo = "XML demasiado grande"; return false; }

            var ajustes = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaximoCaracteres,
                MaxCharactersFromEntities = 0,
                IgnoreComments = true,
                IgnoreProcessingInstructions = true
            };

            var doc = new XmlDocument { XmlResolver = null };
            try
            {
                using var texto = new StringReader(xml);
                using XmlReader r = XmlReader.Create(texto, ajustes);
                doc.Load(r);
            }
            catch (XmlException e) { motivo = "XML invalido: " + e.Message; return false; }

            XmlElement? raiz = doc.DocumentElement;
            if (raiz is null || raiz.LocalName != "Task" || raiz.NamespaceURI != EspacioDeNombres)
            { motivo = "no es una tarea del Programador de tareas"; return false; }

            var ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("t", EspacioDeNombres);

            // --- Disparadores de inicio, solo los habilitados ---
            var disparadores = new List<DisparadorDeInicio>();
            TimeSpan? retraso = null;
            foreach (XmlElement d in Hijos(raiz.SelectSingleNode("t:Triggers", ns)))
            {
                DisparadorDeInicio? tipo = d.LocalName switch
                {
                    "LogonTrigger" => DisparadorDeInicio.InicioDeSesion,
                    "BootTrigger" => DisparadorDeInicio.Arranque,
                    _ => null
                };
                if (tipo is null) continue;
                bool? activo = Booleano(d.SelectSingleNode("t:Enabled", ns)?.InnerText);
                if (activo is null && d.SelectSingleNode("t:Enabled", ns) is not null)
                { motivo = "valor de Enabled desconocido en un disparador"; return false; }
                if (activo == false) continue;

                if (!disparadores.Contains(tipo.Value)) disparadores.Add(tipo.Value);
                if (Duracion(d.SelectSingleNode("t:Delay", ns)?.InnerText) is { } r && (retraso is null || r < retraso)) retraso = r;
            }
            if (disparadores.Count == 0) return true;   // se entendio; no es de inicio

            // --- Acciones ---
            var comandos = new List<string>();
            bool com = false;
            int acciones = 0;
            foreach (XmlElement a in Hijos(raiz.SelectSingleNode("t:Actions", ns)))
            {
                if (++acciones > MaximoAcciones) { motivo = "demasiadas acciones"; return false; }
                if (a.LocalName == "ComHandler") { com = true; continue; }
                if (a.LocalName != "Exec") continue;   // SendEmail y ShowMessage estan obsoletas y no ejecutan nada

                string comando = (a.SelectSingleNode("t:Command", ns)?.InnerText ?? "").Trim();
                string argumentos = (a.SelectSingleNode("t:Arguments", ns)?.InnerText ?? "").Trim();
                if (comando.Length == 0) { motivo = "una accion Exec sin comando"; return false; }
                if (ContieneControl(comando) || ContieneControl(argumentos))
                { motivo = "el comando contiene caracteres de control"; return false; }

                // Con comillas si tiene espacios, para que se lea igual que una linea de Run.
                string exe = comando.Contains(' ') && comando[0] != '"' ? "\"" + comando + "\"" : comando;
                comandos.Add(argumentos.Length == 0 ? exe : exe + " " + argumentos);
            }

            // --- Ajustes y principal ---
            XmlNode? ajustesTarea = raiz.SelectSingleNode("t:Settings", ns);
            XmlNode? nodoHabilitada = ajustesTarea?.SelectSingleNode("t:Enabled", ns);
            bool? habilitada = nodoHabilitada is null ? true : Booleano(nodoHabilitada.InnerText);
            if (habilitada is null) { motivo = "valor de Enabled desconocido en la tarea"; return false; }
            bool oculta = Booleano(ajustesTarea?.SelectSingleNode("t:Hidden", ns)?.InnerText) == true;

            XmlNode? principal = raiz.SelectSingleNode("t:Principals/t:Principal", ns);
            string? usuario = Limpio(principal?.SelectSingleNode("t:UserId", ns)?.InnerText)
                              ?? Limpio(principal?.SelectSingleNode("t:GroupId", ns)?.InnerText);
            bool maximos = principal?.SelectSingleNode("t:RunLevel", ns)?.InnerText.Trim() == "HighestAvailable";
            string? autor = Limpio(raiz.SelectSingleNode("t:RegistrationInfo/t:Author", ns)?.InnerText);

            tarea = new TareaDeInicio(ruta, disparadores, comandos, com, habilitada.Value, oculta, usuario, maximos, retraso, autor);
            return true;
        }

        private static IEnumerable<XmlElement> Hijos(XmlNode? nodo)
            => nodo is null ? Enumerable.Empty<XmlElement>() : nodo.ChildNodes.OfType<XmlElement>();

        private static bool? Booleano(string? s) => s?.Trim() switch
        {
            "true" or "1" => true,
            "false" or "0" => false,
            _ => null
        };

        private static TimeSpan? Duracion(string? s)
        {
            if (string.IsNullOrWhiteSpace(s)) return null;
            try { TimeSpan t = XmlConvert.ToTimeSpan(s.Trim()); return t >= TimeSpan.Zero ? t : null; }
            catch (FormatException) { return null; }
            catch (OverflowException) { return null; }
        }

        /// <summary>Texto informativo: si trae caracteres de control se omite, no invalida la tarea.</summary>
        private static string? Limpio(string? s)
            => string.IsNullOrWhiteSpace(s) || ContieneControl(s.Trim()) ? null : s.Trim();

        private static bool ContieneControl(string s)
        {
            foreach (char c in s)
                if (char.IsControl(c)) return true;
            return false;
        }
    }

    /// <summary>Las tareas de inicio encontradas y lo que no se pudo leer.</summary>
    public sealed class InventarioDeTareas
    {
        public InventarioDeTareas(bool carpetaDisponible, string? motivo, IReadOnlyList<TareaDeInicio> tareas,
                                  int archivosLeidos, IReadOnlyList<string> ilegibles, IReadOnlyList<string> descartadas, bool truncado)
        {
            CarpetaDisponible = carpetaDisponible; Motivo = motivo; Tareas = tareas; ArchivosLeidos = archivosLeidos;
            Ilegibles = ilegibles; Descartadas = descartadas; Truncado = truncado;
        }

        public bool CarpetaDisponible { get; }
        public string? Motivo { get; }

        /// <summary>Tareas que se ejecutan al arrancar o al iniciar sesion, por ruta.</summary>
        public IReadOnlyList<TareaDeInicio> Tareas { get; }

        public int ArchivosLeidos { get; }

        /// <summary>Archivos o carpetas sin permiso de lectura (casi todas las de \Microsoft\ sin administrador).</summary>
        public IReadOnlyList<string> Ilegibles { get; }

        /// <summary>Archivos que no se pudieron interpretar, con el motivo.</summary>
        public IReadOnlyList<string> Descartadas { get; }

        /// <summary>Se alcanzo el maximo de archivos: la lista no es completa.</summary>
        public bool Truncado { get; }

        /// <summary>
        /// La lista esta completa solo si se pudo recorrer TODO: carpeta disponible, nada ilegible, nada sin
        /// interpretar y nada truncado. Si no, faltan tareas y no se sabe cuales.
        /// </summary>
        public bool Completo => CarpetaDisponible && Ilegibles.Count == 0 && Descartadas.Count == 0 && !Truncado;
    }

    /// <summary>
    /// Recorre la carpeta de tareas (C:\Windows\System32\Tasks) y devuelve las de inicio. Solo lee. No entra en
    /// uniones ni enlaces (ReparsePoint) y una carpeta sin permisos no corta el recorrido: se anota como ilegible.
    ///
    /// Limitacion conocida: el Programador de tareas tambien guarda las tareas en el registro (TaskCache). Una
    /// tarea cuyo XML se borro pero sigue en el registro no se ve aqui.
    /// </summary>
    public static class LectorDeTareas
    {
        public const int MaximoArchivos = 5000;

        public static string CarpetaDelSistema()
            => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");

        public static InventarioDeTareas Leer(string raiz, int maximoArchivos = MaximoArchivos)
        {
            var tareas = new List<TareaDeInicio>();
            var ilegibles = new List<string>();
            var descartadas = new List<string>();
            int leidos = 0;
            bool truncado = false;

            if (!Directory.Exists(raiz))
                return new InventarioDeTareas(false, "no existe la carpeta de tareas: " + raiz, tareas, 0, ilegibles, descartadas, false);

            var opciones = new EnumerationOptions
            {
                RecurseSubdirectories = false,
                AttributesToSkip = FileAttributes.ReparsePoint,
                IgnoreInaccessible = false
            };

            var pendientes = new Stack<string>();
            pendientes.Push(raiz);
            while (pendientes.Count > 0 && !truncado)
            {
                string carpeta = pendientes.Pop();
                string[] archivos, subcarpetas;
                try
                {
                    archivos = Directory.GetFiles(carpeta, "*", opciones);
                    subcarpetas = Directory.GetDirectories(carpeta, "*", opciones);
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException || ex is DirectoryNotFoundException || ex is IOException)
                {
                    string r = RutaDeTarea(raiz, carpeta);
                    ilegibles.Add(r.EndsWith('\\') ? r : r + @"\");
                    continue;
                }

                foreach (string archivo in archivos.OrderBy(a => a, StringComparer.OrdinalIgnoreCase))
                {
                    if (leidos >= maximoArchivos) { truncado = true; break; }
                    string ruta = RutaDeTarea(raiz, archivo);
                    leidos++;

                    string xml;
                    try
                    {
                        if (new FileInfo(archivo).Length > ParserDeTareaProgramada.MaximoCaracteres * 2L)
                        { descartadas.Add(ruta + ": archivo demasiado grande"); continue; }
                        // Las tareas se guardan en UTF-16 con BOM; ReadAllText lo detecta.
                        xml = File.ReadAllText(archivo);
                    }
                    catch (Exception ex) when (ex is UnauthorizedAccessException || ex is IOException)
                    {
                        ilegibles.Add(ruta);
                        continue;
                    }

                    if (!ParserDeTareaProgramada.TryParse(xml, ruta, out TareaDeInicio? t, out string? motivo))
                        descartadas.Add(ruta + ": " + motivo);
                    else if (t is not null)
                        tareas.Add(t);
                }

                foreach (string sub in subcarpetas.OrderByDescending(s => s, StringComparer.OrdinalIgnoreCase))
                    pendientes.Push(sub);
            }

            return new InventarioDeTareas(true, null,
                tareas.OrderBy(t => t.Ruta, StringComparer.OrdinalIgnoreCase).ToList(), leidos, ilegibles, descartadas, truncado);
        }

        /// <summary>La ruta como la muestra el Programador de tareas: \Carpeta\Nombre.</summary>
        private static string RutaDeTarea(string raiz, string ruta)
        {
            string rel = Path.GetRelativePath(raiz, ruta).Replace(Path.DirectorySeparatorChar, '\\');
            return rel == "." ? @"\" : @"\" + rel;
        }
    }
}
