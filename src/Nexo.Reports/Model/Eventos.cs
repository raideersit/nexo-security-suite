using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Nexo.Reports.Model
{
    /// <summary>
    /// Fabricas tipadas de eventos, agrupadas por modulo consumidor.
    ///
    /// Por que existen: si cada modulo construyera su NexoEvent a mano, el nombre
    /// de los campos del front matter se iria desincronizando entre modulos y las
    /// busquedas de Obsidian dejarian de funcionar a los dos meses. Aqui el
    /// esquema queda en un solo archivo y el compilador obliga a respetarlo.
    ///
    /// Anadir un tipo de evento nuevo = anadir un metodo aqui. Los modulos no
    /// tocan NexoEvent directamente salvo para casos puntuales.
    /// </summary>
    public static class Eventos
    {
        private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        /// <summary>Formatea bytes para que la nota la lea una persona, no un parser.</summary>
        public static string FormatearBytes(long bytes)
        {
            string[] u = { "B", "KB", "MB", "GB", "TB" };
            double v = bytes;
            int i = 0;
            while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
            return v.ToString(i == 0 ? "0" : "0.##", Inv) + " " + u[i];
        }

        // ================================================================
        //  MODULO DE AMENAZAS  (Prompt 1)
        // ================================================================
        public static class Amenazas
        {
            /// <summary>Una deteccion del motor de firmas o de la heuristica de comportamiento.</summary>
            public static NexoEvent Detectada(
                string firma,
                string rutaArchivo,
                string motor,
                Severidad severidad,
                Accion accion,
                string? sha256 = null,
                string? procesoOrigen = null)
            {
                string nombreArchivo = SoloNombre(rutaArchivo);

                var ev = new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.AmenazaDetectada,
                             firma + " en " + nombreArchivo)
                {
                    Severidad = severidad,
                    Accion = accion
                };

                ev.Con("firma", firma)
                  .Con("motor", motor)
                  .Con("ruta", Redactable.Ruta(rutaArchivo))
                  .Con("sha256", sha256)
                  .EnlazaA(EntidadRef.Archivo(nombreArchivo, rutaArchivo));

                if (!string.IsNullOrWhiteSpace(procesoOrigen))
                {
                    ev.Con("proceso_origen", procesoOrigen)
                      .EnlazaA(EntidadRef.Proceso(procesoOrigen!));
                }

                return ev;
            }

            /// <summary>Un archivo movido a la carpeta de cuarentena.</summary>
            public static NexoEvent Cuarentena(
                string rutaOriginal,
                string idCuarentena,
                long bytes,
                DateTimeOffset restaurableHasta,
                string? firma = null)
            {
                string nombreArchivo = SoloNombre(rutaOriginal);

                var ev = new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.ArchivoEnCuarentena,
                             "Cuarentena de " + nombreArchivo)
                {
                    Severidad = Severidad.Alta,
                    Accion = Accion.Cuarentena,
                    Cuerpo =
                        "El archivo fue movido, cifrado, a la carpeta de cuarentena. No se elimino.\n\n" +
                        "Para restaurarlo: **Nexo > Cuarentena > Restaurar**, o `nexo quarantine restore " +
                        idCuarentena + "` desde la consola.\n"
                };

                return ev
                    .Con("ruta_original", Redactable.Ruta(rutaOriginal))
                    .Con("id_cuarentena", idCuarentena)
                    .Con("bytes", bytes)
                    .Con("tamano", FormatearBytes(bytes))
                    .Con("firma", firma)
                    .Con("restaurable_hasta", restaurableHasta)
                    .EnlazaA(EntidadRef.Archivo(nombreArchivo, rutaOriginal));
            }

            /// <summary>Una conexion bloqueada por el firewall.</summary>
            public static NexoEvent Firewall(
                string aplicacion,
                string direccion,
                string ipRemota,
                int puerto,
                string protocolo,
                string regla)
            {
                // El titulo usa solo el ejecutable: es lo que se convierte en nombre
                // de archivo, y una ruta completa lo vuelve ilegible una vez saneada.
                var ev = new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.BloqueoFirewall,
                             "Firewall bloqueo " + SoloNombre(aplicacion) + " hacia " +
                             ipRemota + " puerto " + puerto.ToString(Inv))
                {
                    Severidad = Severidad.Media,
                    Accion = Accion.Bloqueada
                };

                return ev
                    .Con("aplicacion", aplicacion)
                    .Con("direccion", direccion)
                    .Con("ip_remota", ipRemota)
                    .Con("puerto", puerto)
                    .Con("protocolo", protocolo)
                    .Con("regla", regla)
                    .EnlazaA(EntidadRef.Aplicacion(SoloNombre(aplicacion), aplicacion));
            }

            /// <summary>
            /// Una regla del firewall creada, eliminada o (des)habilitada por Nexo.
            /// Es el rastro de un cambio de configuracion, distinto del bloqueo de
            /// una conexion (<see cref="Firewall"/>).
            /// </summary>
            public static NexoEvent ReglaFirewall(
                string cambio,          // "creada" | "eliminada" | "habilitada" | "deshabilitada"
                string regla,
                string accion,          // "bloquear" | "permitir"
                string direccion,       // "entrante" | "saliente"
                string? aplicacion)
            {
                var ev = new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.ReglaFirewall,
                             "Regla de firewall " + cambio + ": " + regla)
                {
                    Severidad = Severidad.Info,
                    Accion = Accion.Registrada,
                    Cuerpo = cambio == "creada"
                        ? "Para revertirlo: `nexo-firewall quitar \"" + regla + "\"` o Firewall de Windows con\n" +
                          "seguridad avanzada > Reglas > grupo \"Nexo Security Suite\".\n"
                        : null
                };

                ev.Con("regla", regla)
                  .Con("cambio", cambio)
                  .Con("accion_regla", accion)
                  .Con("direccion", direccion)
                  .Con("reversible", true);

                if (!string.IsNullOrWhiteSpace(aplicacion))
                {
                    ev.Con("aplicacion", aplicacion)
                      .EnlazaA(EntidadRef.Aplicacion(SoloNombre(aplicacion!), aplicacion));
                }
                return ev;
            }

            /// <summary>Se activo o desactivo el modo sigiloso.</summary>
            public static NexoEvent ModoSigiloso(bool activado, int reglas)
            {
                return new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.ModoSigiloso,
                           activado ? "Modo sigiloso activado" : "Modo sigiloso desactivado")
                {
                    Severidad = Severidad.Info,
                    Accion = Accion.Registrada,
                    Cuerpo = activado
                        ? "Se bloquean los Echo Request (ping) entrantes de ICMPv4 e ICMPv6. El resto del\n" +
                          "trafico entrante no solicitado ya lo descarta en silencio el Firewall de Windows.\n"
                        : "Se retiraron las reglas de Nexo que bloqueaban el ping entrante.\n"
                }
                .Con("activado", activado)
                .Con("reglas_afectadas", reglas)
                .Con("reversible", true);
            }

            /// <summary>Resultado de un escaneo bajo demanda o programado.</summary>
            public static NexoEvent Escaneo(
                string alcance,
                int archivosAnalizados,
                int detecciones,
                TimeSpan duracion,
                string motor)
            {
                var ev = new NexoEvent(ModuloOrigen.Amenazas, TipoEvento.ResultadoEscaneo,
                             "Escaneo de " + SoloNombre(alcance) +
                             (detecciones == 0 ? " sin hallazgos" : " con " + detecciones.ToString(Inv) + " hallazgos"))
                {
                    Severidad = detecciones == 0 ? Severidad.Info : Severidad.Alta,
                    Accion = Accion.Registrada
                };

                return ev
                    .Con("alcance", Redactable.Ruta(alcance))
                    .Con("archivos_analizados", archivosAnalizados)
                    .Con("detecciones", detecciones)
                    .Con("duracion_segundos", Math.Round(duracion.TotalSeconds, 1))
                    .Con("motor", motor);
            }
        }

        // ================================================================
        //  MODULO DE PRIVACIDAD  (Prompt 2)
        // ================================================================
        public static class Privacidad
        {
            public static NexoEvent Vpn(
                string servidor,
                string pais,
                bool conectado,
                TimeSpan? duracion = null,
                long? bytesEnviados = null,
                long? bytesRecibidos = null)
            {
                var ev = new NexoEvent(ModuloOrigen.Privacidad, TipoEvento.ConexionVpn,
                             (conectado ? "VPN conectada a " : "VPN desconectada de ") + servidor)
                {
                    Severidad = Severidad.Info,
                    Accion = Accion.Registrada
                };

                ev.Con("servidor", servidor)
                  .Con("pais", pais)
                  .Con("estado", conectado ? "conectado" : "desconectado")
                  .Con("protocolo", "WireGuard");

                if (duracion.HasValue) ev.Con("duracion_minutos", Math.Round(duracion.Value.TotalMinutes, 1));
                if (bytesEnviados.HasValue) ev.Con("enviado", FormatearBytes(bytesEnviados.Value));
                if (bytesRecibidos.HasValue) ev.Con("recibido", FormatearBytes(bytesRecibidos.Value));

                return ev;
            }

            /// <summary>Una aplicacion accedio a la camara o al microfono.</summary>
            public static NexoEvent AccesoDispositivo(
                string aplicacion,
                string dispositivo,
                bool autorizado)
            {
                var ev = new NexoEvent(ModuloOrigen.Privacidad, TipoEvento.AccesoDispositivo,
                             SoloNombre(aplicacion) + " accedio a " + dispositivo)
                {
                    Severidad = autorizado ? Severidad.Info : Severidad.Alta,
                    Accion = autorizado ? Accion.Registrada : Accion.Bloqueada
                };

                return ev
                    .Con("aplicacion", aplicacion)
                    .Con("dispositivo", dispositivo)
                    .Con("autorizado", autorizado)
                    .EnlazaA(EntidadRef.Aplicacion(SoloNombre(aplicacion), aplicacion))
                    .EnlazaA(EntidadRef.Dispositivo(dispositivo));
            }
        }

        // ================================================================
        //  MODULO DE IDENTIDAD  (Prompt 3)
        // ================================================================
        public static class Identidad
        {
            /// <summary>
            /// Una cuenta aparecio en una filtracion conocida.
            ///
            /// IMPORTANTE: los parametros NO incluyen la credencial, ni su hash, ni
            /// un prefijo de su hash — a proposito. Solo metadatos de la brecha.
            /// Si alguien intenta anadir un campo "password" al evento, el Redactor
            /// lanza una excepcion antes de que llegue al disco.
            /// </summary>
            public static NexoEvent Brecha(
                string correo,
                string nombreBrecha,
                DateTimeOffset fechaBrecha,
                string[] datosExpuestos,
                long cuentasAfectadas)
            {
                var ev = new NexoEvent(ModuloOrigen.Identidad, TipoEvento.BrechaDetectada,
                             "Filtracion en " + nombreBrecha)
                {
                    Severidad = Severidad.Alta,
                    Accion = Accion.PendienteConfirmacion,
                    Cuerpo =
                        "> [!todo] Que hacer ahora\n" +
                        "> 1. Cambia la contrasena de esa cuenta.\n" +
                        "> 2. Si la reutilizaste en otros sitios, cambiala tambien ahi.\n" +
                        "> 3. Activa verificacion en dos pasos si el servicio la ofrece.\n\n" +
                        "Nexo **no guarda** la contrasena filtrada ni ninguna parte de ella.\n"
                };

                return ev
                    .Con("cuenta", Redactable.Correo(correo))
                    .Con("brecha", nombreBrecha)
                    .Con("fecha_brecha", fechaBrecha)
                    .Con("datos_expuestos", datosExpuestos)
                    .Con("cuentas_afectadas", cuentasAfectadas)
                    .Con("fuente", "Have I Been Pwned")
                    .EnlazaA(EntidadRef.Cuenta(EnmascararParaNombre(correo)));
            }

            /// <summary>Senal local de posible compromiso: cuenta nueva, RDP activado, autorun nuevo.</summary>
            public static NexoEvent Alerta(
                string titulo,
                string senal,
                string origen,
                Severidad severidad,
                string? detalle = null)
            {
                var ev = new NexoEvent(ModuloOrigen.Identidad, TipoEvento.AlertaIdentidad, titulo)
                {
                    Severidad = severidad,
                    Accion = Accion.PendienteConfirmacion,
                    Cuerpo = detalle
                };

                return ev
                    .Con("senal", senal)
                    .Con("origen", origen);
            }
        }

        // ================================================================
        //  MODULO DE LIMPIEZA  (Prompt 4)
        // ================================================================
        public static class Limpieza
        {
            /// <summary>
            /// Una sesion de limpieza ya ejecutada. El flag confirmadoPorUsuario es
            /// obligatorio: la regla del Prompt 4 es que ningun borrado ocurre sin
            /// vista previa y confirmacion, y la nota debe dejar constancia de ello.
            /// </summary>
            public static NexoEvent Sesion(
                string[] categorias,
                int archivosEliminados,
                long bytesLiberados,
                bool confirmadoPorUsuario,
                bool enviadoAPapelera,
                TimeSpan duracion)
            {
                if (!confirmadoPorUsuario)
                    throw new InvalidOperationException(
                        "No se puede registrar una sesion de limpieza sin confirmacion del usuario. " +
                        "Si el borrado ocurrio sin confirmar, el bug esta en el modulo de limpieza, no aqui.");

                var ev = new NexoEvent(ModuloOrigen.Limpieza, TipoEvento.SesionLimpieza,
                             "Limpieza libero " + FormatearBytes(bytesLiberados))
                {
                    Severidad = Severidad.Info,
                    Accion = Accion.Eliminada
                };

                return ev
                    .Con("categorias", categorias)
                    .Con("archivos_eliminados", archivosEliminados)
                    .Con("bytes_liberados", bytesLiberados)
                    .Con("espacio_liberado", FormatearBytes(bytesLiberados))
                    .Con("confirmado_por_usuario", confirmadoPorUsuario)
                    .Con("a_papelera", enviadoAPapelera)
                    .Con("duracion_segundos", Math.Round(duracion.TotalSeconds, 1));
            }

            public static NexoEvent Duplicados(int grupos, int archivos, long bytesRecuperables, string algoritmo)
            {
                var ev = new NexoEvent(ModuloOrigen.Limpieza, TipoEvento.DuplicadosDetectados,
                             grupos.ToString(Inv) + " grupos de duplicados, " + FormatearBytes(bytesRecuperables) + " recuperables")
                {
                    Severidad = Severidad.Info,
                    Accion = Accion.PendienteConfirmacion,
                    Cuerpo = "Comparacion por contenido (" + algoritmo + "), no por nombre ni tamano.\n" +
                             "Nada se ha borrado: esto es solo el resultado del analisis.\n"
                };

                return ev
                    .Con("grupos", grupos)
                    .Con("archivos", archivos)
                    .Con("bytes_recuperables", bytesRecuperables)
                    .Con("espacio_recuperable", FormatearBytes(bytesRecuperables))
                    .Con("algoritmo", algoritmo);
            }

            /// <summary>Lectura S.M.A.R.T. de un disco.</summary>
            public static NexoEvent SaludDisco(
                string modelo,
                string numeroSerieRedactado,
                bool prediccionDeFallo,
                int? temperaturaC,
                int? porcentajeDesgaste,
                long? horasEncendido,
                IReadOnlyList<string>? alertas = null,
                Severidad? severidadPorAlertas = null,
                bool sinDatos = false)
            {
                bool hayAlertas = alertas is { Count: > 0 };

                // "No pude leer" no es "esta bien": sin datos, el titulo no dice "correcta".
                bool sinLectura = sinDatos && !prediccionDeFallo && !hayAlertas;

                var ev = new NexoEvent(ModuloOrigen.Limpieza, TipoEvento.SaludDisco,
                             "Salud de " + modelo
                             + (prediccionDeFallo ? " — FALLO PREDICHO"
                                : hayAlertas ? " — con alertas"
                                : sinLectura ? " — sin datos suficientes"
                                : " — correcta"))
                {
                    Severidad = prediccionDeFallo ? Severidad.Critica
                                : hayAlertas ? (severidadPorAlertas ?? Severidad.Media)
                                : Severidad.Info,
                    Accion = Accion.Registrada,
                    Cuerpo = prediccionDeFallo
                        ? "> [!danger] El disco reporta prediccion de fallo\n" +
                          "> Respalda tus datos **hoy**. Un disco que activa esta bandera puede\n" +
                          "> fallar en horas o durar meses; no hay forma de saber cual de las dos.\n"
                        : sinLectura
                            ? "> [!note] No se pudo evaluar este disco\n" +
                              "> Esto NO significa que este sano: significa que no se obtuvieron datos.\n" +
                              "> Las limitaciones concretas (permisos, puente USB, NVMe, RAID) estan en\n" +
                              "> el campo `limitaciones` de esta nota.\n"
                        : hayAlertas
                            ? "> [!warning] Atributos S.M.A.R.T. fuera de lo normal\n" +
                              string.Concat(alertas!.Select(a => "> - " + a + "\n")) +
                              "> La bandera de prediccion de fallo aun no se ha activado, pero estos\n" +
                              "> atributos son los que mejor anticipan un fallo real. Respalda tus datos.\n"
                            : null
                };

                if (hayAlertas) ev.Con("alertas", alertas!.ToArray());

                return ev
                    .Con("modelo", modelo)
                    .Con("serie", numeroSerieRedactado)
                    .Con("prediccion_fallo", prediccionDeFallo)
                    .Con("temperatura_c", temperaturaC)
                    .Con("desgaste_pct", porcentajeDesgaste)
                    .Con("horas_encendido", horasEncendido)
                    .Con("fuente", "WMI root\\wmi MSStorageDriver_FailurePredictStatus")
                    .EnlazaA(EntidadRef.Dispositivo(modelo, numeroSerieRedactado));
            }

            /// <summary>
            /// Un programa de inicio se habilito o se deshabilito. Nunca se borra la
            /// entrada original: se cambia el mismo indicador que usa la pestana
            /// "Inicio" del Administrador de tareas, asi que es reversible y visible.
            /// </summary>
            public static NexoEvent InicioModificado(string nombre, string origen, bool habilitada)
            {
                var ev = new NexoEvent(ModuloOrigen.Limpieza, TipoEvento.InicioModificado,
                             (habilitada ? "Inicio habilitado: " : "Inicio deshabilitado: ") + nombre)
                {
                    Severidad = Severidad.Info,
                    Accion = Accion.Registrada,
                    Cuerpo = habilitada
                        ? null
                        : "No se borro nada. Para revertirlo: Administrador de tareas > Inicio >\n" +
                          "clic derecho sobre el programa > Habilitar.\n"
                };

                return ev
                    .Con("programa", nombre)
                    .Con("origen", origen)
                    .Con("estado_nuevo", habilitada ? "habilitado" : "deshabilitado")
                    .Con("reversible", true)
                    .EnlazaA(EntidadRef.Aplicacion(nombre));
            }

            public static NexoEvent Triturado(string rutaArchivo, long bytes, int pasadas, bool esSsd)
            {
                string nombreArchivo = SoloNombre(rutaArchivo);

                var ev = new NexoEvent(ModuloOrigen.Limpieza, TipoEvento.ArchivoTriturado,
                             "Triturado " + nombreArchivo)
                {
                    Severidad = Severidad.Info,
                    Accion = Accion.Eliminada,
                    Cuerpo = esSsd
                        ? "> [!warning] Este volumen es un SSD\n" +
                          "> La sobrescritura **no garantiza** el borrado: el controlador reparte las\n" +
                          "> escrituras (wear leveling) y los bloques originales pueden seguir intactos\n" +
                          "> en celdas no direccionables. La unica garantia real en SSD es tener el\n" +
                          "> volumen cifrado con BitLocker desde antes.\n"
                        : null
                };

                return ev
                    .Con("ruta", Redactable.Ruta(rutaArchivo))
                    .Con("bytes", bytes)
                    .Con("pasadas", pasadas)
                    .Con("medio", esSsd ? "ssd" : "hdd")
                    .Con("garantia_borrado", esSsd ? "parcial" : "alta");
            }
        }

        private static string SoloNombre(string ruta)
        {
            if (string.IsNullOrWhiteSpace(ruta)) return "desconocido";
            int i = ruta.LastIndexOfAny(new[] { '\\', '/' });
            return i >= 0 && i < ruta.Length - 1 ? ruta.Substring(i + 1) : ruta;
        }

        private static string EnmascararParaNombre(string correo)
        {
            int a = correo.IndexOf('@');
            if (a <= 0) return "cuenta";
            string local = correo.Substring(0, a);
            string dominio = correo.Substring(a + 1);
            // Guion bajo y no asterisco: '*' esta prohibido en nombres de archivo de
            // Windows y el saneador lo convertiria en '-', perdiendo la mascara.
            string visible = local.Length <= 2 ? local.Substring(0, 1) : local.Substring(0, 2);
            return visible + "___@" + dominio;
        }
    }
}
