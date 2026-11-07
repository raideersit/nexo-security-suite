using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;

namespace Nexo.Vuln.Demo
{
    internal static partial class Program
    {
        private static int _fallos;

        private static CuentaLocal Cuenta(string nombre, int rid, bool habilitada = true, bool sinClave = false, bool noExpira = false, bool bloqueada = false)
            => new(nombre, rid, habilitada, sinClave, noExpira, bloqueada);

        private static readonly PoliticaDeContrasenas PoliticaBuena = new(12, TimeSpan.FromDays(90), 5, 10);
        private static readonly EstadoDeAutologon SinAutologon = new(false, null, false);

        private static InstantaneaDeCuentas Sana() => new(
            new[] { Cuenta("ana", 1001), Cuenta("Administrador", 500, habilitada: false), Cuenta("Invitado", 501, habilitada: false) },
            PoliticaBuena, SinAutologon);

        private static bool Tiene(ResultadoDeAnalisis r, string id) => r.Hallazgos.Any(h => h.Id == id);

        public static int Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            ProbarSistemaSano();
            ProbarCuentas();
            ProbarPolitica();
            ProbarAutologon();
            ProbarNoEvaluado();
            ProbarEventos();
            ProbarParserWifi();
            ProbarReglasWifi();
            ProbarConexionWifi();
            ProbarEstadosWifi();
            ProbarEventosWifi();
            ProbarWingetReal();
            ProbarVariantesDeWinget();
            ProbarReglasDeAplicaciones();

            Console.WriteLine();
            Console.WriteLine(_fallos == 0 ? "TODAS LAS VERIFICACIONES PASARON" : _fallos + " VERIFICACIONES FALLIDAS");
            return _fallos == 0 ? 0 : 1;
        }

        private static void Check(bool condicion, string descripcion, string? detalle = null)
        {
            if (!condicion) _fallos++;
            Console.WriteLine($"  [{(condicion ? "OK" : "FALLO")}]    {descripcion}");
            if (!condicion && detalle is not null) Console.WriteLine("           " + detalle);
        }

        private static void ProbarSistemaSano()
        {
            Console.WriteLine("1. Un sistema sin problemas");
            ResultadoDeAnalisis r = AnalizadorDeCuentas.Analizar(Sana());
            Check(r.Hallazgos.Count == 0 && r.Completo, "sin hallazgos y leido por completo", string.Join(",", r.Hallazgos.Select(h => h.Id)));
            Check(r.Maxima == Severidad.Info, "la severidad maxima es Info");
        }

        private static void ProbarCuentas()
        {
            Console.WriteLine("2. Cuentas");
            ResultadoDeAnalisis guest = AnalizadorDeCuentas.Analizar(Sana() with { Cuentas = new[] { Cuenta("Invitado", 501) } });
            Check(Tiene(guest, "CUENTA-INVITADO-ACTIVA") && guest.Hallazgos.First(h => h.Id == "CUENTA-INVITADO-ACTIVA").Severidad == Severidad.Media, "Invitado habilitada -> Media");

            // El Invitado se reconoce por el RID (501), no por el nombre: el nombre cambia con el idioma.
            ResultadoDeAnalisis visitante = AnalizadorDeCuentas.Analizar(Sana() with { Cuentas = new[] { Cuenta("Visitante", 501) } });
            Check(Tiene(visitante, "CUENTA-INVITADO-ACTIVA"), "una cuenta con RID 501 llamada «Visitante» SI se detecta como Invitado");
            ResultadoDeAnalisis falsaGuest = AnalizadorDeCuentas.Analizar(Sana() with { Cuentas = new[] { Cuenta("Guest", 1002) } });
            Check(!Tiene(falsaGuest, "CUENTA-INVITADO-ACTIVA"), "una cuenta normal llamada «Guest» (RID 1002) NO se toma por el Invitado");

            ResultadoDeAnalisis sinClave = AnalizadorDeCuentas.Analizar(Sana() with { Cuentas = new[] { Cuenta("ana", 1001, sinClave: true) } });
            HallazgoDeSistema hs = sinClave.Hallazgos.Single(h => h.Id == "CUENTA-SIN-CONTRASENA-REQUERIDA");
            Check(hs.Severidad == Severidad.Media && hs.Sujeto == "ana", "cuenta normal con «contrasena no requerida» -> Media");
            Check(hs.Detalle.Contains("no significa que no tenga una"), "y el texto aclara que NO significa que no tenga contrasena (Nexo no puede saberlo)");

            ResultadoDeAnalisis adminSin = AnalizadorDeCuentas.Analizar(Sana() with { Cuentas = new[] { Cuenta("Administrador", 500, sinClave: true) } });
            Check(adminSin.Hallazgos.Single(h => h.Id == "CUENTA-SIN-CONTRASENA-REQUERIDA").Severidad == Severidad.Alta, "el Administrador integrado sin contrasena requerida -> Alta");
            Check(Tiene(adminSin, "CUENTA-ADMIN-INTEGRADA-ACTIVA") && adminSin.Hallazgos.First(h => h.Id == "CUENTA-ADMIN-INTEGRADA-ACTIVA").Severidad == Severidad.Baja, "y que este habilitado es un hallazgo Bajo aparte");

            Check(AnalizadorDeCuentas.Analizar(Sana() with { Cuentas = new[] { Cuenta("ana", 1001, noExpira: true) } }).Hallazgos.Single().Severidad == Severidad.Info,
                  "«la contrasena no caduca» es solo Info (hoy no se recomienda forzar la caducidad)");
            Check(Tiene(AnalizadorDeCuentas.Analizar(Sana() with { Cuentas = new[] { Cuenta("ana", 1001, bloqueada: true) } }), "CUENTA-BLOQUEADA"), "una cuenta bloqueada ahora se avisa (Baja)");

            // Las deshabilitadas no se pueden usar: ningun hallazgo.
            ResultadoDeAnalisis desh = AnalizadorDeCuentas.Analizar(Sana() with
            {
                Cuentas = new[] { Cuenta("Invitado", 501, habilitada: false), Cuenta("Administrador", 500, habilitada: false, sinClave: true), Cuenta("x", 1003, habilitada: false, sinClave: true, noExpira: true, bloqueada: true) }
            });
            Check(desh.Hallazgos.Count == 0, "cuentas deshabilitadas, con las banderas que tengan, no dan ningun hallazgo", string.Join(",", desh.Hallazgos.Select(h => h.Id)));

            // Orden por gravedad.
            ResultadoDeAnalisis varias = AnalizadorDeCuentas.Analizar(new InstantaneaDeCuentas(
                new[] { Cuenta("a", 1001, noExpira: true), Cuenta("Administrador", 500, sinClave: true), Cuenta("Invitado", 501) },
                new PoliticaDeContrasenas(0, null, 0, 0), new EstadoDeAutologon(true, "a", true)));
            Check(varias.Hallazgos.Zip(varias.Hallazgos.Skip(1), (x, y) => x.Severidad >= y.Severidad).All(b => b), "los hallazgos salen de mas a menos graves", string.Join(",", varias.Hallazgos.Select(h => h.Severidad)));
            Check(varias.Maxima == Severidad.Alta, "la maxima es Alta");
        }

        private static void ProbarPolitica()
        {
            Console.WriteLine("3. Politica de contrasenas");
            ResultadoDeAnalisis cero = AnalizadorDeCuentas.Analizar(Sana() with { Politica = new PoliticaDeContrasenas(0, null, 0, 10) });
            Check(cero.Hallazgos.Single().Id == "POLITICA-SIN-LONGITUD-MINIMA" && cero.Hallazgos.Single().Severidad == Severidad.Media, "longitud minima 0 -> Media");
            ResultadoDeAnalisis siete = AnalizadorDeCuentas.Analizar(Sana() with { Politica = new PoliticaDeContrasenas(7, null, 0, 10) });
            Check(siete.Hallazgos.Single().Id == "POLITICA-LONGITUD-CORTA" && siete.Hallazgos.Single().Severidad == Severidad.Baja, "longitud minima 7 -> Baja");
            Check(AnalizadorDeCuentas.Analizar(Sana() with { Politica = new PoliticaDeContrasenas(8, null, 0, 10) }).Hallazgos.Count == 0, "longitud minima 8 -> nada (el limite es exacto)");
            ResultadoDeAnalisis sinBloqueo = AnalizadorDeCuentas.Analizar(Sana() with { Politica = new PoliticaDeContrasenas(12, null, 0, 0) });
            Check(sinBloqueo.Hallazgos.Single().Id == "POLITICA-SIN-BLOQUEO-POR-INTENTOS", "umbral de bloqueo 0 -> Baja");
            Check(AnalizadorDeCuentas.Analizar(Sana() with { Politica = new PoliticaDeContrasenas(12, null, 0, 5) }).Hallazgos.Count == 0, "umbral 5 -> nada");
        }

        private static void ProbarAutologon()
        {
            Console.WriteLine("4. Inicio de sesion automatico");
            ResultadoDeAnalisis plano = AnalizadorDeCuentas.Analizar(Sana() with { Autologon = new EstadoDeAutologon(true, "ana", true) });
            HallazgoDeSistema h = plano.Hallazgos.Single();
            Check(h.Id == "AUTOLOGON-CONTRASENA-EN-REGISTRO" && h.Severidad == Severidad.Alta && h.Sujeto == "ana", "autologon con la contrasena en el registro -> Alta");
            Check(h.Detalle.Contains("no leyo su valor"), "y el texto dice que Nexo no leyo su valor");

            ResultadoDeAnalisis activo = AnalizadorDeCuentas.Analizar(Sana() with { Autologon = new EstadoDeAutologon(true, "ana", false) });
            Check(activo.Hallazgos.Single().Id == "AUTOLOGON-ACTIVO" && activo.Hallazgos.Single().Severidad == Severidad.Media, "autologon activo sin la contrasena a la vista -> Media");

            // Una contrasena guardada pero con el autologon apagado no es hallazgo (no se usa).
            Check(AnalizadorDeCuentas.Analizar(Sana() with { Autologon = new EstadoDeAutologon(false, "ana", true) }).Hallazgos.Count == 0, "con el autologon apagado, un DefaultPassword sobrante no se marca (no se usa)");

            // Estructural: el modelo NO puede transportar la contrasena, porque su valor nunca se lee.
            var textos = typeof(EstadoDeAutologon).GetProperties().Where(p => p.PropertyType == typeof(string)).Select(p => p.Name).ToList();
            Check(textos.SequenceEqual(new[] { "Usuario" }), "el unico texto que lleva EstadoDeAutologon es el usuario: no hay donde poner la contrasena", string.Join(",", textos));
        }

        private static void ProbarNoEvaluado()
        {
            Console.WriteLine("5. Lo que no se pudo leer NO es «sin problemas»");
            ResultadoDeAnalisis nada = AnalizadorDeCuentas.Analizar(new InstantaneaDeCuentas(null, null, null));
            Check(nada.Hallazgos.Count == 0 && nada.NoEvaluado.Count == 3 && !nada.Completo, "sin leer nada: 0 hallazgos pero 3 «no evaluado» y Completo = false");

            ResultadoDeAnalisis soloPolitica = AnalizadorDeCuentas.Analizar(Sana() with { Politica = null });
            Check(!soloPolitica.Completo && soloPolitica.NoEvaluado.Single().Contains("politica"), "si falta solo la politica, lo dice y no es completo");
            ResultadoDeAnalisis soloCuentas = AnalizadorDeCuentas.Analizar(Sana() with { Cuentas = null });
            Check(!soloCuentas.Completo && soloCuentas.NoEvaluado.Single().Contains("cuentas"), "si faltan las cuentas, lo dice");
            ResultadoDeAnalisis soloAuto = AnalizadorDeCuentas.Analizar(Sana() with { Autologon = null });
            Check(!soloAuto.Completo && soloAuto.NoEvaluado.Single().Contains("inicio de sesion automatico"), "si falta el autologon, lo dice");

            // Lo leido se sigue analizando aunque algo falte.
            ResultadoDeAnalisis parcial = AnalizadorDeCuentas.Analizar(new InstantaneaDeCuentas(null, new PoliticaDeContrasenas(0, null, 0, 0), new EstadoDeAutologon(true, "a", true)));
            Check(parcial.Hallazgos.Count == 3 && parcial.NoEvaluado.Count == 1, "si faltan las cuentas, la politica y el autologon leidos se analizan igual (3 hallazgos + 1 no evaluado)", parcial.Hallazgos.Count + "/" + parcial.NoEvaluado.Count);

            bool lanzo = false;
            try { AnalizadorDeCuentas.Analizar(null!); } catch (ArgumentNullException) { lanzo = true; }
            Check(lanzo, "una instantanea null se rechaza");
        }

        private static void ProbarEventos()
        {
            Console.WriteLine("6. Evento de la revision");
            NexoEvent limpio = EventosDeVulnerabilidades.RevisionDeCuentas(AnalizadorDeCuentas.Analizar(Sana()));
            Check(limpio.Severidad == Severidad.Info && limpio.Modulo == ModuloOrigen.Amenazas && limpio.Tipo == TipoEvento.VulnerabilidadDetectada, "completa y limpia: Info, modulo Amenazas, tipo vulnerabilidad");
            Check(limpio.Titulo.Contains("sin hallazgos"), "el titulo dice «sin hallazgos»");

            NexoEvent incompleta = EventosDeVulnerabilidades.RevisionDeCuentas(AnalizadorDeCuentas.Analizar(new InstantaneaDeCuentas(null, PoliticaBuena, SinAutologon)));
            Check(incompleta.Severidad == Severidad.Media, "incompleta y sin hallazgos: severidad MEDIA (lo desconocido no es «bien»)", incompleta.Severidad.ToString());
            Check(incompleta.Titulo.Contains("incompleta") && !incompleta.Titulo.Contains("sin hallazgos"), "el titulo dice «incompleta», no «sin hallazgos»");
            Check(incompleta.Cuerpo!.Contains("NO significa que este bien"), "el cuerpo aclara que no significa que este bien");
            Check(!incompleta.Cuerpo.Contains("No se encontro nada"), "y NO dice «no se encontro nada»");

            NexoEvent grave = EventosDeVulnerabilidades.RevisionDeCuentas(AnalizadorDeCuentas.Analizar(Sana() with { Autologon = new EstadoDeAutologon(true, "ana", true) }));
            Check(grave.Severidad == Severidad.Alta && grave.Cuerpo!.Contains("| Alta |"), "con un hallazgo grave: severidad Alta y tabla en el cuerpo");
            Check(Convert.ToInt32(grave.Campos["hallazgos"]) == 1 && Equals(grave.Campos["completa"], true), "los campos llevan el conteo y si fue completa");

            // Una barra vertical en un nombre no rompe la tabla de Markdown.
            NexoEvent raro = EventosDeVulnerabilidades.RevisionDeCuentas(AnalizadorDeCuentas.Analizar(Sana() with { Cuentas = new[] { Cuenta("a|b\nc", 1001, sinClave: true) } }));
            string fila = raro.Cuerpo!.Split('\n').First(l => l.StartsWith("| Media"));
            Check(fila.Count(c => c == '|') == 4 && !fila.Contains("\r\r"), "un nombre con «|» y salto de linea no rompe la tabla (4 barras por fila)", fila);
        }
    }
}
