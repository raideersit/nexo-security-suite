using System;
using System.Linq;
using System.Text;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Modules.Threats.Windows;
using Nexo.Native.Accounts;

namespace Nexo.Vuln.Windows.Demo
{
    internal static class Program
    {
        private static int _fallos;

        public static int Main()
        {
            Console.OutputEncoding = new UTF8Encoding(false);
            bool admin = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent())
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            Console.WriteLine("Administrador: " + (admin ? "si" : "no") + " (no hace falta)");

            Console.WriteLine("1. Capa nativa (netapi32)");
            var cuentas = CuentasLocales.Enumerar(out uint e1);
            Check(cuentas is not null, "NetUserEnum enumera las cuentas locales", "error " + e1);
            if (cuentas is not null)
            {
                Console.WriteLine("      INFO: " + cuentas.Count + " cuentas locales: " + string.Join(", ", cuentas.Select(c => c.Nombre + "(" + c.Rid + (c.Tiene(CuentaLocalNativa.CuentaDeshabilitada) ? ",deshab." : "") + ")")));
                Check(cuentas.Any(c => c.Rid == 500), "existe el Administrador integrado (RID 500): siempre debe estar, aunque este deshabilitado");
                Check(cuentas.Any(c => c.Rid == 501), "existe el Invitado (RID 501)");
                Check(cuentas.Select(c => c.Rid).Distinct().Count() == cuentas.Count, "no hay RID repetidos (se enumero cada cuenta una vez)");
                Check(cuentas.Any(c => string.Equals(c.Nombre, Environment.UserName, StringComparison.OrdinalIgnoreCase)),
                      "la cuenta con la que corre este programa (" + Environment.UserName + ") esta en la lista", "puede ser una cuenta de Microsoft con otro nombre local");
            }

            var p = CuentasLocales.LeerPolitica(out uint e2);
            Check(p is not null, "NetUserModalsGet lee la politica local de contrasenas", "error " + e2);
            if (p is not null)
                Console.WriteLine("      INFO: longitud minima " + p.Value.LongitudMinima + ", caducidad " +
                                  (p.Value.EdadMaximaSegundos == PoliticaNativa.ParaSiempre ? "nunca" : TimeSpan.FromSeconds(p.Value.EdadMaximaSegundos).TotalDays + " dias") +
                                  ", historial " + p.Value.HistorialDeContrasenas + ", bloqueo tras " + p.Value.UmbralDeBloqueo + " intentos (0 = sin bloqueo)");

            Console.WriteLine("2. Lector completo y analizador");
            InstantaneaDeCuentas s = LectorDeCuentasWindows.Leer();
            Check(s.Cuentas is not null && s.Politica is not null && s.Autologon is not null, "se leyeron las tres partes (cuentas, politica, inicio automatico)");
            if (s.Autologon is not null)
                Console.WriteLine("      INFO: inicio automatico " + (s.Autologon.Activo ? "ACTIVO" : "inactivo") + (s.Autologon.Activo ? ", usuario " + s.Autologon.Usuario + ", contrasena en texto plano: " + (s.Autologon.ContrasenaEnTextoPlano ? "SI" : "no") : "") + " (nunca se lee el valor de la contrasena)");

            ResultadoDeAnalisis r = AnalizadorDeCuentas.Analizar(s);
            Check(r.Completo, "el analisis es completo (nada quedo sin evaluar)", string.Join("; ", r.NoEvaluado));
            Console.WriteLine("      INFO: " + r.Hallazgos.Count + " hallazgo(s):");
            foreach (HallazgoDeSistema h in r.Hallazgos)
                Console.WriteLine("        - [" + h.Severidad + "] " + h.Titulo + (h.Sujeto is null ? "" : " (" + h.Sujeto + ")"));

            // Cruce: el analisis coincide con lo que se leyo.
            if (s.Cuentas is not null)
            {
                bool invitadoHab = s.Cuentas.Any(c => c.Rid == 501 && c.Habilitada);
                Check(invitadoHab == r.Hallazgos.Any(h => h.Id == "CUENTA-INVITADO-ACTIVA"), "«Invitado habilitada» coincide con lo leido");
                bool adminHab = s.Cuentas.Any(c => c.Rid == 500 && c.Habilitada);
                Check(adminHab == r.Hallazgos.Any(h => h.Id == "CUENTA-ADMIN-INTEGRADA-ACTIVA"), "«Administrador integrado habilitado» coincide con lo leido");
            }

            // Estructural: nada de lo que sale de aqui puede llevar una contrasena.
            string todo = string.Join("\n", r.Hallazgos.Select(h => h.Titulo + h.Detalle + h.Recomendacion));
            Check(!todo.Contains("DefaultPassword=", StringComparison.OrdinalIgnoreCase), "ningun hallazgo contiene un valor de contrasena");

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
    }
}
