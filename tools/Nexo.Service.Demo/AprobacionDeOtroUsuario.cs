using System;
using System.Security.Principal;
using Nexo.Ipc;
using Nexo.Service;

namespace Nexo.Service.Demo
{
    internal static partial class Program
    {
        // Un usuario estandar con UAC aprueba con las credenciales de OTRO administrador. Aqui no hay dos usuarios reales: se
        // fabrican contextos con SIDs distintos para comprobar la regla del servicio. (El UAC real sigue SIN PROBAR: ver guion de VM.)
        private static ContextoDeLlamada Ctx(string sid, bool admin, bool utilizable = true)
        {
            using WindowsIdentity yo = WindowsIdentity.GetCurrent();
            return new ContextoDeLlamada(new SecurityIdentifier(sid), utilizable ? TokenImpersonationLevel.Impersonation : TokenImpersonationLevel.Identification,
                                         utilizable ? new WindowsIdentity(yo.AccessToken.DangerousGetHandle()) : null, admin);
        }

        private static void ProbarAprobacionDeOtroUsuario()
        {
            Console.WriteLine("13. Un administrador distinto aprueba el plan de otro usuario: se ejecuta COMO el dueno");

            const string Dueno = "S-1-5-21-1-2-3-1001", Admin = "S-1-5-21-1-2-3-500", Otro = "S-1-5-21-1-2-3-1002";
            DateTimeOffset ahora = DateTimeOffset.Now;
            var planes = new PlanesPendientes<string>(TimeSpan.FromMinutes(10), reloj: () => ahora);
            using ContextoDeLlamada dueno = Ctx(Dueno, admin: false);
            using ContextoDeLlamada admin = Ctx(Admin, admin: true);
            using ContextoDeLlamada otro = Ctx(Otro, admin: false);

            // El mismo usuario aplica: con su propia identidad.
            (string t1, _) = planes.Guardar("p1", dueno);
            using (PlanTomado<string>? x = planes.Tomar(t1, dueno))
                Check(x is not null && x.Plan == "p1" && x.Contexto == dueno && !x.AprobadoPorOtro, "el dueno aplica con su propia identidad");

            // Otro usuario SIN elevar: rechazado, y el token queda gastado.
            (string t2, _) = planes.Guardar("p2", dueno);
            Check(planes.Tomar(t2, otro) is null, "otro usuario sin permisos elevados no puede aplicar el plan");
            Check(planes.Tomar(t2, dueno) is null, "y el intento gasto el token (no se puede reintentar con el)");

            // Un administrador distinto aplica: se ejecuta como el dueno, no como el.
            (string t3, _) = planes.Guardar("p3", dueno);
            using (PlanTomado<string>? x = planes.Tomar(t3, admin))
            {
                Check(x is not null && x.Plan == "p3", "un administrador distinto puede aprobar el plan del usuario");
                Check(x is not null && x.AprobadoPorOtro && x.Contexto.Usuario == new SecurityIdentifier(Dueno),
                      "pero se ejecuta con la identidad del DUENO, no con la del administrador (aprueba, no gana acceso)");
                Check(x is not null && x.Contexto != admin, "el contexto efectivo no es el del administrador");
            }
            Check(planes.Tomar(t3, admin) is null, "y el token sigue siendo de un solo uso");

            // Si no se puede actuar como el dueno, no se recurre a nadie mas.
            using ContextoDeLlamada sinId = Ctx(Dueno, admin: false, utilizable: false);
            (string t4, _) = planes.Guardar("p4", sinId);
            Check(planes.Tomar(t4, admin) is null, "si no se puede actuar como el dueno (sin identidad), un administrador tampoco puede aplicarlo");

            // Plan sin dueno (firewall, purga): con la identidad de quien aplica.
            (string t5, _) = planes.Guardar("p5");
            using (PlanTomado<string>? x = planes.Tomar(t5, admin))
                Check(x is not null && x.Contexto == admin && !x.AprobadoPorOtro, "un plan sin dueno se ejecuta con la identidad de quien aplica");

            // Caducado, falso, sin llamador.
            (string t6, _) = planes.Guardar("p6", dueno);
            ahora = ahora.AddMinutes(11);
            Check(planes.Tomar(t6, admin) is null, "un plan caducado no lo salva la aprobacion de un administrador");
            (string t7, _) = planes.Guardar("p7", dueno);
            Check(planes.Tomar(t7, null) is null, "sin contexto de llamador no se aplica");
            Check(planes.Tomar(new string('a', 64), admin) is null && planes.Tomar(null, admin) is null && planes.Tomar("corto", admin) is null,
                  "token falso, nulo o de longitud rara: nada");

            Console.WriteLine();
        }
    }
}
