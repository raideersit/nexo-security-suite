using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Nexo.Modules.Threats.Apps;

namespace Nexo.Movil.Demo
{
    internal static partial class Program
    {
        private static ModeloDeApp Instalada(string paquete, long primeraInstalacion = 1000, bool sospechosa = false) =>
            (sospechosa ? Sospechosa(paquete) : Normal(paquete)) with { PrimeraInstalacionMs = primeraInstalacion };

        private static void ProbarConfianza()
        {
            var p = new PuntuadorDeRiesgo(CatalogoDeSenales.Embebido());
            var v = new VigilanteDeInstalaciones(p);

            Titulo("Confianza: el almacen");
            var a = new AlmacenDeConfianza();
            var mia = Instalada("com.mi.app");
            Check(a.Confiar(mia) && a.Confia(mia) && a.Cantidad == 1, "confiar en una app");
            Check(a.Confiar(mia) && a.Cantidad == 1, "confiar dos veces no la duplica");
            Check(!a.Confiar(Instalada("")) && !a.Confiar(Instalada("sinpunto")) && !a.Confiar(Instalada("com.x; DROP")) && !a.Confiar(Instalada(new string('a', 300) + ".b")) && a.Cantidad == 1, "no guarda nombres que no son paquetes");
            Check(!a.Confiar(Instalada("com.sin.fecha", 0)) && !a.Confiar(Instalada("com.fecha.negativa", -5)), "sin fecha de instalacion no se puede atar la confianza: no se guarda");
            Check(a.DejarDeConfiar("com.mi.app") && !a.Confia(mia) && !a.DejarDeConfiar("com.mi.app"), "dejar de confiar, y hacerlo otra vez no falla");

            Titulo("Confianza: atada a UNA instalacion (el agujero que encontro la prueba en el emulador)");
            var original = Instalada("com.banco.app", 5000);
            var b = new AlmacenDeConfianza(); b.Confiar(original);
            var actualizada = original with { VersionCode = 2, UltimaActualizacionMs = 9999 };
            Check(b.Confia(actualizada), "una ACTUALIZACION conserva la confianza (misma primera instalacion)");
            var reinstalada = Instalada("com.banco.app", 8000);
            Check(!b.Confia(reinstalada), "una app con el mismo nombre pero instalada DE NUEVO no hereda la confianza, aunque no haya habido ninguna revision entre medias");
            Check(b.Vigentes(new[] { reinstalada }).Count == 0 && b.Vigentes(new[] { actualizada }).Count == 1, "Vigentes lo refleja");
            Check(p.Evaluar(Instalada("com.banco.app", 8000, true), b.Vigentes(new[] { Instalada("com.banco.app", 8000, true) })).Nivel == NivelDeRiesgo.Prioritaria, "la reinstalada vuelve a salir «prioritaria»");

            Titulo("Confianza: poda");
            var c = new AlmacenDeConfianza(); c.Confiar(Instalada("com.sigue", 1)); c.Confiar(Instalada("com.se.fue", 2)); c.Confiar(Instalada("com.reinstalada", 3));
            var ahora = new[] { Instalada("com.sigue", 1), Instalada("com.reinstalada", 99), Instalada("com.otra", 4) };
            Check(c.Podar(ahora) == 2 && c.Cantidad == 1 && c.Confia(ahora[0]), "se olvida lo desinstalado y lo reinstalado; lo que sigue igual se conserva", c.Cantidad.ToString());

            Titulo("Confianza: persistencia");
            var dir = Path.Combine(Path.GetTempPath(), "nexo-movil-conf-" + Guid.NewGuid().ToString("N"));
            try
            {
                var ruta = Path.Combine(dir, "confiadas.json");
                var d = new AlmacenDeConfianza(); d.Confiar(Instalada("com.persiste", 777));
                d.Guardar(ruta);
                Check(File.Exists(ruta) && !File.Exists(ruta + ".tmp"), "guarda sin dejar temporal");
                var e = AlmacenDeConfianza.Cargar(ruta, out var aviso);
                Check(aviso == null && e.Confia(Instalada("com.persiste", 777)) && !e.Confia(Instalada("com.persiste", 778)), "recarga lo guardado y sigue atado a la misma instalacion");
                Check(AlmacenDeConfianza.Cargar(Path.Combine(dir, "no.json"), out var a0).Cantidad == 0 && a0 == null, "sin archivo: vacio, sin aviso");
                File.WriteAllText(ruta, "{roto");
                Check(AlmacenDeConfianza.Cargar(ruta, out var a1).Cantidad == 0 && a1 != null, "archivo roto: vacio y con aviso");
                File.WriteAllText(ruta, "{\"Version\":2,\"Instalaciones\":{\"com.bien\":5,\"esto no es un paquete!\":6}}");
                Check(AlmacenDeConfianza.Cargar(ruta, out var a2).Cantidad == 0 && a2 != null, "una sola entrada invalida descarta TODO (no se confia a medias)");
                File.WriteAllText(ruta, "{\"Version\":2,\"Instalaciones\":{\"com.bien\":0}}");
                Check(AlmacenDeConfianza.Cargar(ruta, out var a4).Cantidad == 0 && a4 != null, "una fecha invalida tambien");
                File.WriteAllText(ruta, "{\"Version\":1,\"Paquetes\":[\"com.vieja\"]}");
                Check(AlmacenDeConfianza.Cargar(ruta, out var a3).Cantidad == 0 && a3 != null, "el formato antiguo (sin fechas) NO se migra: no se puede saber a que instalacion pertenecia");
            }
            finally { try { Directory.Delete(dir, true); } catch (IOException) { } }

            Titulo("Confianza: efecto en la puntuacion y en los avisos");
            var sospechosa = Instalada("com.confio.esta", 1000, true);
            var conf = new HashSet<string> { "com.confio.esta" };
            var sin = p.Evaluar(sospechosa);
            var con = p.Evaluar(sospechosa, conf);
            Check(sin.Nivel == NivelDeRiesgo.Prioritaria && con.Nivel == NivelDeRiesgo.Confiada, "de «prioritaria» a «confiada»");
            Check(con.Puntos == sin.Puntos && con.Motivos.SequenceEqual(sin.Motivos), "conserva los puntos y los motivos: no se esconde nada");
            var lista = p.EvaluarTodas(new[] { sospechosa, Dudosa("com.otra.dudosa") }, conf);
            Check(lista.Count(r => r.Nivel is NivelDeRiesgo.ARevisar or NivelDeRiesgo.Prioritaria) == 1 && lista.Single(r => r.Nivel == NivelDeRiesgo.Confiada).Paquete == "com.confio.esta", "solo la otra sigue «a revisar»");

            var e1 = new EstadoDeVigilancia(); v.Revisar(new[] { Normal("com.a") }, e1, 1);
            Check(v.Revisar(new[] { Normal("com.a"), sospechosa }, e1, 2, null, null, conf).Alertas.Count == 0, "una app de confianza que se instala no avisa");
            var e2 = new EstadoDeVigilancia(); v.Revisar(new[] { Normal("com.a") }, e2, 1);
            var lm = new[] { ListaDeHuellas.Desde("lista-de-prueba.txt", new StringReader(HuellaMala)) };
            Check(v.Revisar(new[] { Normal("com.a"), Normal("com.confio.esta") }, e2, 2, HuellaDe("com.confio.esta", HuellaMala), lm, conf).Alertas.Count == 1, "pero si coincide con una huella conocida, AVISA aunque confies en ella");
            Check(p.Evaluar(Normal("com.confio.esta"), conf).Nivel == NivelDeRiesgo.Normal, "confiar en una app sin señales no cambia su nivel");
        }
    }
}
