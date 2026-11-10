using System;
using System.IO;
using System.Linq;
using System.Text;
using Nexo.Modules.Threats.Ransomware;

namespace Nexo.Vuln.Demo
{
    internal static partial class Program
    {
        private static readonly DateTimeOffset T0 = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);

        private static void ProbarCopiaVersionada()
        {
            Console.WriteLine("29. Copia versionada (disco real, carpeta temporal propia)");
            string raiz = Path.Combine(Path.GetTempPath(), "nexo-copia-" + Guid.NewGuid().ToString("N"));
            string docs = Path.Combine(raiz, "docs"), copia = Path.Combine(raiz, "copia"), rest = Path.Combine(raiz, "rest");
            try
            {
                Directory.CreateDirectory(Path.Combine(docs, "sub"));
                File.WriteAllText(Path.Combine(docs, "a.txt"), "uno");
                File.WriteAllText(Path.Combine(docs, "sub", "ñandú.txt"), "dos");
                var cfg = new ConfiguracionDeCopia(new[] { docs }, copia, 2);

                ResultadoDeCopia r1 = CopiaVersionada.Copiar(cfg, T0);
                Check(r1.Correcto && r1.Instantanea!.Entradas.Count == 2 && r1.ArchivosNuevos == 2, "primera copia: 2 archivos nuevos", r1.Error);
                ResultadoDeCopia r2 = CopiaVersionada.Copiar(cfg, T0.AddMinutes(1));
                Check(r2.Correcto && r2.ArchivosNuevos == 0 && r2.ArchivosReutilizados == 2, "segunda sin cambios: no copia nada otra vez (deduplicada)");

                File.WriteAllText(Path.Combine(docs, "a.txt"), "uno cambiado");
                ResultadoDeCopia r3 = CopiaVersionada.Copiar(cfg, T0.AddMinutes(2));
                Check(r3.Correcto && r3.ArchivosNuevos == 1 && r3.Podadas == 1, "tercera: solo lo cambiado es nuevo y con tope 2 se poda 1 versión", $"nuevos={r3.ArchivosNuevos} podadas={r3.Podadas}");
                Check(CopiaVersionada.Listar(copia, out int mal).Count == 2 && mal == 0, "quedan 2 versiones");
                string idViejo = CopiaVersionada.Listar(copia, out _).First().Id;
                Check(File.ReadAllText(Path.Combine(docs, "a.txt")) == "uno cambiado", "los originales no se tocaron");

                // Restaurar la versión vieja (la de «uno cambiado» aún no, la primera ya se podó: la 2ª tiene «uno»).
                ResultadoDeRestauracion rr = CopiaVersionada.Restaurar(copia, idViejo, rest);
                Check(rr.Correcto && rr.Restaurados == 2, "restaurar la versión más vieja que queda", rr.Error);
                Check(File.ReadAllText(Path.Combine(rest, "docs", "a.txt")) == "uno" && File.ReadAllText(Path.Combine(rest, "docs", "sub", "ñandú.txt")) == "dos", "y trae el contenido de ENTONCES (con «ñ»)");
                ResultadoDeRestauracion otra = CopiaVersionada.Restaurar(copia, idViejo, rest);
                Check(!otra.Correcto && otra.Error!.Contains("no pisa"), "restaurar sobre una carpeta con cosas se niega");
                Check(!CopiaVersionada.Restaurar(copia, idViejo, Path.Combine(copia, "x")).Correcto, "no se restaura dentro de la carpeta de copias");
                Check(!CopiaVersionada.Restaurar(copia, "no-existe", Path.Combine(raiz, "r2")).Correcto, "una copia que no existe da error");

                ResultadoDeVerificacion v = CopiaVersionada.Verificar(copia);
                Check(v.Correcto && v.Comprobados >= 3, "verificar: todo en orden");

                // Daño en el contenido guardado
                string blob = Directory.GetFiles(Path.Combine(copia, CopiaVersionada.CarpetaDeCopias, "contenido"), "*", SearchOption.AllDirectories)
                                       .First(f => Path.GetFileName(f).Length == 64);
                File.WriteAllText(blob, "dañado");
                ResultadoDeVerificacion v2 = CopiaVersionada.Verificar(copia);
                Check(!v2.Correcto && v2.Problemas.Any(p => p.Motivo.Contains("cambió")), "verificar caza un contenido alterado");
                string rest2 = Path.Combine(raiz, "rest2");
                ResultadoDeRestauracion rd = CopiaVersionada.Restaurar(copia, CopiaVersionada.Listar(copia, out _).Last().Id, rest2);
                Check(!rd.Correcto && rd.NoRestaurados.Any(p => p.Motivo.Contains("dañado")) && !Directory.GetFiles(rest2, "*", SearchOption.AllDirectories).Any(f => File.ReadAllText(f) == "dañado"),
                      "restaurar NO entrega un archivo dañado");

            }
            finally { try { Directory.Delete(raiz, true); } catch { } }
        }

        private static void ProbarCopiaVersionadaReglas()
        {
            Console.WriteLine("30. Copia versionada: reglas");
            string raiz = Path.Combine(Path.GetTempPath(), "nexo-copia2-" + Guid.NewGuid().ToString("N"));
            string docs = Path.Combine(raiz, "docs"), copia = Path.Combine(raiz, "copia");
            try
            {
                Directory.CreateDirectory(docs);
                Check(CopiaVersionada.Validar(new ConfiguracionDeCopia(new[] { docs }, Path.Combine(docs, "copia"))) is { } a && a.Contains("a sí misma"), "destino dentro del origen se rechaza");
                Check(CopiaVersionada.Validar(new ConfiguracionDeCopia(new[] { Path.Combine(raiz, "docs") }, raiz)) is { } b && b.Contains("dentro del destino"), "origen dentro del destino se rechaza");
                Check(CopiaVersionada.Validar(new ConfiguracionDeCopia(new[] { docs + "x" }, copia)) is not null, "origen que no existe se rechaza");
                Check(CopiaVersionada.Validar(new ConfiguracionDeCopia(Array.Empty<string>(), copia)) is not null, "sin orígenes se rechaza");
                Check(CopiaVersionada.Validar(new ConfiguracionDeCopia(new[] { docs }, copia, 0)) is not null, "0 versiones se rechaza");
                Check(CopiaVersionada.Validar(new ConfiguracionDeCopia(new[] { docs }, docs + "-otra")) is null, "«docs-otra» junto a «docs» NO se toma por estar dentro (prefijo de nombre)");
                Check(!CopiaVersionada.Copiar(new ConfiguracionDeCopia(new[] { docs }, Path.Combine(docs, "c")), T0).Correcto, "Copiar con config mala no hace nada");
                Check(!Directory.Exists(Path.Combine(docs, "c")), "y no creó carpetas");

                // Tope por archivo y omitidos con motivo
                File.WriteAllText(Path.Combine(docs, "grande.bin"), new string('x', 100));
                File.WriteAllText(Path.Combine(docs, "chico.txt"), "ok");
                var conTope = new ConfiguracionDeCopia(new[] { docs }, copia, 3, TopePorArchivoBytes: 10);
                ResultadoDeCopia rt = CopiaVersionada.Copiar(conTope, T0);
                Check(rt.Correcto && rt.Instantanea!.Entradas.Count == 1 && rt.Instantanea.Omitidos.Any(o => o.Ruta.EndsWith("grande.bin") && o.Motivo.Contains("grande")), "un archivo sobre el tope queda en Omitidos con motivo");

                // Archivo abierto en exclusiva: omitido, no rompe la copia
                string bloq = Path.Combine(docs, "abierto.txt");
                File.WriteAllText(bloq, "x");
                using (new FileStream(bloq, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                    ResultadoDeCopia ra = CopiaVersionada.Copiar(conTope with { TopePorArchivoBytes = 1000 }, T0.AddMinutes(1));
                    Check(ra.Correcto && ra.Instantanea!.Omitidos.Any(o => o.Ruta.EndsWith("abierto.txt")), "un archivo abierto en exclusiva se omite con motivo y la copia sigue");
                }
                Check(!Directory.GetFiles(Path.Combine(copia, CopiaVersionada.CarpetaDeCopias, "contenido"), "*.tmp", SearchOption.AllDirectories).Any(), "no quedan temporales");

                // Ransomware: muchos archivos cambian de golpe -> sospechosa y NO se poda
                string r = Path.Combine(raiz, "muchos"), c2 = Path.Combine(raiz, "copia2");
                Directory.CreateDirectory(r);
                for (int i = 0; i < 30; i++) File.WriteAllText(Path.Combine(r, "f" + i + ".txt"), "contenido " + i);
                var cfg = new ConfiguracionDeCopia(new[] { r }, c2, 1);
                CopiaVersionada.Copiar(cfg, T0);
                CopiaVersionada.Copiar(cfg, T0.AddMinutes(1)); // normal: con tope 1 poda
                Check(CopiaVersionada.Listar(c2, out _).Count == 1, "con tope 1 y sin cambios queda 1 versión");
                for (int i = 0; i < 30; i++) File.WriteAllText(Path.Combine(r, "f" + i + ".txt"), "CIFRADO " + i);
                ResultadoDeCopia rs = CopiaVersionada.Copiar(cfg, T0.AddMinutes(2));
                Check(rs.Correcto && rs.Instantanea!.Sospechosa && rs.PodaSuspendida && rs.Podadas == 0, "30 de 30 cambiados -> sospechosa y no se poda", rs.MotivoDePoda);
                Check(CopiaVersionada.Listar(c2, out _).Count == 2, "la versión BUENA anterior sigue ahí");
                Check(CopiaVersionada.Verificar(c2).Correcto, "y todo verifica");

                // Pocos cambios (3 de 30) no son sospechosos
                string c3 = Path.Combine(raiz, "copia3");
                var cfg3 = new ConfiguracionDeCopia(new[] { r }, c3, 5);
                CopiaVersionada.Copiar(cfg3, T0);
                for (int i = 0; i < 3; i++) File.WriteAllText(Path.Combine(r, "f" + i + ".txt"), "otra cosa " + i);
                Check(!CopiaVersionada.Copiar(cfg3, T0.AddMinutes(1)).Instantanea!.Sospechosa, "3 de 30 cambiados NO es sospechoso");
                // Pocos archivos en total (<20): nunca sospechoso
                string p = Path.Combine(raiz, "pocos"), c4 = Path.Combine(raiz, "copia4");
                Directory.CreateDirectory(p);
                File.WriteAllText(Path.Combine(p, "a"), "1"); File.WriteAllText(Path.Combine(p, "b"), "2");
                var cfg4 = new ConfiguracionDeCopia(new[] { p }, c4, 5);
                CopiaVersionada.Copiar(cfg4, T0);
                File.WriteAllText(Path.Combine(p, "a"), "11"); File.WriteAllText(Path.Combine(p, "b"), "22");
                Check(!CopiaVersionada.Copiar(cfg4, T0.AddMinutes(1)).Instantanea!.Sospechosa, "con menos de 20 archivos no se sospecha (demasiado ruido)");

                // Poda: no borra contenido que otra versión usa; no borra si hay una lista ilegible
                string c5 = Path.Combine(raiz, "copia5"); string q = Path.Combine(raiz, "q");
                Directory.CreateDirectory(q); File.WriteAllText(Path.Combine(q, "a"), "A"); File.WriteAllText(Path.Combine(q, "b"), "B");
                var cfg5 = new ConfiguracionDeCopia(new[] { q }, c5, 2);
                CopiaVersionada.Copiar(cfg5, T0);
                File.WriteAllText(Path.Combine(q, "a"), "A2");
                CopiaVersionada.Copiar(cfg5, T0.AddMinutes(1));
                File.WriteAllText(Path.Combine(q, "a"), "A3");
                CopiaVersionada.Copiar(cfg5, T0.AddMinutes(2));
                Check(CopiaVersionada.Verificar(c5).Correcto, "tras podar, lo que las versiones vivas usan sigue (B compartido)");
                string blobs = Path.Combine(c5, CopiaVersionada.CarpetaDeCopias, "contenido");
                Check(Directory.GetFiles(blobs, "*", SearchOption.AllDirectories).Length == 3, "y se borró el contenido que nadie usa (A queda fuera: 3 = B, A2, A3)",
                      Directory.GetFiles(blobs, "*", SearchOption.AllDirectories).Length.ToString());
                File.WriteAllText(Path.Combine(c5, CopiaVersionada.CarpetaDeCopias, "instantaneas", "roto.json"), "{no es json");
                File.WriteAllText(Path.Combine(q, "a"), "A4");
                ResultadoDeCopia rp = CopiaVersionada.Copiar(cfg5, T0.AddMinutes(3));
                Check(rp.Correcto && rp.Podadas == 0 && rp.PodaSuspendida && rp.MotivoDePoda!.Contains("no se pudieron leer"), "con una lista ilegible NO se poda nada", rp.MotivoDePoda);

                // Tras una copia sospechosa, la siguiente (comparada con la cifrada) sale «normal»: no puede llevarse la última versión buena
                string pr = Path.Combine(raiz, "prot"), cp = Path.Combine(raiz, "copiaprot");
                Directory.CreateDirectory(pr);
                for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(pr, "f" + i), "bueno " + i);
                var cfgp = new ConfiguracionDeCopia(new[] { pr }, cp, 1);
                string idBueno = CopiaVersionada.Copiar(cfgp, T0).Instantanea!.Id;
                for (int i = 0; i < 25; i++) File.WriteAllText(Path.Combine(pr, "f" + i), "CIFRADO " + i);
                ResultadoDeCopia sosp = CopiaVersionada.Copiar(cfgp, T0.AddMinutes(1));
                ResultadoDeCopia siguiente = CopiaVersionada.Copiar(cfgp, T0.AddMinutes(2));
                Check(sosp.Instantanea!.Sospechosa && !siguiente.Instantanea!.Sospechosa, "la copia siguiente a la sospechosa se compara con la cifrada y sale «normal»");
                var tras = CopiaVersionada.Listar(cp, out _);
                Check(tras.Any(v => v.Id == idBueno) && tras.Any(v => v.Id == sosp.Instantanea.Id), "pero la versión buena y la sospechosa NO se podan (tope 1)", string.Join(",", tras.Select(v => v.Id)));
                Check(CopiaVersionada.Verificar(cp).Correcto, "y todo sigue verificando");
                string rb = Path.Combine(raiz, "rb");
                Check(CopiaVersionada.Restaurar(cp, idBueno, rb).Correcto && File.ReadAllText(Path.Combine(rb, "prot", "f0")) == "bueno 0", "la versión buena se puede restaurar");

                // Descartar la sospecha: deja de estar protegida y la poda vuelve a funcionar
                string firmaAntes = CopiaVersionada.FirmaDeLasListas(cp);
                Check(!CopiaVersionada.DescartarSospecha(cp, idBueno).Correcto, "no se puede descartar la sospecha de una copia que no es sospechosa");
                Check(!CopiaVersionada.DescartarSospecha(cp, "no-existe").Correcto, "ni de una que no existe");
                var desc = CopiaVersionada.DescartarSospecha(cp, sosp.Instantanea.Id);
                Check(desc.Correcto && !CopiaVersionada.Listar(cp, out _).First(v => v.Id == sosp.Instantanea.Id).Sospechosa, "descartar la sospecha de la elegida", desc.Error);
                Check(CopiaVersionada.Listar(cp, out _).First(v => v.Id == sosp.Instantanea.Id).MotivoSospecha!.Contains("dada por buena"), "deja constancia en el motivo");
                Check(CopiaVersionada.FirmaDeLasListas(cp) != firmaAntes, "la firma de las listas cambia (así el servicio se entera)");
                ResultadoDeCopia trasDescartar = CopiaVersionada.Copiar(cfgp, T0.AddMinutes(3));
                Check(CopiaVersionada.Listar(cp, out _).Count == 1 && trasDescartar.Podadas >= 1 && CopiaVersionada.Verificar(cp).Correcto, "sin sospechosas, la poda vuelve a aplicar el tope (1 versión) y todo verifica");

                // Mismo segundo: no pisa
                string c6 = Path.Combine(raiz, "copia6");
                var cfg6 = new ConfiguracionDeCopia(new[] { q }, c6, 5);
                CopiaVersionada.Copiar(cfg6, T0); CopiaVersionada.Copiar(cfg6, T0);
                Check(CopiaVersionada.Listar(c6, out _).Count == 2, "dos copias en el mismo segundo no se pisan");

                // Dos orígenes con el mismo nombre de carpeta
                string x1 = Path.Combine(raiz, "u1", "Docs"), x2 = Path.Combine(raiz, "u2", "Docs");
                Directory.CreateDirectory(x1); Directory.CreateDirectory(x2);
                File.WriteAllText(Path.Combine(x1, "a"), "uno"); File.WriteAllText(Path.Combine(x2, "a"), "dos");
                string c7 = Path.Combine(raiz, "copia7"), r7 = Path.Combine(raiz, "rest7");
                ResultadoDeCopia rc = CopiaVersionada.Copiar(new ConfiguracionDeCopia(new[] { x1, x2 }, c7), T0);
                ResultadoDeRestauracion rr = CopiaVersionada.Restaurar(c7, rc.Instantanea!.Id, r7);
                Check(rr.Correcto && rr.Restaurados == 2 && Directory.GetFiles(r7, "a", SearchOption.AllDirectories).Select(File.ReadAllText).OrderBy(s => s).SequenceEqual(new[] { "dos", "uno" }),
                      "dos orígenes con el mismo nombre no se mezclan al restaurar");

                // Lista manipulada con «..»: en un escenario limpio, para que la prueba no pase por otra razón.
                string m = Path.Combine(raiz, "m"), cm = Path.Combine(raiz, "cm"), rm3 = Path.Combine(raiz, "rm3", "dentro");
                Directory.CreateDirectory(m); File.WriteAllText(Path.Combine(m, "a.txt"), "secreto");
                ResultadoDeCopia rcm = CopiaVersionada.Copiar(new ConfiguracionDeCopia(new[] { m }, cm), T0);
                string man = Path.Combine(cm, CopiaVersionada.CarpetaDeCopias, "instantaneas", rcm.Instantanea!.Id + ".json");
                string texto = File.ReadAllText(man);
                string manipulado = texto.Replace("\"Relativa\": \"a.txt\"", "\"Relativa\": \"../../fuera.txt\"");
                Check(manipulado != texto, "(la lista de la prueba sí se manipuló)");
                File.WriteAllText(man, manipulado);
                ResultadoDeRestauracion rmm = CopiaVersionada.Restaurar(cm, rcm.Instantanea.Id, rm3);
                Check(!rmm.Correcto && rmm.NoRestaurados.Any(x => x.Motivo.Contains("manipulada")) && !File.Exists(Path.Combine(raiz, "rm3", "fuera.txt")) && !File.Exists(Path.Combine(raiz, "fuera.txt")),
                      "una lista manipulada no saca archivos de la carpeta de restauración", rmm.Error);
            }
            finally { try { Directory.Delete(raiz, true); } catch { } }
        }
    }
}
