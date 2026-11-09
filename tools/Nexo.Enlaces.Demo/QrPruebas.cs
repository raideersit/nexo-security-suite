using System;
using System.Collections.Generic;
using System.Linq;
using Nexo.Modules.Threats.Enlaces;
using Nexo.Modules.Threats.Vulnerabilidades;
using Nexo.Reports.Model;
using ZXing;
using ZXing.QrCode;

namespace Nexo.Enlaces.Demo
{
    internal static partial class Program
    {
        /// <summary>Un QR de verdad, generado con el escritor de ZXing (pixeles BGRA), como el de una captura de pantalla.</summary>
        internal static (byte[] Bgra, int Ancho, int Alto) Qr(string contenido, int lado = 300)
        {
            var w = new BarcodeWriterPixelData
            {
                Format = BarcodeFormat.QR_CODE,
                Options = new QrCodeEncodingOptions { Width = lado, Height = lado, Margin = 2, CharacterSet = "UTF-8" }
            };
            var p = w.Write(contenido);
            return (p.Pixels, p.Width, p.Height);
        }

        private static (byte[], int, int) Invertir((byte[] B, int W, int H) q)
        {
            byte[] r = (byte[])q.B.Clone();
            for (int i = 0; i < r.Length; i += 4) { r[i] = (byte)(255 - r[i]); r[i + 1] = (byte)(255 - r[i + 1]); r[i + 2] = (byte)(255 - r[i + 2]); }
            return (r, q.W, q.H);
        }

        private static (byte[], int, int) Girar90((byte[] B, int W, int H) q)
        {
            byte[] r = new byte[q.B.Length];
            for (int y = 0; y < q.H; y++)
                for (int x = 0; x < q.W; x++)
                    Array.Copy(q.B, (y * q.W + x) * 4, r, (x * q.H + (q.H - 1 - y)) * 4, 4);
            return (r, q.H, q.W);
        }

        /// <summary>Dos QR lado a lado sobre fondo blanco.</summary>
        private static (byte[], int, int) DosJuntos((byte[] B, int W, int H) a, (byte[] B, int W, int H) b)
        {
            int w = a.W + b.W + 40, h = Math.Max(a.H, b.H);
            byte[] r = Enumerable.Repeat((byte)255, w * h * 4).ToArray();
            for (int y = 0; y < a.H; y++) Array.Copy(a.B, y * a.W * 4, r, y * w * 4, a.W * 4);
            for (int y = 0; y < b.H; y++) Array.Copy(b.B, y * b.W * 4, r, (y * w + a.W + 40) * 4, b.W * 4);
            return (r, w, h);
        }

        private static void ProbarQr()
        {
            Console.WriteLine("15. Códigos QR");
            const string estafa = "https://www.roblox.com.ml/users/364354365772/profile";
            var q = Qr(estafa);
            LecturaDeQr l = LectorDeQr.Leer(q.Bgra, q.Ancho, q.Alto);
            Check(l.Contenidos.SequenceEqual(new[] { estafa }) && l.Motivo is null, "un QR con una dirección REAL de OpenPhish se lee tal cual", l.Motivo ?? string.Join("|", l.Contenidos));
            var inv = Invertir(q);
            Check(LectorDeQr.Leer(inv.Item1, inv.Item2, inv.Item3).Contenidos.SingleOrDefault() == estafa, "invertido (blanco sobre negro) también");
            var gir = Girar90(q);
            Check(LectorDeQr.Leer(gir.Item1, gir.Item2, gir.Item3).Contenidos.SingleOrDefault() == estafa, "girado 90 grados también");
            var dos = DosJuntos(q, Qr("WIFI:S:Cafe Libre;T:nopass;;"));
            LecturaDeQr ld = LectorDeQr.Leer(dos.Item1, dos.Item2, dos.Item3);
            Check(ld.Contenidos.Count == 2 && ld.Contenidos.Contains(estafa), "dos QR en la misma imagen: se leen los dos", string.Join("|", ld.Contenidos));
            const string tildes = "Pagá acá: https://municipalidad.cl/trámite?año=2026";
            var qt = Qr(tildes);
            Check(LectorDeQr.Leer(qt.Bgra, qt.Ancho, qt.Alto).Contenidos.SingleOrDefault() == tildes, "con tildes y eñes (UTF-8)", LectorDeQr.Leer(qt.Bgra, qt.Ancho, qt.Alto).Contenidos.SingleOrDefault());

            byte[] blanco = Enumerable.Repeat((byte)255, 200 * 200 * 4).ToArray();
            LecturaDeQr lb = LectorDeQr.Leer(blanco, 200, 200);
            Check(lb.Contenidos.Count == 0 && lb.Motivo!.Contains("ningún código QR"), "una imagen sin QR lo dice", lb.Motivo);
            Check(LectorDeQr.Leer(new byte[16], 10_000, 10_000).Motivo!.Contains("demasiado grande"), "una imagen de 100 MP se rechaza sin intentar leerla");
            Check(LectorDeQr.Leer(new byte[100], 300, 300).Motivo!.Contains("incompletos"), "datos más cortos que la imagen que dicen ser: se rechaza (no se lee fuera del arreglo)");
            Check(LectorDeQr.Leer(Array.Empty<byte>(), 0, 0).Motivo!.Contains("vacía"), "una imagen de 0 × 0: vacía");

            // El contenido del QR pasa por las mismas reglas que un mensaje.
            RevisionDeMensaje r = AnalizadorDeMensajes.Analizar(string.Join("\n", l.Contenidos), Listas(), Ahora);
            Check(r.Veredicto == Veredicto.Peligroso, "el QR con la dirección de OpenPhish: Peligroso", Todo(r));
        }

        private static void ProbarAccionesDeQr()
        {
            Console.WriteLine("16. Lo que un QR puede hacer además de abrir un enlace");
            RevisionDeMensaje abierta = A("WIFI:S:Cafe Libre;T:nopass;;");
            Check(H(abierta, "MSJ-WIFI") is { Severidad: Severidad.Media } h1 && h1.Titulo.Contains("abierta") && h1.Titulo.Contains("«Cafe Libre»"), "unirse a una red abierta: Media, con su nombre", Todo(abierta));
            RevisionDeMensaje sinTipo = A("WIFI:S:Aeropuerto Gratis;;");
            Check(H(sinTipo, "MSJ-WIFI")?.Severidad == Severidad.Media, "sin tipo de seguridad = abierta");
            RevisionDeMensaje wep = A("WIFI:T:WEP;S:Viejo;P:12345;;");
            Check(H(wep, "MSJ-WIFI") is { Severidad: Severidad.Media } hw && hw.Titulo.Contains("WEP"), "WEP: Media (los campos pueden venir en cualquier orden)", Todo(wep));
            RevisionDeMensaje casa = A("WIFI:S:Mi\\;Casa;T:WPA;P:secreta\\;123;H:false;;");
            HallazgoDeSistema? hc = H(casa, "MSJ-WIFI");
            Check(hc is { Severidad: Severidad.Info } && hc.Titulo.Contains("«Mi;Casa»"), "WPA: solo nota, y el «\\;» del nombre se entiende", hc?.Titulo);
            Check(casa.Analisis.Hallazgos.All(x => !(x.Titulo + x.Detalle + x.Recomendacion + x.Sujeto).Contains("secreta")), "la contraseña de la red NUNCA aparece en ningún texto");
            RevisionDeMensaje sms = A("SMSTO:3030:ALTA PREMIUM");
            Check(H(sms, "MSJ-SMS") is { Severidad: Severidad.Media } hs && hs.Titulo == "Envía un SMS al 3030" && hs.Detalle.Contains("«ALTA PREMIUM»"), "enviar un SMS: Media, con el número y el texto", Todo(sms));
            RevisionDeMensaje tel = A("Llámanos: tel:+56 2 2345-6789");
            Check(H(tel, "MSJ-LLAMADA") is { Severidad: Severidad.Baja } ht && ht.Titulo == "Llama al +56223456789", "llamar: Baja, con el número entero (prefijo incluido)", H(tel, "MSJ-LLAMADA")?.Titulo);
            RevisionDeMensaje cripto = A("Paga aquí: bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.01");
            Check(H(cripto, "MSJ-CRIPTO")?.Severidad == Severidad.Media && cripto.Veredicto == Veredicto.Sospechoso, "pedir un pago en criptomonedas: Media", Todo(cripto));
            RevisionDeMensaje normal = A("Mi wifi: casa. Te llamo por tel: más tarde. Hablamos de bitcoin: es volátil.");
            Check(normal.Analisis.Hallazgos.All(x => !x.Id.StartsWith("MSJ-WIFI") && x.Id is not ("MSJ-LLAMADA" or "MSJ-CRIPTO" or "MSJ-SMS")), "hablar de wifi, teléfono o bitcoin en un texto normal no salta", Todo(normal));
        }
    }
}
