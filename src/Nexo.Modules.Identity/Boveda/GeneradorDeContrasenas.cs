using System;
using System.Security.Cryptography;
using System.Text;

namespace Nexo.Modules.Identity.Boveda
{
    /// <summary>Que clases de caracteres puede usar una contrasena generada.</summary>
    public sealed record OpcionesDeGenerador(int Longitud = 20, bool Minusculas = true, bool Mayusculas = true, bool Digitos = true, bool Simbolos = true, bool EvitarAmbiguos = true);

    /// <summary>
    /// Contrasenas aleatorias con un generador criptografico (<see cref="RandomNumberGenerator"/>), sin sesgo de modulo
    /// (<see cref="RandomNumberGenerator.GetInt32(int)"/> descarta los valores que sesgarian) y con al menos un caracter de
    /// cada clase pedida. Nunca usa <see cref="Random"/>.
    /// </summary>
    public static class GeneradorDeContrasenas
    {
        public const int LongitudMinima = 8, LongitudMaxima = 128;

        private const string Min = "abcdefghijklmnopqrstuvwxyz", May = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", Dig = "0123456789", Sim = "!@#$%^&*()-_=+[]{};:,.?/";
        private const string Ambiguos = "O0oIl1|";

        public static string Generar(OpcionesDeGenerador? opciones = null)
        {
            OpcionesDeGenerador o = opciones ?? new OpcionesDeGenerador();
            if (o.Longitud < LongitudMinima || o.Longitud > LongitudMaxima)
                throw new ArgumentOutOfRangeException(nameof(opciones), "La longitud debe estar entre " + LongitudMinima + " y " + LongitudMaxima + ".");

            var clases = new System.Collections.Generic.List<string>();
            if (o.Minusculas) clases.Add(Filtrar(Min, o.EvitarAmbiguos));
            if (o.Mayusculas) clases.Add(Filtrar(May, o.EvitarAmbiguos));
            if (o.Digitos) clases.Add(Filtrar(Dig, o.EvitarAmbiguos));
            if (o.Simbolos) clases.Add(Filtrar(Sim, o.EvitarAmbiguos));
            if (clases.Count == 0) throw new ArgumentException("Hace falta al menos una clase de caracteres.", nameof(opciones));
            if (o.Longitud < clases.Count) throw new ArgumentOutOfRangeException(nameof(opciones), "La longitud no alcanza para una de cada clase.");

            string todo = string.Concat(clases);
            char[] r = new char[o.Longitud];

            // Un caracter de cada clase pedida, en posiciones aleatorias, y el resto de cualquiera.
            for (int i = 0; i < r.Length; i++) r[i] = todo[RandomNumberGenerator.GetInt32(todo.Length)];
            int[] posiciones = Barajar(o.Longitud);
            for (int c = 0; c < clases.Count; c++) r[posiciones[c]] = clases[c][RandomNumberGenerator.GetInt32(clases[c].Length)];

            return new string(r);
        }

        private static string Filtrar(string s, bool evitar)
        {
            if (!evitar) return s;
            var sb = new StringBuilder(s.Length);
            foreach (char ch in s) if (Ambiguos.IndexOf(ch) < 0) sb.Append(ch);
            return sb.ToString();
        }

        /// <summary>Permutacion aleatoria de 0..n-1 (Fisher-Yates con generador criptografico).</summary>
        private static int[] Barajar(int n)
        {
            int[] a = new int[n];
            for (int i = 0; i < n; i++) a[i] = i;
            for (int i = n - 1; i > 0; i--)
            {
                int j = RandomNumberGenerator.GetInt32(i + 1);
                (a[i], a[j]) = (a[j], a[i]);
            }
            return a;
        }
    }
}
