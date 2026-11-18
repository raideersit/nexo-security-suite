using System.IO;
using Android.Content;

namespace Nexo.Ui.Movil.Vigilancia;

/// <summary>Donde guarda Nexo sus archivos. Las listas van en la carpeta externa de la app para poder dejarlas por adb o por un explorador.</summary>
public static class RutasDeNexo
{
    public static string Cache(Context c) => Path.Combine(c.FilesDir!.AbsolutePath, "huellas.json");
    public static string Confiadas(Context c) => Path.Combine(c.FilesDir!.AbsolutePath, "confiadas.json");
    public static string Vigilancia(Context c) => Path.Combine(c.FilesDir!.AbsolutePath, "vigilancia.json");
    public static string Equipo(Context c) => Path.Combine(c.FilesDir!.AbsolutePath, "equipo.json");
    public static string Firewall(Context c) => Path.Combine(c.FilesDir!.AbsolutePath, "firewall.json");
    public static string CarpetaDeListas(Context c) => Path.Combine(c.GetExternalFilesDir(null)?.AbsolutePath ?? c.FilesDir!.AbsolutePath, "listas");
}
