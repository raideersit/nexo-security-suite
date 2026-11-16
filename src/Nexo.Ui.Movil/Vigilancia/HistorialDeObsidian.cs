using System;
using System.Collections.Generic;
using System.IO;
using Android.Content;
using Nexo.Reports;
using Nexo.Reports.Model;
using Nexo.Reports.Vault;

namespace Nexo.Ui.Movil.Vigilancia;

/// <summary>
/// Historial opcional en notas de Obsidian (Salida 7, 3.9). APAGADO por omision: muchos usuarios de telefono no usan Obsidian.
/// Escribe en Documents/Nexo con la misma biblioteca que el escritorio (Nexo.Reports). Escribir ahi no necesita MANAGE_EXTERNAL_STORAGE
/// (verificado en la fase 0). Cada escritura es independiente y si falla se informa, no se traga.
/// </summary>
public static class HistorialDeObsidian
{
    private static readonly object Candado = new();
    private static ReportWriter? _escritor;
    private static string? _rutaDelEscritor;

    public static bool Activado(Context c) => c.GetSharedPreferences("nexo", FileCreationMode.Private)!.GetBoolean("historial_obsidian", false);

    public static string Carpeta() => Path.Combine(Android.OS.Environment.ExternalStorageDirectory!.AbsolutePath, "Documents", "Nexo");

    public static void Activar(Context c)
    {
        Escribir(Array.Empty<NexoEvent>()); // crea la estructura del vault ahora, para que el error (si lo hay) salga al activar
        c.GetSharedPreferences("nexo", FileCreationMode.Private)!.Edit()!.PutBoolean("historial_obsidian", true)!.Apply();
    }

    public static void Desactivar(Context c) =>
        c.GetSharedPreferences("nexo", FileCreationMode.Private)!.Edit()!.PutBoolean("historial_obsidian", false)!.Apply();

    /// <summary>Escribe los eventos. Lanza si el vault no se puede escribir: quien llama lo muestra.</summary>
    public static int Escribir(IEnumerable<NexoEvent> eventos)
    {
        lock (Candado)
        {
            var ruta = Carpeta();
            if (_escritor is null || _rutaDelEscritor != ruta)
            {
                _escritor?.Dispose();
                _escritor = new ReportWriter(new VaultOptions { RutaVault = ruta, Equipo = "Android", RetencionDias = 90 });
                _rutaDelEscritor = ruta;
            }
            _escritor.InicializarVaultAsync().GetAwaiter().GetResult();
            int n = 0;
            foreach (var e in eventos) { _escritor.EscribirAsync(e).GetAwaiter().GetResult(); n++; }
            return n;
        }
    }
}
