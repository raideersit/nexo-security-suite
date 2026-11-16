*Tipo: Interfaz*

# Bandeja del sistema

[Nexo.Ui.Tray](../02%20Proyectos/Nexo.Ui.Tray.md) — `nexo-tray.exe`. Tiene dos papeles:

1. **Icono y menú**: estado general, señuelos ([Señuelos](../03%20Funciones/Se%C3%B1uelos.md)), copia ([Copia versionada](../03%20Funciones/Copia%20versionada.md)), detecciones ([Tiempo real](../03%20Funciones/Tiempo%20real.md)), revisar lo no visto, «Limpiar archivos basura…» ([Limpieza de archivos basura](../03%20Funciones/Limpieza%20de%20archivos%20basura.md)), «Salir». Muestra avisos globo (por ejemplo Wi‑Fi sin cifrado, [Vulnerabilidades](../03%20Funciones/Vulnerabilidades.md)).
2. **Aplicar planes aprobados**: `nexo-tray.exe --aplicar <tipo> <token> --pipe <nombre>`, lanzado con `runas` para que salga el UAC ([Vista previa, token y aprobación](../01%20Arquitectura/Vista%20previa%2C%20token%20y%20aprobaci%C3%B3n.md)).

Se registra para arrancar con Windows en `HKLM\...\Run\NexoTray`; se arranca **sin elevar**, después del explorador ([Instalación en Program Files](Instalaci%C3%B3n%20en%20Program%20Files.md)). Antes de elevarse comprueba que su carpeta no sea modificable por el usuario.
