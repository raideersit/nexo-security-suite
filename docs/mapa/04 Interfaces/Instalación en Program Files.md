*Tipo: Interfaz*

# Instalación en Program Files

`tools\Instalador\instalar-nexo.ps1 -Accion instalar` (PowerShell como administrador) publica y copia a `C:\Program Files\Nexo\`:

```
Nexo\
  service\         nexo-service.exe + appsettings.json  -> [Servicio NexoService](../03%20Funciones/Servicio%20NexoService.md)
  tray\            nexo-tray.exe                        -> [Bandeja del sistema](Bandeja%20del%20sistema.md)
  desktop\         nexo-desktop.exe                     -> [Ventana principal](Ventana%20principal.md)
  autocompletado\  nexo-autocompletar.exe              -> [Nexo.Autocompletado.Host](../02%20Proyectos/Nexo.Autocompletado.Host.md)
  extension\       la extensión                         -> [Nexo.Autocompletado.Extension](../02%20Proyectos/Nexo.Autocompletado.Extension.md)
  instalador\      los guiones
```

- La carpeta queda protegida: SYSTEM y administradores control total, usuarios solo leer y ejecutar. Es imprescindible porque Nexo **eleva ejecutables** y nadie sin permisos debe poder sustituirlos.
- Servicio `NexoService` (LocalSystem), inicio manual salvo `-Automatico`. Bandeja en el arranque. Acceso directo «Nexo» y entrada en «Aplicaciones».
- Al **actualizar** se conserva `appsettings.json`. `-Autocontenido` publica con el runtime incluido (~425 MB) y `-SoloPublicar` solo copia, sin servicio.
- Los datos (vault, cuarentena, bóveda) **no** se borran al desinstalar.

Ver [Arquitectura general](../01%20Arquitectura/Arquitectura%20general.md).
