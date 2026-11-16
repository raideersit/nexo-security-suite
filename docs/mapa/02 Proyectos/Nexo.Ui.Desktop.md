*Tipo: Proyecto*

# Nexo.Ui.Desktop

La ventana principal (Avalonia, tema Classic) con 12 pestañas. Habla con el servicio por el pipe; algunas pestañas (bóveda, enlaces, VPN, vulnerabilidades) usan además lógica portable directamente. Para pedir aprobación lanza `nexo-tray.exe` elevado.

**Tamaño:** 40 archivos, ~7 400 líneas.

## Depende de
- [Nexo.Modules.Threats](Nexo.Modules.Threats.md)
- [Nexo.Modules.Identity](Nexo.Modules.Identity.md)
- [Nexo.Modules.Threats.Windows](Nexo.Modules.Threats.Windows.md)
- [Nexo.Ipc](Nexo.Ipc.md)

## Lo usan
- Es un ejecutable o paquete final: nadie lo referencia.

## Qué funciones implementa o soporta
- [Ventana principal](../04%20Interfaces/Ventana%20principal.md)

Volver a [Mapa de proyectos](Mapa%20de%20proyectos.md) · [Arquitectura general](../01%20Arquitectura/Arquitectura%20general.md)
