*Tipo: Proyecto*

# Nexo.Ipc

El canal entre procesos: cliente y servidor de *named pipe*, tramas, contratos de solicitud/respuesta y la ACL del pipe (`SeguridadDePipe`). Es lo único que comparten la ventana, la bandeja y el servicio.

**Tamaño:** 6 archivos, ~560 líneas.

## Depende de
- Nada (es una hoja del grafo de dependencias).

## Lo usan
- [Nexo.Service](Nexo.Service.md)
- [Nexo.Ui.Desktop](Nexo.Ui.Desktop.md)
- [Nexo.Ui.Tray](Nexo.Ui.Tray.md)

## Qué funciones implementa o soporta
- [Pipe IPC y su ACL](../01%20Arquitectura/Pipe%20IPC%20y%20su%20ACL.md)

Volver a [Mapa de proyectos](Mapa%20de%20proyectos.md) · [Arquitectura general](../01%20Arquitectura/Arquitectura%20general.md)
