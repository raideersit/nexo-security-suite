*Tipo: Proyecto*

# Nexo.Service

El servicio de Windows `NexoService` (cuenta SYSTEM). Aloja todos los módulos que necesitan privilegios o que deben seguir vivos sin ventana, escucha en el pipe y es quien aplica los cambios aprobados. `NexoWorker` lo monta todo leyendo `appsettings.json`; `PoliticaDeAprobacion` decide cuándo hace falta UAC.

**Tamaño:** 25 archivos, ~4 000 líneas.

## Depende de
- [Nexo.Ipc](Nexo.Ipc.md)
- [Nexo.Modules.Threats.Windows](Nexo.Modules.Threats.Windows.md)
- [Nexo.Modules.Cleanup.Windows](Nexo.Modules.Cleanup.Windows.md)
- [Nexo.Reports](Nexo.Reports.md)

## Lo usan
- Es un ejecutable o paquete final: nadie lo referencia.

## Qué funciones implementa o soporta
- [Servicio NexoService](../03%20Funciones/Servicio%20NexoService.md)

Volver a [Mapa de proyectos](Mapa%20de%20proyectos.md) · [Arquitectura general](../01%20Arquitectura/Arquitectura%20general.md)
