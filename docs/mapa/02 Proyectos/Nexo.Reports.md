*Tipo: Proyecto*

# Nexo.Reports

Convierte todo lo que pasa en notas markdown de un vault de Obsidian. Es la base: casi todos los módulos dependen de él para dejar rastro. Incluye el modelo de eventos (`NexoEvent`, `TipoEvento`), el escritor de reportes (`ReportWriter`), la estructura del vault (`VaultLayout`, `VaultBootstrapper`, `DailyNoteWriter`, `EntityNoteWriter`, `AtomicFile`, `YamlWriter`) y el redactor de datos sensibles (`Redactor`).

**Tamaño:** 21 archivos, ~2 600 líneas.

## Depende de
- Nada (es una hoja del grafo de dependencias).

## Lo usan
- [Nexo.Modules.Threats](Nexo.Modules.Threats.md)
- [Nexo.Modules.Cleanup](Nexo.Modules.Cleanup.md)
- [Nexo.Modules.Identity](Nexo.Modules.Identity.md)
- [Nexo.Service](Nexo.Service.md)

## Qué funciones implementa o soporta
- [Reportes y vault de Obsidian](../03%20Funciones/Reportes%20y%20vault%20de%20Obsidian.md)

Volver a [Mapa de proyectos](Mapa%20de%20proyectos.md) · [Arquitectura general](../01%20Arquitectura/Arquitectura%20general.md)
