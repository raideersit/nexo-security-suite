*Tipo: Función*

# Reportes y vault de Obsidian

Todo módulo, al hacer algo relevante, le pasa un `NexoEvent` a `ReportWriter`, que lo convierte en notas markdown de un vault de Obsidian. Es lo que permite revisar la historia de la máquina con el grafo de Obsidian.

## Cómo funciona
- `NexoEvent` lleva tipo (`TipoEvento`), módulo de origen, texto y **entidades** referenciadas (archivo, proceso, aplicación, dispositivo, dominio, cuenta).
- `DailyNoteWriter` añade una línea a la **nota diaria** (`yyyy-MM-dd`) y `EntityNoteWriter` crea/actualiza una nota por entidad con prefijo (`Archivo-`, `App-`, `Dominio-`…) para que en el grafo se vea de qué tipo es cada nodo.
- `Redactor` quita o enmascara datos sensibles antes de escribir (rutas con usuario, claves…).
- Las escrituras son atómicas (`AtomicFile`) para no dejar notas a medias si se corta la luz.

## Estructura del vault
Carpetas con prefijo numérico: `00 Panel`, `01 Diario`, `02 Eventos`, `03 Entidades` y `99 Sistema`. Por módulo: Amenazas, Privacidad, Identidad, Limpieza, Sistema. Hay un ejemplo en `vault-demo` del repositorio.

## Dónde vive
- [Nexo.Reports](../02%20Proyectos/Nexo.Reports.md)
- Lo usan todos los proyectos de módulos y el servicio ([Mapa de proyectos](../02%20Proyectos/Mapa%20de%20proyectos.md)).

Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md) y [Arquitectura general](../01%20Arquitectura/Arquitectura%20general.md).
