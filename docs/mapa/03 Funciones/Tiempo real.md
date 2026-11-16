*Tipo: Función*

# Tiempo real

Vigila cambios en carpetas y escanea lo nuevo. **Detecta y avisa; no bloquea** (el archivo ya está escrito).

## Cómo funciona
Dos fuentes: `FileSystemWatcher` o el **diario USN** del volumen (necesita administrador; lo hace el servicio como SYSTEM). `FiltroDeCambios` descarta ruido; `ParserDeUsn` lee el diario; `VigilanteEnTiempoReal` coordina. Solo lectura por el pipe.

## Dónde vive
- [Nexo.Modules.Threats](../02%20Proyectos/Nexo.Modules.Threats.md)
- [Nexo.Modules.Threats.Windows](../02%20Proyectos/Nexo.Modules.Threats.Windows.md)
- [Nexo.Native](../02%20Proyectos/Nexo.Native.md)
- [Nexo.Service](../02%20Proyectos/Nexo.Service.md)

## Métodos del pipe
- `tiempo-real.estado`
- `tiempo-real.detecciones`

## Interfaz
- Pestaña **Tiempo real**: cobertura, carpetas, detecciones, revisar lo no visto. No se enciende desde la ventana, a propósito.
- [Bandeja del sistema](../04%20Interfaces/Bandeja%20del%20sistema.md): avisos de detección.

## Notas que deja en Obsidian
Tipos de evento: `amenaza-detectada`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- Sin métodos para apagarlo ni cambiar carpetas ([Apagado por omisión](../01%20Arquitectura/Apagado%20por%20omisi%C3%B3n.md)).

## Configuración
`Nexo:TiempoReal` (Activo, Fuente, Raíces).

## Estado
Apagado por omisión. El diario USN se probó como administrador.

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
