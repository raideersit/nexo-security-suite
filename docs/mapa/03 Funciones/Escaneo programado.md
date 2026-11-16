*Tipo: Función*

# Escaneo programado

Escaneo periódico de carpetas fijas lanzado por el propio servicio.

## Cómo funciona
Se configura **solo** en `appsettings.json`; no hay métodos del pipe para activarlo, apagarlo o cambiar carpetas ni intervalo. Solo detecta: llevar algo a cuarentena sigue siendo el flujo con token. Consulta a [Perfiles de actividad](Perfiles%20de%20actividad.md) antes de arrancar para no molestar jugando.

## Dónde vive
- [Nexo.Service](../02%20Proyectos/Nexo.Service.md)
- [Nexo.Modules.Threats](../02%20Proyectos/Nexo.Modules.Threats.md)

## Métodos del pipe
- `escaneo-programado.estado`
- `escaneo-programado.detecciones`

## Interfaz
- Se ve en la pestaña **Estado**.

## Notas que deja en Obsidian
Tipos de evento: `resultado-escaneo`, `amenaza-detectada`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- Un proceso del usuario no puede apagarlo ([Apagado por omisión](../01%20Arquitectura/Apagado%20por%20omisi%C3%B3n.md)).

## Configuración
`Nexo:EscaneoProgramado` (Activo, IntervaloHoras, Raíces).

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
