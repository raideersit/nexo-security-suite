*Tipo: Función*

# Criptominería

Detecta procesos y conexiones típicos de criptojacking.

## Cómo funciona
Cada pocos segundos el servicio toma una muestra de procesos y conexiones TCP y se la pasa a `VigilanteDeMineria`, que la compara con una lista de pools. Solo observa.

## Dónde vive
- [Nexo.Modules.Threats](../02%20Proyectos/Nexo.Modules.Threats.md)
- [Nexo.Modules.Threats.Windows](../02%20Proyectos/Nexo.Modules.Threats.Windows.md)
- [Nexo.Native](../02%20Proyectos/Nexo.Native.md)
- [Nexo.Service](../02%20Proyectos/Nexo.Service.md)

## Métodos del pipe
- `mineria.estado`

## Interfaz
- Lectura en el estado general.

## Seguridad
- Solo lectura.

## Configuración
`Nexo:Mineria` (Activo, SegundosEntreMuestras, ListaDePools).

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
