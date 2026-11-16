*Tipo: Función*

# Salud del disco

Lee S.M.A.R.T. de los discos y avisa si empeoran.

## Cómo funciona
El servicio lee al arrancar y cada `IntervaloHoras` (por WMI, como SYSTEM para ver atributos ATA). `disco.estado` devuelve lo último sin releer; `disco.leer` pide una lectura nueva con un mínimo entre lecturas. Se guarda historial; un disco que no expone atributos sale «sin evaluar», nunca «sano» por defecto. Ojo: un disco USB suele no exponerlos.

## Dónde vive
- [Nexo.Modules.Cleanup](../02%20Proyectos/Nexo.Modules.Cleanup.md)
- [Nexo.Modules.Cleanup.Windows](../02%20Proyectos/Nexo.Modules.Cleanup.Windows.md)
- [Nexo.Service](../02%20Proyectos/Nexo.Service.md)

## Métodos del pipe
- `disco.estado`
- `disco.leer`

## Interfaz
- Pestaña **Disco**.

## Notas que deja en Obsidian
Tipos de evento: `salud-disco`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- Solo lectura.

## Configuración
`Nexo:Disco` (Activo, IntervaloHoras).

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
