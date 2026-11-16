*Tipo: Función*

# Comportamiento

Puntúa el comportamiento sospechoso de procesos con una sesión **ETW**.

## Cómo funciona
`PuntuadorDeComportamiento` suma señales por proceso. Solo OBSERVA: no detiene ni borra nada. Si la sesión no arranca, el estado lo dice y **nunca** da «sin sospechas».

## Dónde vive
- [Nexo.Modules.Threats](../02%20Proyectos/Nexo.Modules.Threats.md)
- [Nexo.Modules.Threats.Windows](../02%20Proyectos/Nexo.Modules.Threats.Windows.md)
- [Nexo.Service](../02%20Proyectos/Nexo.Service.md)

## Métodos del pipe
- `comportamiento.estado`

## Interfaz
- Lectura en el estado general.

## Seguridad
- Solo observa; exige administrador (el servicio ya lo es).

## Configuración
`Nexo:Comportamiento:Activo` (apagado por omisión).

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
