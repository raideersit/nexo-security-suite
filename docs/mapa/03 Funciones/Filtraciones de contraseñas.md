*Tipo: Función*

# Filtraciones de contraseñas

Audita la bóveda contra contraseñas filtradas conocidas, sin enviar la contraseña.

## Cómo funciona
`AuditoriaDeBoveda` y `ComprobadorDeContrasenas` consultan por **rangos** (`ConsultaDeRangosHttp`): solo viaja un prefijo de la huella, nunca la contraseña.

## Dónde vive
- [Nexo.Modules.Identity](../02%20Proyectos/Nexo.Modules.Identity.md)

## Interfaz
- Dentro de la pestaña **Contraseñas**.

## Notas que deja en Obsidian
Tipos de evento: `boveda-auditada`, `brecha-detectada`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- Consulta por rangos: no se comparte la contraseña.

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
