*Tipo: Función*

# Bóveda de contraseñas

Guarda contraseñas en un archivo cifrado `.nxv`, con generador de contraseñas y códigos TOTP.

## Cómo funciona
`Boveda` + `FormatoDeBoveda` + `ParametrosDeClave` (derivación de clave). `GeneradorDeContrasenas` y `GeneradorDeTotp`. El portapapeles se borra al cerrar la ventana y la bóveda se bloquea sola. Vive en `%LOCALAPPDATA%\Nexo`, **no** pasa por el servicio.

## Dónde vive
- [Nexo.Modules.Identity](../02%20Proyectos/Nexo.Modules.Identity.md)
- [Nexo.Ui.Desktop](../02%20Proyectos/Nexo.Ui.Desktop.md)

## Interfaz
- Pestaña **Contraseñas**.

## Notas que deja en Obsidian
Tipos de evento: `boveda-creada`, `boveda-desbloqueada`, `boveda-fallo-de-desbloqueo`, `boveda-bloqueada`, `boveda-copia-guardada`, `boveda-restaurada`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- Las notas del vault nunca llevan contraseñas ([Reportes y vault de Obsidian](Reportes%20y%20vault%20de%20Obsidian.md) redacta datos sensibles).

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
