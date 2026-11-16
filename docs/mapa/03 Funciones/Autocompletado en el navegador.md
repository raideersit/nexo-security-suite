*Tipo: Función*

# Autocompletado en el navegador

Rellena usuario y contraseña en Brave/Chrome desde la bóveda, con emparejamiento previo.

## Cómo funciona
La extensión ([Nexo.Autocompletado.Extension](../02%20Proyectos/Nexo.Autocompletado.Extension.md)) habla con el host nativo ([Nexo.Autocompletado.Host](../02%20Proyectos/Nexo.Autocompletado.Host.md)), que usa `CanalDeAutocompletado` y `PuenteDeAutocompletado` de [Nexo.Modules.Identity](../02%20Proyectos/Nexo.Modules.Identity.md). `SitioDeEntrada` decide qué sitios coinciden. El registro del host es **por usuario** (HKCU).

## Dónde vive
- [Nexo.Modules.Identity](../02%20Proyectos/Nexo.Modules.Identity.md)
- [Nexo.Autocompletado.Host](../02%20Proyectos/Nexo.Autocompletado.Host.md)
- [Nexo.Autocompletado.Extension](../02%20Proyectos/Nexo.Autocompletado.Extension.md)
- [Nexo.Ui.Desktop](../02%20Proyectos/Nexo.Ui.Desktop.md)

## Interfaz
- Panel de la extensión del navegador.
- Estado y emparejamiento en la pestaña **Contraseñas**.

## Notas que deja en Obsidian
Tipos de evento: `autocompletado-emparejado`, `autocompletado-rechazado`, `autocompletado-no-solicitado`, `autocompletado-olvidado`, `autocompletado-rellenado`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- Emparejado explícito; rellenar sin que se pida queda registrado como `autocompletado-no-solicitado`.

## Estado
Se registra con `nexo-autocompletar.exe --instalar`, sin administrador.

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
