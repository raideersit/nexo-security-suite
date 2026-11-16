*Tipo: Función*

# Cuarentena

Aísla archivos detectados, los lista, los restaura o los elimina cuando vencen.

## Cómo funciona
Solo se pone en cuarentena lo que detectó un escaneo del propio servicio, nombrado por el **id de ese escaneo**: el cliente no puede pasar rutas suyas (si pudiera, tendría a SYSTEM moviendo cualquier archivo). Retirar y restaurar se hace con la identidad del llamador. Restaurar es solo a la ruta original y nunca pisa un archivo.

## Dónde vive
- [Nexo.Modules.Threats](../02%20Proyectos/Nexo.Modules.Threats.md)
- [Nexo.Service](../02%20Proyectos/Nexo.Service.md)

## Métodos del pipe
- `cuarentena.listar`
- `cuarentena.previsualizar`
- `cuarentena.aplicar`
- `cuarentena.previsualizar-restauracion`
- `cuarentena.restaurar`
- `cuarentena.previsualizar-purga`
- `cuarentena.purgar`

## Interfaz
- Pestaña **Cuarentena**: lista, restaurar, eliminar vencidos.

## Notas que deja en Obsidian
Tipos de evento: `archivo-en-cuarentena`, `archivo-restaurado`, `cuarentena-purgada`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- Identidad del llamador ([Identidad del llamador](../01%20Arquitectura/Identidad%20del%20llamador.md)).
- Todo cambio lleva vista previa y token ([Vista previa, token y aprobación](../01%20Arquitectura/Vista%20previa%2C%20token%20y%20aprobaci%C3%B3n.md)).

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
