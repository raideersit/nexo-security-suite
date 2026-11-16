*Tipo: Función*

# Limpieza de archivos basura

Borra archivos basura de un **catálogo de reglas** con vista previa y confirmación.

## Cómo funciona
El cliente elige reglas por id, **nunca rutas**: el catálogo es la lista de lo que Nexo tiene permiso para destruir. Todo se hace con la identidad del llamador y sobre su perfil (carpetas base de su AppData). `GuardiaDeRutas` valida cada ruta; el borrado va a la Papelera (`BorradorPapelera`).

## Dónde vive
- [Nexo.Modules.Cleanup](../02%20Proyectos/Nexo.Modules.Cleanup.md)
- [Nexo.Modules.Cleanup.Windows](../02%20Proyectos/Nexo.Modules.Cleanup.Windows.md)
- [Nexo.Service](../02%20Proyectos/Nexo.Service.md)

## Métodos del pipe
- `limpieza.reglas`
- `limpieza.previsualizar`
- `limpieza.aplicar`

## Interfaz
- Pestaña **Limpieza**: reglas, vista previa, BORRAR.
- [Bandeja del sistema](../04%20Interfaces/Bandeja%20del%20sistema.md): «Limpiar archivos basura…».

## Notas que deja en Obsidian
Tipos de evento: `sesion-limpieza`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- Identidad del llamador ([Identidad del llamador](../01%20Arquitectura/Identidad%20del%20llamador.md)).
- Catálogo cerrado: no se puede pedir borrar una ruta arbitraria.

## Configuración
`Nexo:Limpieza:Modo` (papelera).

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
