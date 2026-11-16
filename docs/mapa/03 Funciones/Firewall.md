*Tipo: Función*

# Firewall

Crea y quita reglas del Firewall de Windows **por aplicación** y activa el modo sigiloso. También lee los bloqueos (evento 5157) para saber qué se bloqueó.

## Cómo funciona
Dos pasos: previsualizar (no cambia nada, devuelve un token) y aplicar (ejecuta solo el plan de ese token). `AdministradorDeFirewall` y `GuardiaDeReglas` validan rutas y protegen procesos críticos; `TraductorDeRutasNt` convierte rutas del kernel a rutas normales; `ParserDeEvento5157` interpreta los bloqueos.

## Dónde vive
- [Nexo.Modules.Threats](../02%20Proyectos/Nexo.Modules.Threats.md)
- [Nexo.Modules.Threats.Windows](../02%20Proyectos/Nexo.Modules.Threats.Windows.md)
- [Nexo.Service](../02%20Proyectos/Nexo.Service.md)

## Métodos del pipe
- `firewall.estado`
- `firewall.previsualizar`
- `firewall.aplicar`

## Interfaz
- Pestaña **Firewall** de la [Ventana principal](../04%20Interfaces/Ventana%20principal.md): perfiles, modo sigiloso, bloquear un programa, quitar una regla de Nexo.
- [Bandeja del sistema](../04%20Interfaces/Bandeja%20del%20sistema.md): aprobación con UAC.

## Notas que deja en Obsidian
Tipos de evento: `bloqueo-firewall`, `regla-firewall`, `modo-sigiloso`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- La validación la hace `GuardiaDeReglas`, no el módulo del pipe.
- Solo toca reglas que Nexo creó.

## Estado
Verificado contra el Firewall de Windows real.

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
