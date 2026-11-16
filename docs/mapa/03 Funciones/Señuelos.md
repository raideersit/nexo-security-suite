*Tipo: Función*

# Señuelos

Coloca archivos señuelo en carpetas del usuario y avisa si algo los toca: señal temprana de ransomware.

## Cómo funciona
El servicio los pone (a veces ocultos) y los revisa cada pocos segundos. Si uno cambia o desaparece, deja una nota y un aviso. Reponerlos requiere vista previa, token y aprobación: así un proceso del usuario no puede «dar por visto» el aviso a escondidas.

## Dónde vive
- [Nexo.Modules.Threats](../02%20Proyectos/Nexo.Modules.Threats.md)
- [Nexo.Modules.Threats.Windows](../02%20Proyectos/Nexo.Modules.Threats.Windows.md)
- [Nexo.Service](../02%20Proyectos/Nexo.Service.md)

## Métodos del pipe
- `senuelos.estado`
- `senuelos.previsualizar`
- `senuelos.reponer`

## Interfaz
- [Bandeja del sistema](../04%20Interfaces/Bandeja%20del%20sistema.md): opción de señuelos y avisos.

## Notas que deja en Obsidian
Tipos de evento: `senuelos-puestos`, `senuelo-tocado`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- Se activa solo en `appsettings.json`; sin método para apagarlo ([Apagado por omisión](../01%20Arquitectura/Apagado%20por%20omisi%C3%B3n.md)).

## Configuración
`Nexo:Senuelos` (Activo, SegundosEntreRevisiones, Ocultos, Carpetas).

## Estado
Probados de verdad como SYSTEM (2026-11-14).

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
