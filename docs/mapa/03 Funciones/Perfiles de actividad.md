*Tipo: Función*

# Perfiles de actividad

Pospone las tareas pesadas automáticas cuando estás jugando, en pantalla completa o con batería.

## Cómo funciona
Cada pocos segundos lee energía y pantalla completa, elige un perfil con histéresis y se lo da a `PuertaDeTareasPesadas`, que consultan [Escaneo programado](Escaneo%20programado.md) y [Copia versionada](Copia%20versionada.md) antes de arrancar. Solo **posterga** (con máximo de espera): no toca el plan de energía ni prioridades.

## Dónde vive
- [Nexo.Modules.Cleanup](../02%20Proyectos/Nexo.Modules.Cleanup.md)
- [Nexo.Modules.Cleanup.Windows](../02%20Proyectos/Nexo.Modules.Cleanup.Windows.md)
- [Nexo.Native](../02%20Proyectos/Nexo.Native.md)
- [Nexo.Service](../02%20Proyectos/Nexo.Service.md)

## Métodos del pipe
- `perfil.estado`

## Interfaz
- Lectura en el estado general.

## Seguridad
- Cambia CUÁNDO corren las tareas, no QUÉ protege.

## Configuración
`Nexo:Perfiles` (Activo, SegundosEntreLecturas, MaximoEsperaHoras).

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
