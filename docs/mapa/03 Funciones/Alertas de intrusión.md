*Tipo: Función*

# Alertas de intrusión

Busca señales de intrusión en los registros de Seguridad y de Sistema de Windows.

## Cómo funciona
Solo lectura: no cambia la política de auditoría ni nada. Exige administrador, por eso corre en el servicio. Tiene tope de frecuencia: un programa no debe poder ponerlo a leer sin parar. Deja una nota por revisión.

## Dónde vive
- [Nexo.Modules.Threats](../02%20Proyectos/Nexo.Modules.Threats.md)
- [Nexo.Modules.Threats.Windows](../02%20Proyectos/Nexo.Modules.Threats.Windows.md)
- [Nexo.Native](../02%20Proyectos/Nexo.Native.md)
- [Nexo.Service](../02%20Proyectos/Nexo.Service.md)

## Métodos del pipe
- `alertas.revisar`

## Interfaz
- Avisos desde la [Bandeja del sistema](../04%20Interfaces/Bandeja%20del%20sistema.md).

## Notas que deja en Obsidian
Tipos de evento: `alerta-identidad`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- Solo lectura y con límite de frecuencia.

## Estado
Probado como SYSTEM junto con los señuelos (2026-11-14).

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
