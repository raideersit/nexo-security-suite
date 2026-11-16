*Tipo: Función*

# Carpetas protegidas

Activa la protección de «Acceso controlado a carpetas» de Windows Defender.

## Cómo funciona
`PlanificadorDeCarpetasProtegidas` solo **activa** (o pasa a auditoría si estaba apagada): nunca apaga ni debilita. Mismo camino que el firewall y la VPN: previsualizar → token → aprobación → aplicar → releer estado.

## Dónde vive
- [Nexo.Modules.Threats](../02%20Proyectos/Nexo.Modules.Threats.md)
- [Nexo.Modules.Threats.Windows](../02%20Proyectos/Nexo.Modules.Threats.Windows.md)
- [Nexo.Service](../02%20Proyectos/Nexo.Service.md)

## Métodos del pipe
- `cfa.previsualizar`
- `cfa.aplicar`

## Interfaz
- Pestaña **Seguridad**.

## Notas que deja en Obsidian
Tipos de evento: `proteccion-ransomware-revisada`, `proteccion-ransomware-cambiada`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- Solo puede reforzar.

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
