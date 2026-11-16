*Tipo: Función*

# VPN

Revisa un archivo `.conf` de WireGuard y conecta o desconecta un túnel.

## Cómo funciona
`AnalizadorDeVpn` y `ConfiguracionWireGuard` leen y puntúan el archivo (servidor en listas, `AllowedIPs`, DNS…). `PlanificadorDeVpn` decide qué se hace. El texto viaja por el pipe local y vive en memoria hasta aplicar o caducar el token: **nunca se escribe en el vault** (contiene la clave privada).

## Dónde vive
- [Nexo.Modules.Threats](../02%20Proyectos/Nexo.Modules.Threats.md)
- [Nexo.Modules.Threats.Windows](../02%20Proyectos/Nexo.Modules.Threats.Windows.md)
- [Nexo.Service](../02%20Proyectos/Nexo.Service.md)

## Métodos del pipe
- `vpn.estado`
- `vpn.previsualizar`
- `vpn.aplicar`

## Interfaz
- Pestaña **VPN** de la [Ventana principal](../04%20Interfaces/Ventana%20principal.md): cargar archivo, ver hallazgos, conectar o desconectar.

## Notas que deja en Obsidian
Tipos de evento: `conexion-vpn`, `configuracion-vpn-revisada`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- Aprobación con UAC real ([Vista previa, token y aprobación](../01%20Arquitectura/Vista%20previa%2C%20token%20y%20aprobaci%C3%B3n.md)).
- Nexo no instala WireGuard: es el cliente oficial, gratuito (MIT).

## Estado
Probado el 2026-11-15 con un túnel de prueba: conectar y desconectar desde la ventana con UAC real.

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
