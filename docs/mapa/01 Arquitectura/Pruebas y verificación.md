*Tipo: Concepto*

# Pruebas y verificación

El proyecto no usa un framework de pruebas: cada área tiene un ejecutable `Demo` en `tools\` que corre comprobaciones y termina con «TODAS LAS VERIFICACIONES PASARON». Ejemplos: `Nexo.Service.Demo` (el servicio), `Nexo.Desktop.Demo` (la ventana sin pantalla), `Nexo.Vpn.Demo`, `Nexo.Tray.Demo`, `Nexo.Ipc.Demo`, `Nexo.Scan.Demo`, `Nexo.Firewall.Demo`…

Las baterías se corren en **ambos modos**: como administrador y como usuario normal (`runas /trustlevel:0x20000`), porque cambian lo que se puede hacer.

## Verificado en un equipo real (resumen)
- 2026-11-14: señuelos y alertas de intrusión como SYSTEM; `-Autocontenido`; VPN con WireGuard 1.1.1.
- 2026-11-15: bandeja tras cerrar sesión; **copia real** de ~15 GB en un disco interno; **vigilante del destino** con un USB desconectado a propósito; **UAC real de la VPN** desde la ventana (con el arreglo de la ruta de la bandeja); limpieza de carpetas temporales de las pruebas.

Ver [Mapa de proyectos](../02%20Proyectos/Mapa%20de%20proyectos.md).
