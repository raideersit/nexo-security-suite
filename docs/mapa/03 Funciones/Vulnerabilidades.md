*Tipo: Función*

# Vulnerabilidades

Revisa aplicaciones instaladas (cruce con CVE/NVD), cuentas locales, dispositivos y redes Wi‑Fi.

## Cómo funciona
`ModeloDeAplicaciones`, `ModeloDeCuentas`, `ModeloDeDispositivos` y `ModeloWifi` interpretan lo que leen los lectores de Windows (WinGet, cuentas, dispositivos, WLAN). `CruceConCve` y `ConsultaNvdHttp` consultan el NVD. Un Wi‑Fi sin cifrado dispara un aviso en la bandeja.

## Dónde vive
- [Nexo.Modules.Threats](../02%20Proyectos/Nexo.Modules.Threats.md)
- [Nexo.Modules.Threats.Windows](../02%20Proyectos/Nexo.Modules.Threats.Windows.md)
- [Nexo.Native](../02%20Proyectos/Nexo.Native.md)

## Interfaz
- Pestaña **Seguridad**.
- [Bandeja del sistema](../04%20Interfaces/Bandeja%20del%20sistema.md): aviso de Wi‑Fi sin cifrado.

## Notas que deja en Obsidian
Tipos de evento: `vulnerabilidad-detectada`, `acceso-dispositivo`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- Solo lectura.

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
