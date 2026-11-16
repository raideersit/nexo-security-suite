*Tipo: Función*

# Escaneo bajo demanda

Escanea carpetas o archivos con ClamAV (clamd) y, opcionalmente, YARA y AMSI.

## Cómo funciona
Un escaneo dura más que el límite por petición, así que es un **trabajo**: `iniciar` devuelve un id y se consulta con `progreso` y `resultado`. Escanear no modifica nada; llevar algo a cuarentena es otro flujo ([Cuarentena](Cuarentena.md)).

## Dónde vive
- [Nexo.Modules.Threats](../02%20Proyectos/Nexo.Modules.Threats.md)
- [Nexo.Modules.Threats.Windows](../02%20Proyectos/Nexo.Modules.Threats.Windows.md)
- [Nexo.Native](../02%20Proyectos/Nexo.Native.md)
- [Nexo.Service](../02%20Proyectos/Nexo.Service.md)

## Métodos del pipe
- `escaneo.estado`
- `escaneo.iniciar`
- `escaneo.progreso`
- `escaneo.resultado`
- `escaneo.cancelar`

## Interfaz
- Pestaña **Escaneo**: escanear, ver avance, cancelar, ver resultado.

## Notas que deja en Obsidian
Tipos de evento: `resultado-escaneo`, `amenaza-detectada`. Ver [Eventos y notas del vault](../01%20Arquitectura/Eventos%20y%20notas%20del%20vault.md).

## Seguridad
- El servicio lee con su cuenta, así que el escaneo solo cubre lo que el servicio decide permitir.
- Motor configurable (`Nexo:Motor`): `clamd` u otro básico.

## Configuración
Secciones `Yara` y `Amsi` de `appsettings.json` ([Configuración del servicio](../01%20Arquitectura/Configuraci%C3%B3n%20del%20servicio.md)).

## Estado
Probado contra un clamd falso; ClamAV real pendiente según el README.

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
