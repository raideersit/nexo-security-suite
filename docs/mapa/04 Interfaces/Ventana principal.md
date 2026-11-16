*Tipo: Interfaz*

# Ventana principal

[Nexo.Ui.Desktop](../02%20Proyectos/Nexo.Ui.Desktop.md) — Avalonia, tema Classic, 12 pestañas. Habla con el servicio por el pipe y, cuando algo requiere aprobación, lanza [Bandeja del sistema](Bandeja%20del%20sistema.md) elevada ([Vista previa, token y aprobación](../01%20Arquitectura/Vista%20previa%2C%20token%20y%20aprobaci%C3%B3n.md)).

## Pestañas y a qué función corresponden
| Pestaña | Función |
|---|---|
| Estado | Resumen de todo: tiempo real, motor, escaneo programado, firewall y cuarentena |
| Escaneo | [Escaneo bajo demanda](../03%20Funciones/Escaneo%20bajo%20demanda.md) |
| Cuarentena | [Cuarentena](../03%20Funciones/Cuarentena.md) |
| Firewall | [Firewall](../03%20Funciones/Firewall.md) |
| Limpieza | [Limpieza de archivos basura](../03%20Funciones/Limpieza%20de%20archivos%20basura.md) y [Duplicados](../03%20Funciones/Duplicados.md) |
| Tiempo real | [Tiempo real](../03%20Funciones/Tiempo%20real.md) |
| Disco | [Salud del disco](../03%20Funciones/Salud%20del%20disco.md) |
| Seguridad | [Carpetas protegidas](../03%20Funciones/Carpetas%20protegidas.md) y [Vulnerabilidades](../03%20Funciones/Vulnerabilidades.md) |
| Contraseñas | [Bóveda de contraseñas](../03%20Funciones/B%C3%B3veda%20de%20contrase%C3%B1as.md), [Filtraciones de contraseñas](../03%20Funciones/Filtraciones%20de%20contrase%C3%B1as.md), [Autocompletado en el navegador](../03%20Funciones/Autocompletado%20en%20el%20navegador.md) |
| Enlaces | [Enlaces y phishing](../03%20Funciones/Enlaces%20y%20phishing.md) |
| VPN | [VPN](../03%20Funciones/VPN.md) |
| Copias | [Copia versionada](../03%20Funciones/Copia%20versionada.md) |

## Cómo está hecha
Cada pestaña tiene un *modelo* (`...Modelo.cs`) con la lógica y un archivo XAML. Los modelos se prueban sin pantalla (batería `Nexo.Desktop.Demo`, en Windows y Linux).
