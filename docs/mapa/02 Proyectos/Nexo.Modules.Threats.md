*Tipo: Proyecto*

# Nexo.Modules.Threats

La lógica portable de amenazas: firewall, escáner (clamd, AMSI, YARA), cuarentena, tiempo real, alertas, comportamiento, criptominería, ransomware (señuelos, carpetas protegidas, copia versionada), VPN, enlaces/phishing y vulnerabilidades. Es el proyecto más grande. No toca Windows directamente: define interfaces que implementa `Nexo.Modules.Threats.Windows`.

**Tamaño:** 45 archivos, ~9 200 líneas.

## Depende de
- [Nexo.Reports](Nexo.Reports.md)

## Lo usan
- [Nexo.Modules.Threats.Windows](Nexo.Modules.Threats.Windows.md)
- [Nexo.Ui.Desktop](Nexo.Ui.Desktop.md)

## Qué funciones implementa o soporta
- [Firewall](../03%20Funciones/Firewall.md)
- [Escaneo bajo demanda](../03%20Funciones/Escaneo%20bajo%20demanda.md)
- [Cuarentena](../03%20Funciones/Cuarentena.md)
- [Escaneo programado](../03%20Funciones/Escaneo%20programado.md)
- [Tiempo real](../03%20Funciones/Tiempo%20real.md)
- [Alertas de intrusión](../03%20Funciones/Alertas%20de%20intrusi%C3%B3n.md)
- [Comportamiento](../03%20Funciones/Comportamiento.md)
- [Criptominería](../03%20Funciones/Criptominer%C3%ADa.md)
- [Señuelos](../03%20Funciones/Se%C3%B1uelos.md)
- [Carpetas protegidas](../03%20Funciones/Carpetas%20protegidas.md)
- [Copia versionada](../03%20Funciones/Copia%20versionada.md)
- [VPN](../03%20Funciones/VPN.md)
- [Enlaces y phishing](../03%20Funciones/Enlaces%20y%20phishing.md)
- [Vulnerabilidades](../03%20Funciones/Vulnerabilidades.md)

Volver a [Mapa de proyectos](Mapa%20de%20proyectos.md) · [Arquitectura general](../01%20Arquitectura/Arquitectura%20general.md)
