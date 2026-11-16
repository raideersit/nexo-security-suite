*Tipo: Concepto*

# Pipe IPC y su ACL

El pipe `NexoIpc` es el único canal. Implementado en [Nexo.Ipc](../02%20Proyectos/Nexo.Ipc.md): `ServidorDePipe` (en el servicio), `ClienteDePipe` (ventana y bandeja), `Tramas` (formato con longitud), `Contratos` (`Solicitud` / `Respuesta`, JSON).

## ACL (`SeguridadDePipe`)
- SYSTEM y Administradores: control total.
- Usuario interactivo: lectura y escritura.
- **Red denegada explícitamente.** Nadie más (ni Everyone, ni invitados).
- Solo SYSTEM/Administradores pueden *crear* el pipe: por eso el cliente puede aceptar suplantación sin riesgo de un servidor falso ([Identidad del llamador](Identidad%20del%20llamador.md)).

## Todos los métodos
| Área | Métodos |
|---|---|
| [Firewall](../03%20Funciones/Firewall.md) | `firewall.estado`, `.previsualizar`, `.aplicar` |
| [Escaneo bajo demanda](../03%20Funciones/Escaneo%20bajo%20demanda.md) | `escaneo.estado`, `.iniciar`, `.progreso`, `.resultado`, `.cancelar` |
| [Cuarentena](../03%20Funciones/Cuarentena.md) | `cuarentena.listar`, `.previsualizar`, `.aplicar`, `.previsualizar-restauracion`, `.restaurar`, `.previsualizar-purga`, `.purgar` |
| [Escaneo programado](../03%20Funciones/Escaneo%20programado.md) | `escaneo-programado.estado`, `.detecciones` |
| [Tiempo real](../03%20Funciones/Tiempo%20real.md) | `tiempo-real.estado`, `.detecciones` |
| [Alertas de intrusión](../03%20Funciones/Alertas%20de%20intrusi%C3%B3n.md) | `alertas.revisar` |
| [Comportamiento](../03%20Funciones/Comportamiento.md) | `comportamiento.estado` |
| [Criptominería](../03%20Funciones/Criptominer%C3%ADa.md) | `mineria.estado` |
| [Señuelos](../03%20Funciones/Se%C3%B1uelos.md) | `senuelos.estado`, `.previsualizar`, `.reponer` |
| [Carpetas protegidas](../03%20Funciones/Carpetas%20protegidas.md) | `cfa.previsualizar`, `cfa.aplicar` |
| [Copia versionada](../03%20Funciones/Copia%20versionada.md) | `copia.estado`, `copia.hacer`, `copia.descartar` |
| [VPN](../03%20Funciones/VPN.md) | `vpn.estado`, `vpn.previsualizar`, `vpn.aplicar` |
| [Limpieza de archivos basura](../03%20Funciones/Limpieza%20de%20archivos%20basura.md) | `limpieza.reglas`, `.previsualizar`, `.aplicar` |
| [Salud del disco](../03%20Funciones/Salud%20del%20disco.md) | `disco.estado`, `disco.leer` |
| [Perfiles de actividad](../03%20Funciones/Perfiles%20de%20actividad.md) | `perfil.estado` |

Fíjate en lo que **no** hay: métodos para apagar protecciones, cambiar destinos o restaurar ([Apagado por omisión](Apagado%20por%20omisi%C3%B3n.md)).

Ver [Arquitectura general](Arquitectura%20general.md).
