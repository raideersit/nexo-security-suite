*Tipo: Concepto*

# Configuración del servicio

`C:\Program Files\Nexo\service\appsettings.json`, sección `Nexo`:

| Clave | Qué controla |
|---|---|
| `Vault`, `PipeName`, `Motor` | Dónde se escriben las notas, nombre del pipe y motor de firmas (`clamd`) |
| `Yara`, `Amsi` | Motores adicionales de escaneo ([Escaneo bajo demanda](../03%20Funciones/Escaneo%20bajo%20demanda.md)) |
| `Limpieza` | Modo de borrado (`papelera`) ([Limpieza de archivos basura](../03%20Funciones/Limpieza%20de%20archivos%20basura.md)) |
| `TiempoReal` | [Tiempo real](../03%20Funciones/Tiempo%20real.md) |
| `EscaneoProgramado` | [Escaneo programado](../03%20Funciones/Escaneo%20programado.md) |
| `Disco` | [Salud del disco](../03%20Funciones/Salud%20del%20disco.md) |
| `Perfiles` | [Perfiles de actividad](../03%20Funciones/Perfiles%20de%20actividad.md) |
| `Comportamiento` | [Comportamiento](../03%20Funciones/Comportamiento.md) |
| `Mineria` | [Criptominería](../03%20Funciones/Criptominer%C3%ADa.md) |
| `Senuelos` | [Señuelos](../03%20Funciones/Se%C3%B1uelos.md) |
| `Copia` | [Copia versionada](../03%20Funciones/Copia%20versionada.md) |

Lo dice así: `Activo` booleano y parámetros propios. El instalador **conserva** este archivo al actualizar. Ver [Apagado por omisión](Apagado%20por%20omisi%C3%B3n.md).
