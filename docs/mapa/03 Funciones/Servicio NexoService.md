*Tipo: Función*

# Servicio NexoService

Proceso de fondo (cuenta SYSTEM) que aloja los módulos privilegiados y es quien **aplica** los cambios aprobados. `NexoWorker.CrearModulos` lee `appsettings.json` y construye solo lo que está activo.

## Módulos que aloja
- [Firewall](Firewall.md)
- [Escaneo bajo demanda](Escaneo%20bajo%20demanda.md)
- [Cuarentena](Cuarentena.md)
- [Escaneo programado](Escaneo%20programado.md)
- [Tiempo real](Tiempo%20real.md)
- [Alertas de intrusión](Alertas%20de%20intrusi%C3%B3n.md)
- [Comportamiento](Comportamiento.md)
- [Criptominería](Criptominer%C3%ADa.md)
- [Señuelos](Se%C3%B1uelos.md)
- [Carpetas protegidas](Carpetas%20protegidas.md)
- [Copia versionada](Copia%20versionada.md)
- [VPN](VPN.md)
- [Limpieza de archivos basura](Limpieza%20de%20archivos%20basura.md)
- [Salud del disco](Salud%20del%20disco.md)
- [Perfiles de actividad](Perfiles%20de%20actividad.md)

Además hay un módulo de **rastro de ventana** (`ModuloRastroDeVentana`) que deja constancia de lo que se hace desde la ventana.

## Piezas clave
- `IModuloDelServicio`: cada módulo declara sus `Metodos` y atiende `ManejarAsync`.
- `PoliticaDeAprobacion`: decide si aplicar exige token elevado ([Vista previa, token y aprobación](../01%20Arquitectura/Vista%20previa%2C%20token%20y%20aprobaci%C3%B3n.md)).
- `PlanesPendientes`: guarda los planes con caducidad hasta que llega «aplicar».
- Instalación: servicio `NexoService`, inicio **manual** salvo `-Automatico` ([Instalación en Program Files](../04%20Interfaces/Instalaci%C3%B3n%20en%20Program%20Files.md)).

Ver [Pipe IPC y su ACL](../01%20Arquitectura/Pipe%20IPC%20y%20su%20ACL.md) · [Configuración del servicio](../01%20Arquitectura/Configuraci%C3%B3n%20del%20servicio.md) · [Nexo.Service](../02%20Proyectos/Nexo.Service.md)

Volver a [Mapa de funciones](Mapa%20de%20funciones.md)
