# Material de la VM `NexoVM`

Scripts que se usaron para probar el servicio real en una VM (ver `GUION-PRUEBA-VM.md`). Se guardan para
no rehacerlos si hay que volver a montarla. **Son del montaje del Acer**: tienen rutas fijas
(`C:\VMs\stage`, `C:\Users\nexo\...`, `\\vboxsvr\stage`) y suponen la carpeta compartida `stage`. Ajusta las
rutas antes de usarlos. No forman parte del producto ni se compilan.

| Archivo | Para qué |
|---|---|
| `vm-sec6.ps1`, `vm-sec7.ps1`, `vm-todo.ps1`, `vm-todo2.ps1` | Guion §6 (limpieza/Papelera), §7 (tiempo real y USN) y el conjunto |
| `rt-5x.ps1` | Enciende el tiempo real vigilando una carpeta y recrea el EICAR (para §5 con la bandeja) |
| `inst.ps1`, `prepara.ps1` | Instalar el servicio y la bandeja, preparar el entorno |
| `ipc-prueba.ps1`, `prueba82.ps1` | Llamadas por el pipe (§3, §5.1, §8.2) |
| `corpus-grande.ps1`, `eicar-memoria.ps1` | Carga de 400 archivos para medir el escaneo en paralelo (§8.3), EICAR sin pasar por disco |
| `*.bat`, `guest6.ps1` | Lanzadores para `schtasks /it` y guestcontrol |

El cliente del pipe que usaban (`rpc.exe`) se perdió como código; está reescrito en `tools/Nexo.Ipc.Cli`
(`nexo-rpc <pipe> <metodo> [json]` y `nexo-rpc <pipe> flujo <previsualizar> <aplicar> [json]`).
Compila, pero **no se ha ejecutado todavía**.

## Montaje (resumen)

1. VirtualBox; VM Windows 10 22H2, 4 GB, 2 núcleos, 40 GB, red NAT; snapshot `limpia` al terminar la instalación.
2. Descargar en el **anfitrión** el ISO, el SDK de .NET y ClamAV con sus firmas, y pasarlos por carpeta
   compartida: el internet del invitado por NAT se cae con descargas largas.
3. Dos cuentas: una administradora y una estándar sin derechos de administrador.
4. .NET sin administrador en `C:\Users\<admin>\dotnet` y `DOTNET_ROOT` apuntando ahí para los *apphost*.
5. Publicar `Nexo.Service` y `Nexo.Ui.Tray` en `C:\Program Files\Nexo\...` e instalar con `nexo-service.ps1`.

## Trampas conocidas

- `guestcontrol` se traba: `VBoxManage controlvm <vm> reset` lo destraba, pero deja en ceros los archivos
  recién copiados. Usar `start` + `copyfrom` en vez de `run`.
- Los procesos de guestcontrol corren en una sesión aislada; para una consola visible usar `schtasks /it`.
- La CLI `--cuarentena` exige consola interactiva (se niega con la entrada redirigida, por diseño).
- Defender se reactiva solo y borra el EICAR: apagarlo a mano justo antes (no se automatiza) o excluir la
  carpeta con `Add-MpPreference -ExclusionPath`.
- La bandeja no escanea ni restaura: su menú «detecciones» solo muestra lo del tiempo real, que está
  apagado por omisión (`Nexo:TiempoReal:Activo`). Restaurar se hace con `nexo-rpc` desde una consola elevada.
- Al aprobar la cuarentena desde un usuario estándar, el UAC pide las credenciales de otro administrador.
