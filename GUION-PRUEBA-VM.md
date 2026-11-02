# Guion de prueba en la VM `NexoVM`

Objetivo: comprobar lo que los arneses no pueden (servicio real con el SCM, otro usuario, UAC, bandeja visible, Papelera, ClamAV).
Anota cada resultado como **OK / FALLO / NOTA** en la tabla del final. Un fallo es información útil, no un problema.

## 0. Antes de empezar

- VM Windows 10/11 con **snapshot "limpia"**. Todo lo de abajo se hace dentro de la VM, nunca en el equipo principal.
- Dos cuentas: `admin` (administrador, la que instala) y `usuario` (estándar, sin derechos de administrador).
- .NET SDK 8 en la VM (o publica en el equipo principal y copia las carpetas).
- Copia el repo a la VM, p. ej. a `C:\src\nexo-security-suite` (fuera de Program Files).

## 1. Publicar e instalar (como `admin`, PowerShell elevado)

```powershell
cd C:\src\nexo-security-suite
dotnet publish src\Nexo.Service -c Release -o "C:\Program Files\Nexo\service"
dotnet publish src\Nexo.Ui.Tray -c Release -o "C:\Program Files\Nexo\tray"
.\src\Nexo.Service\Install\nexo-service.ps1 -Accion instalar `
  -Ruta "C:\Program Files\Nexo\service\nexo-service.exe" `
  -Bandeja "C:\Program Files\Nexo\tray\nexo-tray.exe"
.\src\Nexo.Service\Install\nexo-service.ps1 -Accion estado
```

Debería verse: servicio `NexoService` instalado (manual) y la bandeja en el arranque.

| # | Comprobación | Esperado |
|---|---|---|
| 1.1 | El script se ejecuta sin errores | Es la primera vez que corre: anota cualquier excepción tal cual |
| 1.2 | `icacls "$env:ProgramData\Nexo"` | Solo SYSTEM y Administradores |
| 1.3 | Instalar desde `C:\src\...` (carpeta modificable) | El script **se niega** con el mensaje de ubicación insegura |

## 2. Arrancar el servicio

```powershell
Start-Service NexoService
Get-Service NexoService
Get-WinEvent -LogName Application -MaxEvents 20 | Where-Object ProviderName -match 'Nexo'
```

| # | Comprobación | Esperado |
|---|---|---|
| 2.1 | Estado `Running` | Arranca como LocalSystem |
| 2.2 | Existe una nota de arranque en el vault | `%ProgramData%\Nexo\Vault` (evento `ServicioIniciado`) |
| 2.3 | Matar el proceso (`Stop-Process -Name nexo-service -Force`) | Windows lo reinicia a los ~5 s |

## 3. Consulta desde la bandeja sin pantalla (como `usuario`)

```powershell
& "C:\Program Files\Nexo\tray\nexo-tray.exe" --una-vez --salida $env:TEMP\nexo.json
Get-Content $env:TEMP\nexo.json
```

| # | Comprobación | Esperado |
|---|---|---|
| 3.1 | `conectado: true` | Un usuario estándar llega al pipe `NexoIpc` (ACL: Interactive ReadWrite) |
| 3.2 | Con el servicio parado | `conectado: false` y estado de error, **no** "todo bien" |

## 4. La bandeja a la vista (cierra sesión y entra como `usuario`)

Primera vez que una persona la ve: anota todo lo raro (icono borroso, menú cortado, globos que no salen, DPI).

| # | Comprobación | Esperado |
|---|---|---|
| 4.1 | Aparece el icono al iniciar sesión (clave Run) | Sí, con estado coherente |
| 4.2 | Menú contextual | Se abre, textos legibles |
| 4.3 | Parar el servicio | El icono pasa a estado "sin conexión" |
| 4.4 | Reiniciar el servicio | Vuelve a conectado sin reiniciar la bandeja |

## 5. Escaneo y cuarentena con el usuario real

Descarga el archivo de prueba **EICAR** de eicar.org y guárdalo en `C:\Users\usuario\Desktop\prueba\`. Defender puede quitarlo antes de que Nexo lo vea: si pasa, anótalo (es la cuestión de exclusión mutua con Defender) y desactiva la protección en tiempo real solo en la VM para continuar.

| # | Comprobación | Esperado |
|---|---|---|
| 5.1 | Escanear esa carpeta desde la bandeja | Detección listada |
| 5.2 | Previsualizar cuarentena | Plan con un token; **no** se mueve nada aún |
| 5.3 | Aplicar → aviso de UAC | Sale el aviso (escritorio seguro). Con un estándar pide credenciales de `admin` |
| 5.4 | Aceptar el UAC | El archivo pasa a cuarentena; mensaje del proceso elevado |
| 5.5 | Cancelar el UAC en otro intento | "No se aprobó… No se ha cambiado nada" y el archivo sigue ahí |
| 5.6 | Restaurar | Vuelve a su ruta original |
| 5.7 | **Punto delicado:** con un usuario estándar el UAC elevado corre con el SID del admin, no el del dueño del plan | Anota qué ocurre (sabemos que es un hueco: el plan es del SID del usuario) |
| 5.8 | Desde `C:\src\...\nexo-tray.exe` (no segura), pedir aprobar | Se niega con el mensaje de ubicación; no sale UAC |

## 6. Limpieza y Papelera

Crea archivos de prueba en una categoría del catálogo (p. ej. `%TEMP%` del usuario) antes.

| # | Comprobación | Esperado |
|---|---|---|
| 6.1 | Previsualizar limpieza | Solo toca el perfil de `usuario`, no el de SYSTEM |
| 6.2 | Aplicar (modo papelera) | Los archivos aparecen en la **Papelera de `usuario`** (pendiente de probar: servicio suplantando a otro usuario) |
| 6.3 | Rutas fuera del perfil/catálogo | Nunca se tocan |

## 7. Tiempo real y diario USN (opcional)

Se activa por configuración (`Nexo:TiempoReal:*` en `appsettings.json` del servicio; apagado por omisión) y se reinicia el servicio.

| # | Comprobación | Esperado |
|---|---|---|
| 7.1 | Crear un archivo de prueba en una carpeta vigilada | Aviso en la bandeja tras escribirse (detecta, no previene) |
| 7.2 | Carga alta (copiar miles de archivos) | Anota si hay sobrecarga o error 1181 del diario |

## 8. ClamAV real (opcional)

Instala ClamAV, arranca `clamd` y configura `Nexo:ClamdHost` / `Nexo:ClamdPuerto`.

| # | Comprobación | Esperado |
|---|---|---|
| 8.1 | Escaneo con el motor real | Detecciones y recuento de analizados coherentes |
| 8.2 | Parar `clamd` en mitad de un escaneo | Se informa como "motor no disponible" (-32020); **nunca** como limpio |
| 8.3 | Rendimiento en una carpeta grande | Anota tiempos y si Defender estorba |

## 9. Desinstalar

```powershell
.\src\Nexo.Service\Install\nexo-service.ps1 -Accion desinstalar
.\src\Nexo.Service\Install\nexo-service.ps1 -Accion estado
```

Esperado: servicio y clave Run eliminados; vault y cuarentena se conservan (el script lo dice).

## Tabla de resultados

| Paso | Resultado (OK/FALLO/NOTA) | Detalle |
|---|---|---|
| 1.1 | | |
| 1.2 | | |
| 1.3 | | |
| 2.1 | | |
| 2.2 | | |
| 2.3 | | |
| 3.1 | | |
| 3.2 | | |
| 4.1–4.4 | OK | Icono ámbar «tiempo real apagado» al conectar; gris «sin conexión» con el servicio parado; vuelve a conectado sin reiniciar la bandeja. Sin problemas visuales. |
| 5.1–5.8 | OK (5.7 NOTA) | 5.1: tiempo real detecta, icono rojo y aviso. 5.2: plan sin mover nada. 5.3: UAC con credenciales de `nexo` (NOTA: «editor desconocido», ejecutable sin firmar). 5.4: «1 archivo en cuarentena». 5.5: «No se aprobó: el aviso de UAC se canceló. No se ha cambiado nada», archivo intacto. 5.6: restaurado vía pipe desde PowerShell elevado (68 B). 5.7: con usuario estándar el plan SÍ se aplicó (no se rechazó por SID): pendiente entender por qué. 5.8: se niega por ubicación no segura, sin UAC. Nota: la bandeja no tiene restaurar ni escanear. |
| 6.1–6.3 | | |
| 7.1–7.2 | | |
| 8.1–8.3 | OK / NOTA (en Linux, no en la VM) | Hecho el 2026-11-02 con `nexo-scan` en Linux contra ClamAV 1.5.4 real (Docker `clamav/clamav:1.5.4`, solo 127.0.0.1), **no por el servicio ni en Windows**. 8.1: 8/8 EICAR detectados, también dentro de un zip anidado 5 niveles; 24 MB analizado, 30 MB omitido y anotado. HALLAZGO (corregido): un nombre con salto de línea partía la consola, metía un encabezado falso en la nota y podía añadir líneas falsas al plan de cuarentena. 8.2: `docker stop` a mitad → «ESCANEO INCOMPLETO: 5 errores seguidos del motor… Connection reset by peer», nunca «limpio»; sin motor desde el inicio, código 2. NOTA (corregida): el resumen decía «NO analizados: 5» sin aclarar que lo que faltaba (~895 archivos) ni se intentó. 8.3: 1017 binarios reales (258 MB), 4 núcleos, en frío: `--paralelo` 1 = 38,9 s, 2 = 15,8 s, 4 = 8,5 s, 8 = 8,2 s. clamd cachea los archivos limpios: una segunda pasada tarda 4,6 s. **Sin probar:** convivencia con Defender y el camino por el servicio (`escaneo.*` por el pipe). |
| 9 | | |

Al terminar, pásame esta tabla (con los mensajes de error literales) y corrijo lo que haya fallado.
