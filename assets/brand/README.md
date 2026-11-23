# Assets de marca - Nexo Security Suite

Logo: cristal (Nexo de LoL) dentro de un anillo hexagonal.
Paleta: noche #0B1E3F, anillo #29D3F0, cristal #9FEFFF / #52D2FA / #6CBBFA / #4C9BF0, núcleo #F2FDFF.

## Contenido
- svg/nexo-logo.svg: logo maestro (usar para tamaños de 48 px o más).
- svg/nexo-logo-small.svg: versión simplificada (para 32 px o menos).
- svg/android-*.svg: capas del icono adaptativo (viewBox 108, contenido dentro de la zona segura de 66).
- png/nexo-logo-{256,512,1024}.png: PNG del logo (README de GitHub, social preview, etc.).
- png/windows/nexo.ico: ICO con 256, 48, 32, 24 y 16 px.
- png/windows/icon-*.png: PNG sueltos por tamaño.
- png/android/res/: carpeta lista para copiar a app/src/main/res (mipmap-*, anydpi-v26 con ic_launcher.xml, y color de fondo).
- png/android/play-store/ic_launcher-playstore.png: 512 px para Google Play.

## Prompt sugerido para Claude en la terminal
Agrega el logo de Nexo al proyecto usando la carpeta assets/brand de este repositorio:
1. Copia assets/brand al repo y úsalo como fuente única de verdad.
2. Windows (Nexo.Ui.Desktop, Avalonia): usa png/windows/nexo.ico como icono de la ventana (propiedad Icon de Window) y como ApplicationIcon en el .csproj del ejecutable.
3. Nexo.Ui.Tray: usa el .ico (o icon-16/icon-32) para el icono de la bandeja.
4. Instalador/servicio: referencia el .ico si aplica.
5. README.md del repo: agrega svg/nexo-logo.svg o png/nexo-logo-512.png en el encabezado.
6. Android: copia png/android/res/* a app/src/main/res y confirma que AndroidManifest use android:icon="@mipmap/ic_launcher" y android:roundIcon="@mipmap/ic_launcher_round".
No modifiques los archivos de marca; solo referencia.
