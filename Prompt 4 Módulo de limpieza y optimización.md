Actúa como ingeniero de software senior especializado en desarrollo de utilidades de sistema para Windows (C++/C#), con experiencia en la API de Windows para archivos, registro y procesos de arranque.

CONTEXTO
- Proyecto: módulo de limpieza y optimización de un antivirus para uso personal en Windows 10/11.
- Sigue la arquitectura general ya definida (pegada en <arquitectura>); no la rediseñes.

<arquitectura>
[PEGAR AQUÍ la salida completa del Prompt 0]
</arquitectura>

TAREA
Diseña e implementa un MVP funcional del módulo de limpieza y optimización.

<requisitos>
1. Limpieza de archivos basura, caché, cookies e historial en un clic.
2. Eliminación de archivos duplicados y desinstalación de aplicaciones sin uso.
3. Optimización de inicio del sistema (deshabilitar programas que consumen recursos al arrancar).
4. Perfiles automáticos de rendimiento según actividad (trabajo, juegos, video, batería, Wi-Fi público).
5. Monitoreo de la salud del disco duro con alertas tempranas de fallos (datos S.M.A.R.T.).
6. Triturador de archivos (file shredder) para borrado seguro e irrecuperable.
</requisitos>

REGLAS
- Cada sesión de limpieza (archivos borrados, duplicados encontrados, espacio liberado) debe generar una nota a través de la librería de reportes definida en el módulo de reportes y visualización, para poder revisar el historial abriendo la carpeta como vault de Obsidian mientras desarrollas y pruebas.
- Antes de borrar cualquier archivo, el diseño debe incluir una etapa de "vista previa": mostrar qué se va a borrar y cuánto espacio se libera, y pedir confirmación del usuario.
- Para archivos duplicados, especifica el método de comparación (hash del contenido, no solo nombre/tamaño) para evitar falsos positivos.
- Para la salud del disco, usa datos S.M.A.R.T. accesibles vía WMI; no inventes métricas propias.
- El triturador de archivos debe explicar qué método de sobrescritura usa, y aclarar que la sobrescritura múltiple clásica no aplica igual en discos SSD por el wear leveling.
- Los perfiles de rendimiento deben basarse en señales reales del sistema (batería conectada o no, proceso de juego en primer plano, red Wi-Fi pública detectada), no solo en configuración manual.

SALIDA
1. Diseño técnico de los 6 submódulos.
2. Código esqueleto de la limpieza de archivos temporales/caché y del detector de duplicados (los de implementación más directa), con comentarios.
3. Lista de rutas típicas de Windows que debe cubrir la limpieza (temp, caché de navegadores, papelera, logs), señalando cuáles requieren permisos de administrador.

VERIFICACIÓN
Antes de responder, confirma que ninguna operación de borrado sea irreversible sin confirmación previa del usuario, y que el detector de duplicados use comparación por hash y no solo nombre o tamaño de archivo.