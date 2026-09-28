Actúa como ingeniero de software senior especializado en generación de documentación técnica, formatos basados en Markdown, y en el ecosistema de plugins de Obsidian.

CONTEXTO
- Proyecto: módulo de reportes y visualización de un antivirus para uso personal en Windows 10/11.
- Sigue la arquitectura general ya definida (pegada en <arquitectura>); no la rediseñes.
- Se decidió usar Obsidian como capa de visualización en vez de construir un dashboard propio desde cero: Obsidian no requiere una API para integrarse, solo una carpeta de archivos markdown (un "vault") con formato consistente, y a cambio entrega grafo de notas, backlinks, búsqueda y filtrado por etiquetas de forma nativa.
- Este módulo también sirve como herramienta de desarrollo: mientras se programan y prueban los módulos de limpieza y de protección contra amenazas, sus reportes se revisan abriendo la carpeta de reportes como vault en Obsidian, sin necesidad de una UI propia todavía.

<arquitectura>
[PEGAR AQUÍ la salida completa del Prompt 0]
</arquitectura>

TAREA
Diseña e implementa el módulo de reportes: la estructura de carpetas del vault, el formato de cada tipo de nota (con front matter YAML), y una librería/clase reutilizable en C++/C# que los demás módulos (protección contra amenazas, privacidad, identidad, limpieza) puedan llamar para generar sus notas automáticamente.

<requisitos>
1. Cada evento relevante genera una nota markdown individual: amenaza detectada, archivo puesto en cuarentena, conexión VPN, resultado de un escaneo, sesión de limpieza ejecutada, alerta de identidad.
2. Las notas usan front matter YAML con campos consistentes (fecha, módulo de origen, tipo de evento, severidad, acción tomada) para poder filtrarlas y tabularlas.
3. Las notas relacionadas se enlazan entre sí usando wikilinks de Obsidian (por ejemplo, una nota de amenaza enlaza a la nota del archivo afectado y a la nota-resumen del día), para aprovechar el grafo y los backlinks nativos.
4. Existe una nota-resumen diaria que enlaza a todos los eventos del día, a modo de dashboard simple y navegable.
5. El diseño debe funcionar abriendo la carpeta directamente como vault, sin exigir que el usuario instale ningún plugin de Obsidian para lo básico.
6. Como mejora opcional (documentar, no implementar todavía), evalúa el uso del plugin comunitario "Dataview" para que el usuario arme tablas y consultas sobre las notas generadas, sin que el antivirus tenga que construir su propio motor de reportes.
</requisitos>

REGLAS
- No propongas llamar a una API de Obsidian: no existe una API pública para aplicaciones externas. La única integración confiable es escribir archivos .md bien formados dentro de la carpeta del vault.
- Define una convención de nombres de archivo que evite colisiones (por ejemplo, incluyendo timestamp) y que siga siendo legible para una persona.
- El componente que escribe las notas debe ser una clase o librería reutilizable, no código duplicado en cada módulo que la consume.
- Si más adelante se quisiera una vista embebida dentro de la propia app (un panel visual, no solo la carpeta abierta en Obsidian), aclara que eso requeriría programar un plugin de Obsidian en TypeScript —un stack aparte del C++/C# del resto del proyecto— y trátalo como fase futura opcional, no parte de este MVP.
- La carpeta de reportes puede contener información sensible (por ejemplo, referencias a contraseñas filtradas detectadas por el módulo de identidad, o nombres de archivos personales); indica cómo se protege esa carpeta o al menos advierte explícitamente sobre el riesgo en el diseño.

SALIDA
1. Estructura de carpetas del vault (por categoría de módulo y por fecha).
2. Formato exacto de front matter YAML para cada tipo de nota, con un ejemplo concreto de cada una.
3. Código esqueleto en C++/C# de la clase/librería que genera las notas y gestiona los wikilinks entre ellas.
4. Ejemplo de cómo un módulo externo (por ejemplo, el de limpieza) llamaría a esta librería para registrar un evento.

VERIFICACIÓN
Antes de responder, confirma que el formato de nota propuesto es markdown válido y que Obsidian lo reconocería sin plugins adicionales, que los wikilinks usan la sintaxis correcta ([[nombre de nota]]), y que el diseño no deja en texto plano información que debería quedar cifrada o al menos advertida (por ejemplo, credenciales filtradas detectadas por el módulo de identidad).