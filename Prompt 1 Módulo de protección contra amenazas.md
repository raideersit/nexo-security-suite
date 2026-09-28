Actúa como ingeniero de seguridad de software senior, especializado en C++ para Windows, con experiencia en motores de detección de malware, drivers en modo kernel/minifiltro, y en el Windows Filtering Platform (WFP) para firewalls.

CONTEXTO
- Proyecto: módulo de protección contra amenazas de un antivirus para uso personal en Windows 10/11, desarrollado por una sola persona con experiencia en Python/Linux pero nueva en C++ de bajo nivel.
- Este módulo sigue la arquitectura general definida previamente (pegada en <arquitectura>). Respeta las tecnologías y la estructura de carpetas ya definidas ahí; no propongas una arquitectura distinta.
- No es un producto comercial certificado; el objetivo es un motor funcional para proteger el propio equipo del desarrollador.

<arquitectura>
[PEGAR AQUÍ la salida completa del Prompt 0]
</arquitectura>

TAREA
Diseña e implementa un MVP funcional del módulo de protección contra amenazas.

<requisitos>
1. Antivirus en tiempo real contra virus, malware, spyware y rootkits, con análisis de comportamiento para detectar aplicaciones sospechosas antes de que actúen.
2. Protección anti-ransomware que respalda archivos sensibles y bloquea intentos de cifrado no autorizado.
3. Firewall inteligente con reglas por aplicación y modo sigiloso frente a accesos no autorizados.
4. Protección contra criptojacking.
5. Escaneo de vulnerabilidades: apps desactualizadas, contraseñas débiles del sistema, Wi-Fi inseguro.
6. Entorno de rescate para eliminar infecciones persistentes que sobreviven fuera del sistema operativo (por ejemplo, un medio de arranque tipo WinPE).
</requisitos>

REGLAS
- Cada amenaza detectada, archivo puesto en cuarentena o bloqueo del firewall debe generar una nota a través de la librería de reportes definida en el módulo de reportes y visualización, en vez de manejar logs propios y separados.
- No inventes un motor de detección de firmas desde cero: propone integrar un motor open source existente (por ejemplo, el engine de ClamAV o reglas YARA) para la detección basada en firmas, y complementa con heurística propia solo para el análisis de comportamiento.
- Para el firewall, usa la Windows Filtering Platform (WFP) o la API de Windows Firewall; explica si el modo sigiloso requiere un driver o se puede lograr en modo usuario.
- Sé explícito cuando una función requiera un driver en modo kernel, firma digital de Microsoft, o modo de prueba de firmas (test signing) para funcionar sin certificado EV.
- El entorno de rescate se diseña como una imagen WinPE separada, no como parte del ejecutable principal.
- Prioriza que el código compile y corra como prueba de concepto sobre cubrir el 100% de los casos de un antivirus comercial.
- Usa el estilo de proyecto y las convenciones de nombres ya definidas en <arquitectura>.

SALIDA
1. Diseño técnico de cada uno de los 6 submódulos (qué hace, con qué API/librería, qué permisos necesita).
2. Código esqueleto en C++/C# de los dos submódulos más viables como primer MVP (recomienda cuáles, según <arquitectura>), con comentarios explicando cada bloque.
3. Lista de riesgos técnicos y limitaciones conocidas del módulo (falsos positivos, exclusiones necesarias, impacto en rendimiento).

VERIFICACIÓN
Antes de responder, confirma que el código propuesto compila conceptualmente en un proyecto Windows estándar, que no depende de APIs deprecadas, y que cada función marcada como "requiere driver firmado" lo indica claramente en el texto, no solo en el código.