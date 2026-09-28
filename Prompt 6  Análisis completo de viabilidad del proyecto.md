Actúa como consultor técnico senior especializado en evaluación de viabilidad de proyectos de software, con experiencia en ciberseguridad, desarrollo de producto y gestión de proyectos individuales (side projects / bootstrapped).

CONTEXTO
- Proyecto: un antivirus/suite de seguridad para uso personal en Windows 10/11, desarrollado en C++/C# por una sola persona.
- Quien desarrolla es estudiante de Ingeniería Civil Industrial, con experiencia previa en Python, Linux y Node.js, pero nueva en desarrollo nativo de Windows de bajo nivel (drivers, WFP, APIs de kernel). Además tiene otras responsabilidades (estudios, un negocio propio), así que el tiempo disponible es limitado.
- Ya existe una arquitectura general definida (pegada en <arquitectura>) que divide el sistema en cinco módulos: protección contra amenazas, privacidad y navegación, identidad y cuentas, limpieza y optimización, y reportes/visualización (integrado con un vault de Obsidian).
- Antes de empezar a programar cada módulo, se necesita un análisis de viabilidad completo: qué tan realista es este alcance para una sola persona, qué riesgos técnicos y legales existen, y qué recortes de alcance conviene hacer.

<arquitectura>
[PEGAR AQUÍ la salida completa del Prompt 0, y si ya las tienes, un resumen de las salidas de los Prompts 1 a 5]
</arquitectura>

TAREA
Realiza un análisis de viabilidad completo del proyecto, evaluando cada uno de los cinco módulos por separado y el proyecto en conjunto.

REGLAS
- Sé brutalmente honesto sobre la viabilidad real para un desarrollador individual con tiempo limitado; no suavices los riesgos para sonar alentador.
- Para cada módulo, evalúa: dificultad técnica real, tiempo estimado de desarrollo para una persona con el perfil descrito, costo de las dependencias externas necesarias (certificados de firma de código, APIs de pago, servidores VPN), y nivel de riesgo de abandono (qué tan probable es que quede incompleto).
- Identifica riesgos legales y regulatorios específicos de este tipo de software: uso de un driver en modo kernel sin certificación WHQL, posibles conflictos con Windows Defender u otros antivirus instalados, tratamiento de datos sensibles (credenciales filtradas, historial de navegación) y qué implica almacenarlos aunque sea localmente, y cualquier restricción de nombrar o presentar el software como "antivirus" si en la práctica no pasa por certificaciones de laboratorios como AV-TEST.
- Señala qué funciones del alcance actual son razonables para un MVP personal y cuáles deberían quedar fuera o posponerse, con la justificación de por qué.
- No repitas el contenido completo de <arquitectura>; asume que quien lee el análisis ya la conoce, y refiérete a los módulos por nombre.

SALIDA
1. Matriz de viabilidad: módulo → dificultad técnica (baja/media/alta) → tiempo estimado → dependencias externas y su costo → riesgo de abandono.
2. Lista de riesgos legales/regulatorios identificados, con su nivel de gravedad y una mitigación concreta para cada uno.
3. Recomendación de alcance para un MVP realista (qué funciones sí, cuáles se posponen), con una estimación de tiempo total si se dedica un número razonable de horas semanales a un proyecto personal.
4. Tres a cinco próximos pasos concretos y en orden, no genéricos.

VERIFICACIÓN
Antes de responder, revisa que la matriz cubra los cinco módulos sin excepción, que cada riesgo legal tenga una mitigación específica (no genérica del tipo "consultar a un abogado"), y que la recomendación de alcance sea coherente con el perfil de tiempo limitado descrito en el contexto.