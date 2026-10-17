Actúa como arquitecto de software senior, especializado en seguridad de endpoints (EDR/antivirus) y en desarrollo nativo para Windows con C++ y C#.

CONTEXTO
- Proyecto: un antivirus/suite de seguridad para uso personal en Windows 10/11, desarrollado por una sola persona.
- Quien desarrolla tiene experiencia sólida en Python, entornos Linux y Node.js, pero es nuevo en desarrollo nativo de Windows (C++/C#, drivers, APIs de bajo nivel).
- No es un producto comercial ni certificado por laboratorios de antivirus (AV-TEST, AV-Comparatives); no necesita pasar por Microsoft WHQL todavía, pero sí debe funcionar de forma estable en un equipo real.
- El sistema cubre cuatro áreas funcionales (detalladas en <requisitos>): protección contra amenazas, privacidad y navegación, identidad y cuentas, y limpieza/optimización del equipo.
- Este documento de arquitectura será la base de cuatro prompts posteriores, uno por cada área funcional, que se le entregarán a un modelo de IA para generar el diseño detallado y el código de cada módulo.

TAREA
Diseña la arquitectura completa del sistema: los módulos que lo componen, cómo se comunican entre sí, qué tecnología usa cada uno, la estructura de carpetas del proyecto, y un plan de desarrollo por fases (MVP viable primero, funciones avanzadas después).

REPORTES Y VISUALIZACIÓN
- Generación de notas markdown para cada evento relevante de los demás módulos (amenazas, limpieza, red, identidad).
- Vault de Obsidian como capa de visualización (grafo, backlinks, búsqueda por etiquetas), sin necesidad de UI propia para el MVP.

<requisitos>
PROTECCIÓN CONTRA AMENAZAS
- Antivirus en tiempo real contra virus, malware, spyware y rootkits, con análisis de comportamiento.
- Protección anti-ransomware con respaldo de archivos sensibles y bloqueo de cifrado no autorizado.
- Firewall inteligente con reglas por aplicación y modo sigiloso.
- Protección contra criptojacking.
- Escaneo de vulnerabilidades (apps desactualizadas, contraseñas débiles, Wi-Fi inseguro).
- Entorno de rescate para eliminar infecciones persistentes fuera del sistema operativo.

PRIVACIDAD Y NAVEGACIÓN
- VPN incluida.
- Navegador seguro aislado para pagos y transacciones bancarias.
- Protección anti-phishing y contra estafas (SMS, deepfakes).
- Bloqueo de rastreadores.
- Protección de cámara web y micrófono.

IDENTIDAD Y CUENTAS
- Gestor de contraseñas con bóveda cifrada y autocompletado.
- Monitoreo de la dark web.
- Alertas de robo de identidad.

LIMPIEZA Y OPTIMIZACIÓN
- Limpieza de archivos basura, caché, cookies e historial en un clic.
- Eliminación de duplicados y desinstalación de apps sin uso.
- Optimización de inicio del sistema.
- Perfiles automáticos de rendimiento según actividad.
- Monitoreo de salud del disco duro.
- Triturador de archivos (file shredder).
</requisitos>

REGLAS
- Sé honesto sobre las limitaciones reales de Windows: qué funciones necesitan un driver en modo kernel (y por lo tanto firma digital o modo de prueba), cuáles se logran con APIs de usuario (Win32, ETW, WFP, WMI), y cuáles dependen de infraestructura externa que un desarrollador individual no puede montar solo (servidores VPN propios, bases de datos de firmas de malware, etc.).
- Para cada función que dependa de un tercero (VPN, monitoreo de dark web, detección de deepfakes, base de firmas de virus), propone una alternativa concreta y viable para un proyecto personal: una librería open source, una API con capa gratuita, o un servicio integrable sin construirlo desde cero.
- No generes código todavía; esta etapa es solo de arquitectura y planificación.
- Cada función de <requisitos> debe quedar asignada a un módulo específico; no dejes funciones sin dueño.
- Indica qué permisos de administrador o de sistema requerirá cada módulo.

SALIDA
1. Diagrama de módulos en texto (qué módulos existen, cómo se comunican: servicio en segundo plano, UI, IPC, etc.).
2. Tabla: módulo → funciones que cubre → tecnología/API que usa → si necesita driver, permisos especiales o servicio externo.
3. Estructura de carpetas propuesta para el proyecto en Visual Studio.
4. Plan de desarrollo por fases: qué se construye primero (MVP realista para una sola persona) y qué se deja para después.
5. Lista de dependencias externas necesarias (librerías, SDKs, APIs), con al menos una alternativa gratuita o de bajo costo para cada una.

VERIFICACIÓN
Antes de entregar la respuesta, revisa que: (a) las 20 funciones de <requisitos> aparezcan todas en la tabla de módulos, (b) cada función que requiera driver de kernel o firma digital esté marcada explícitamente, y (c) el plan de fases sea realista para un desarrollador individual con experiencia previa en Python pero no en C++/C# de bajo nivel.****