Actúa como ingeniero de software senior especializado en seguridad de aplicaciones, criptografía aplicada (cifrado simétrico/asimétrico) y manejo seguro de credenciales.

CONTEXTO
- Proyecto: módulo de gestión de identidad de un antivirus para uso personal en Windows 10/11.
- Sigue la arquitectura general ya definida (pegada en <arquitectura>); no la rediseñes.

<arquitectura>
[PEGAR AQUÍ la salida completa del Prompt 0]
</arquitectura>

TAREA
Diseña e implementa un MVP funcional del módulo de identidad.

<requisitos>
1. Gestor de contraseñas con bóveda cifrada y autocompletado en el navegador/apps.
2. Monitoreo de la dark web para detectar si el correo o las credenciales del usuario fueron filtrados.
3. Alertas de robo de identidad.
</requisitos>

REGLAS
- Para el gestor de contraseñas, especifica el algoritmo de cifrado de la bóveda (por ejemplo, AES-256 con una clave derivada de la contraseña maestra vía PBKDF2 o Argon2) y cómo se protege esa clave en memoria.
- Para el monitoreo de dark web, no propongas construir un rastreador propio: recomienda integrar una API existente de verificación de brechas de datos (por ejemplo, la API de "Have I Been Pwned" u otra equivalente), incluyendo sus límites de uso gratuito.
- Las alertas de robo de identidad deben basarse en lo que el monitoreo de brechas y el comportamiento de las cuentas realmente puedan detectar; no prometas detección "en general" sin una fuente de datos concreta detrás.
- El autocompletado debe funcionar en el navegador seguro del módulo de privacidad; indica cómo se integran ambos módulos (extensión o API interna compartida).

SALIDA
1. Diseño técnico de los 3 submódulos, con el esquema de cifrado de la bóveda explicado paso a paso.
2. Código esqueleto del gestor de contraseñas (creación de bóveda, guardar/leer una credencial cifrada), con comentarios.
3. Diseño de la integración con la API de verificación de brechas, incluyendo manejo de límites de tasa y qué hacer si la API no responde.

VERIFICACIÓN
Antes de responder, confirma que el esquema de cifrado no almacena la contraseña maestra en texto plano en ningún punto, y que el código de ejemplo no expone credenciales en logs ni en memoria sin cifrar más tiempo del necesario.