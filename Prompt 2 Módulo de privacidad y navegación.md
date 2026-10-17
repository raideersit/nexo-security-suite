Actúa como ingeniero de software senior especializado en redes, criptografía aplicada y desarrollo de componentes de navegador embebido en C++/C# para Windows.

CONTEXTO
- Proyecto: módulo de privacidad y navegación segura de un antivirus para uso personal en Windows 10/11.
- Sigue la arquitectura general ya definida (pegada en <arquitectura>); no la rediseñes.

<arquitectura>
[PEGAR AQUÍ la salida completa del Prompt 0]
</arquitectura>

TAREA
Diseña e implementa un MVP funcional del módulo de privacidad.

<requisitos>
1. VPN incluida (cliente que se conecta a un servidor VPN; no se espera que el usuario opere su propia infraestructura de servidores).
2. Navegador seguro aislado para pagos y transacciones bancarias, protegido contra keyloggers y phishing.
3. Protección anti-phishing y contra estafas, incluyendo detección de fraudes por SMS o video (deepfakes).
4. Bloqueo de rastreadores durante la navegación.
5. Protección de cámara web y micrófono contra accesos no autorizados por otras aplicaciones.
</requisitos>

REGLAS
- Para la VPN, no diseñes un protocolo propio: propone un cliente basado en WireGuard u OpenVPN (librerías/SDKs existentes) y aclara que se necesita contratar o levantar un servidor VPN aparte; este módulo es el cliente, no la infraestructura.
- Para el navegador seguro, evalúa si conviene un control embebido (WebView2 o CefSharp) en modo restringido, en vez de un navegador completo desde cero; justifica la elección.
- La detección de deepfakes es la función más difícil de lograr con recursos de una sola persona: dilo explícitamente y propone una versión reducida y realista (verificación de remitente/dominio en SMS y alertas basadas en reglas, en vez de un modelo propio de detección de video).
- Para cámara y micrófono, usa las APIs de Windows para consultar y restringir el acceso por aplicación (Media Foundation, Device Access APIs).
- Prioriza que cada submódulo funcione de forma aislada, sin depender de que los otros cuatro estén terminados.

SALIDA
1. Diseño técnico de cada uno de los 5 submódulos, con la tecnología/librería elegida y su justificación.
2. Código esqueleto del bloqueador de cámara/micrófono y del bloqueador de rastreadores (los dos más viables sin infraestructura externa), con comentarios.
3. Nota clara sobre qué partes del módulo requieren un servicio externo de pago (servidor VPN, API de reputación de dominios) y cuáles son 100% locales.

VERIFICACIÓN
Antes de responder, revisa que ninguna función prometa capacidades no alcanzables sin infraestructura externa, y que el código respete los permisos de privacidad de Windows (el usuario debe poder ver y revocar accesos).