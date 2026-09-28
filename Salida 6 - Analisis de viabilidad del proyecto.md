---
titulo: Análisis de viabilidad — Nexo Security Suite
tipo: analisis-viabilidad
version: 1.0
fecha: 2026-09-28
estado: definitivo
tags: [nexo/viabilidad, nexo/fase-0, nexo/decision]
---

# Análisis de viabilidad — Nexo Security Suite

> Salida del [[Prompt 6  Análisis completo de viabilidad del proyecto]], sobre la base de [[Salida 0 - Arquitectura general del sistema]].
> Propósito: decidir **qué se construye y qué no**, antes de escribir código.

> [!note] Corrección de perfil (2026-09-28)
> El enunciado del prompt decía "Ingeniería Civil **Industrial**"; el perfil real es
> **Ingeniería Civil Informática**, en Chile. Qué cambia y qué no:
>
> - **Cambia:** la curva de aprendizaje de C++, punteros, concurrencia y conceptos de
>   sistema operativo es notablemente menor. Las horas de los módulos M1 y M2 —los que
>   más dependen de ese aprendizaje— pueden caer entre un 10% y un 20% respecto de los
>   rangos de §1. El driver de kernel sigue siendo otro oficio, no una extensión de la
>   carrera.
> - **No cambia:** ni una sola de las estimaciones de riesgo de abandono. El limitante
>   de este proyecto es el **tiempo disponible**, no la capacidad técnica, y eso no lo
>   corrige un cambio de carrera. Tampoco cambia ningún riesgo legal ni la
>   recomendación de alcance de §3.
>
> Los rangos de §1 se dejan tal cual, como cota superior.

---

## Resumen ejecutivo (lee esto aunque no leas el resto)

El alcance completo de los cinco módulos son **900 a 1.400 horas efectivas** de desarrollo sin contar el driver de kernel, y **1.300 a 1.900** contándolo. A 8–10 horas semanales *nominales* —que en la práctica, con estudios y un negocio, son unas **30 horas efectivas al mes**— eso son **entre 30 y 52 meses**. Dos años y medio a cuatro años.

Esto corrige a la baja la estimación de 18–24 meses que aparece al cierre de [[Salida 0 - Arquitectura general del sistema]]: esa cifra asumía semanas sin fricción, y no las habrá.

**La probabilidad de terminar el alcance completo es muy baja** —del orden del 5%—, y no por falta de capacidad técnica, sino por aritmética: ningún proyecto personal sin usuarios externos ni ingresos sobrevive cuatro años de motivación propia.

**La probabilidad de terminar el MVP recortado que propongo en §3 es alta** —del orden del 70%—, porque son 200–260 horas, unos 7–8 meses, y produce una herramienta que usarías de verdad a partir del tercer mes.

La decisión real no es "¿puedo hacer esto?". Es "¿estoy dispuesto a entregar el 70% del alcance a cambio de que el 30% restante exista?". Recomiendo que sí.

---

## 1. Matriz de viabilidad

Horas = **horas efectivas de teclado**, ya descontando el tiempo de leer documentación de Microsoft, que en este dominio es aproximadamente el 40% del total y **ya está incluido** en los rangos.

| Módulo | Dificultad técnica real | Horas | Meses (a 30 h/mes) | Dependencias externas y costo | Riesgo de abandono |
|---|---|---|---|---|---|
| **M5 — Reportes / Obsidian** | **Baja.** Es escritura de archivos y plantillas de texto. Lo único no trivial es la escritura atómica y evitar colisiones de nombres. Tu experiencia previa en Python/Node se transfiere casi entera. | **25–40** | 1–1,5 | Obsidian (USD 0). Ninguna más. | **Muy bajo (~5%).** Se termina en semanas y da satisfacción inmediata. |
| **M4 — Limpieza y optimización** | **Media.** Seis submódulos independientes, ninguno conceptualmente difícil, pero con fricción real: `IFileOperation` es COM crudo desde C#, el S.M.A.R.T. por WMI devuelve arrays de bytes sin documentar bien, y la vista previa + confirmación es más UI de la que parece. | **120–180** | 4–6 | Ninguna. USD 0. | **Bajo (~15%).** Resultados visibles la primera semana. Es el módulo que engancha. |
| **M3 — Identidad y cuentas** | **Media-alta.** La criptografía en sí es fácil (Argon2id + AES-GCM son cuatro llamadas). Lo difícil es todo lo demás: manejo de clave en memoria, migración de formato de bóveda, recuperación ante corrupción, y **el autocompletado, que es frágil por naturaleza** y puede consumir 60 h para quedar a medias. | **170–220** | 6–7 | HIBP API v3: **USD 47/año** (opcional; Pwned Passwords es gratis). | **Medio (~35%).** El autofill es el punto donde la gente se atasca. |
| **M1 — Protección contra amenazas** | **Alta sin driver. Muy alta con driver.** Sin driver ya es el módulo más grande: ETW con `TraceEvent` tiene una curva real, WFP en modo usuario está mal documentado, y el USN Journal exige entender estructuras nativas. El minifiltro es otro oficio: C, WinDbg, depuración por red, BSOD como rutina. | **250–400** sin driver · **+300–500** el driver | 8–13 · **+10–17** | ClamAV/YARA USD 0 · Certificado EV **USD 250–600/año** solo si se firma el driver · Windows ADK USD 0 | **Alto (~55%) sin driver. Muy alto (~85%) con driver.** Es donde mueren estos proyectos. |
| **M2 — Privacidad y navegación** | **Alta, y con la peor relación esfuerzo/valor.** Casi todo ya existe gratis y mejor: WireGuard oficial, uBlock Origin, Windows Sandbox. Estarías reimplementando peor lo que puedes instalar hoy. El navegador seguro es el submódulo más caro (80–120 h) para el menor valor incremental. | **280–400** | 9–13 | **VPS de VPN: USD 0 (Oracle Always Free) a USD 60/año (Hetzner)** · Safe Browsing USD 0 · Windows Pro para Sandbox (si no lo tienes) | **Alto (~60%).** Alto esfuerzo, baja recompensa percibida. |
| **TOTAL sin driver** | — | **845–1.240** | **28–41** | — | — |
| **TOTAL con driver** | — | **1.145–1.740** | **38–58** | **USD 250–660/año** | — |

*(Los totales no incluyen el overhead de integración, instalador, pruebas y mantenimiento: súmale un 15–20% más.)*

### Lectura de la matriz

- **M5 y M4 son el proyecto viable.** Juntos son ~5 meses y no dependen de nada externo.
- **M1 sin driver es un proyecto en sí mismo**, comparable en tamaño a M4 + M5 + M3 juntos.
- **M1 con driver duplica el proyecto completo.** Y el certificado EV no es solo dinero: exige verificación de identidad de una entidad (idealmente una empresa con registro comercial), token físico enviado por correo internacional, y cuenta en Partner Center. Para un estudiante a título personal, el trámite por sí solo puede tardar semanas y puede simplemente no aprobarse.
- **M2 es el candidato obvio a recortar entero**, no por dificultad sino porque el sustituto gratuito ya instalado es mejor que lo que vas a construir.

### Costo total de propiedad

| Escenario | Costo anual | Comentario |
|---|---|---|
| MVP recortado (§3) | **USD 0** | Sin certificados, sin APIs de pago, sin servidores |
| MVP + identidad con HIBP | **USD 47** | Único gasto realmente justificable |
| + VPN propia | **USD 47–107** | USD 0 si usas la capa gratuita de Oracle Cloud |
| + firma de la app (OV) | **USD 147–307** | Solo si lo distribuyes a terceros |
| + driver firmado (EV) | **USD 400–900** | Solo en un escenario que no recomiendo |

---

## 2. Riesgos legales y regulatorios

Contexto asumido: desarrollador **persona natural en Chile**, uso personal en su propio equipo. Los riesgos cambian radicalmente en el momento en que el software se instala en un equipo ajeno, y ese umbral está marcado abajo.

| # | Riesgo | Gravedad | Mitigación concreta |
|---|---|---|---|
| L1 | **GPLv2 de libclamav.** Enlazar `libclamav` (estática o dinámicamente) convierte a Nexo en obra derivada y obliga a publicarlo bajo GPLv2, con código fuente disponible. Es el riesgo legal **más probable de materializarse** porque ocurre por accidente, con un `#include`. | **Alta** | Hablar con **`clamd` por TCP 3310** (protocolo INSTREAM), nunca enlazar la librería. Proceso separado, comunicación por socket = no hay obra derivada, misma lógica que usar PostgreSQL. Distribuir ClamAV como dependencia que el usuario instala aparte, no rebundleado. Alternativa limpia: **solo YARA (BSD-3)**, sin ClamAV. |
| L2 | **Licencias de las listas de bloqueo.** EasyList/EasyPrivacy son GPLv3 + CC-BY-SA; StevenBlack/hosts es MIT; CoinBlockerLists tiene términos propios. Redistribuirlas embebidas en el instalador arrastra obligaciones de atribución y, en el caso GPL, discusión sobre derivación. | **Media** | **Descargarlas en tiempo de ejecución desde su URL original**, no incluirlas en el instalador. Mostrar atribución y licencia en una pantalla "Acerca de / Fuentes de datos". Guardar el archivo `LICENSE` de cada lista junto a la copia en caché. |
| L3 | **Términos de uso de las APIs de terceros.** Google Safe Browsing exige mostrar la atribución *"Advisory provided by Google Safe Browsing"* y prohíbe usos fuera de los términos. HIBP exige un `User-Agent` identificable, respeta límites de tasa y **la clave es por usuario, no redistribuible**. | **Media** | Incluir la atribución de Safe Browsing en la ventana de advertencia, literal. Usar `User-Agent: NexoSecuritySuite/1.0 (+contacto)`. **La clave de HIBP se pide al usuario y se guarda en su equipo (DPAPI); nunca embebida en el binario.** Implementar back-off exponencial ante HTTP 429 y degradar a "no verificado" en vez de reintentar en bucle. |
| L4 | **Driver de kernel sin certificación WHQL.** Un `.sys` sin firma válida no carga en Windows 10/11 con arranque normal. La vía de *attestation signing* no requiere pasar las pruebas HLK, pero sí certificado EV + Partner Center. Y Microsoft puede añadir un driver a la lista de bloqueo (`DriverSiPolicy`) si se detecta que se abusa de él. | **Alta** (si se intenta) | **No construir el driver.** Es la mitigación real. Si aun así se hace: desarrollarlo **exclusivamente en una VM** con `testsigning`, nunca en el equipo principal, y no distribuirlo jamás a terceros sin firma. Usar una *altitude* solicitada formalmente a Microsoft (`fltmgr` altitude request) para no colisionar con otros minifiltros. |
| L5 | **`testsigning` rompe el equipo de desarrollo.** Activarlo exige **desactivar Secure Boot**, lo que: fuerza a introducir la clave de recuperación de BitLocker, deshabilita la Integridad de Memoria (HVCI), rompe anti-cheats de kernel (Vanguard, Easy Anti-Cheat, BattlEye) y puede bajar la calidad de streaming por DRM. | **Media** | Confinar `testsigning` a una **VM de Hyper-V dedicada, con snapshot previo**. Nunca en el equipo de uso diario ni en el que usas para el negocio. Anotar la clave de recuperación de BitLocker **antes** de tocar Secure Boot, en un medio fuera del equipo. |
| L6 | **Conflicto con Windows Defender.** Dos motores de tiempo real sobre el mismo archivo causan cuelgues y, en el peor caso, pérdida de datos. Además, **Defender va a detectar a Nexo como malware**: escanear memoria de procesos, leer el USN Journal, tocar claves `Run` y poner archivos en cuarentena cifrada son exactamente las heurísticas de un troyano. | **Alta** | No desactivar Defender (además, Tamper Protection lo impide programáticamente). Añadir exclusiones mutuas explícitas: la carpeta de cuarentena de Nexo en las exclusiones de Defender vía `Add-MpPreference -ExclusionPath`. **No inyectar código en procesos ajenos ni hacer hooking** —es la línea que dispara la detección—. Si Defender marca el binario, enviarlo como falso positivo por el portal de Microsoft Security Intelligence (gratis, respuesta en días). Firmar la app con un certificado OV reduce mucho los falsos positivos de SmartScreen. |
| L7 | **Datos sensibles en el vault de reportes.** La carpeta contiene, en **texto plano**, nombres de archivos personales, dominios visitados, hallazgos de brechas y rutas de la bóveda. Es un objetivo de mayor valor que muchos de los datos que protege. | **Alta** | (a) **Nunca escribir credenciales, ni siquiera parciales**: registrar `dominio + fecha de la brecha + tipo de dato expuesto`, jamás la contraseña ni su hash completo. (b) Volumen con **BitLocker** activo. (c) ACL de la carpeta: quitar herencia, dejar solo el usuario dueño y SYSTEM. (d) **No sincronizar el vault con OneDrive, Dropbox ni Obsidian Sync** — añadir la carpeta a las exclusiones de OneDrive explícitamente. (e) Política de retención: purga automática de notas >90 días, configurable. (f) La nota de identidad enlaza a la entrada de la bóveda por identificador, no por contenido. |
| L8 | **Ley 21.719 de protección de datos personales (Chile).** Entra en plena vigencia el **1 de diciembre de 2026** —en unos dos meses— y crea una Agencia con potestad sancionatoria. Contiene una exención para el tratamiento "por persona natural en el ámbito exclusivamente personal o doméstico", que es donde este proyecto está hoy. **Esa exención se pierde en el instante en que instalas Nexo en el equipo de otra persona.** | **Baja hoy · Alta si se distribuye** | Mientras sea uso propio: documentarlo explícitamente en el README ("uso personal, sin tratamiento de datos de terceros"). Antes de instalarlo en el equipo de un familiar o cliente: consentimiento por escrito, finalidad declarada, y minimización (no recolectar historial de navegación si no es necesario para la función). **Si algún día se distribuye, la mitigación técnica es no telemetría: cero datos salen del equipo**, lo que deja la mayor parte de la ley sin aplicación material. Verificar la fecha de entrada en vigencia antes de tomar decisiones basadas en ella. |
| L9 | **Ley 21.459 de delitos informáticos (Chile).** Tipifica acceso ilícito, interceptación ilícita y —relevante aquí— el **abuso de dispositivos**: producir o facilitar herramientas diseñadas para cometer esos delitos. Un módulo que dumpea la SAM, intercepta tráfico TLS o captura entradas de teclado es funcionalmente indistinguible de una herramienta ofensiva. | **Media** | Tres líneas rojas de diseño, ya incorporadas en la arquitectura y que **no deben cruzarse**: (1) **no dumpear la SAM ni hashes de contraseñas** —la auditoría de contraseñas débiles se hace por flags de cuenta y política—; (2) **no hacer MITM de TLS** —el bloqueo de rastreadores es por DNS y por `WebResourceRequested`, nunca con un certificado raíz propio—; (3) **no capturar pulsaciones de teclado**, ni siquiera "para proteger". Si el binario nunca contiene esas capacidades, el tipo penal no tiene dónde aplicarse. |
| L10 | **Llamarlo "antivirus".** No hay una norma que reserve la palabra, pero sí hay exposición: presentar como antivirus algo que no detecta en tiempo real ni tiene firmas actualizadas es, ante SERNAC, publicidad engañosa si media una transacción; y ante un usuario al que se lo instalaste, una falsa sensación de seguridad con consecuencias reales. Además, registrarse en el Centro de Seguridad de Windows exige el programa **MVI de Microsoft**, que requiere ser empresa y tener certificación de laboratorios (AV-TEST, AV-Comparatives o equivalente) — inaccesible a título individual. | **Media** | **Renombrar el posicionamiento, no necesariamente el proyecto**: "suite de higiene y monitoreo de seguridad para Windows". En el README y en la UI, una línea explícita: *"Nexo complementa a Microsoft Defender; no lo reemplaza y no debe usarse como única protección."* **No publicar tasas de detección** ni comparaciones con productos comerciales. No registrarse en el Security Center. |
| L11 | **Responsabilidad por pérdida de datos.** El módulo de limpieza y el triturador borran archivos de forma irreversible. Un bug en la canonicalización de rutas o en el detector de duplicados puede destruir datos propios o de un tercero. | **Alta** | Vista previa obligatoria + confirmación con token de un solo uso emitido por el servicio (ya en la arquitectura). **Papelera por defecto**, borrado permanente solo como opción explícita. Lista blanca de raíces permitidas, con `%SystemRoot%`, `Program Files`, `Users\*\Documents` y perfiles de otros usuarios **denegados por diseño**. Nunca borrar sin `File.Exists` + verificación de que la ruta canonicalizada sigue dentro de la raíz autorizada. Licencia MIT o Apache-2.0, que incluye exclusión de garantía, desde el primer commit. Y probar exclusivamente en la VM con corpus sintético. |
| L12 | **Bóveda propia como único almacén de contraseñas reales.** El riesgo no es legal sino existencial: una bóveda sin auditar, con un bug de derivación o un fallo de escritura atómica, pierde todas tus contraseñas de una vez, sin recuperación posible por diseño. | **Alta** | **Usar KeePassXC o Bitwarden para las contraseñas reales.** La bóveda de Nexo se construye como ejercicio y se llena con credenciales de prueba hasta que tenga: vectores de prueba contra implementaciones de referencia, respaldo automático versionado, y al menos seis meses de uso sin incidentes. Implementar export a formato KeePass desde el día uno, para que nunca haya lock-in. |
| L13 | **Ley 21.663 Marco de Ciberseguridad (Chile).** Se aplica a operadores de importancia vital y servicios esenciales. | **Nula** | No aplica a un proyecto personal. Se menciona solo para descartarla explícitamente y no perder tiempo investigándola. |

---

## 3. Alcance recomendado para el MVP

Criterio de corte, aplicado en este orden: **(1)** ¿lo usarías tú, de verdad, al menos una vez por semana? **(2)** ¿existe ya un sustituto gratuito y mejor que puedas instalar hoy? **(3)** ¿requiere driver, infraestructura o dinero?

### ✅ Dentro del MVP — 205–265 horas · 7–9 meses

| Función | Módulo | Horas | Por qué entra |
|---|---|---|---|
| Librería de reportes + vault de Obsidian | M5 | 25–40 | Es infraestructura de todo lo demás **y tu herramienta de depuración**. Sin esto, depurar los otros módulos es a punta de `Console.WriteLine`. |
| Limpieza de basura/caché en un clic, con vista previa | M4 | 30–45 | La función que más usarías. Resultado medible en MB el primer día. |
| Detector de duplicados por hash en tres etapas | M4 | 20–30 | Algoritmo interesante, cero riesgo, resultado visible. |
| Optimización de inicio | M4 | 20–30 | Registro puro. Valor real y perceptible al arrancar. |
| Salud del disco (S.M.A.R.T. por WMI) | M4 | 20–30 | Es la única función del proyecto que puede **evitarte perder datos de verdad**. La de mayor valor esperado. |
| Triturador de archivos | M4 | 15–25 | Cerrado, autocontenido, fácil de probar. |
| Firewall por aplicación + modo sigiloso | M1 | 30–40 | `INetFwPolicy2` es COM sencillo y da una victoria de seguridad real sin driver. |
| Escaneo bajo demanda con YARA | M1 | 25–35 | Sin tiempo real. Te enseña el dominio de detección sin la complejidad del USN Journal ni del ETW. |
| Wi-Fi inseguro + apps desactualizadas (`winget`) | M1 | 20–30 | Baratísimas de implementar, se apoyan en herramientas ya instaladas. |
| Bandeja del sistema + diálogos de confirmación | UI | 25–35 | Sin esto nada de lo anterior es usable. Se suele subestimar. |

**Costo del MVP: USD 0.** Ni una sola dependencia de pago, ni un certificado, ni un servidor.

### ⏸ Se pospone a Fase 2 — solo si el MVP está vivo y en uso a los 9 meses

| Función | Por qué se pospone, no se descarta |
|---|---|
| Bóveda de contraseñas (Argon2id + AES-GCM) | Alto valor de aprendizaje, pero ver **L12**: no puede ser tu almacén real hasta estar auditada. Constrúyela después, sin prisa. |
| Pwned Passwords (k-anonimato, gratis) | 15 horas, valor alto. Entra apenas exista la bóveda. |
| Alertas por Registro de eventos de Seguridad | Barato (~40 h) y genuinamente útil, pero no es lo que te falta hoy. |
| Cámara y micrófono | ~40 h. El valor real es la *detección* de uso, no el bloqueo; Windows 11 ya muestra un indicador. |
| Perfiles de rendimiento automáticos | Función cómoda, no de seguridad. Primero que funcione lo importante. |
| Cliente VPN WireGuard | El cliente oficial de WireGuard es gratuito, está firmado y funciona mejor. Solo vale la pena por la integración de reportes. |
| Anti-phishing con Safe Browsing | Útil, pero Edge y Chrome ya lo traen. Valor incremental bajo. |

### ❌ Fuera del alcance — con justificación

| Función | Por qué queda fuera |
|---|---|
| **Minifiltro de kernel** y todo lo que depende de él (bloqueo preventivo, anti-ransomware propio, tiempo real real) | 300–500 h, otro lenguaje, otro flujo de depuración, certificado EV que como persona natural probablemente no obtengas, y `testsigning` que rompe tu equipo (**L4**, **L5**). Sustituto honesto: **Controlled Folder Access de Defender**, que Nexo configura y monitorea. Ya existe, ya está firmado, ya funciona. |
| **Detección de rootkits** | Por definición requiere ver lo que el SO oculta: es kernel o no es. Sin driver, cualquier implementación sería teatro de seguridad. |
| **Callout de WFP / inspección profunda de paquetes** | Mismo problema de firma, y el firewall por aplicación ya cubre el 90% del valor práctico. |
| **Entorno de rescate WinPE** | 80–120 h para reconstruir algo que **Microsoft Defender Offline ya hace, gratis, con un clic**, y con firmas actualizadas. Reconstruirlo peor no tiene defensa. |
| **Navegador seguro propio** | 80–120 h, el submódulo más caro del proyecto. **Windows Sandbox** ya da aislamiento real, gratis, con un archivo `.wsb` de diez líneas. Escribe el `.wsb`, no el navegador. |
| **Detección de deepfakes** | Infactible para una persona. Los detectores publicados no generalizan fuera de su dataset y producen falsos positivos masivos. Prometerlo sería deshonesto con el usuario y contigo. |
| **Estafas por SMS** | Windows no expone una API para leer SMS; Phone Link no tiene SDK público. La versión "pega el texto aquí" es real pero es un juguete de 10 horas: hazla si te divierte, no la cuentes como función. |
| **Autocompletado global en apps Win32** | UIAutomation contra aplicaciones arbitrarias es frágil por naturaleza. Se rompe con cada actualización de cada app. Pozo sin fondo de mantenimiento. |
| **Monitoreo de dark web de pago** | El tramo gratuito de Pwned Passwords cubre el caso real (¿mi contraseña está filtrada?). Los USD 47/año de la API de brechas por email son gasto justificable **después**, no antes. |
| **Anti-criptojacking** | Heurística pura con falsos positivos garantizados: un compilador, Blender o un juego disparan exactamente las mismas señales. Alto esfuerzo, alta molestia, bajo valor. |
| **Análisis de comportamiento con ETW** | 80–120 h solo para dominar `TraceEvent`, y sin capacidad de bloquear (solo matar el proceso tarde). Es un proyecto de investigación, no una función de MVP. |
| **Desinstalador de "apps sin uso"** | La métrica no es fiable: NTFS trae `LastAccessTime` deshabilitado por defecto desde Vista. Recomendarías desinstalar cosas en uso. Función que genera desconfianza. |

**Se descarta el módulo M2 completo del MVP.** No por dificultad, sino porque cada una de sus cinco funciones tiene hoy un sustituto gratuito, mantenido y superior: WireGuard oficial, Windows Sandbox, uBlock Origin, SmartScreen y el indicador de cámara de Windows 11. Construir peores versiones de todas ellas es la forma más segura de gastar nueve meses sin ganar nada.

### Cronograma del MVP

| Mes | Hito | Criterio de "hecho" |
|---|---|---|
| 1 | Entorno + M5 Reportes | Se generan 50 notas sintéticas y el vault se navega en Obsidian con grafo y backlinks funcionando |
| 2–3 | Limpieza + duplicados + vista previa | **Lo usas en tu propio equipo y liberas espacio real** |
| 4 | Inicio + S.M.A.R.T. + triturador | M4 cerrado |
| 5–6 | Firewall por app + modo sigiloso | Reglas que sobreviven a un reinicio y se reportan al vault |
| 7 | Escaneo YARA + Wi-Fi + `winget` | Escaneo manual de una carpeta, con cuarentena |
| 8–9 | Bandeja, instalador, estabilización | Se instala en una VM limpia y corre una semana sin intervención |

---

## 4. Próximos pasos

**1. Esta semana — montar la VM y tomar el primer snapshot.**
Hyper-V o VirtualBox, Windows 11 Pro, 8 GB de RAM, snapshot llamado `limpia`. Instalar Visual Studio 2022 Community con el workload *.NET desktop development* únicamente (no instales el WDK: no lo vas a usar, y son 15 GB). Poblar `C:\TestCorpus` con ~2 GB de archivos sintéticos y duplicados generados por script. **Todo el desarrollo de M4 ocurre aquí, nunca en tu equipo.** Ver **L5** y **L11**.

**2. Esta semana — fijar el posicionamiento por escrito, antes de escribir código.**
Un `README.md` con: el nombre, la frase *"suite de higiene y monitoreo de seguridad para Windows; complementa a Microsoft Defender y no lo reemplaza"*, la licencia (MIT o Apache-2.0, por la exclusión de garantía de **L11**), y una sección "Fuera de alcance" copiada de §3. Esto no es burocracia: define el texto de cada diálogo de la UI y te ahorra rediseñar la mitad del proyecto en el mes 6. Ver **L10**.

**3. Semanas 2–4 — ejecutar [[Prompt 5 Módulo de reportes y visualización (integración con Obsidian)]] e implementarlo completo.**
Criterio de término: un test que genere 50 notas sintéticas de los seis tipos de evento, que abras el vault en Obsidian y que el grafo, los backlinks y la nota-resumen diaria funcionen **sin instalar ningún plugin**. Valida el formato ahora, porque en tres meses habrá cuatro módulos dependiendo de él y cambiar el front matter será caro. Aplica desde ya la política de redacción de **L7**: la librería debe rechazar por diseño cualquier intento de escribir un campo marcado como secreto.

**4. Mes 2 — ejecutar [[Prompt 4 Módulo de limpieza y optimización]] e implementar solo la limpieza de temporales.**
Un submódulo, no seis. Con vista previa, confirmación y borrado a papelera por defecto. Contra `C:\TestCorpus`, en la VM. Cuando libere espacio real en tu equipo por primera vez, el proyecto habrá pasado su punto de mayor riesgo de abandono.

**5. Mes 3 — punto de decisión, agendado desde hoy.**
Anota la fecha en el calendario ahora. Si al cumplirse **no tienes M5 + limpieza de temporales funcionando y usándolos al menos una vez por semana**, la conclusión no es "esforzarme más": es que el tiempo disponible es menor al estimado. En ese caso, recorta a **M5 + M4 exclusivamente**, publícalo como una utilidad de limpieza con reportes en Obsidian —que es un proyecto honesto, completo y útil— y cierra los otros tres módulos como documentación de diseño. **Un proyecto pequeño y terminado vale más que uno grande y abandonado**, tanto para ti como para un portafolio.

---

## 5. Verificación

- **(a)** La matriz de §1 cubre los cinco módulos —M1, M2, M3, M4, M5— sin excepción, cada uno con dificultad, horas, costo de dependencias y riesgo de abandono cuantificado.
- **(b)** Los 13 riesgos de §2 tienen mitigación técnica o de diseño concreta y accionable. Ninguna es "consultar a un abogado": son cambios específicos de arquitectura (hablar con `clamd` por socket en vez de enlazar), de configuración (`Add-MpPreference -ExclusionPath`, ACL sin herencia, BitLocker), de proceso (VM con snapshot, corpus sintético) o de producto (renombrar el posicionamiento, licencia con exclusión de garantía, no telemetría).
- **(c)** El alcance de §3 son 205–265 horas contra las 845–1.240 del alcance completo: un recorte del 75–80%, coherente con 30 horas efectivas mensuales. El cronograma entrega algo usable en el mes 3, no en el mes 30, e incluye un criterio explícito de recorte adicional en el paso 5 de §4.
