// Lógica de la extensión SIN APIs del navegador: se prueba con Node (tools/Nexo.Autocompletado.Extension.Pruebas).
// fondo.js le pasa las funciones que sí tocan el navegador (native messaging, almacenamiento, pestañas, inyección).

export const NOMBRE_DEL_HOST = 'com.nexo.autocompletado';
export const MAX_ENTRADAS = 50;

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NOMBRE = /^[a-z0-9-]{1,32}$/;

export function aBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

/** El código de 6 cifras que se compara con el que muestra Nexo. Mismo cálculo que PuenteDeAutocompletado.CodigoDe (C#). */
export async function codigoDe(clave) {
  const datos = new TextEncoder().encode('nexo-emparejar:' + aBase64(clave));
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', datos));
  const n = ((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0;
  const s = String(n % 1000000).padStart(6, '0');
  return s.slice(0, 3) + ' ' + s.slice(3);
}

/** «brave-3f9a», «edge-…»: el tipo de navegador y un sufijo por perfil, para que dos perfiles no se pisen el emparejamiento en Nexo. */
export function nombreDeNavegador({ esBrave, marcas }, sufijo) {
  const m = (marcas || []).map(x => String(x && x.brand));
  const tipo = esBrave ? 'brave' : m.includes('Microsoft Edge') ? 'edge' : m.includes('Google Chrome') ? 'chrome' : 'chromium';
  const n = tipo + '-' + String(sufijo).toLowerCase();
  if (!NOMBRE.test(n)) throw new Error('nombre de navegador no válido');
  return n;
}

/** La página de la pestaña (la URL la da el navegador, nunca la página). Solo https y sin «usuario@» delante del sitio. */
export function analizarPagina(url) {
  let u;
  try { u = new URL(String(url)); } catch { return { motivo: 'Esta pestaña no tiene una dirección web.' }; }
  if (u.protocol === 'http:') return { motivo: 'Esta página no usa conexión cifrada (http): Nexo no rellena contraseñas aquí.' };
  if (u.protocol !== 'https:') return { motivo: 'Nexo solo rellena en páginas web (https).' };
  if (u.username || u.password) return { motivo: 'La dirección lleva un usuario antes del sitio («…@…»), un truco típico de phishing.' };
  if (!u.hostname) return { motivo: 'No se reconoce el sitio de esta página.' };
  return { host: u.hostname };
}

/** Lo que dice Chromium cuando el host no está registrado o no autoriza esta extensión, frente a cualquier otro corte. */
export function estadoPorDesconexion(mensaje) {
  const m = String(mensaje || '');
  if (/not found|forbidden|not registered/i.test(m)) return { estado: 'host_no_instalado' };
  return { estado: 'error', motivo: 'se cortó la conexión con Nexo' };
}

const corto = (t) => String(t ?? '').slice(0, 300);

/** Una respuesta de Nexo que no es «ok», en una frase para la persona. Lo desconocido NUNCA se toma por bueno. */
export function mensajeDeEstado(r) {
  const motivo = r && typeof r.motivo === 'string' ? corto(r.motivo) : '';
  switch (r && r.estado) {
    case 'sin_nexo': return { tipo: 'aviso', texto: 'Nexo no está abierto. Ábrelo y desbloquea la bóveda.' };
    case 'host_no_instalado': return { tipo: 'error', texto: 'Nexo no está instalado para este navegador (o no autoriza esta extensión). Ejecuta «nexo-autocompletar --instalar».' };
    case 'bloqueada': return { tipo: 'aviso', texto: 'La bóveda está bloqueada. Desbloquéala en Nexo.' };
    case 'no_emparejado': return { tipo: 'aviso', texto: 'Este navegador no está emparejado con Nexo.' };
    case 'rechazada': return { tipo: 'aviso', texto: 'Nexo no rellena aquí: ' + motivo };
    case 'limite': return { tipo: 'aviso', texto: 'Nexo frenó los rellenados: ' + (motivo || 'demasiados seguidos; espera un minuto.') };
    case 'rechazado': return { tipo: 'aviso', texto: 'Nexo no aceptó el emparejamiento.' + (motivo ? ' (' + motivo + ')' : '') };
    case 'ocupado': return { tipo: 'aviso', texto: 'Ya hay un emparejamiento esperando respuesta en Nexo.' };
    case 'no_encontrada': return { tipo: 'aviso', texto: 'Esa entrada ya no está en la bóveda.' };
    case 'error': return { tipo: 'error', texto: 'Error: ' + (motivo || 'sin detalles') };
    default: return { tipo: 'error', texto: 'Nexo contestó algo que no se entiende.' };
  }
}

/** La respuesta de «buscar», comprobada campo a campo. null = forma inesperada (se trata como error, no como «no hay nada»). */
export function validarBusqueda(r) {
  if (!r || r.estado !== 'ok' || typeof r.sitio !== 'string' || !Array.isArray(r.entradas) || r.entradas.length > MAX_ENTRADAS) return null;
  const entradas = [];
  for (const e of r.entradas) {
    if (!e || typeof e.id !== 'string' || !GUID.test(e.id) || typeof e.usuario !== 'string' || e.usuario.length > 512
        || typeof e.sitio !== 'string' || e.sitio.length > 2048) return null;
    entradas.push({ id: e.id, usuario: e.usuario, sitio: e.sitio });
  }
  const mas = Number.isInteger(r.mas) && r.mas >= 0 ? r.mas : 0;
  return { sitio: r.sitio, entradas, mas };
}

export function validarRelleno(r) {
  if (!r || r.estado !== 'ok' || typeof r.usuario !== 'string' || typeof r.contrasena !== 'string' || r.contrasena.length === 0) return null;
  return { usuario: r.usuario, contrasena: r.contrasena };
}

/** Lo que devuelve rellenar.js, en una frase. */
export function mensajeDeRelleno(resultado) {
  switch (resultado) {
    case 'relleno': return { tipo: 'ok', texto: 'Usuario y contraseña rellenados.' };
    case 'relleno_solo_clave': return { tipo: 'ok', texto: 'Contraseña rellenada (no se encontró el campo de usuario).' };
    case 'relleno_solo_usuario': return { tipo: 'ok', texto: 'Usuario rellenado. La contraseña se pide en el paso siguiente: vuelve a abrir Nexo ahí.' };
    case 'la_pagina_cambio': return { tipo: 'aviso', texto: 'La página cambió mientras tanto: no se rellenó nada.' };
    case 'registro': return { tipo: 'aviso', texto: 'Parece un formulario para CREAR una contraseña: no se rellena una guardada.' };
    case 'sin_campos': return { tipo: 'aviso', texto: 'No se ve ningún campo de usuario ni de contraseña en esta página.' };
    default: return { tipo: 'error', texto: 'No se pudo rellenar en esta página.' };
  }
}

/**
 * Atiende los mensajes de la ventanita de la extensión. deps:
 *   idPropio, urlVentana         para aceptar SOLO mensajes de nuestra propia ventanita
 *   nativo(msg) → Promise<obj>   una ida y vuelta con Nexo (nunca rechaza: los fallos son {estado})
 *   leerIdentidad() / crearIdentidad() / olvidarIdentidad()   {navegador, clave(base64)} en chrome.storage.local
 *   pestana(tabId) → Promise<{url}>   la URL según el NAVEGADOR
 *   inyectar(tabId, datos) → Promise<string>   ejecuta rellenar.js en el marco principal de esa pestaña
 * La contraseña nunca vuelve a la ventanita: va de Nexo a la página y nada más.
 */
export function crearAtendedor(deps) {
  return async function atender(msg, sender) {
    if (!sender || sender.id !== deps.idPropio || typeof sender.url !== 'string' || !sender.url.startsWith(deps.urlVentana))
      return { tipo: 'error', texto: 'Petición no permitida.' };
    const accion = msg && msg.accion;
    try {
      if (accion === 'estado') {
        const id = await deps.leerIdentidad();
        const r = await deps.nativo(id ? { tipo: 'estado', navegador: id.navegador, clave: id.clave } : { tipo: 'estado', navegador: 'nuevo' });
        if (r.estado !== 'ok' || typeof r.emparejado !== 'boolean' || typeof r.bloqueada !== 'boolean') return mensajeDeEstado(r);
        return { tipo: 'ok', emparejado: !!id && r.emparejado, bloqueada: r.bloqueada };
      }
      if (accion === 'preparar') {
        const id = (await deps.leerIdentidad()) || (await deps.crearIdentidad());
        return { tipo: 'ok', navegador: id.navegador, codigo: await codigoDe(Uint8Array.from(atob(id.clave), c => c.charCodeAt(0))) };
      }
      if (accion === 'emparejar') {
        const id = await deps.leerIdentidad();
        if (!id) return { tipo: 'error', texto: 'Primero hay que preparar el emparejamiento.' };
        const r = await deps.nativo({ tipo: 'emparejar', navegador: id.navegador, clave: id.clave });
        return r.estado === 'ok' && r.emparejado === true ? { tipo: 'ok', texto: 'Emparejado con Nexo.' } : mensajeDeEstado(r);
      }
      if (accion === 'olvidar') {
        await deps.olvidarIdentidad();
        return { tipo: 'ok', texto: 'Este navegador ya no tiene clave de Nexo. (En Nexo puedes quitarlo también de la lista.)' };
      }
      if (accion === 'buscar' || accion === 'rellenar') {
        if (!Number.isInteger(msg.tabId)) return { tipo: 'error', texto: 'Pestaña no válida.' };
        const id = await deps.leerIdentidad();
        if (!id) return mensajeDeEstado({ estado: 'no_emparejado' });
        const tab = await deps.pestana(msg.tabId);
        const pagina = analizarPagina(tab && tab.url);
        if (pagina.motivo) return { tipo: 'aviso', texto: pagina.motivo };

        if (accion === 'buscar') {
          const r = await deps.nativo({ tipo: 'buscar', navegador: id.navegador, clave: id.clave, url: tab.url });
          if (r.estado !== 'ok') return mensajeDeEstado(r);
          const b = validarBusqueda(r);
          return b ? { tipo: 'ok', ...b } : mensajeDeEstado({});
        }

        if (typeof msg.id !== 'string' || !GUID.test(msg.id)) return { tipo: 'error', texto: 'Entrada no válida.' };
        // La URL se vuelve a leer AHORA (no la del momento de buscar): Nexo comprueba que la entrada sea de esta página.
        const r = await deps.nativo({ tipo: 'rellenar', navegador: id.navegador, clave: id.clave, url: tab.url, id: msg.id });
        if (r.estado !== 'ok') return mensajeDeEstado(r);
        const v = validarRelleno(r);
        if (!v) return mensajeDeEstado({});
        let resultado;
        try { resultado = await deps.inyectar(msg.tabId, { usuario: v.usuario, contrasena: v.contrasena, host: pagina.host }); }
        catch { resultado = 'fallo'; }
        return mensajeDeRelleno(resultado);
      }
      return { tipo: 'error', texto: 'Acción desconocida.' };
    } catch {
      return { tipo: 'error', texto: 'Algo falló en la extensión.' };
    }
  };
}
