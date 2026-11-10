// Service worker de la extensión: lo único que habla con Nexo (native messaging) y lo único que inyecta en las páginas.
// La lógica está en nucleo.js (probada con Node); aquí solo se conectan las APIs del navegador.
import { NOMBRE_DEL_HOST, crearAtendedor, estadoPorDesconexion, nombreDeNavegador } from './nucleo.js';

const CLAVE_DE_ALMACEN = 'nexoIdentidad';
const TOPE_MS = 150000; // algo más que los 2 min que Nexo espera a que aceptes el emparejamiento

/** Una ida y vuelta con Nexo. connectNative (y no sendNativeMessage) mantiene vivo el service worker mientras espera. */
function nativo(mensaje) {
  return new Promise((resolver) => {
    let puerto = null;
    let hecho = false;
    let reloj = null;
    const fin = (r) => {
      if (hecho) return;
      hecho = true;
      clearTimeout(reloj);
      try { puerto && puerto.disconnect(); } catch { /* ya cerrado */ }
      resolver(r && typeof r === 'object' ? r : {});
    };
    try { puerto = chrome.runtime.connectNative(NOMBRE_DEL_HOST); }
    catch (e) { fin(estadoPorDesconexion(e && e.message)); return; }
    puerto.onMessage.addListener((m) => fin(m));
    puerto.onDisconnect.addListener(() => fin(estadoPorDesconexion(chrome.runtime.lastError && chrome.runtime.lastError.message)));
    reloj = setTimeout(() => fin({ estado: 'error', motivo: 'Nexo no contestó a tiempo' }), TOPE_MS);
    puerto.postMessage(mensaje);
  });
}

// Solo chrome.storage.local: NUNCA .sync (subiría la clave a la cuenta del navegador).
async function leerIdentidad() {
  const r = await chrome.storage.local.get(CLAVE_DE_ALMACEN);
  const id = r[CLAVE_DE_ALMACEN];
  return id && typeof id.navegador === 'string' && typeof id.clave === 'string' ? id : null;
}

async function crearIdentidad() {
  const clave = crypto.getRandomValues(new Uint8Array(32));
  const sufijo = Array.from(crypto.getRandomValues(new Uint8Array(2)), (b) => b.toString(16).padStart(2, '0')).join('');
  const esBrave = !!(navigator.brave && (await navigator.brave.isBrave()));
  const marcas = (navigator.userAgentData && navigator.userAgentData.brands) || [];
  let s = '';
  for (const b of clave) s += String.fromCharCode(b);
  const id = { navegador: nombreDeNavegador({ esBrave, marcas }, sufijo), clave: btoa(s) };
  await chrome.storage.local.set({ [CLAVE_DE_ALMACEN]: id });
  return id;
}

async function olvidarIdentidad() { await chrome.storage.local.remove(CLAVE_DE_ALMACEN); }

async function pestana(tabId) { return await chrome.tabs.get(tabId); }

async function inyectar(tabId, datos) {
  const objetivo = { tabId, frameIds: [0] };
  await chrome.scripting.executeScript({ target: objetivo, files: ['rellenar.js'] });
  const [r] = await chrome.scripting.executeScript({ target: objetivo, func: (d) => globalThis.nexoRellenar(d), args: [datos] });
  return r && r.result;
}

const atender = crearAtendedor({
  idPropio: chrome.runtime.id,
  urlVentana: chrome.runtime.getURL('ventana.html'),
  nativo, leerIdentidad, crearIdentidad, olvidarIdentidad, pestana, inyectar,
});

chrome.runtime.onMessage.addListener((msg, sender, responder) => {
  atender(msg, sender).then(responder);
  return true; // la respuesta llega después (asíncrona)
});
