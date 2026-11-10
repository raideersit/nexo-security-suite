// Se inyecta SOLO cuando la persona elige una entrada en la ventanita de Nexo, SOLO en el marco principal de la pestaña, y corre en el
// «mundo aislado» de la extensión (los scripts de la página no ven estas variables). Script clásico, sin módulos: lo carga
// chrome.scripting.executeScript({files}) y también la página de pruebas. Devuelve solo un estado, nunca la contraseña.
globalThis.nexoRellenar = function (datos) {
  // La página pudo cambiar entre que Nexo dio la contraseña y este momento: se vuelve a comprobar el sitio exacto.
  if (location.protocol !== 'https:' || location.hostname !== datos.host) return 'la_pagina_cambio';

  const visible = (el) => {
    if (el.disabled || el.readOnly) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    const cs = getComputedStyle(el);
    return cs.visibility !== 'hidden' && cs.display !== 'none' && Number(cs.opacity) > 0.1;
  };
  const tiposDeUsuario = ['text', 'email', 'tel'];
  const esUsuario = (el) => tiposDeUsuario.includes(el.type) && visible(el);
  const nueva = (el) => (el.autocomplete || '').split(/\s+/).includes('new-password');

  const campos = Array.from(document.querySelectorAll('input'));
  const claves = campos.filter((el) => el.type === 'password' && visible(el));
  const clave = claves.find((el) => !nueva(el)) || null;
  if (!clave && claves.length > 0) return 'registro';       // solo campos «contraseña nueva»: no se rellena una guardada

  let usuario = null;
  if (clave) {
    // El campo de usuario más cercano ANTES de la contraseña, en su mismo formulario (o en la página si no hay formulario).
    const ambito = clave.form ? Array.from(clave.form.querySelectorAll('input')) : campos;
    for (let i = ambito.indexOf(clave) - 1; i >= 0; i--) {
      if (esUsuario(ambito[i])) { usuario = ambito[i]; break; }
    }
  } else {
    // Páginas que piden primero el usuario y en otro paso la contraseña: solo si el campo dice claramente que es de usuario.
    usuario = campos.find((el) => esUsuario(el) && /\b(username|email)\b/.test(el.autocomplete || ''))
           || campos.find((el) => el.type === 'email' && visible(el)) || null;
  }
  if (!clave && !usuario) return 'sin_campos';

  const ponerValor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  const poner = (el, v) => {
    el.focus();
    ponerValor.call(el, v);                                   // el setter nativo: también lo notan los formularios hechos con React
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };
  if (usuario && datos.usuario) poner(usuario, datos.usuario);
  if (clave) poner(clave, datos.contrasena);
  if (clave) return usuario && datos.usuario ? 'relleno' : 'relleno_solo_clave';
  return datos.usuario ? 'relleno_solo_usuario' : 'sin_campos';
};
