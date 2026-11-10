// La ventanita que se abre al pulsar el botón de Nexo (o Alt+Mayús+N). Todo el texto se pone con textContent:
// un usuario o un sitio guardado con «<» nunca se interpreta como HTML.
const $estado = document.getElementById('estado');
const $contenido = document.getElementById('contenido');
const $olvidar = document.getElementById('olvidar');

const pedir = (m) => chrome.runtime.sendMessage(m);

function decir(r) {
  $estado.textContent = r.texto || '';
  $estado.className = r.tipo === 'ok' ? 'ok' : r.tipo === 'aviso' ? 'aviso' : 'error';
}

function boton(texto, alPulsar, clase) {
  const b = document.createElement('button');
  b.textContent = texto;
  if (clase) b.className = clase;
  b.addEventListener('click', alPulsar);
  return b;
}

function limpiar() { $contenido.replaceChildren(); }

async function vistaEmparejar() {
  limpiar();
  decir({ tipo: 'aviso', texto: 'Este navegador no está emparejado con Nexo.' });
  $contenido.append(boton('Emparejar con Nexo', async () => {
    const p = await pedir({ accion: 'preparar' });
    if (p.tipo !== 'ok') return decir(p);
    limpiar();
    const caja = document.createElement('div');
    caja.className = 'codigo';
    const t = document.createElement('p');
    t.textContent = 'En Nexo aparecerá una pregunta. Acepta SOLO si muestra este mismo código:';
    const c = document.createElement('strong');
    c.textContent = p.codigo;
    const n = document.createElement('p');
    n.className = 'nota';
    n.textContent = 'Navegador: ' + p.navegador + '. Esta ventanita puede cerrarse al pasar a Nexo; después vuelve a abrirla.';
    caja.append(t, c, n);
    $contenido.append(caja);
    decir({ tipo: 'aviso', texto: 'Esperando a que aceptes en Nexo…' });
    const r = await pedir({ accion: 'emparejar' });
    decir(r);
    if (r.tipo === 'ok') setTimeout(iniciar, 800);
  }));
}

async function vistaEntradas(tab) {
  limpiar();
  const b = await pedir({ accion: 'buscar', tabId: tab.id });
  if (b.tipo !== 'ok') return decir(b);
  if (b.entradas.length === 0) return decir({ tipo: 'aviso', texto: 'No hay entradas de ' + b.sitio + ' en la bóveda.' });
  decir({ tipo: 'ok', texto: 'Entradas de ' + b.sitio + ':' });
  const lista = document.createElement('ul');
  for (const e of b.entradas) {
    const li = document.createElement('li');
    const btn = boton(e.usuario || '(sin usuario)', async () => {
      lista.querySelectorAll('button').forEach((x) => { x.disabled = true; });
      const r = await pedir({ accion: 'rellenar', tabId: tab.id, id: e.id });
      decir(r);
      if (r.tipo === 'ok') setTimeout(() => window.close(), 900);
      else lista.querySelectorAll('button').forEach((x) => { x.disabled = false; });
    }, 'entrada');
    const s = document.createElement('span');
    s.textContent = e.sitio;
    btn.append(s);
    li.append(btn);
    lista.append(li);
  }
  $contenido.append(lista);
  if (b.mas > 0) {
    const m = document.createElement('p');
    m.className = 'nota';
    m.textContent = 'Y ' + b.mas + ' más: búscalas en Nexo.';
    $contenido.append(m);
  }
}

async function iniciar() {
  limpiar();
  $olvidar.hidden = true;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const e = await pedir({ accion: 'estado' });
  if (e.tipo !== 'ok') {
    decir(e);
    $contenido.append(boton('Volver a intentar', iniciar));
    return;
  }
  if (!e.emparejado) return vistaEmparejar();
  $olvidar.hidden = false;
  if (e.bloqueada) {
    decir({ tipo: 'aviso', texto: 'La bóveda está bloqueada. Desbloquéala en Nexo.' });
    $contenido.append(boton('Ya la desbloqueé', iniciar));
    return;
  }
  if (!tab) return decir({ tipo: 'error', texto: 'No hay una pestaña activa.' });
  await vistaEntradas(tab);
}

$olvidar.addEventListener('click', async () => {
  decir(await pedir({ accion: 'olvidar' }));
  $olvidar.hidden = true;
  limpiar();
});

iniciar();
