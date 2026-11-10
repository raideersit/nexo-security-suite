// Pruebas de la extensión de autocompletado. Uso:  node tools/Nexo.Autocompletado.Extension.Pruebas/correr.mjs [--sin-navegador]
// 1-3 con Node (lógica, atendedor con dobles, manifiesto y código). 4: rellenar.js en un Edge REAL sin ventana, con un perfil
// temporal propio (no toca el perfil de la persona), contra una página servida por https en 127.0.0.1 con un certificado de usar y tirar.
import { readFileSync, mkdtempSync, rmSync, readdirSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const AQUI = dirname(fileURLToPath(import.meta.url));
const RAIZ = join(AQUI, '..', '..');
const EXT = join(RAIZ, 'src', 'Nexo.Autocompletado.Extension');
const N = await import(pathToFileURL(join(EXT, 'nucleo.js')).href);

let fallos = 0;
function check(c, d, detalle) {
  if (!c) fallos++;
  console.log(`  [${c ? 'OK' : 'FALLO'}]    ${d}`);
  if (!c && detalle !== undefined) console.log('           ' + (typeof detalle === 'string' ? detalle : JSON.stringify(detalle)));
}

// ------------------------------------------------------------------------------------------------
console.log('1. Lógica pura (nucleo.js)');
const clave0 = Uint8Array.from({ length: 32 }, (_, i) => i);
check(await N.codigoDe(clave0) === '915 824', 'el código de la clave 0..31 es «915 824», el MISMO vector que en C# (Nexo.Identity.Demo)', await N.codigoDe(clave0));
const otra = crypto.getRandomValues(new Uint8Array(32));
check(/^\d{3} \d{3}$/.test(await N.codigoDe(otra)) && (await N.codigoDe(otra)) !== '915 824', 'otra clave: otro código, con la forma «123 456»');

check(N.nombreDeNavegador({ esBrave: true, marcas: [{ brand: 'Chromium' }] }, '3f9a') === 'brave-3f9a', 'Brave → «brave-3f9a»');
check(N.nombreDeNavegador({ esBrave: false, marcas: [{ brand: 'Microsoft Edge' }, { brand: 'Chromium' }] }, 'ab12') === 'edge-ab12', 'Edge → «edge-…»');
check(N.nombreDeNavegador({ esBrave: false, marcas: [{ brand: 'Google Chrome' }] }, 'ab12') === 'chrome-ab12' && N.nombreDeNavegador({ marcas: [] }, '0000') === 'chromium-0000', 'Chrome y otros');
let lanzo = false;
try { N.nombreDeNavegador({ marcas: [] }, 'x y'); } catch { lanzo = true; }
check(lanzo, 'un sufijo con espacios: error (Nexo lo rechazaría)');

check(N.analizarPagina('https://github.com/login?x=1').host === 'github.com', 'https: el sitio según la URL');
check(N.analizarPagina('https://аpple.com/').host === 'xn--pple-43d.com', '«аpple.com» con «а» cirílica se ve como punycode (no como apple.com)', N.analizarPagina('https://аpple.com/'));
check(/cifrada/.test(N.analizarPagina('http://github.com').motivo), 'http: no');
check(['file:///C:/x.html', 'chrome://settings', 'data:text/html,x', 'edge://extensions', 'about:blank', '', undefined].every(u => N.analizarPagina(u).motivo), 'file:, chrome:, data:, edge:, about:, vacío: no');
check(/phishing/.test(N.analizarPagina('https://bancoestado.cl@malo.top/').motivo), '«https://banco@malo»: no, y se dice por qué');

check(N.estadoPorDesconexion('Specified native messaging host not found.').estado === 'host_no_instalado'
   && N.estadoPorDesconexion('Access to the specified native messaging host is forbidden.').estado === 'host_no_instalado', 'host no registrado o no autoriza la extensión: «host_no_instalado»');
check(N.estadoPorDesconexion('Native host has exited.').estado === 'error' && N.estadoPorDesconexion(undefined).estado === 'error', 'cualquier otro corte: error');

for (const e of ['sin_nexo', 'host_no_instalado', 'bloqueada', 'no_emparejado', 'rechazada', 'limite', 'rechazado', 'ocupado', 'no_encontrada', 'error']) {
  const m = N.mensajeDeEstado({ estado: e, motivo: 'm' });
  check(typeof m.texto === 'string' && m.texto.length > 5 && m.tipo !== 'ok', 'estado «' + e + '»: frase en español y no es «ok»', m);
}
check(N.mensajeDeEstado({ estado: 'ok' }).tipo === 'error' && N.mensajeDeEstado({ estado: 'raro' }).tipo === 'error' && N.mensajeDeEstado(null).tipo === 'error', 'algo desconocido NUNCA se toma por bueno');
check(N.mensajeDeEstado({ estado: 'error', motivo: 'x'.repeat(5000) }).texto.length < 400, 'un motivo enorme se recorta');

const G = '0d1f8f3e-2b9c-4f7a-9d2e-1a2b3c4d5e6f';
const ok = { estado: 'ok', sitio: 'github.com', entradas: [{ id: G, usuario: 'ana', sitio: 'github.com', contrasena: 'NO-DEBE-PASAR' }], mas: 0 };
const vb = N.validarBusqueda(ok);
check(vb && vb.entradas.length === 1 && !JSON.stringify(vb).includes('NO-DEBE-PASAR'), 'buscar: se queda solo con id, usuario y sitio (aunque llegara una contraseña, no pasa a la ventanita)');
for (const [que, r] of [
  ['id que no es GUID', { ...ok, entradas: [{ id: '1', usuario: 'a', sitio: 's' }] }],
  ['usuario que no es texto', { ...ok, entradas: [{ id: G, usuario: 5, sitio: 's' }] }],
  ['más de 50 entradas', { ...ok, entradas: Array.from({ length: 51 }, () => ({ id: G, usuario: 'a', sitio: 's' })) }],
  ['entradas que no es lista', { ...ok, entradas: {} }],
  ['sin sitio', { estado: 'ok', entradas: [] }],
  ['estado que no es ok', { ...ok, estado: 'okk' }],
]) check(N.validarBusqueda(r) === null, 'buscar con ' + que + ': forma inesperada (null)');
check(N.validarRelleno({ estado: 'ok', usuario: 'a', contrasena: 'b' }).contrasena === 'b' && N.validarRelleno({ estado: 'ok', usuario: 'a', contrasena: '' }) === null
   && N.validarRelleno({ estado: 'ok', contrasena: 'b' }) === null, 'rellenar: exige usuario (texto) y contraseña no vacía');
for (const r of ['relleno', 'relleno_solo_clave', 'relleno_solo_usuario']) check(N.mensajeDeRelleno(r).tipo === 'ok', 'resultado «' + r + '»: ok');
for (const r of ['la_pagina_cambio', 'registro', 'sin_campos', undefined, 'otro']) check(N.mensajeDeRelleno(r).tipo !== 'ok', 'resultado «' + r + '»: no es ok');

// ------------------------------------------------------------------------------------------------
console.log('2. El atendedor del service worker (con dobles del navegador)');
const ID = 'kffjcngenealkjoecfdcliemblgbihpc';
const VENTANA = 'chrome-extension://' + ID + '/ventana.html';
const DE_LA_VENTANA = { id: ID, url: VENTANA };
function montar(op = {}) {
  const s = {
    identidad: op.identidad === undefined ? { navegador: 'brave-3f9a', clave: N.aBase64(clave0) } : op.identidad,
    enviados: [], inyectados: [], urls: op.urls || ['https://github.com/login'], creadas: 0,
  };
  const respuestas = op.respuestas || {};
  const atender = N.crearAtendedor({
    idPropio: ID, urlVentana: VENTANA,
    nativo: async (m) => { s.enviados.push(m); const r = respuestas[m.tipo]; if (r instanceof Error) throw r; return r || { estado: 'ok' }; },
    leerIdentidad: async () => s.identidad,
    crearIdentidad: async () => { s.creadas++; s.identidad = { navegador: 'edge-0001', clave: N.aBase64(otra) }; return s.identidad; },
    olvidarIdentidad: async () => { s.identidad = null; },
    pestana: async () => ({ url: s.urls.length > 1 ? s.urls.shift() : s.urls[0] }),
    inyectar: async (tabId, d) => { s.inyectados.push({ tabId, d }); if (op.inyectar) return op.inyectar(); return 'relleno'; },
  });
  return { s, atender };
}

{
  const { s, atender } = montar();
  for (const [que, sender] of [['otra extensión', { id: 'abcdefghijklmnopabcdefghijklmnop', url: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop/ventana.html' }],
                               ['otra página de la extensión', { id: ID, url: 'chrome-extension://' + ID + '/otra.html' }],
                               ['una página web', { id: ID, url: 'https://malo.top/' }], ['nadie', undefined]]) {
    const r = await atender({ accion: 'rellenar', tabId: 1, id: G }, sender);
    check(r.tipo === 'error' && s.enviados.length === 0, 'mensaje de ' + que + ': rechazado y no se habla con Nexo');
  }
}
{
  const { s, atender } = montar({ identidad: null, respuestas: { estado: { estado: 'ok', emparejado: true, bloqueada: false } } });
  const r = await atender({ accion: 'estado' }, DE_LA_VENTANA);
  check(r.tipo === 'ok' && r.emparejado === false && s.enviados[0].navegador === 'nuevo' && !('clave' in s.enviados[0]),
    'sin clave guardada: pregunta sin clave y «no emparejado» aunque Nexo dijera otra cosa', r);
}
{
  const { s, atender } = montar({ respuestas: { estado: { estado: 'ok', emparejado: true, bloqueada: true } } });
  const r = await atender({ accion: 'estado' }, DE_LA_VENTANA);
  check(r.tipo === 'ok' && r.emparejado && r.bloqueada && s.enviados[0].clave === N.aBase64(clave0), 'con clave: estado con la clave, emparejado y bloqueada');
}
for (const [que, resp, tipo] of [['sin_nexo', { estado: 'sin_nexo' }, 'aviso'], ['host no instalado', { estado: 'host_no_instalado' }, 'error'], ['estado sin «emparejado»', { estado: 'ok', bloqueada: false }, 'error']]) {
  const { atender } = montar({ respuestas: { estado: resp } });
  const r = await atender({ accion: 'estado' }, DE_LA_VENTANA);
  check(r.tipo === tipo, 'estado → ' + que + ': ' + tipo, r);
}
{
  const { s, atender } = montar({ identidad: null });
  const a = await atender({ accion: 'preparar' }, DE_LA_VENTANA);
  const b = await atender({ accion: 'preparar' }, DE_LA_VENTANA);
  check(a.tipo === 'ok' && s.creadas === 1 && a.codigo === b.codigo && a.codigo === await N.codigoDe(otra) && a.navegador === 'edge-0001',
    'preparar: crea la clave UNA vez y el código es el de esa clave', [a, b, s.creadas]);
  check(s.enviados.length === 0, 'preparar no habla con Nexo (solo calcula el código)');
}
{
  const { s, atender } = montar({ identidad: null });
  check((await atender({ accion: 'emparejar' }, DE_LA_VENTANA)).tipo === 'error' && s.enviados.length === 0, 'emparejar sin preparar: error');
  const m = montar({ respuestas: { emparejar: { estado: 'ok', emparejado: true } } });
  const r = await m.atender({ accion: 'emparejar' }, DE_LA_VENTANA);
  check(r.tipo === 'ok' && m.s.enviados[0].tipo === 'emparejar' && m.s.enviados[0].clave === N.aBase64(clave0), 'emparejar: manda la clave y dice «Emparejado»');
  const n = montar({ respuestas: { emparejar: { estado: 'rechazado', motivo: 'no se aceptó en Nexo' } } });
  check((await n.atender({ accion: 'emparejar' }, DE_LA_VENTANA)).tipo === 'aviso', 'emparejar rechazado: aviso');
  const o = montar({ respuestas: { emparejar: { estado: 'ok' } } });
  check((await o.atender({ accion: 'emparejar' }, DE_LA_VENTANA)).tipo !== 'ok', 'emparejar «ok» sin «emparejado: true»: no se da por emparejado');
}
{
  const { s, atender } = montar({ respuestas: { buscar: ok } });
  const r = await atender({ accion: 'buscar', tabId: 7, url: 'https://malo.top/' }, DE_LA_VENTANA);
  check(r.tipo === 'ok' && s.enviados[0].url === 'https://github.com/login', 'buscar usa la URL de la pestaña según el NAVEGADOR, no la que venga en el mensaje', s.enviados[0]);
  check(!JSON.stringify(r).includes('NO-DEBE-PASAR'), 'y a la ventanita no llega ninguna contraseña');
}
{
  const { s, atender } = montar({ urls: ['http://github.com/login'] });
  const r = await atender({ accion: 'buscar', tabId: 7 }, DE_LA_VENTANA);
  check(r.tipo === 'aviso' && s.enviados.length === 0, 'pestaña http: aviso, sin hablar con Nexo');
  const m = montar({ identidad: null });
  check((await m.atender({ accion: 'buscar', tabId: 7 }, DE_LA_VENTANA)).tipo === 'aviso' && m.s.enviados.length === 0, 'sin emparejar: no se pregunta a Nexo');
  const n = montar({ respuestas: { buscar: { estado: 'ok', sitio: 'x', entradas: 'mal' } } });
  check((await n.atender({ accion: 'buscar', tabId: 7 }, DE_LA_VENTANA)).tipo === 'error', 'respuesta de buscar con forma rara: error, no «no hay entradas»');
  check((await n.atender({ accion: 'buscar', tabId: 'x' }, DE_LA_VENTANA)).tipo === 'error', 'pestaña que no es un número: error');
}
{
  const relleno = { estado: 'ok', usuario: 'ana', contrasena: 'clave-gh' };
  const { s, atender } = montar({ urls: ['https://github.com/login', 'https://gist.github.com/x'], respuestas: { rellenar: relleno } });
  const r = await atender({ accion: 'rellenar', tabId: 9, id: G }, DE_LA_VENTANA);
  check(r.tipo === 'ok' && s.enviados[0].tipo === 'rellenar' && s.enviados[0].id === G, 'rellenar: pide UNA entrada por su id', r);
  check(s.inyectados.length === 1 && s.inyectados[0].tabId === 9 && s.inyectados[0].d.contrasena === 'clave-gh' && s.inyectados[0].d.host === 'github.com',
    'inyecta en esa pestaña con el sitio exacto que se comprobó', s.inyectados);
  check(!JSON.stringify(r).includes('clave-gh'), 'la contraseña NO vuelve a la ventanita');
  const r2 = await atender({ accion: 'rellenar', tabId: 9, id: G }, DE_LA_VENTANA);
  check(s.enviados[1].url === 'https://gist.github.com/x' && s.inyectados[1].d.host === 'gist.github.com', 'cada rellenar vuelve a leer la URL de la pestaña en ese momento', s.enviados[1]);
  void r2;
}
{
  const { s, atender } = montar({ respuestas: { rellenar: { estado: 'rechazada', motivo: 'esa entrada no es de github.com' } } });
  const r = await atender({ accion: 'rellenar', tabId: 9, id: G }, DE_LA_VENTANA);
  check(r.tipo === 'aviso' && s.inyectados.length === 0 && /no rellena aquí/.test(r.texto), 'Nexo dice «rechazada»: no se inyecta nada y se dice por qué');
  const m = montar({ respuestas: { rellenar: { estado: 'ok', usuario: 'ana', contrasena: '' } } });
  check((await m.atender({ accion: 'rellenar', tabId: 9, id: G }, DE_LA_VENTANA)).tipo === 'error' && m.s.inyectados.length === 0, 'respuesta sin contraseña: no se inyecta');
  const n = montar();
  check((await n.atender({ accion: 'rellenar', tabId: 9, id: 'no-guid' }, DE_LA_VENTANA)).tipo === 'error' && n.s.enviados.length === 0, 'id que no es GUID: ni se pregunta');
  const o = montar({ respuestas: { rellenar: { estado: 'ok', usuario: 'a', contrasena: 'b' } }, inyectar: () => { throw new Error('Cannot access contents of url'); } });
  check((await o.atender({ accion: 'rellenar', tabId: 9, id: G }, DE_LA_VENTANA)).tipo === 'error', 'la inyección falla (p. ej. página protegida): error, no «rellenado»');
  const p = montar({ respuestas: { rellenar: { estado: 'ok', usuario: 'a', contrasena: 'b' } }, inyectar: () => 'la_pagina_cambio' });
  check((await p.atender({ accion: 'rellenar', tabId: 9, id: G }, DE_LA_VENTANA)).tipo === 'aviso', 'la página cambió antes de escribir: aviso');
  const q = montar({ respuestas: { buscar: new Error('roto') } });
  check((await q.atender({ accion: 'buscar', tabId: 9 }, DE_LA_VENTANA)).tipo === 'error', 'una excepción dentro: error, sin tumbar la extensión');
  const t = montar();
  check((await t.atender({ accion: 'borrar_todo' }, DE_LA_VENTANA)).tipo === 'error', 'acción desconocida: error');
  const u = montar();
  await u.atender({ accion: 'olvidar' }, DE_LA_VENTANA);
  check(u.s.identidad === null, 'olvidar: borra la clave de este navegador');
}

// ------------------------------------------------------------------------------------------------
console.log('3. Manifiesto y código de la extensión');
const man = JSON.parse(readFileSync(join(EXT, 'manifest.json'), 'utf8'));
const idDeClave = Array.from(createHash('sha256').update(Buffer.from(man.key, 'base64')).digest().subarray(0, 16))
  .map(b => String.fromCharCode(97 + (b >> 4)) + String.fromCharCode(97 + (b & 15))).join('');
check(idDeClave === ID, 'el «key» del manifiesto da el ID que autoriza el host (' + ID + ')', idDeClave);
const cs = readFileSync(join(RAIZ, 'src', 'Nexo.Modules.Identity', 'Autocompletado', 'InstaladorDeHostNativo.cs'), 'utf8');
check(cs.includes('"' + man.key + '"') && cs.includes('IdDeLaExtension = "' + ID + '"'), 'es la misma clave y el mismo ID que en InstaladorDeHostNativo.cs');
check(cs.includes('NombreDelHost = "' + N.NOMBRE_DEL_HOST + '"'), 'el nombre del host coincide con el de C# (' + N.NOMBRE_DEL_HOST + ')');
check(man.manifest_version === 3 && JSON.stringify([...man.permissions].sort()) === JSON.stringify(['activeTab', 'nativeMessaging', 'scripting', 'storage']),
  'Manifest V3 y SOLO cuatro permisos: nativeMessaging, activeTab, scripting, storage', man.permissions);
check(!('host_permissions' in man) && !('optional_host_permissions' in man) && !('content_scripts' in man), 'SIN permisos sobre sitios ni scripts en las páginas: solo toca la pestaña cuando la pides');
check(!('externally_connectable' in man) && !('web_accessible_resources' in man), 'ni páginas web ni otras extensiones pueden hablarle; no expone archivos a las páginas');
check(man.content_security_policy?.extension_pages === "script-src 'self'; object-src 'none'", 'CSP estricta (sin scripts de fuera ni eval)');
check(man.background?.service_worker === 'fondo.js' && man.action?.default_popup === 'ventana.html', 'fondo.js y ventana.html (lo que esperan las pruebas de remitente)');
const archivos = readdirSync(EXT).filter(f => /\.(js|html)$/.test(f));
const texto = archivos.map(f => readFileSync(join(EXT, f), 'utf8')).join('\n');
for (const [que, re] of [['storage.sync', /storage\.sync/], ['innerHTML', /innerHTML|outerHTML|insertAdjacentHTML/], ['eval', /\beval\s*\(|new Function/],
                         ['fetch o XMLHttpRequest (red)', /\bfetch\s*\(|XMLHttpRequest|WebSocket/], ['scripts de fuera', /<script[^>]+src=["']https?:/i], ['console.log', /console\.log/]])
  check(!re.test(texto), 'en el código de la extensión no hay ' + que);
check(archivos.every(f => existsSync(join(EXT, f))) && ['fondo.js', 'nucleo.js', 'rellenar.js', 'ventana.html', 'ventana.js'].every(f => archivos.includes(f)), 'están los cinco archivos');

// ------------------------------------------------------------------------------------------------
if (process.argv.includes('--sin-navegador')) {
  console.log('4. (saltado: --sin-navegador)');
} else {
  console.log('4. rellenar.js en un Edge REAL sin ventana (perfil temporal propio, https en 127.0.0.1)');
  const edge = ['C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Microsoft/Edge/Application/msedge.exe'].find(existsSync);
  if (!edge) check(false, 'no se encontró Edge');
  else {
    const tmp = mkdtempSync(join(tmpdir(), 'nexo-ext-'));
    try {
      const pfx = join(tmp, 'c.pfx');
      const ps = "$r=[Security.Cryptography.RSA]::Create(2048);$q=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=127.0.0.1',$r,'SHA256',[Security.Cryptography.RSASignaturePadding]::Pkcs1);"
        + "$s=[Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new();$s.AddIpAddress([Net.IPAddress]::Parse('127.0.0.1'));$q.CertificateExtensions.Add($s.Build());"
        + "$c=$q.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1),[DateTimeOffset]::Now.AddDays(1));[IO.File]::WriteAllBytes($env:NEXO_PFX,$c.Export('Pfx','x'))";
      const g = spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command', ps], { env: { ...process.env, NEXO_PFX: pfx }, encoding: 'utf8' });
      if (g.status !== 0 || !existsSync(pfx)) throw new Error('no se pudo crear el certificado de prueba: ' + g.stderr);
      const servir = { '/pruebas.html': [join(AQUI, 'pagina-de-pruebas.html'), 'text/html'], '/rellenar.js': [join(EXT, 'rellenar.js'), 'text/javascript'] };
      const srv = createServer({ pfx: readFileSync(pfx), passphrase: 'x' }, (req, res) => {
        const a = servir[req.url];
        if (!a) { res.writeHead(404); res.end(); return; }
        res.writeHead(200, { 'Content-Type': a[1] + '; charset=utf-8' });
        res.end(readFileSync(a[0]));
      });
      await new Promise(r => srv.listen(0, '127.0.0.1', r));
      const url = 'https://127.0.0.1:' + srv.address().port + '/pruebas.html';
      const salida = await new Promise((resolver) => {
        const p = spawn(edge, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--disable-extensions',
                               '--user-data-dir=' + join(tmp, 'perfil'), '--ignore-certificate-errors', '--virtual-time-budget=5000', '--dump-dom', url]);
        let o = '';
        p.stdout.on('data', d => { o += d; });
        const t = setTimeout(() => { p.kill(); }, 90000);
        p.on('close', () => { clearTimeout(t); resolver(o); });
      });
      srv.close();
      const m = /RESULTADOS:(.*?)<\/pre>/s.exec(salida);
      if (!m) check(false, 'Edge devolvió la página con los resultados', salida.slice(0, 400));
      else {
        const res = JSON.parse(m[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&'));
        for (const r of res) check(r.ok, r.n, r.detalle);
        check(res.length === 18, 'se ejecutaron los 18 casos', String(res.length));
      }
      await cargarLaExtension(edge, tmp);
    } catch (e) {
      check(false, 'la prueba con Edge no pudo correr', String(e && e.message));
    } finally {
      for (let i = 0; i < 5; i++) { try { rmSync(tmp, { recursive: true, force: true }); break; } catch { await new Promise(r => setTimeout(r, 500)); } }
    }
  }
}

/**
 * 5. La extensión cargada «sin empaquetar» en Edge real (perfil temporal, SIN host registrado: no se toca el registro). Se abre su
 * ventanita por el protocolo de depuración y se espera a que diga algo: tiene que ser «no está instalado», no «Consultando…» ni «ok».
 */
async function cargarLaExtension(edge, tmp) {
  console.log('5. La extensión cargada en Edge real (con o sin el host de Nexo registrado en este equipo)');
  const dormir = (ms) => new Promise(r => setTimeout(r, ms));
  const perfil = join(tmp, 'perfil-ext');
  const p = spawn(edge, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--user-data-dir=' + perfil,
                         '--load-extension=' + EXT, '--disable-extensions-except=' + EXT, '--remote-debugging-port=0', 'about:blank']);
  try {
    let puerto = null;
    for (let i = 0; i < 100 && !puerto; i++) {
      await dormir(200);
      try { puerto = readFileSync(join(perfil, 'DevToolsActivePort'), 'utf8').split('\n')[0].trim(); } catch { /* aún no */ }
    }
    if (!puerto) { check(false, 'Edge abrió el puerto de depuración'); return; }
    const pestana = await (await fetch('http://127.0.0.1:' + puerto + '/json/new?chrome-extension://' + ID + '/ventana.html', { method: 'PUT' })).json();
    const ws = new WebSocket(pestana.webSocketDebuggerUrl);
    await new Promise((r, f) => { ws.onopen = r; ws.onerror = f; });
    let n = 0;
    const evaluar = (expr) => new Promise((resolver) => {
      const id = ++n;
      const h = (ev) => { const m = JSON.parse(ev.data); if (m.id === id) { ws.removeEventListener('message', h); resolver(m.result && m.result.result && m.result.result.value); } };
      ws.addEventListener('message', h);
      ws.send(JSON.stringify({ id, method: 'Runtime.evaluate', params: { expression: expr, returnByValue: true } }));
    });
    let texto = null;
    for (let i = 0; i < 75; i++) {
      texto = await evaluar("document.getElementById('estado') && document.getElementById('estado').textContent");
      if (texto && !texto.startsWith('Consultando')) break;
      await dormir(200);
    }
    const datos = await evaluar("JSON.stringify({ id: chrome.runtime.id, permisos: chrome.runtime.getManifest().permissions, clase: document.getElementById('estado').className, botones: [...document.querySelectorAll('#contenido button')].map(b => b.textContent) })");
    ws.close();
    const d = JSON.parse(datos || '{}');
    check(d.id === ID, 'Edge la carga con el ID fijo (el «key» funciona)', d.id);
    // Lo que debe decir depende de este equipo: si el host de Nexo está registrado (Edge mira su clave y después la de Chrome) y no hay
    // ninguna ventana de Nexo abierta, «Nexo no está abierto» (prueba Edge → host → canal); sin registrar, «no está instalado».
    const registrado = ['HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.nexo.autocompletado', 'HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.nexo.autocompletado']
      .some(k => spawnSync('reg', ['query', k, '/ve'], { encoding: 'utf8' }).status === 0);
    const ventanaAbierta = /nexo-desktop\.exe/i.test(spawnSync('tasklist', ['/FI', 'IMAGENAME eq nexo-desktop.exe'], { encoding: 'utf8' }).stdout || '');
    if (ventanaAbierta) {
      console.log('           (hay una ventana de Nexo abierta: no se comprueba qué dice la ventanita, porque dependería de esa ventana)');
    } else if (registrado) {
      check(/Nexo no está abierto/.test(texto || '') && d.clase === 'aviso',
        'host REGISTRADO y Nexo cerrado: la ventanita dice «Nexo no está abierto» (Edge lanzó el host de verdad y el host contestó)', texto);
    } else {
      check(/no está instalado para este navegador/.test(texto || '') && d.clase === 'error',
        'sin host registrado, la ventanita lo dice en rojo («no está instalado…»): el service worker arrancó y native messaging contestó', texto);
    }
    check(Array.isArray(d.botones) && d.botones.includes('Volver a intentar') && !d.botones.some(b => /Emparejar/.test(b)) || ventanaAbierta,
      'ofrece «Volver a intentar» y NO ofrece emparejar con Nexo ausente', d.botones);
  } finally {
    p.kill();
    await dormir(1500);
  }
}

console.log();
console.log(fallos === 0 ? 'TODAS LAS VERIFICACIONES PASARON' : fallos + ' VERIFICACIONES FALLIDAS');
process.exit(fallos === 0 ? 0 : 1);
