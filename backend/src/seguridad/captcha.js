const crypto = require('crypto');

// Captcha propio, sin servicios externos ni costo: una suma sencilla dibujada
// como SVG con ruido. Cada reto vale 5 minutos y se consume en el primer
// intento (acierte o no). Los retos viven en memoria del proceso, suficiente
// para el laboratorio (un solo proceso). En producción conviene un captcha
// gestionado (p. ej. Cloudflare Turnstile, que también es gratuito) o un
// almacén compartido si hay varias instancias.

const VIGENCIA_MS = 5 * 60 * 1000;
const MAXIMO_RETOS = 5000;
const retos = new Map();

function purgar(ahora = Date.now()) {
  for (const [id, reto] of retos) {
    if (reto.expira <= ahora) retos.delete(id);
  }
  // Si aún se excede (inundación), se descartan los más antiguos.
  while (retos.size >= MAXIMO_RETOS) retos.delete(retos.keys().next().value);
}

const azar = (min, max) => crypto.randomInt(min, max + 1);

// Las cifras se dibujan como trazos (no como <text>): un bot no puede leer el
// resultado del SVG; tendría que reconocer la imagen. Cada trazo se deforma al
// azar para que dos retos con la misma operación no produzcan el mismo SVG.
const P = { a: [0, 0], b: [1, 0], c: [1, 0.5], d: [1, 1], e: [0, 1], f: [0, 0.5] };
const SEG = { t: ['a', 'b'], ur: ['b', 'c'], lr: ['c', 'd'], bo: ['d', 'e'], ll: ['e', 'f'], ul: ['f', 'a'], m: ['f', 'c'] };
const GLIFOS = {
  0: ['t', 'ur', 'lr', 'bo', 'll', 'ul'], 1: ['ur', 'lr'], 2: ['t', 'ur', 'm', 'll', 'bo'],
  3: ['t', 'ur', 'm', 'lr', 'bo'], 4: ['ul', 'm', 'ur', 'lr'], 5: ['t', 'ul', 'm', 'lr', 'bo'],
  6: ['t', 'ul', 'm', 'lr', 'bo', 'll'], 7: ['t', 'ur', 'lr'], 8: Object.keys(SEG), 9: ['t', 'ul', 'ur', 'm', 'lr', 'bo']
};
const SIMBOLOS = {
  '+': [[[0.5, 0.2], [0.5, 0.8]], [[0.15, 0.5], [0.85, 0.5]]],
  '=': [[[0.15, 0.35], [0.85, 0.35]], [[0.15, 0.65], [0.85, 0.65]]]
};
const ruido = escala => (crypto.randomInt(0, 2001) / 1000 - 1) * escala;

function trazosDe(caracter) {
  if (SIMBOLOS[caracter]) return SIMBOLOS[caracter];
  return GLIFOS[caracter].map(s => SEG[s].map(p => P[p]));
}

function dibujarCaracter(caracter, x0, y0) {
  const ancho = azar(12, 15);
  const alto = azar(24, 28);
  const giro = ruido(0.3);
  const [cx, cy] = [x0 + ancho / 2, y0 + alto / 2];
  const transformar = ([u, v]) => {
    const x = x0 + (u + ruido(0.07)) * ancho - cx;
    const y = y0 + (v + ruido(0.05)) * alto - cy;
    return [cx + x * Math.cos(giro) - y * Math.sin(giro), cy + x * Math.sin(giro) + y * Math.cos(giro)];
  };
  const color = `hsl(${azar(200, 225)},60%,${azar(18, 30)}%)`;
  return trazosDe(caracter).map(([p1, p2]) => {
    const [x1, y1] = transformar(p1);
    const [x2, y2] = transformar(p2);
    const [qx, qy] = [(x1 + x2) / 2 + ruido(3), (y1 + y2) / 2 + ruido(3)];
    return `<path d="M${x1.toFixed(1)} ${y1.toFixed(1)}Q${qx.toFixed(1)} ${qy.toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}" stroke="${color}" stroke-width="3.2" stroke-linecap="round" fill="none"/>`;
  }).join('');
}

function dibujar(texto) {
  const ancho = 170;
  const alto = 56;
  const partes = [];
  for (let i = 0; i < 7; i += 1) {
    partes.push(`<path d="M${azar(0, ancho)} ${azar(0, alto)}Q${azar(0, ancho)} ${azar(0, alto)} ${azar(0, ancho)} ${azar(0, alto)}" stroke="hsl(${azar(190, 230)},35%,${azar(60, 78)}%)" stroke-width="${azar(1, 2)}" fill="none"/>`);
  }
  for (let i = 0; i < 30; i += 1) {
    partes.push(`<circle cx="${azar(0, ancho)}" cy="${azar(0, alto)}" r="1" fill="hsl(${azar(180, 240)},30%,60%)"/>`);
  }
  // Los trazos se mezclan en orden aleatorio para que el orden del SVG no
  // revele qué trazos forman cada cifra.
  const trazos = [];
  let x = 12;
  for (const caracter of texto) {
    if (caracter === ' ') { x += 6; continue; }
    trazos.push(...dibujarCaracter(caracter, x, azar(12, 18)).split('/>').filter(Boolean).map(t => `${t}/>`));
    x += azar(20, 24);
  }
  for (let i = trazos.length - 1; i > 0; i -= 1) {
    const j = crypto.randomInt(0, i + 1);
    [trazos[i], trazos[j]] = [trazos[j], trazos[i]];
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${ancho}" height="${alto}" viewBox="0 0 ${ancho} ${alto}"><rect width="100%" height="100%" fill="#f1f5f9"/>${partes.join('')}${trazos.join('')}</svg>`;
}

// Uso interno y en pruebas: devuelve también la respuesta. La ruta HTTP solo
// expone { id, svg }.
function crearReto() {
  purgar();
  const a = azar(2, 19);
  const b = azar(2, 9);
  const id = crypto.randomBytes(16).toString('hex');
  retos.set(id, { respuesta: String(a + b), expira: Date.now() + VIGENCIA_MS });
  return { id, svg: dibujar(`${a} + ${b} =`), respuesta: String(a + b) };
}

// true solo si el reto existe, no venció y la respuesta coincide. El reto se
// elimina en cualquier caso: no admite un segundo intento.
function verificarCaptcha(id, respuesta) {
  if (typeof id !== 'string' || !/^[a-f0-9]{32}$/.test(id)) return false;
  const reto = retos.get(id);
  if (!reto) return false;
  retos.delete(id);
  if (reto.expira <= Date.now()) return false;
  const dada = Buffer.from(String(respuesta ?? '').trim().slice(0, 4).padEnd(4, ' '));
  const esperada = Buffer.from(reto.respuesta.padEnd(4, ' '));
  return crypto.timingSafeEqual(dada, esperada);
}

module.exports = { crearReto, verificarCaptcha };
