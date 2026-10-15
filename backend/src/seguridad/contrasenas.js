const crypto = require('crypto');

// bcrypt nativo (hilos de libuv, no bloquea el event loop) con respaldo en
// bcryptjs. Los hash de ambos son compatibles entre sí.
let bcrypt;
try {
  bcrypt = require('bcrypt');
} catch {
  bcrypt = require('bcryptjs');
}

// Costo configurable: 10 en laboratorio (~40 ms), 12 recomendado en producción.
function costo() {
  const valor = Number(process.env.BCRYPT_COST || (process.env.NODE_ENV === 'production' ? 12 : 10));
  return Number.isSafeInteger(valor) && valor >= 4 && valor <= 15 ? valor : 10;
}

function hashContrasena(texto) {
  return bcrypt.hash(texto, costo());
}

// Hash de relleno: si el correo no existe se compara contra él, de modo que la
// respuesta tarda lo mismo y no revela qué correos tienen cuenta.
let relleno = null;
function hashRelleno() {
  if (!relleno) relleno = bcrypt.hash(crypto.randomBytes(24).toString('hex'), costo());
  return relleno;
}

async function compararContrasena(texto, hash) {
  const objetivo = hash || await hashRelleno();
  const coincide = await bcrypt.compare(String(texto), objetivo);
  return Boolean(hash) && coincide;
}

module.exports = { hashContrasena, compararContrasena, hashRelleno };
