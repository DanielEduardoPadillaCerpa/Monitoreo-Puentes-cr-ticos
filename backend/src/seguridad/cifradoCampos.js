const crypto = require('crypto');

// Cifrado por campo para el registro verificado (padrón y solicitudes).
//
// Formato: "v<versión>:<iv>:<tag>:<cifrado>" (base64url). El AAD es el nombre
// del campo: un valor cifrado como "nit" no descifra si se copia a la columna
// "nombre". La versión identifica la clave, de modo que rotar consiste en
// definir ENC_KEY nueva con ENC_KEY_VERSION=2 y conservar la anterior en
// ENC_KEY_V1 mientras queden datos cifrados con ella.
//
// ENC_KEY y HMAC_KEY son distintas (32 bytes en hex): comprometer una no
// compromete la otra. Viven solo en .env; nunca en la base, en n8n ni en el repo.

const ALGORITMO = 'aes-256-gcm';
const HEX_32 = /^[0-9a-f]{64}$/i;

function errorClave(mensaje, code = 'SEG_KEYS_INVALID') {
  return Object.assign(new Error(mensaje), { code });
}

let cache = null;
function claves() {
  const fuente = Object.keys(process.env)
    .filter(k => k === 'ENC_KEY' || k === 'ENC_KEY_VERSION' || k === 'HMAC_KEY' || /^ENC_KEY_V\d+$/.test(k))
    .sort()
    .map(k => `${k}=${process.env[k]}`)
    .join('|');
  if (cache && cache.fuente === fuente) return cache;

  const enc = process.env.ENC_KEY || '';
  const hmac = process.env.HMAC_KEY || '';
  if (!HEX_32.test(enc)) throw errorClave('ENC_KEY debe tener 32 bytes en hexadecimal (64 caracteres).');
  if (!HEX_32.test(hmac)) throw errorClave('HMAC_KEY debe tener 32 bytes en hexadecimal (64 caracteres).');
  if (enc.toLowerCase() === hmac.toLowerCase()) throw errorClave('ENC_KEY y HMAC_KEY deben ser distintas.');

  const version = Number(process.env.ENC_KEY_VERSION || 1);
  if (!Number.isSafeInteger(version) || version < 1 || version > 999) throw errorClave('ENC_KEY_VERSION no es válida.');
  const porVersion = new Map([[version, Buffer.from(enc, 'hex')]]);
  for (const [k, v] of Object.entries(process.env)) {
    const m = /^ENC_KEY_V(\d+)$/.exec(k);
    if (!m || Number(m[1]) === version) continue;
    if (!HEX_32.test(v || '')) throw errorClave(`${k} debe tener 32 bytes en hexadecimal.`);
    porVersion.set(Number(m[1]), Buffer.from(v, 'hex'));
  }
  cache = { fuente, version, porVersion, hmac: Buffer.from(hmac, 'hex') };
  return cache;
}

function clavesConfiguradas() {
  try {
    claves();
    return true;
  } catch {
    return false;
  }
}

function cifrarCampo(campo, texto) {
  if (texto === null || texto === undefined) return null;
  const { version, porVersion } = claves();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITMO, porVersion.get(version), iv);
  cipher.setAAD(Buffer.from(campo, 'utf8'));
  const cifrado = Buffer.concat([cipher.update(String(texto), 'utf8'), cipher.final()]);
  return `v${version}:${iv.toString('base64url')}:${cipher.getAuthTag().toString('base64url')}:${cifrado.toString('base64url')}`;
}

function descifrarCampo(campo, valor) {
  if (valor === null || valor === undefined) return null;
  const partes = String(valor).split(':');
  const m = /^v(\d+)$/.exec(partes[0] || '');
  if (partes.length !== 4 || !m) throw errorClave('Valor cifrado con formato desconocido.', 'DECRYPT_FAILED');
  const clave = claves().porVersion.get(Number(m[1]));
  if (!clave) throw errorClave('No hay clave para esa versión.', 'DECRYPT_FAILED');
  try {
    const decipher = crypto.createDecipheriv(ALGORITMO, clave, Buffer.from(partes[1], 'base64url'));
    decipher.setAAD(Buffer.from(campo, 'utf8'));
    decipher.setAuthTag(Buffer.from(partes[2], 'base64url'));
    return Buffer.concat([decipher.update(Buffer.from(partes[3], 'base64url')), decipher.final()]).toString('utf8');
  } catch {
    throw errorClave('El valor fue alterado o la clave no corresponde.', 'DECRYPT_FAILED');
  }
}

// Índice ciego: permite buscar por igualdad (WHERE nit_hash = ?) sin guardar
// el valor. El prefijo separa dominios: el mismo número como "nit" y como otra
// cosa produce índices distintos.
function indiceCiego(dominio, valorNormalizado) {
  return crypto.createHmac('sha256', claves().hmac).update(`${dominio}:${valorNormalizado}`).digest('hex');
}

// Comparación en tiempo constante de dos textos de longitud arbitraria: se
// comparan sus HMAC (siempre 32 bytes), así la duración no depende de cuántos
// caracteres coinciden ni de la longitud.
function igualesTiempoConstante(a, b) {
  const k = claves().hmac;
  const ha = crypto.createHmac('sha256', k).update(`cmp:${a}`).digest();
  const hb = crypto.createHmac('sha256', k).update(`cmp:${b}`).digest();
  return crypto.timingSafeEqual(ha, hb);
}

module.exports = { cifrarCampo, descifrarCampo, indiceCiego, igualesTiempoConstante, clavesConfiguradas, claves };
