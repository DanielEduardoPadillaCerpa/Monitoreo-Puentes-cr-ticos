const crypto = require('crypto');
const { anilloConfigurado, proteccionIdentificadoresDisponible } = require('./crypto');
const { claves } = require('./seguridad/cifradoCampos');

// Valores que delatan un secreto de ejemplo o escrito a mano.
const PATRON_EJEMPLO = /cambia|cambiar|replace_|change_?me|example|ejemplo|secreto|password|tu_clave|tu_c/i;

function secretoDebil(valor, minimo = 32) {
  return typeof valor !== 'string' || valor.length < minimo || PATRON_EJEMPLO.test(valor);
}

// JWT_SECRET sin valor por defecto conocido. Fuera de producción, si falta, se
// usa uno aleatorio por proceso (las sesiones se pierden al reiniciar).
let secretoEfimero = null;
function secretoJwt() {
  const valor = process.env.JWT_SECRET;
  if (valor) return valor;
  if (process.env.NODE_ENV === 'production') throw new Error('JWT_SECRET no está configurado.');
  if (!secretoEfimero) {
    secretoEfimero = crypto.randomBytes(48).toString('hex');
    console.warn('[config] JWT_SECRET no está definido: se usa un secreto temporal; las sesiones se perderán al reiniciar.');
  }
  return secretoEfimero;
}

// Comprobaciones de arranque. En producción, los secretos débiles impiden
// iniciar; fuera de producción solo se avisa (nunca se imprime el valor).
function validarConfiguracionSegura({ produccion = process.env.NODE_ENV === 'production' } = {}) {
  const errores = [];
  const avisos = [];
  const revisar = (variable, minimo = 32) => {
    if (secretoDebil(process.env[variable], minimo)) {
      (produccion ? errores : avisos).push(`${variable} falta, es corto o parece un valor de ejemplo.`);
    }
  };
  // Registro verificado: estas tres impiden arrancar en cualquier entorno.
  // Se generan con: node scripts/generar-claves.js --escribir
  if (secretoDebil(process.env.JWT_SECRET)) {
    errores.push('JWT_SECRET falta, tiene menos de 32 caracteres o parece un valor de ejemplo.');
  }
  try {
    claves();
  } catch (err) {
    errores.push(err.message);
  }
  revisar('MFA_TOKEN_PEPPER');
  if (process.env.CRYPTO_KEYS) {
    if (!anilloConfigurado()) errores.push('CRYPTO_KEYS o CRYPTO_KEY_ACTIVA no son válidos.');
  } else {
    avisos.push('CRYPTO_KEYS no está definido: los datos nuevos se cifran con la clave heredada CRYPTO_KEY.');
    revisar('CRYPTO_KEY');
  }
  if (!proteccionIdentificadoresDisponible()) {
    avisos.push('CRYPTO_KEYS o IDENT_HMAC_KEY no están configurados: la verificación de identidad en la compra queda deshabilitada.');
  }
  if (secretoDebil(process.env.N8N_W11_CALLBACK_SECRET)) {
    avisos.push('N8N_W11_CALLBACK_SECRET no está configurado: las respuestas de n8n sobre la entidad serán rechazadas.');
  }
  for (const aviso of avisos) console.warn(`[config] ${aviso}`);
  if (errores.length) {
    throw new Error(`Configuración insegura:\n - ${errores.join('\n - ')}`);
  }
  return { avisos };
}

module.exports = { secretoJwt, secretoDebil, validarConfiguracionSegura };
