const nodemailer = require('nodemailer');

// Envío de correo con SMTP configurable (SMTP_HOST, SMTP_PORT, SMTP_SECURE,
// SMTP_USER, SMTP_PASSWORD, SMTP_FROM). Opciones gratuitas: Mailpit en Docker
// para laboratorio (http://localhost:8025) o una cuenta de correo con
// contraseña de aplicación.
//
// Laboratorio sin SMTP (o con el SMTP local apagado): el mensaje se imprime en
// la consola del servidor para poder probar el flujo completo. En producción
// sin SMTP es un error y nunca se imprime nada.

let transporte = null;
let firmaTransporte = '';

function produccion() {
  return process.env.NODE_ENV === 'production';
}

function obtenerTransporte() {
  const host = process.env.SMTP_HOST;
  if (!host) return null;
  const firma = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_SECURE', 'SMTP_USER', 'SMTP_PASSWORD'].map(k => process.env[k] || '').join('|');
  if (transporte && firma === firmaTransporte) return transporte;
  transporte = nodemailer.createTransport({
    host,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === 'true',
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD || '' } : undefined,
    connectionTimeout: 5000,
    greetingTimeout: 5000,
    socketTimeout: 10000
  });
  firmaTransporte = firma;
  return transporte;
}

function validarConfiguracionCorreo() {
  if (produccion() && !process.env.SMTP_HOST) {
    throw Object.assign(new Error('SMTP_HOST es obligatorio en producción.'), { code: 'SMTP_NOT_CONFIGURED' });
  }
}

function imprimirEnConsola({ to, subject, text }) {
  console.log([
    '',
    '──────── [correo-laboratorio] (sin SMTP disponible; no ocurre en producción) ────────',
    `Para:   ${to}`,
    `Asunto: ${subject}`,
    '',
    text,
    '──────────────────────────────────────────────────────────────────────────────────',
    ''
  ].join('\n'));
}

async function enviarCorreo({ to, subject, text, html }) {
  validarConfiguracionCorreo();
  const t = obtenerTransporte();
  if (!t) {
    imprimirEnConsola({ to, subject, text });
    return { via: 'consola' };
  }
  try {
    await t.sendMail({
      from: process.env.SMTP_FROM || 'Suministros Institucionales <no-reply@localhost>',
      to,
      subject,
      text,
      html
    });
    return { via: 'smtp' };
  } catch (err) {
    if (produccion()) {
      throw Object.assign(new Error('EMAIL_DELIVERY_FAILED'), { code: 'EMAIL_DELIVERY_FAILED' });
    }
    console.warn('[correo] El SMTP de laboratorio no respondió:', err.code || 'SMTP_ERROR');
    imprimirEnConsola({ to, subject, text });
    return { via: 'consola' };
  }
}

// Envío que nunca bloquea ni falla la petición que lo origina.
function enviarCorreoEnSegundoPlano(mensaje) {
  setImmediate(() => {
    enviarCorreo(mensaje).catch(err => console.error('[correo] No se pudo enviar:', err.code || 'EMAIL_DELIVERY_FAILED'));
  });
}

const escaparHtml = texto => String(texto).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

module.exports = { enviarCorreo, enviarCorreoEnSegundoPlano, validarConfiguracionCorreo, escaparHtml };
