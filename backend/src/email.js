const { enviarCorreo } = require('./seguridad/correo');

// Correos de comprobantes. Se envían por SMTP directo (nodemailer): el correo
// del cliente y el enlace firmado ya no pasan por n8n.

function errorConfiguracion(codigo) {
  const error = new Error(codigo);
  error.code = codigo;
  return error;
}

function esLocalhost(hostname) {
  return ['localhost', '127.0.0.1', '::1'].includes(hostname);
}

async function enviarMensaje({ to, subject, text, html }) {
  await enviarCorreo({ to, subject, text, html });
}

function obtenerBaseUrlComprobante() {
  const baseUrl = process.env.RECEIPT_LINK_BASE_URL;
  let url;
  try {
    url = new URL(baseUrl);
  } catch {
    throw errorConfiguracion('RECEIPT_LINK_BASE_URL_INVALID');
  }
  const localhost = esLocalhost(url.hostname);
  if ((url.protocol !== 'https:' && !(localhost && url.protocol === 'http:')) ||
      url.username || url.password) {
    throw errorConfiguracion('RECEIPT_LINK_BASE_URL_INVALID');
  }
  return url.toString().replace(/\/+$/, '');
}

async function enviarEnlaceComprobanteCliente({ correo, pedidoId, numero, token }) {
  const enlace = `${obtenerBaseUrlComprobante()}/api/comprobantes/${encodeURIComponent(pedidoId)}?token=${encodeURIComponent(token)}`;
  const enlaceHtml = enlace.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
  await enviarMensaje({
    to: correo,
    subject: `Comprobante de compra ${numero}`,
    text: `Tu comprobante está disponible en este enlace seguro, válido por 24 horas:\n${enlace}\n\nEste documento es un comprobante de compra y no una factura electrónica DIAN.`,
    html: `<p>Tu comprobante de compra <strong>${numero}</strong> está disponible en este <a href="${enlaceHtml}">enlace seguro</a>, válido por 24 horas.</p><p>Este documento es un comprobante de compra y no una factura electrónica DIAN.</p>`
  });
}

async function enviarAvisoComprobanteAdmin({ pedidoId, numero, totalCentavos, moneda, fecha }) {
  const destinatario = process.env.ADMIN_NOTIFICATION_EMAIL;
  if (!destinatario) {
    throw errorConfiguracion('ADMIN_NOTIFICATION_EMAIL_NOT_CONFIGURED');
  }
  const monto = BigInt(totalCentavos);
  const total = `${(monto / 100n).toString()}.${String(monto % 100n).padStart(2, '0')}`;
  await enviarMensaje({
    to: destinatario,
    subject: `Pago aprobado · Pedido #${pedidoId}`,
    text: [
      `Pedido: #${pedidoId}`,
      `Comprobante: ${numero}`,
      'Estado: aprobado',
      `Total: ${total} ${moneda}`,
      `Fecha: ${fecha}`
    ].join('\n'),
    html: `<p>Pago aprobado</p><ul><li>Pedido: #${Number(pedidoId)}</li><li>Comprobante: ${numero}</li><li>Total: ${total} ${moneda}</li><li>Fecha: ${fecha}</li></ul>`
  });
}

module.exports = {
  enviarEnlaceComprobanteCliente,
  enviarAvisoComprobanteAdmin
};
