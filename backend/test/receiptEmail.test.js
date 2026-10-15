const test = require('node:test');
const assert = require('node:assert/strict');
const nodemailer = require('nodemailer');

// Los comprobantes salen por SMTP directo (nodemailer). El correo del cliente
// y el enlace firmado nunca pasan por n8n.
const enviados = [];
nodemailer.createTransport = () => ({ sendMail: async mensaje => { enviados.push(mensaje); } });
const { enviarEnlaceComprobanteCliente } = require('../src/email');

const variables = ['SMTP_HOST', 'SMTP_FROM', 'RECEIPT_LINK_BASE_URL', 'NODE_ENV'];

function guardarEntorno(t) {
  const anteriores = Object.fromEntries(variables.map(nombre => [nombre, process.env[nombre]]));
  t.after(() => {
    for (const [nombre, valor] of Object.entries(anteriores)) {
      if (valor === undefined) delete process.env[nombre];
      else process.env[nombre] = valor;
    }
  });
}

test('el comprobante se envía por SMTP directo y nunca por un webhook', async t => {
  guardarEntorno(t);
  process.env.SMTP_HOST = 'smtp.prueba.local';
  process.env.SMTP_FROM = 'Suministros <no-reply@prueba.local>';
  process.env.RECEIPT_LINK_BASE_URL = 'http://localhost:8081';
  const fetchAnterior = global.fetch;
  let llamadasFetch = 0;
  global.fetch = async () => { llamadasFetch += 1; return { ok: true }; };
  t.after(() => { global.fetch = fetchAnterior; });
  enviados.length = 0;

  await enviarEnlaceComprobanteCliente({ correo: 'cliente@example.com', pedidoId: 15, numero: 'CMP-15', token: 'a'.repeat(64) });

  assert.equal(llamadasFetch, 0);
  assert.equal(enviados.length, 1);
  assert.equal(enviados[0].to, 'cliente@example.com');
  assert.match(enviados[0].text, /http:\/\/localhost:8081\/api\/comprobantes\/15\?token=a{64}/);
  assert.match(enviados[0].subject, /CMP-15/);
});

test('el enlace del comprobante exige una URL base válida', async t => {
  guardarEntorno(t);
  process.env.SMTP_HOST = 'smtp.prueba.local';
  process.env.RECEIPT_LINK_BASE_URL = 'ftp://example.com';
  await assert.rejects(
    enviarEnlaceComprobanteCliente({ correo: 'cliente@example.com', pedidoId: 15, numero: 'CMP-15', token: 'a'.repeat(64) }),
    { code: 'RECEIPT_LINK_BASE_URL_INVALID' }
  );
});

test('en producción sin SMTP el envío falla en lugar de imprimirse', async t => {
  guardarEntorno(t);
  delete process.env.SMTP_HOST;
  process.env.NODE_ENV = 'production';
  process.env.RECEIPT_LINK_BASE_URL = 'https://tienda.example.com';
  await assert.rejects(
    enviarEnlaceComprobanteCliente({ correo: 'cliente@example.com', pedidoId: 15, numero: 'CMP-15', token: 'a'.repeat(64) }),
    { code: 'SMTP_NOT_CONFIGURED' }
  );
});
