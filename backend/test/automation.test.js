const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { firmarPayload, verificarPayload } = require('../src/automationSignatures');
const { requiereTokenAutomatizacion } = require('../src/automationAuth');

const secreto = 'test-only-automation-secret-32-characters';

test('automation signatures verify payload, timestamp, and tampering', () => {
  const payload = {
    evento: 'pago',
    pedido_id: 42,
    estado: 'aprobado',
    total: '12345',
    moneda: 'COP',
    fecha: '2026-10-08T12:00:00.000Z'
  };
  const ahora = Date.now();
  const firmado = firmarPayload(payload, secreto, ahora);
  const headers = {
    'x-automation-timestamp': firmado.timestamp,
    'x-automation-signature': firmado.firma
  };

  assert.equal(verificarPayload(payload, headers, secreto, ahora), true);
  assert.equal(verificarPayload({ ...payload, total: '1' }, headers, secreto, ahora), false);
  assert.equal(verificarPayload(payload, headers, secreto, ahora + 6 * 60 * 1000), false);
});

test('n8n workflow exports are valid JSON and Code nodes parse', () => {
  const directory = path.join(__dirname, '..', '..', 'n8n', 'workflows');
  const archivos = fs.readdirSync(directory).filter(nombre => nombre.endsWith('.json'));
  assert.equal(archivos.length, 12);
  assert.ok(archivos.includes('W11-verificacion-compra.json'));
  assert.ok(archivos.includes('W12-avisos-registro.json'));
  assert.ok(archivos.includes('W6-asistente-escalado.json'));
  assert.ok(archivos.includes('W7-resumen-preguntas-asistente.json'));
  assert.ok(archivos.includes('W8-notificaciones-cuenta.json'));
  assert.ok(archivos.includes('W9-comprobantes-email.json'));
  assert.ok(archivos.includes('W10-contexto-institucional.json'));

  for (const archivo of archivos) {
    const workflow = JSON.parse(fs.readFileSync(path.join(directory, archivo), 'utf8'));
    assert.equal(workflow.active, false);
    for (const nodo of workflow.nodes.filter(item => item.type === 'n8n-nodes-base.code')) {
      new Function(nodo.parameters.jsCode);
    }
  }
});

test('W8 valida la firma y permite solo los tres eventos de cuenta', () => {
  const directory = path.join(__dirname, '..', '..', 'n8n', 'workflows');
  const workflow = JSON.parse(fs.readFileSync(path.join(directory, 'W8-notificaciones-cuenta.json'), 'utf8'));
  const code = workflow.nodes.find(node => node.name === 'Validar firma y preparar aviso').parameters.jsCode;
  const ejecutar = new Function('require', '$input', 'process', '$env', code);
  const ambiente = {
    env: {
      N8N_W8_ACCOUNT_SECRET: secreto,
      MFA_FROM_EMAIL: 'seguridad@example.test',
      ADMIN_ALERT_FROM: 'administracion@example.test',
      ADMIN_ALERT_TO: 'admin@example.test'
    }
  };
  const ejecutarFirmado = (payload, bodyAsObject = false) => {
    const firmado = firmarPayload(payload, secreto);
    return ejecutar(require, {
      first: () => ({
        json: {
          body: bodyAsObject ? JSON.parse(firmado.cuerpo) : firmado.cuerpo,
          headers: {
            'x-automation-timestamp': firmado.timestamp,
            'x-automation-signature': firmado.firma
          }
        }
      })
    }, { env: {} }, ambiente.env)[0].json;
  };

  const ahora = new Date().toISOString();
  const mfa = ejecutarFirmado({
    evento: 'mfa.email.change.code',
    email: 'nuevo@example.test',
    token_mfa: '123456',
    timestamp: ahora,
    vigencia_segundos: 300
  }, true);
  assert.equal(mfa.to, 'nuevo@example.test');
  assert.match(mfa.html, /123456/);

  const aviso = ejecutarFirmado({
    evento: 'security.notice',
    email: 'anterior@example.test',
    tipo: 'correo_cambiado',
    timestamp: ahora
  });
  assert.equal(aviso.to, 'anterior@example.test');

  const solicitud = ejecutarFirmado({
    evento: 'admin.solicitud_cuenta',
    solicitud_id: 81,
    tipo: 'correccion',
    timestamp: ahora
  });
  assert.equal(solicitud.to, 'admin@example.test');
  assert.match(solicitud.html, /81/);
  assert.doesNotMatch(solicitud.html, /correo|nit|detalle personal/i);

  assert.throws(() => ejecutarFirmado({
    evento: 'admin.solicitud_cuenta',
    solicitud_id: 81,
    tipo: 'correccion',
    timestamp: ahora,
    email: 'no-permitido@example.test'
  }), /Invalid account request event/);
});

test('automation endpoints require their own configured token', () => {
  const variable = 'TEST_AUTOMATION_TOKEN';
  const previous = process.env[variable];
  process.env[variable] = secreto;
  let nextCalled = false;
  const middleware = requiereTokenAutomatizacion(variable);

  middleware(
    { get: () => secreto },
    { status() { return this; }, json() { throw new Error('Unexpected authorization rejection'); } },
    () => { nextCalled = true; }
  );
  assert.equal(nextCalled, true);

  let statusCode;
  let errorBody;
  middleware(
    { get: () => 'incorrect-token' },
    {
      status(code) { statusCode = code; return this; },
      json(body) { errorBody = body; }
    },
    () => { throw new Error('Invalid token was accepted'); }
  );
  assert.equal(statusCode, 401);
  assert.deepEqual(errorBody, { error: 'No autorizado.' });

  if (previous === undefined) delete process.env[variable];
  else process.env[variable] = previous;
});
