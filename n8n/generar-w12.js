#!/usr/bin/env node
// Genera n8n/workflows/W12-avisos-registro.json: recibe los avisos de
// solicitudes de registro del backend y verifica su firma.
//
// El backend solo envía { evento, solicitud_id, resultado } (nunca NIT, nombre,
// correo, hashes ni claves), con:
//   X-Timestamp: segundos Unix
//   X-Signature: hex(HMAC-SHA256(N8N_REGISTRO_SECRET, `${timestamp}.${evento}.${solicitud_id}`))
//
// Requisitos del contenedor de n8n (en n8n/.env):
//   NODE_FUNCTION_ALLOW_BUILTIN=crypto
//   N8N_BLOCK_ENV_ACCESS_IN_NODE=false
//   N8N_REGISTRO_SECRET=<el mismo valor que en backend/.env>
//
//   node n8n/generar-w12.js

const fs = require('fs');
const path = require('path');

// Código del nodo "Verificar firma". Se exporta para probarlo tal cual.
const codigoVerificar = `
const crypto = require('crypto');
const secreto = $env.N8N_REGISTRO_SECRET || '';
if (secreto.length < 32) throw new Error('N8N_REGISTRO_SECRET no está configurado');

const entrada = $input.first().json;
const cabeceras = entrada.headers || {};
const cuerpo = entrada.body || {};
const timestamp = String(cabeceras['x-timestamp'] || '');
const firma = String(cabeceras['x-signature'] || '');

// 1. Ventana de 5 minutos contra repeticiones.
const ahora = Math.floor(Date.now() / 1000);
if (!/^\\d{9,11}$/.test(timestamp) || Math.abs(ahora - Number(timestamp)) > 300) {
  throw new Error('Aviso vencido o sin marca de tiempo');
}

// 2. Forma exacta del cuerpo: solo estas tres claves.
const EVENTOS = ['registro.recibido', 'registro.aprobado', 'registro.rechazado'];
const claves = Object.keys(cuerpo).sort().join(',');
if (claves !== 'evento,resultado,solicitud_id' || !EVENTOS.includes(cuerpo.evento) ||
    !Number.isSafeInteger(cuerpo.solicitud_id) || typeof cuerpo.resultado !== 'string' || cuerpo.resultado.length > 40) {
  throw new Error('Cuerpo no permitido');
}

// 3. Firma HMAC en tiempo constante.
const esperada = crypto.createHmac('sha256', secreto)
  .update(timestamp + '.' + cuerpo.evento + '.' + cuerpo.solicitud_id)
  .digest('hex');
const a = Buffer.from(/^[a-f0-9]{64}$/.test(firma) ? firma : '0'.repeat(64), 'hex');
const b = Buffer.from(esperada, 'hex');
if (!crypto.timingSafeEqual(a, b)) throw new Error('Firma inválida');

return [{ json: { evento: cuerpo.evento, solicitud_id: cuerpo.solicitud_id, resultado: cuerpo.resultado } }];
`.trim();

const nodo = (id, nombre, tipo, version, posicion, parametros, extra = {}) => ({
  parameters: parametros, id: `5e9d2a40-0000-4000-8000-00000000000${id}`, name: nombre, type: tipo, typeVersion: version, position: posicion, ...extra
});

const workflow = {
  name: 'W12 - Avisos de solicitudes de registro',
  nodes: [
    nodo(1, 'Webhook W12 firmado', 'n8n-nodes-base.webhook', 2, [0, 0],
      { httpMethod: 'POST', path: 'registro-avisos', authentication: 'none', responseMode: 'responseNode', options: {} },
      { webhookId: 'registro-avisos' }),
    nodo(2, 'Verificar firma', 'n8n-nodes-base.code', 2, [260, 0], { jsCode: codigoVerificar }, { onError: 'continueErrorOutput' }),
    nodo(3, 'Responder recibido', 'n8n-nodes-base.respondToWebhook', 1.1, [520, -80],
      { respondWith: 'json', responseBody: '={"ok":true}', options: { responseCode: 200 } }),
    nodo(4, 'Responder rechazado', 'n8n-nodes-base.respondToWebhook', 1.1, [520, 80],
      { respondWith: 'json', responseBody: '={"ok":false}', options: { responseCode: 401 } })
  ],
  connections: {
    'Webhook W12 firmado': { main: [[{ node: 'Verificar firma', type: 'main', index: 0 }]] },
    'Verificar firma': { main: [
      [{ node: 'Responder recibido', type: 'main', index: 0 }],
      [{ node: 'Responder rechazado', type: 'main', index: 0 }]
    ] }
  },
  settings: {
    executionOrder: 'v1',
    saveDataSuccessExecution: 'none',
    saveDataErrorExecution: 'none',
    saveManualExecutions: false,
    saveExecutionProgress: false
  },
  active: false,
  versionId: '5e9d2a40-0000-4000-8000-000000000009',
  meta: { templateCredsSetupCompleted: false },
  tags: []
};

if (require.main === module) {
  const destino = path.join(__dirname, 'workflows', 'W12-avisos-registro.json');
  fs.writeFileSync(destino, `${JSON.stringify(workflow, null, 2)}\n`);
  console.log(`Generado: ${path.relative(process.cwd(), destino)}`);
}

module.exports = { codigoVerificar, workflow };
