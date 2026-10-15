const crypto = require('crypto');

// Avisos a n8n sobre solicitudes de registro. Solo viaja
// { evento, solicitud_id, resultado }: nunca NIT, nombre, correo, hashes ni
// claves. La firma HMAC-SHA256 cubre "timestamp.evento.solicitud_id" y va en
// las cabeceras X-Timestamp y X-Signature (ver docs/REGISTRO_VERIFICADO.md
// para el nodo Code de n8n que la verifica).
//
// El aviso nunca bloquea la respuesta: se lanza en segundo plano con un
// tiempo límite corto y cualquier fallo de n8n solo se registra.

const EVENTOS = new Set(['registro.recibido', 'registro.aprobado', 'registro.rechazado']);
const TIMEOUT_MS = 3000;

function firmar(secreto, timestamp, evento, solicitudId) {
  return crypto.createHmac('sha256', secreto).update(`${timestamp}.${evento}.${solicitudId}`).digest('hex');
}

function configuracion() {
  const url = process.env.N8N_REGISTRO_WEBHOOK_URL;
  const secreto = process.env.N8N_REGISTRO_SECRET;
  if (!url || !secreto || secreto.length < 32) return null;
  return { url, secreto };
}

async function enviarAviso(evento, solicitudId, resultado) {
  const conf = configuracion();
  if (!conf) return false;
  const timestamp = String(Math.floor(Date.now() / 1000));
  const controller = new AbortController();
  const temporizador = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const resp = await fetch(conf.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Timestamp': timestamp,
        'X-Signature': firmar(conf.secreto, timestamp, evento, solicitudId)
      },
      body: JSON.stringify({ evento, solicitud_id: solicitudId, resultado }),
      signal: controller.signal
    });
    if (!resp.ok) console.warn('[n8n] El aviso de registro fue rechazado:', resp.status);
    return resp.ok;
  } catch (err) {
    console.warn('[n8n] No se pudo entregar el aviso de registro:', err.name === 'AbortError' ? 'TIMEOUT' : (err.code || 'FETCH_FAILED'));
    return false;
  } finally {
    clearTimeout(temporizador);
  }
}

function avisarN8n(evento, solicitudId, resultado) {
  if (!EVENTOS.has(evento) || !Number.isSafeInteger(Number(solicitudId))) return;
  setImmediate(() => { enviarAviso(evento, Number(solicitudId), String(resultado)).catch(() => {}); });
}

module.exports = { avisarN8n, enviarAviso, firmar };
