// Registro verificado: cifrado, normalización, verificación contra el padrón,
// captcha, avisos a n8n y el flujo completo registro → aprobación → login MFA.
//
// El flujo HTTP corre contra una base simulada en memoria (sin MySQL) que
// reproduce únicamente las consultas de este flujo.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');

process.env.NODE_ENV = 'test';
process.env.ENC_KEY = crypto.randomBytes(32).toString('hex');
process.env.HMAC_KEY = crypto.randomBytes(32).toString('hex');
process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
process.env.MFA_TOKEN_PEPPER = crypto.randomBytes(32).toString('hex');
process.env.BCRYPT_COST = '4';
process.env.SMTP_HOST = 'smtp.prueba.local';
delete process.env.ENC_KEY_VERSION;

// ---------------------------------------------------------------------------
// Correo simulado (nodemailer) y base simulada, antes de cargar las rutas.
// ---------------------------------------------------------------------------
const nodemailer = require('nodemailer');
const correos = [];
nodemailer.createTransport = () => ({ sendMail: async m => { correos.push(m); } });

const bd = crearBaseSimulada();
require.cache[require.resolve('../src/db')] = {
  id: require.resolve('../src/db'),
  filename: require.resolve('../src/db'),
  loaded: true,
  exports: { pool: bd.pool, poolTransacciones: bd.poolTransacciones }
};

const { cifrarCampo, descifrarCampo, indiceCiego, igualesTiempoConstante } = require('../src/seguridad/cifradoCampos');
const { normalizarNit, normalizarNombre, nombreCompletoValido } = require('../src/seguridad/normalizacion');
const { verificarEnPadron } = require('../src/seguridad/padron');
const { crearReto, verificarCaptcha } = require('../src/seguridad/captcha');
const { enviarAviso, firmar } = require('../src/seguridad/avisosN8n');

const esperar = ms => new Promise(r => setTimeout(r, ms));

// ===========================================================================
// Cifrado por campo
// ===========================================================================
test('cifrado: formato v1:iv:tag:cifrado, IV aleatorio e ida y vuelta', () => {
  const a = cifrarCampo('solicitud.nit', '999000001');
  const b = cifrarCampo('solicitud.nit', '999000001');
  assert.match(a, /^v1:[\w-]{16}:[\w-]{22}:[\w-]+$/);
  assert.notEqual(a, b, 'el mismo texto debe producir cifrados distintos');
  assert.equal(descifrarCampo('solicitud.nit', a), '999000001');
  assert.ok(!a.includes('999000001'));
});

test('cifrado: el AAD (nombre del campo) impide mover un valor a otra columna', () => {
  const nit = cifrarCampo('solicitud.nit', '999000001');
  assert.throws(() => descifrarCampo('solicitud.nombre', nit), { code: 'DECRYPT_FAILED' });
});

test('cifrado: detecta alteraciones', () => {
  const partes = cifrarCampo('padron.nombre', 'JUAN PEREZ').split(':');
  const alterado = Buffer.from(partes[3], 'base64url');
  alterado[0] ^= 1;
  partes[3] = alterado.toString('base64url');
  assert.throws(() => descifrarCampo('padron.nombre', partes.join(':')), { code: 'DECRYPT_FAILED' });
  assert.throws(() => descifrarCampo('padron.nombre', 'texto plano'), { code: 'DECRYPT_FAILED' });
});

test('cifrado: rotación por versión (la clave anterior sigue descifrando)', () => {
  const claveV1 = process.env.ENC_KEY;
  const viejo = cifrarCampo('padron.nombre', 'ANA BELTRAN');
  process.env.ENC_KEY_V1 = claveV1;
  process.env.ENC_KEY = crypto.randomBytes(32).toString('hex');
  process.env.ENC_KEY_VERSION = '2';
  try {
    const nuevo = cifrarCampo('padron.nombre', 'ANA BELTRAN');
    assert.match(nuevo, /^v2:/);
    assert.equal(descifrarCampo('padron.nombre', viejo), 'ANA BELTRAN');
    assert.equal(descifrarCampo('padron.nombre', nuevo), 'ANA BELTRAN');
  } finally {
    process.env.ENC_KEY = claveV1;
    delete process.env.ENC_KEY_V1;
    delete process.env.ENC_KEY_VERSION;
  }
});

test('índice ciego: estable, separado por dominio y distinto de un SHA-256 simple', () => {
  assert.equal(indiceCiego('nit', '999000001'), indiceCiego('nit', '999000001'));
  assert.notEqual(indiceCiego('nit', '999000001'), indiceCiego('cedula', '999000001'));
  assert.notEqual(indiceCiego('nit', '999000001'), crypto.createHash('sha256').update('nit:999000001').digest('hex'));
  assert.match(indiceCiego('nit', '1'), /^[a-f0-9]{64}$/);
});

test('comparación en tiempo constante', () => {
  assert.equal(igualesTiempoConstante('JUAN PEREZ', 'JUAN PEREZ'), true);
  assert.equal(igualesTiempoConstante('JUAN PEREZ', 'JUAN PERES'), false);
  assert.equal(igualesTiempoConstante('A', 'A'.repeat(500)), false);
});

// ===========================================================================
// Normalización
// ===========================================================================
test('NIT: solo dígitos y sin dígito de verificación', () => {
  assert.equal(normalizarNit('999000001-2'), '999000001');
  assert.equal(normalizarNit('999.000.001-2'), '999000001');
  assert.equal(normalizarNit(' 999 000 001 '), '999000001');
  assert.equal(normalizarNit('999000001'), '999000001');
  for (const malo of ['', 'abc', '12345', '9990-00001', '999000001-2-3x', null, '1'.repeat(16)]) {
    assert.equal(normalizarNit(malo), null, `debe rechazar ${malo}`);
  }
});

test('nombre: sin tildes, mayúsculas, solo letras y palabras ordenadas', () => {
  const esperado = normalizarNombre('Juan Camilo Rodríguez');
  assert.equal(esperado, 'CAMILO JUAN RODRIGUEZ');
  assert.equal(normalizarNombre('rodriguez  JUAN-camilo'), esperado);
  assert.equal(normalizarNombre('Rodríguez, Juan Camilo.'), esperado);
  assert.equal(normalizarNombre('Ñoño Peña'), 'NONO PENA');
  assert.equal(nombreCompletoValido('Valentina Morales'), true);
  assert.equal(nombreCompletoValido('Valentina'), false);
  assert.equal(nombreCompletoValido('V M'), false);
  assert.equal(nombreCompletoValido('Valentina 123'), false);
});

// ===========================================================================
// Verificación contra el padrón
// ===========================================================================
test('padrón: NIT + nombre + institución', async () => {
  const casos = [
    [{ nit: '999000001-2', nombre: 'Juan Camilo Rodríguez', tipoInstitucion: 'policia' }, 'coincide'],
    [{ nit: '999000001', nombre: 'RODRIGUEZ JUAN CAMILO', tipoInstitucion: 'policia' }, 'coincide'],
    [{ nit: '999000001', nombre: 'Juan Rodríguez', tipoInstitucion: 'policia' }, 'nombre_no_coincide'],
    [{ nit: '999000001', nombre: 'Juan Camilo Rodríguez', tipoInstitucion: 'defensa' }, 'institucion_no_coincide'],
    [{ nit: '123456789', nombre: 'Juan Camilo Rodríguez', tipoInstitucion: 'policia' }, 'nit_no_existe'],
    [{ nit: 'xx', nombre: 'Juan Camilo Rodríguez', tipoInstitucion: 'policia' }, 'nit_no_existe'],
    [{ nit: '999000003', nombre: 'Persona Retirada', tipoInstitucion: 'bomberos' }, 'persona_inactiva']
  ];
  for (const [entrada, esperado] of casos) {
    const { resultado } = await verificarEnPadron(bd.pool, entrada);
    assert.equal(resultado, esperado, JSON.stringify(entrada));
  }
});

test('padrón: el detalle para el administrador trae el nombre del padrón descifrado', async () => {
  const { coincidencia } = await verificarEnPadron(bd.pool, { nit: '999000001', nombre: 'juan camilo rodriguez', tipoInstitucion: 'policia' }, { incluirDetalle: true });
  assert.equal(coincidencia.nombre, 'Juan Camilo Rodríguez');
  assert.equal(coincidencia.tipoInstitucion, 'policia');
  const sinDetalle = await verificarEnPadron(bd.pool, { nit: '999000001', nombre: 'juan camilo rodriguez', tipoInstitucion: 'policia' });
  assert.equal(sinDetalle.coincidencia, null);
});

test('padrón: una caída de la base se marca como padron_no_disponible', async () => {
  const caida = { query: async () => { throw Object.assign(new Error('x'), { code: 'ECONNRESET' }); } };
  const { resultado } = await verificarEnPadron(caida, { nit: '999000001', nombre: 'Juan Camilo Rodríguez', tipoInstitucion: 'policia' });
  assert.equal(resultado, 'padron_no_disponible');
});

// ===========================================================================
// Captcha
// ===========================================================================
test('captcha: un solo intento, respuesta correcta y vencimiento', () => {
  const reto = crearReto();
  assert.match(reto.svg, /^<svg/);
  assert.ok(!reto.svg.includes(`>${reto.respuesta}<`), 'el SVG no debe contener el resultado');
  assert.ok(!/<text/i.test(reto.svg), 'las cifras van como trazos, no como texto legible por un bot');
  assert.equal(verificarCaptcha(reto.id, reto.respuesta), true);
  assert.equal(verificarCaptcha(reto.id, reto.respuesta), false, 'no se puede reutilizar');
  const otro = crearReto();
  assert.equal(verificarCaptcha(otro.id, String(Number(otro.respuesta) + 1)), false);
  assert.equal(verificarCaptcha(otro.id, otro.respuesta), false, 'un error consume el reto');
  assert.equal(verificarCaptcha('no-es-un-id', '1'), false);
  assert.equal(verificarCaptcha(undefined, undefined), false);
});

// ===========================================================================
// Avisos a n8n
// ===========================================================================
test('n8n: solo viaja {evento, solicitud_id, resultado} con firma verificable', async t => {
  process.env.N8N_REGISTRO_WEBHOOK_URL = 'http://localhost:5678/webhook/registro';
  process.env.N8N_REGISTRO_SECRET = 'secreto-de-prueba-con-mas-de-32-caracteres';
  const fetchAnterior = global.fetch;
  let enviado;
  global.fetch = async (url, opciones) => { enviado = { url, opciones }; return { ok: true }; };
  t.after(() => {
    global.fetch = fetchAnterior;
    delete process.env.N8N_REGISTRO_WEBHOOK_URL;
    delete process.env.N8N_REGISTRO_SECRET;
  });

  assert.equal(await enviarAviso('registro.recibido', 41, 'nombre_no_coincide'), true);
  const cuerpo = JSON.parse(enviado.opciones.body);
  assert.deepEqual(Object.keys(cuerpo).sort(), ['evento', 'resultado', 'solicitud_id']);
  assert.deepEqual(cuerpo, { evento: 'registro.recibido', solicitud_id: 41, resultado: 'nombre_no_coincide' });
  const { 'X-Timestamp': ts, 'X-Signature': firma } = enviado.opciones.headers;
  assert.equal(firma, crypto.createHmac('sha256', process.env.N8N_REGISTRO_SECRET).update(`${ts}.registro.recibido.41`).digest('hex'));
  assert.equal(firma, firmar(process.env.N8N_REGISTRO_SECRET, ts, 'registro.recibido', 41));

  global.fetch = async () => { throw new Error('n8n caído'); };
  assert.equal(await enviarAviso('registro.recibido', 42, 'coincide'), false, 'un fallo de n8n no lanza');
});

test('n8n W12: el nodo Code acepta la firma del backend y rechaza alteraciones', () => {
  const { codigoVerificar } = require(path.join('..', '..', 'n8n', 'generar-w12.js'));
  const secreto = 'secreto-de-prueba-con-mas-de-32-caracteres';
  const ejecutar = (headers, body) => new Function('require', '$input', '$env', codigoVerificar)(
    require, { first: () => ({ json: { headers, body } }) }, { N8N_REGISTRO_SECRET: secreto }
  );
  const ts = String(Math.floor(Date.now() / 1000));
  const cuerpo = { evento: 'registro.aprobado', solicitud_id: 7, resultado: 'aprobada' };
  const headers = { 'x-timestamp': ts, 'x-signature': firmar(secreto, ts, cuerpo.evento, cuerpo.solicitud_id) };

  assert.deepEqual(ejecutar(headers, cuerpo)[0].json, cuerpo);
  assert.throws(() => ejecutar(headers, { ...cuerpo, solicitud_id: 8 }), /Firma inválida/);
  assert.throws(() => ejecutar({ ...headers, 'x-signature': 'f'.repeat(64) }, cuerpo), /Firma inválida/);
  assert.throws(() => ejecutar(headers, { ...cuerpo, nit: '999000001' }), /Cuerpo no permitido/);
  const viejo = String(Number(ts) - 600);
  assert.throws(() => ejecutar({ 'x-timestamp': viejo, 'x-signature': firmar(secreto, viejo, cuerpo.evento, 7) }, cuerpo), /vencido/);
});

// ===========================================================================
// Flujo HTTP: registro → aprobación del admin → login con MFA
// ===========================================================================
const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');

function crearAppPrueba() {
  const app = express();
  app.use(['/api/auth', '/api/admin/solicitudes'], express.json({ limit: '10kb' }));
  app.use('/api/auth', require('../src/routes/auth').router);
  app.use('/api/admin/solicitudes', require('../src/routes/solicitudesRegistro'));
  return app;
}

function captcha() {
  const { id, respuesta } = crearReto();
  return { captchaId: id, captchaRespuesta: respuesta };
}

function registro(cambios = {}) {
  return {
    tipoInstitucion: 'policia',
    nombreCompleto: 'Juan Camilo Rodríguez',
    nit: '999000001-2',
    correo: 'juan.rodriguez@prueba.test',
    password: 'ClaveSegura2026!',
    aceptaTerminos: true,
    aceptaTratamiento: true,
    ...captcha(),
    ...cambios
  };
}

async function codigoEnviadoA(correo) {
  for (let i = 0; i < 50; i += 1) {
    const mensaje = [...correos].reverse().find(m => m.to === correo && /código de acceso/i.test(m.subject));
    if (mensaje) return /(\d{6})/.exec(mensaje.text)[1];
    await esperar(10);
  }
  throw new Error('no llegó el código');
}

const tokenAdmin = () => jwt.sign({ uid: bd.adminId, rol: 'admin', mfa: true, sv: 0 }, process.env.JWT_SECRET);

test('flujo: registro → pendiente → aprobación → login con MFA', async () => {
  const app = crearAppPrueba();
  const admin = { Authorization: `Bearer ${tokenAdmin()}` };

  // 1. Registro: 202 genérico, sin datos en la respuesta.
  const r1 = await request(app).post('/api/auth/registro').send(registro());
  assert.equal(r1.status, 202);
  assert.equal(r1.body.estado, 'solicitud_recibida');
  const usuario = bd.usuarioPorCorreo('juan.rodriguez@prueba.test');
  assert.equal(usuario.estado_cuenta, 'pendiente');
  const solicitud = bd.solicitudDe(usuario.id);
  assert.equal(solicitud.resultado_verificacion, 'coincide');
  assert.ok(!solicitud.nit_cifrado.includes('999000001') && !solicitud.nombre_cifrado.includes('Juan'));

  // 2. Mismo correo otra vez: misma respuesta, no se crea nada nuevo.
  const totalAntes = bd.totalSolicitudes();
  const r2 = await request(app).post('/api/auth/registro').send(registro({ nit: '123456789' }));
  assert.equal(r2.status, 202);
  assert.deepEqual(r2.body, r1.body);
  assert.equal(bd.totalSolicitudes(), totalAntes);

  // 3. Login con la cuenta pendiente: contraseña errónea → 401 genérico;
  //    correcta → recién ahí se informa que está pendiente.
  const malo = await request(app).post('/api/auth/login').send({ correo: 'juan.rodriguez@prueba.test', password: 'otraClave12345', ...captcha() });
  assert.equal(malo.status, 401);
  const pendiente = await request(app).post('/api/auth/login').send({ correo: 'juan.rodriguez@prueba.test', password: 'ClaveSegura2026!', ...captcha() });
  assert.equal(pendiente.status, 403);
  assert.equal(pendiente.body.code, 'CUENTA_PENDIENTE');
  const inexistente = await request(app).post('/api/auth/login').send({ correo: 'nadie@prueba.test', password: 'ClaveSegura2026!', ...captcha() });
  assert.equal(inexistente.status, 401);
  assert.deepEqual(inexistente.body, malo.body);

  // 4. Panel: contador y lista sin NIT ni nombre.
  const contador = await request(app).get('/api/admin/solicitudes/contador').set(admin);
  assert.equal(contador.status, 200);
  assert.equal(contador.body.pendientes, 1);
  const lista = await request(app).get('/api/admin/solicitudes').set(admin);
  assert.equal(lista.status, 200);
  const texto = JSON.stringify(lista.body);
  assert.ok(!/999000001|Rodríguez|Camilo/i.test(texto), 'la lista no expone NIT ni nombre');
  assert.equal(lista.body.solicitudes[0].resultado, 'coincide');

  // 5. Detalle: descifrado en el servidor, con el padrón al lado.
  const detalle = await request(app).get(`/api/admin/solicitudes/${solicitud.id}`).set(admin);
  assert.equal(detalle.status, 200);
  assert.equal(detalle.body.declarado.nit, '999000001');
  assert.equal(detalle.body.padron.nombre, 'Juan Camilo Rodríguez');
  assert.equal(detalle.body.resultadoAhora, 'coincide');

  // 6. Aprobar (atómico) y un segundo intento → 409.
  const aprobada = await request(app).post(`/api/admin/solicitudes/${solicitud.id}/aprobar`).set(admin).send({});
  assert.equal(aprobada.status, 200);
  assert.equal(bd.usuarioPorCorreo('juan.rodriguez@prueba.test').estado_cuenta, 'activa');
  const otraVez = await request(app).post(`/api/admin/solicitudes/${solicitud.id}/aprobar`).set(admin).send({});
  assert.equal(otraVez.status, 409);
  assert.equal(otraVez.body.code, 'YA_DECIDIDA');
  await esperar(20);
  assert.ok(bd.auditoria.some(a => a.accion === 'aprobar_registro' && a.entidad_id === String(solicitud.id)));
  assert.ok(bd.auditoria.every(a => !/999000001|Rodr/i.test(JSON.stringify(a))), 'la auditoría no guarda datos sensibles');

  // 7. Login: paso 1 → 202 con reto; paso 2 con el código del correo → sesión.
  const paso1 = await request(app).post('/api/auth/login').send({ correo: 'juan.rodriguez@prueba.test', password: 'ClaveSegura2026!', ...captcha() });
  assert.equal(paso1.status, 202);
  assert.equal(paso1.body.mfaRequired, true);
  const codigo = await codigoEnviadoA('juan.rodriguez@prueba.test');
  assert.ok(bd.retoVigente(paso1.body.challengeId).codigo_hash !== codigo, 'solo se guarda el HMAC del código');
  const incorrecto = String((Number(codigo) + 1) % 1000000).padStart(6, '0');
  const fallo = await request(app).post('/api/auth/mfa/verificar').send({ challengeId: paso1.body.challengeId, code: incorrecto });
  assert.equal(fallo.status, 401);
  const paso2 = await request(app).post('/api/auth/mfa/verificar').send({ challengeId: paso1.body.challengeId, code: codigo });
  assert.equal(paso2.status, 200);
  const sesion = jwt.verify(paso2.body.token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
  assert.equal(sesion.mfa, true);
  assert.equal(sesion.exp - sesion.iat, 2 * 60 * 60, 'el JWT dura 2 horas');
  const reuso = await request(app).post('/api/auth/mfa/verificar').send({ challengeId: paso1.body.challengeId, code: codigo });
  assert.equal(reuso.status, 401, 'el código es de un solo uso');
});

test('flujo: una verificación que no coincide exige confirmación explícita; el rechazo lleva motivo', async () => {
  const app = crearAppPrueba();
  const admin = { Authorization: `Bearer ${tokenAdmin()}` };

  await request(app).post('/api/auth/registro').send(registro({ correo: 'laura@prueba.test', nombreCompleto: 'Laura Marcela Torres', nit: '999000002', tipoInstitucion: 'policia' }));
  const laura = bd.solicitudDe(bd.usuarioPorCorreo('laura@prueba.test').id);
  assert.equal(laura.resultado_verificacion, 'institucion_no_coincide');

  const sinConfirmar = await request(app).post(`/api/admin/solicitudes/${laura.id}/aprobar`).set(admin).send({});
  assert.equal(sinConfirmar.status, 409);
  assert.equal(sinConfirmar.body.code, 'CONFIRMACION_REQUERIDA');
  assert.equal(bd.usuarioPorCorreo('laura@prueba.test').estado_cuenta, 'pendiente');

  const sinMotivo = await request(app).post(`/api/admin/solicitudes/${laura.id}/rechazar`).set(admin).send({ motivo: '' });
  assert.equal(sinMotivo.status, 400);
  const rechazada = await request(app).post(`/api/admin/solicitudes/${laura.id}/rechazar`).set(admin).send({ motivo: 'La institución declarada no corresponde al padrón.' });
  assert.equal(rechazada.status, 200);

  const login = await request(app).post('/api/auth/login').send({ correo: 'laura@prueba.test', password: 'ClaveSegura2026!', ...captcha() });
  assert.equal(login.status, 403);
  assert.equal(login.body.code, 'CUENTA_RECHAZADA');

  // Con datos corregidos puede volver a solicitar.
  const nueva = await request(app).post('/api/auth/registro').send(registro({ correo: 'laura@prueba.test', nombreCompleto: 'Laura Marcela Torres', nit: '999000002', tipoInstitucion: 'defensa' }));
  assert.equal(nueva.status, 202);
  assert.equal(bd.usuarioPorCorreo('laura@prueba.test').estado_cuenta, 'pendiente');
  const reciente = bd.solicitudDe(bd.usuarioPorCorreo('laura@prueba.test').id);
  assert.equal(reciente.resultado_verificacion, 'coincide');

  const forzada = await request(app).post(`/api/admin/solicitudes/${reciente.id}/aprobar`).set(admin).send({});
  assert.equal(forzada.status, 200);
});

test('flujo: captcha, validación y acceso al panel', async () => {
  const app = crearAppPrueba();
  const sinCaptcha = await request(app).post('/api/auth/registro').send(registro({ captchaRespuesta: '999' }));
  assert.equal(sinCaptcha.status, 400);
  assert.equal(sinCaptcha.body.code, 'CAPTCHA_INVALIDO');

  const nombreCorto = await request(app).post('/api/auth/registro').send(registro({ correo: 'x@prueba.test', nombreCompleto: 'Juancho' }));
  assert.equal(nombreCorto.status, 400);
  assert.ok(nombreCorto.body.errores.nombreCompleto);
  const nitMalo = await request(app).post('/api/auth/registro').send(registro({ correo: 'x@prueba.test', nit: 'abc' }));
  assert.equal(nitMalo.status, 400);
  assert.ok(nitMalo.body.errores.nit);
  const rolInyectado = await request(app).post('/api/auth/registro').send(registro({ correo: 'x@prueba.test', rol: 'admin' }));
  assert.equal(rolInyectado.status, 400);

  const loginSinCaptcha = await request(app).post('/api/auth/login').send({ correo: 'juan.rodriguez@prueba.test', password: 'ClaveSegura2026!' });
  assert.equal(loginSinCaptcha.status, 400);

  const enorme = await request(app).post('/api/auth/login').set('Content-Type', 'application/json').send(JSON.stringify({ relleno: 'x'.repeat(11 * 1024) }));
  assert.equal(enorme.status, 413);

  // Panel: sin token, con token de cliente y con admin sin permiso.
  assert.equal((await request(app).get('/api/admin/solicitudes')).status, 401);
  const cliente = bd.usuarioPorCorreo('juan.rodriguez@prueba.test');
  const tokenCliente = jwt.sign({ uid: cliente.id, rol: 'admin', mfa: true, sv: 0 }, process.env.JWT_SECRET);
  assert.equal((await request(app).get('/api/admin/solicitudes').set('Authorization', `Bearer ${tokenCliente}`)).status, 403,
    'el rol se lee de la base, no del token');
  const tokenSinPermiso = jwt.sign({ uid: bd.adminSinPermisoId, rol: 'admin', mfa: true, sv: 0 }, process.env.JWT_SECRET);
  assert.equal((await request(app).get('/api/admin/solicitudes').set('Authorization', `Bearer ${tokenSinPermiso}`)).status, 403);
  const tokenSinMfa = jwt.sign({ uid: bd.adminId, rol: 'admin', sv: 0 }, process.env.JWT_SECRET);
  assert.equal((await request(app).get('/api/admin/solicitudes').set('Authorization', `Bearer ${tokenSinMfa}`)).status, 401);

  // Aprobar en un solo viaje: la autorización va dentro del UPDATE.
  await request(app).post('/api/auth/registro').send(registro({ correo: 'maria@prueba.test', nombreCompleto: 'María Fernanda López' }));
  const maria = bd.solicitudDe(bd.usuarioPorCorreo('maria@prueba.test').id);
  const sinPermiso = await request(app).post(`/api/admin/solicitudes/${maria.id}/aprobar`).set('Authorization', `Bearer ${tokenSinPermiso}`).send({});
  assert.equal(sinPermiso.status, 403);
  const tokenRevocado = jwt.sign({ uid: bd.adminId, rol: 'admin', mfa: true, sv: 7 }, process.env.JWT_SECRET);
  const revocado = await request(app).post(`/api/admin/solicitudes/${maria.id}/aprobar`).set('Authorization', `Bearer ${tokenRevocado}`).send({});
  assert.equal(revocado.status, 401);
  assert.equal(bd.usuarioPorCorreo('maria@prueba.test').estado_cuenta, 'pendiente', 'ningún intento no autorizado cambia la cuenta');
});

// ===========================================================================
// Base simulada en memoria (solo las consultas de este flujo)
// ===========================================================================
function crearBaseSimulada() {
  const usuarios = new Map();
  const solicitudes = new Map();
  const retos = new Map();
  const permisos = new Set();
  const auditoria = [];
  const padron = [];
  let secuencia = 100;
  const nuevoId = () => (secuencia += 1);

  const adminId = nuevoId();
  usuarios.set(adminId, { id: adminId, correo: 'admin@prueba.test', rol: 'admin', estado_cuenta: 'activa', session_version: 0, debe_cambiar_password: 0, es_superadmin: 0 });
  permisos.add(`${adminId}:clientes.gestionar`);
  const adminSinPermisoId = nuevoId();
  usuarios.set(adminSinPermisoId, { id: adminSinPermisoId, correo: 'otro@prueba.test', rol: 'admin', estado_cuenta: 'activa', session_version: 0, debe_cambiar_password: 0, es_superadmin: 0 });

  let padronCargado = false;
  function cargarPadron() {
    if (padronCargado) return;
    padronCargado = true;
    for (const [nit, nombre, tipo, estado] of [
      ['999000001', 'Juan Camilo Rodríguez', 'policia', 'activa'],
      ['999000001', 'María Fernanda López', 'policia', 'activa'],
      ['999000002', 'Laura Marcela Torres', 'defensa', 'activa'],
      ['999000003', 'Persona Retirada', 'bomberos', 'inactiva']
    ]) {
      padron.push({
        id: nuevoId(),
        nit_hash: indiceCiegoPerezoso('nit', nit),
        nombre_cifrado: cifrarPerezoso('padron.nombre', nombre),
        entidad_cifrada: cifrarPerezoso('padron.entidad', tipo.toUpperCase()),
        tipo_institucion: tipo,
        estado
      });
    }
  }
  const indiceCiegoPerezoso = (...a) => require('../src/seguridad/cifradoCampos').indiceCiego(...a);
  const cifrarPerezoso = (...a) => require('../src/seguridad/cifradoCampos').cifrarCampo(...a);

  const fila = (filas) => [filas, []];
  const ok = (extra = {}) => [{ affectedRows: 1, insertId: 0, ...extra }, []];

  async function query(sql, p = []) {
    const s = String(sql).replace(/\s+/g, ' ').trim();
    cargarPadron();
    if (/FROM padron_institucional WHERE nit_hash = \?/.test(s)) return fila(padron.filter(r => r.nit_hash === p[0]));
    if (/^SELECT id, cliente_id, estado_cuenta FROM usuarios WHERE correo = \?/.test(s)) {
      return fila([...usuarios.values()].filter(u => u.correo === p[0]));
    }
    if (/^SELECT id, correo, password_hash, estado_cuenta FROM usuarios WHERE correo = \?/.test(s)) {
      return fila([...usuarios.values()].filter(u => u.correo === p[0]));
    }
    if (/EXISTS \(SELECT 1 FROM staff_permisos/.test(s)) {
      const u = usuarios.get(Number(p[1]));
      return fila(u ? [{ ...u, tiene_permiso: permisos.has(`${u.id}:${p[0]}`) ? 1 : 0 }] : []);
    }
    if (/COUNT\(\*\) AS pendientes FROM solicitudes_registro/.test(s)) {
      return fila([{ pendientes: [...solicitudes.values()].filter(x => x.estado === 'pendiente').length }]);
    }
    if (/FROM solicitudes_registro s JOIN usuarios u ON u.id = s.usuario_id WHERE s.estado = \?/.test(s)) {
      return fila([...solicitudes.values()].filter(x => x.estado === p[0]).map(x => ({ ...x, correo: usuarios.get(x.usuario_id).correo })));
    }
    if (/s\.nit_cifrado, s\.nombre_cifrado.* WHERE s\.id = \?/.test(s)) {
      const x = solicitudes.get(Number(p[0]));
      return fila(x ? [{ ...x, correo: usuarios.get(x.usuario_id).correo, decidida_por_correo: null }] : []);
    }
    if (/^SELECT u.correo FROM solicitudes_registro s/.test(s)) {
      const x = solicitudes.get(Number(p[0]));
      return fila(x ? [{ correo: usuarios.get(x.usuario_id).correo }] : []);
    }
    if (/^SELECT estado, resultado_verificacion FROM solicitudes_registro WHERE id = \?/.test(s)) {
      const x = solicitudes.get(Number(p[0]));
      return fila(x ? [x] : []);
    }
    if (/SET s.estado = 'aprobada'/.test(s)) {
      const [adminUid, id, confirmar] = p;
      const x = solicitudes.get(Number(id));
      const u = x && usuarios.get(x.usuario_id);
      if (!x || x.estado !== 'pendiente' || u.estado_cuenta !== 'pendiente' || (x.resultado_verificacion !== 'coincide' && confirmar !== 1)) return ok({ affectedRows: 0 });
      Object.assign(x, { estado: 'aprobada', decidida_por: adminUid });
      u.estado_cuenta = 'activa';
      return ok({ affectedRows: 2 });
    }
    if (/SET s.estado = 'rechazada'/.test(s)) {
      const [motivo, adminUid, id] = p;
      const x = solicitudes.get(Number(id));
      const u = x && usuarios.get(x.usuario_id);
      if (!x || x.estado !== 'pendiente' || u.estado_cuenta !== 'pendiente') return ok({ affectedRows: 0 });
      Object.assign(x, { estado: 'rechazada', motivo_rechazo: motivo, decidida_por: adminUid });
      u.estado_cuenta = 'rechazada';
      return ok({ affectedRows: 2 });
    }
    if (/^INSERT INTO auditoria/.test(s)) {
      auditoria.push({ usuario_id: p[0], accion: p[2], entidad: p[3], entidad_id: p[4], detalle: p[5] });
      return ok();
    }
    // MFA paso 2
    if (/FROM retos_mfa r JOIN usuarios u ON u.id = r.usuario_id .* WHERE r.reto_id = \?/.test(s)) {
      const r = retos.get(p[0]);
      if (!r) return fila([]);
      const u = usuarios.get(r.usuario_id);
      return fila([{ ...r, vigente: r.expira > Date.now() ? 1 : 0, correo: u.correo, rol: u.rol, cliente_id: u.cliente_id, session_version: 0, debe_cambiar_password: 0, estado_cuenta: u.estado_cuenta }]);
    }
    if (/^UPDATE retos_mfa SET intentos = intentos \+ 1/.test(s)) { retos.get(p[1]).intentos += 1; return ok(); }
    if (/^UPDATE retos_mfa SET estado = '(\w+)' WHERE reto_id = \?/.test(s)) {
      retos.get(p[0]).estado = /SET estado = '(\w+)'/.exec(s)[1];
      return ok();
    }
    if (/^INSERT INTO refresh_tokens/.test(s) || /^UPDATE usuarios SET correo_verificado_en/.test(s)) return ok();
    throw new Error(`Consulta no simulada: ${s.slice(0, 120)}`);
  }

  function filaAdmin(permiso, uid) {
    const u = usuarios.get(Number(uid));
    return u ? [{ ...u, tiene_permiso: permisos.has(`${u.id}:${permiso}`) ? 1 : 0 }] : [];
  }
  function adminValido(uid, sv, permiso) {
    const u = usuarios.get(Number(uid));
    return Boolean(u && u.session_version === sv && u.estado_cuenta === 'activa' && u.rol === 'admin' &&
      !u.debe_cambiar_password && (u.es_superadmin || permisos.has(`${u.id}:${permiso}`)));
  }

  // Lotes (poolTransacciones)
  async function lote(sql, p) {
    const s = String(sql).replace(/\s+/g, ' ');
    if (/COUNT\(\*\) AS pendientes/.test(s)) {
      return [[filaAdmin(p[0], p[1]), [{ pendientes: [...solicitudes.values()].filter(x => x.estado === 'pendiente').length }]]];
    }
    if (/UPDATE solicitudes_registro s/.test(s)) {
      const aprobar = /SET s.estado = 'aprobada'/.test(s);
      const [permiso, uid, , ...resto] = p;
      const [motivo, id, confirmar, sv] = aprobar ? [null, resto[0], resto[1], resto[2]] : [resto[0], resto[1], null, resto[2]];
      const x = solicitudes.get(Number(id));
      const u = x && usuarios.get(x.usuario_id);
      let cambiadas = 0;
      if (x && x.estado === 'pendiente' && u.estado_cuenta === 'pendiente' && adminValido(uid, sv, permiso) &&
          (!aprobar || x.resultado_verificacion === 'coincide' || confirmar === 1)) {
        Object.assign(x, aprobar ? { estado: 'aprobada', decidida_por: uid } : { estado: 'rechazada', motivo_rechazo: motivo, decidida_por: uid });
        u.estado_cuenta = aprobar ? 'activa' : 'rechazada';
        cambiadas = 2;
      }
      return [[filaAdmin(permiso, uid), { affectedRows: cambiadas }, x ? [{ correo: u.correo }] : []]];
    }
    if (/INSERT INTO clientes/.test(s)) {
      const [, , tipo, , correo, hash, nitHash, nitCif, nombreCif, tipoSol, resultado] = p;
      if ([...usuarios.values()].some(u => u.correo === correo)) throw Object.assign(new Error('dup'), { code: 'ER_DUP_ENTRY' });
      const clienteId = nuevoId();
      const usuarioId = nuevoId();
      usuarios.set(usuarioId, { id: usuarioId, correo, password_hash: hash, cliente_id: clienteId, rol: 'cliente', estado_cuenta: 'pendiente', session_version: 0, tipo });
      const id = nuevoId();
      solicitudes.set(id, { id, usuario_id: usuarioId, cliente_id: clienteId, nit_hash: nitHash, nit_cifrado: nitCif, nombre_cifrado: nombreCif, tipo_institucion: tipoSol, resultado_verificacion: resultado, estado: 'pendiente', creado_en: new Date() });
      return [[{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, [{ solicitud_id: id }]]];
    }
    if (/UPDATE usuarios SET password_hash = \?/.test(s)) {
      const [hash, usuarioId, , , , , clienteId, nitHash, nitCif, nombreCif, tipoSol, resultado] = p;
      const u = usuarios.get(usuarioId);
      if (u.estado_cuenta !== 'rechazada') return [[{}, {}, [{ solicitud_id: null }]]];
      Object.assign(u, { password_hash: hash, estado_cuenta: 'pendiente' });
      const id = nuevoId();
      solicitudes.set(id, { id, usuario_id: usuarioId, cliente_id: clienteId, nit_hash: nitHash, nit_cifrado: nitCif, nombre_cifrado: nombreCif, tipo_institucion: tipoSol, resultado_verificacion: resultado, estado: 'pendiente', creado_en: new Date() });
      return [[{}, {}, [{ solicitud_id: id }]]];
    }
    if (/INSERT INTO retos_mfa/.test(s)) {
      const [usuarioId, retoId, , codigoHash, minutos, , , maximo, , ] = p;
      const recientes = [...retos.values()].filter(r => r.usuario_id === usuarioId).length;
      if (recientes >= maximo) return [[{}, {}, [{ creado: 0 }]]];
      for (const r of retos.values()) if (r.usuario_id === usuarioId && r.estado === 'pendiente') r.estado = 'cancelado';
      retos.set(retoId, { reto_id: retoId, usuario_id: usuarioId, codigo_hash: codigoHash, estado: 'pendiente', intentos: 0, proposito: 'inicio_sesion', expira: Date.now() + minutos * 60000 });
      return [[{}, {}, [{ creado: 1 }]]];
    }
    if (/^ROLLBACK/.test(s.trim())) return [[]];
    throw new Error(`Lote no simulado: ${s.slice(0, 120)}`);
  }

  const conexion = { query, beginTransaction: async () => {}, commit: async () => {}, rollback: async () => {}, release: () => {} };
  return {
    pool: { query, getConnection: async () => conexion },
    poolTransacciones: { getConnection: async () => ({ query: lote, release: () => {} }) },
    adminId,
    adminSinPermisoId,
    auditoria,
    usuarioPorCorreo: correo => [...usuarios.values()].find(u => u.correo === correo),
    solicitudDe: usuarioId => [...solicitudes.values()].filter(x => x.usuario_id === usuarioId).pop(),
    totalSolicitudes: () => solicitudes.size,
    retoVigente: id => retos.get(id)
  };
}

// Permite ejecutar este archivo directamente con node.
if (require.main === module) process.chdir(path.join(__dirname, '..'));
