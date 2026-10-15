const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const path = require('path');

process.env.CRYPTO_KEYS = `k1:${crypto.randomBytes(32).toString('base64')},k2:${crypto.randomBytes(32).toString('base64')}`;
process.env.CRYPTO_KEY_ACTIVA = 'k2';
process.env.IDENT_HMAC_KEY = crypto.randomBytes(32).toString('base64');
process.env.CRYPTO_KEY = 'legacy-key-for-tests-32-chars!!!';

const cifrado = require('../src/crypto');
const { decidirSolicitud, normalizarIdentificador, hashCarrito, nitPersonaJuridica } = require('../src/verificacionCompra');
const { secretoDebil, validarConfiguracionSegura } = require('../src/configSegura');
const { firmarPayload } = require('../src/automationSignatures');

const c = (componente, resultado, extra = {}) => ({ componente, resultado, metodo: 'x', actor_tipo: 'staff', actor_usuario_id: null, ...extra });
const todas = (r1, r2, r3, extra = {}) => [
  c('vinculo_documental', r1, { actor_usuario_id: 1, ...extra.vinculo }),
  c('canal_independiente', r2, { actor_usuario_id: 2, ...extra.canal }),
  c('entidad', r3, { actor_tipo: 'n8n' })
];

test('tabla de decisión: solo tres confirmaciones de personas distintas permiten aprobar', () => {
  assert.deepEqual(decidirSolicitud(todas('confirmado', 'confirmado', 'confirmado')).puedeAprobar, true);
  const mismaPersona = decidirSolicitud(todas('confirmado', 'confirmado', 'confirmado', { canal: { actor_usuario_id: 1 } }));
  assert.equal(mismaPersona.puedeAprobar, false);
  assert.equal(mismaPersona.motivo, 'misma_persona_en_ambas_comprobaciones');
  // El correo institucional lo confirma el sistema: no cuenta como misma persona.
  assert.equal(decidirSolicitud(todas('confirmado', 'confirmado', 'confirmado', { canal: { actor_tipo: 'sistema', actor_usuario_id: null } })).puedeAprobar, true);
});

test('tabla de decisión: ningún resultado distinto de confirmado aprueba y nada rechaza automáticamente', () => {
  const resultados = ['pendiente', 'no_coincide', 'datos_insuficientes', 'fuente_no_disponible', 'respuesta_invalida', 'ambiguo'];
  for (const r of resultados) {
    for (const combinacion of [todas(r, 'confirmado', 'confirmado'), todas('confirmado', r, 'confirmado'), todas('confirmado', 'confirmado', r)]) {
      const d = decidirSolicitud(combinacion);
      assert.equal(d.puedeAprobar, false, `${r} no debe permitir aprobar`);
      assert.notEqual(d.estado, 'rechazada');
      assert.notEqual(d.estado, 'aprobada');
    }
  }
  assert.equal(decidirSolicitud(todas('confirmado', 'confirmado', 'fuente_no_disponible')).estado, 'fuente_no_disponible');
  assert.equal(decidirSolicitud(todas('confirmado', 'no_coincide', 'confirmado')).motivo, 'no_coincidencia');
  assert.equal(decidirSolicitud(todas('ambiguo', 'confirmado', 'confirmado')).motivo, 'resultado_no_concluyente');
  assert.equal(decidirSolicitud(todas('pendiente', 'confirmado', 'confirmado')).estado, 'en_curso');
  assert.equal(decidirSolicitud(todas('confirmado', 'confirmado', 'confirmado').slice(0, 2)).puedeAprobar, false);
});

test('normalización de identificadores: formatos equivalentes producen el mismo valor', () => {
  assert.equal(normalizarIdentificador('CC', '1.023.456.789'), '1023456789');
  assert.equal(normalizarIdentificador('CC', ' 001023456789 '), '1023456789');
  assert.equal(normalizarIdentificador('CC', '12345678901'), null);
  assert.equal(normalizarIdentificador('CC', '0012345'), '12345');
  assert.equal(normalizarIdentificador('CC', '12-345'), '12345');
  assert.equal(normalizarIdentificador('CE', 'ab 12345'), 'AB12345');
  assert.equal(normalizarIdentificador('CC', '12a45'), null);
  assert.equal(normalizarIdentificador('PLACA', '12345'), null);
  assert.equal(normalizarIdentificador('CC', '123'), null);
});

test('índice HMAC: estable para el mismo documento, distinto por tipo y por clave, y no es un SHA-256 simple', () => {
  const a = cifrado.indiceIdentificador('CC', '1023456789');
  assert.equal(a, cifrado.indiceIdentificador('CC', '1023456789'));
  assert.notEqual(a, cifrado.indiceIdentificador('CE', '1023456789'));
  assert.notEqual(a, crypto.createHash('sha256').update('CC:1023456789').digest('hex'));
  const anterior = process.env.IDENT_HMAC_KEY;
  process.env.IDENT_HMAC_KEY = crypto.randomBytes(32).toString('base64');
  assert.notEqual(a, cifrado.indiceIdentificador('CC', '1023456789'));
  process.env.IDENT_HMAC_KEY = '';
  assert.throws(() => cifrado.indiceIdentificador('CC', '1'), /IDENT_HMAC_KEY/);
  process.env.IDENT_HMAC_KEY = anterior;
});

test('cifrado v2: versionado, rotación de clave activa, detección de alteraciones', () => {
  const v = cifrado.cifrarEstricto('1023456789');
  assert.match(v, /^v2:k2:/);
  assert.equal(cifrado.descifrar(v), '1023456789');
  process.env.CRYPTO_KEY_ACTIVA = 'k1';
  const conK1 = cifrado.cifrar('dato');
  assert.match(conK1, /^v2:k1:/);
  process.env.CRYPTO_KEY_ACTIVA = 'k2';
  assert.equal(cifrado.descifrar(conK1), 'dato', 'una clave retirada de la activa sigue descifrando');
  const partes = v.split(':');
  const bytes = Buffer.from(partes[2], 'base64');
  bytes[bytes.length - 1] ^= 1;
  assert.throws(() => cifrado.descifrar(`v2:k2:${bytes.toString('base64')}`), /DECRYPT_FAILED/);
  assert.throws(() => cifrado.descifrar(v.replace('v2:k2:', 'v2:k9:')), /DECRYPT_FAILED/);
  assert.throws(() => cifrado.descifrarEstricto('texto-plano'), /DECRYPT_FAILED/);
  // Datos heredados siguen legibles.
  const anillo = process.env.CRYPTO_KEYS;
  process.env.CRYPTO_KEYS = '';
  const heredado = cifrado.cifrar('viejo');
  assert.doesNotMatch(heredado, /^v2:/);
  assert.throws(() => cifrado.cifrarEstricto('x'), /CRYPTO_KEYS/);
  process.env.CRYPTO_KEYS = anillo;
  assert.equal(cifrado.descifrar(heredado), 'viejo');
  // Documentos binarios.
  const doc = cifrado.cifrarBuffer(Buffer.from('%PDF-1.4 prueba'));
  assert.equal(doc.subarray(0, 4).toString(), 'SIK2');
  assert.equal(cifrado.descifrarBuffer(doc).toString(), '%PDF-1.4 prueba');
});

test('hash del carrito: independiente del orden y de líneas repetidas, sensible a cantidades', () => {
  const a = hashCarrito([{ id: 2, cantidad: 1 }, { id: 1, cantidad: 3 }]);
  assert.equal(a, hashCarrito([{ id: 1, cantidad: 2 }, { id: 2, cantidad: 1 }, { id: 1, cantidad: 1 }]));
  assert.notEqual(a, hashCarrito([{ id: 1, cantidad: 4 }, { id: 2, cantidad: 1 }]));
});

test('solo NIT de persona jurídica sale hacia n8n (nunca uno que contenga una cédula)', () => {
  assert.equal(nitPersonaJuridica('800197268-4'), '800197268');
  assert.equal(nitPersonaJuridica('900123456-7'), '900123456');
  assert.equal(nitPersonaJuridica('1023456789-1'), null);
  assert.equal(nitPersonaJuridica('79123456-3'), null);
  assert.equal(nitPersonaJuridica(null), null);
});

test('configuración segura: en producción rechaza secretos de ejemplo', () => {
  assert.equal(secretoDebil('cambia_esto_por_un_secreto_largo_aleatorio_0123456789'), true);
  assert.equal(secretoDebil(crypto.randomBytes(32).toString('hex')), false);
  const respaldo = { ...process.env };
  try {
    process.env.JWT_SECRET = 'cambia-este-secreto-con-texto-suficientemente-largo';
    process.env.MFA_TOKEN_PEPPER = crypto.randomBytes(32).toString('hex');
    process.env.ENC_KEY = crypto.randomBytes(32).toString('hex');
    process.env.HMAC_KEY = crypto.randomBytes(32).toString('hex');
    assert.throws(() => validarConfiguracionSegura({ produccion: true }), /JWT_SECRET/);
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
    assert.doesNotThrow(() => validarConfiguracionSegura({ produccion: true }));
    // Registro verificado: claves ausentes o iguales impiden arrancar en cualquier entorno.
    process.env.HMAC_KEY = process.env.ENC_KEY;
    assert.throws(() => validarConfiguracionSegura({ produccion: false }), /distintas/);
    delete process.env.ENC_KEY;
    assert.throws(() => validarConfiguracionSegura({ produccion: false }), /ENC_KEY/);
    process.env.ENC_KEY = crypto.randomBytes(32).toString('hex');
    process.env.HMAC_KEY = crypto.randomBytes(32).toString('hex');
    process.env.CRYPTO_KEYS = 'k1:corta';
    assert.throws(() => validarConfiguracionSegura({ produccion: true }), /CRYPTO_KEYS/);
  } finally {
    for (const clave of ['JWT_SECRET', 'MFA_TOKEN_PEPPER', 'CRYPTO_KEYS', 'ENC_KEY', 'HMAC_KEY']) {
      if (respaldo[clave] === undefined) delete process.env[clave]; else process.env[clave] = respaldo[clave];
    }
  }
});

// ---------------------------------------------------------------------------
// Nodos de código de W11 (se ejecutan con el mismo motor que la prueba de W8)
// ---------------------------------------------------------------------------
const { codigoVerificar, codigoClasificar } = require(path.join('..', '..', 'n8n', 'generar-w11.js'));
const SECRETO_W11 = 'test-only-w11-secret-with-32-characters-min';
const SECRETO_RESPUESTA = 'test-only-w11-callback-secret-32-characters';

function ejecutarVerificar(payload, { alterar = false } = {}) {
  const firmado = firmarPayload(payload, SECRETO_W11);
  const fn = new Function('require', '$input', 'process', '$env', codigoVerificar);
  return fn(require, {
    first: () => ({ json: { body: alterar ? firmado.cuerpo.replace('policia', 'defensa') : firmado.cuerpo, headers: { 'x-automation-timestamp': firmado.timestamp, 'x-automation-signature': firmado.firma } } })
  }, { env: {} }, { N8N_W11_SECRET: SECRETO_W11 });
}

test('W11 valida la firma, la forma exacta de cada evento y nunca acepta una cédula como NIT', () => {
  const ref = 'a'.repeat(32);
  const ahora = new Date().toISOString();
  const tareas = ejecutarVerificar({ evento: 'verificacion.solicitada', ref, tipoInstitucion: 'policia', consultarEntidad: true, nit: '800141397', timestamp: ahora });
  assert.deepEqual(tareas.map(t => t.json.ruta), ['entidad', 'aviso_staff']);
  assert.throws(() => ejecutarVerificar({ evento: 'verificacion.solicitada', ref, tipoInstitucion: 'policia', consultarEntidad: true, nit: '800141397', timestamp: ahora }, { alterar: true }), /signature/);
  assert.throws(() => ejecutarVerificar({ evento: 'verificacion.solicitada', ref, tipoInstitucion: 'policia', consultarEntidad: true, nit: '1023456789', timestamp: ahora }), /NIT/);
  assert.throws(() => ejecutarVerificar({ evento: 'verificacion.solicitada', ref, tipoInstitucion: 'policia', consultarEntidad: false, timestamp: ahora, cedula: '1' }), /Invalid/);
  assert.throws(() => ejecutarVerificar({ evento: 'verificacion.aprobar', ref, timestamp: ahora }), /not allowed/);
  const aviso = ejecutarVerificar({ evento: 'verificacion.actualizada', email: 'persona@example.test', estado: 'aprobado', timestamp: ahora });
  assert.equal(aviso[0].json.ruta, 'aviso_titular');
});

function clasificar({ tipo = 'policia', chip, rues }) {
  const base = { ruta: 'entidad', ref: 'b'.repeat(32), tipoInstitucion: tipo, nit: '800141397' };
  const nodos = {
    'Verificar firma y repartir': { all: () => [{ json: base }] },
    'Consultar CHIP (5c7g-ptic)': { first: () => ({ json: chip }) },
    'Consultar RUES (c82u-588k)': { first: () => ({ json: rues }) }
  };
  const fn = new Function('require', '$', 'process', '$env', codigoClasificar);
  const salida = fn(require, nombre => nodos[nombre], { env: {} }, { N8N_W11_CALLBACK_SECRET: SECRETO_RESPUESTA })[0].json;
  const payload = JSON.parse(salida.cuerpo);
  const esperado = crypto.createHmac('sha256', SECRETO_RESPUESTA).update(`${salida.timestamp}.${salida.cuerpo}`).digest('hex');
  assert.equal(salida.firma, esperado);
  return payload;
}

test('W11 clasifica la entidad sin confundir ausencia con fraude', () => {
  const anio = new Date().getUTCFullYear();
  const ok = (body) => ({ statusCode: 200, body });
  assert.equal(clasificar({ chip: ok([{ nit: '800141397:5', a_o: String(anio) }]), rues: ok([]) }).resultado, 'confirmado');
  assert.equal(clasificar({ chip: ok([]), rues: ok([]) }).resultado, 'datos_insuficientes');
  assert.equal(clasificar({ tipo: 'corporativo', chip: ok([]), rues: ok([{ nit: '800141397', estado_matricula: 'ACTIVA', ultimo_ano_renovado: String(anio) }]) }).resultado, 'confirmado');
  assert.equal(clasificar({ tipo: 'corporativo', chip: ok([]), rues: ok([{ nit: '800141397', estado_matricula: 'CANCELADA', ultimo_ano_renovado: '2019' }]) }).resultado, 'no_coincide');
  assert.equal(clasificar({ tipo: 'corporativo', chip: ok([]), rues: ok([{ nit: '800141397', estado_matricula: 'ACTIVA', ultimo_ano_renovado: '2015' }]) }).resultado, 'ambiguo');
  assert.equal(clasificar({ chip: { statusCode: 503, body: '' }, rues: { error: { message: 'ECONNRESET' } } }).resultado, 'fuente_no_disponible');
  assert.equal(clasificar({ chip: ok('<html>'), rues: ok({ raro: true }) }).resultado, 'respuesta_invalida');
  // Una entidad pública con matrícula RUES cancelada pero vigente en CHIP sigue confirmada por CHIP.
  assert.equal(clasificar({ chip: ok([{ nit: '800141397:5', a_o: String(anio) }]), rues: ok([{ nit: '800141397', estado_matricula: 'CANCELADA' }]) }).resultado, 'confirmado');
  const p = clasificar({ chip: ok([]), rues: ok([]) });
  assert.deepEqual(Object.keys(p).sort(), ['componente', 'consultadoEn', 'fuente', 'metodo', 'nonce', 'ref', 'resultado']);
});
