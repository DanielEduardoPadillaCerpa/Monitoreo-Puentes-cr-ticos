'use strict';

const express = require('express');
const jwt = require('jsonwebtoken');
const request = require('supertest');

process.env.JWT_SECRET = 'phase-zero-test-secret-with-enough-length';
process.env.NODE_ENV = 'test';
process.env.ENC_KEY = '1'.repeat(64);
process.env.HMAC_KEY = '2'.repeat(64);

jest.mock('../src/db', () => ({
  pool: {
    query: jest.fn(),
    getConnection: jest.fn()
  }
}));
jest.mock('../src/crypto', () => ({
  cifrar: value => value,
  descifrar: value => value
}));
// El registro verificado (padrón, cifrado, lote transaccional) se prueba en
// test/registro-verificado.test.js; aquí solo interesa el contrato HTTP.
jest.mock('../src/seguridad/registroVerificado', () => ({
  procesarRegistro: jest.fn(),
  insertarRetoMfa: jest.fn()
}));
jest.mock('../src/auditoria', () => ({
  registrarAuditoria: jest.fn().mockResolvedValue(undefined)
}));

const { pool } = require('../src/db');
const { procesarRegistro } = require('../src/seguridad/registroVerificado');
const { crearReto } = require('../src/seguridad/captcha');
const authRouter = require('../src/routes/auth').router;
const clientesRouter = require('../src/routes/clientes');
const checkoutRouter = require('../src/routes/checkout');


// requiereAutenticacion lee de la base session_version, estado_cuenta y rol.
// Convención de estas pruebas: uid < 10 es administrador; el resto, cliente.
const filaSesion = (params, extra = {}) => ({ session_version: 0, estado_cuenta: 'activa', rol: Number(params?.[0]) < 10 ? 'admin' : 'cliente', ...extra });

function appConRutas() {
  const app = express();
  app.use(express.json());
  app.use('/api/auth', authRouter);
  app.use('/api/clientes', clientesRouter);
  app.use('/api/checkout', checkoutRouter);
  return app;
}

function crearConexionMock() {
  const connection = {
    beginTransaction: jest.fn().mockResolvedValue(undefined),
    commit: jest.fn().mockResolvedValue(undefined),
    rollback: jest.fn().mockResolvedValue(undefined),
    release: jest.fn(),
    query: jest.fn(async sql => {
      if (/INSERT INTO clientes/i.test(sql)) return [{ insertId: 71, affectedRows: 1 }, []];
      if (/INSERT INTO usuarios/i.test(sql)) return [{ insertId: 91, affectedRows: 1 }, []];
      if (/INSERT INTO datos_sensibles/i.test(sql)) return [{ insertId: 17, affectedRows: 1 }, []];
      return [{ affectedRows: 1 }, []];
    })
  };
  pool.getConnection.mockResolvedValue(connection);
  return connection;
}

// Contexto de staff leído de MySQL por requierePermiso().
function filaStaff(sql) {
  return /FROM usuarios u\s+LEFT JOIN clientes/i.test(String(sql)) ? [[{ id: 1, rol: 'admin', es_superadmin: 0 }], []] : null;
}

beforeEach(() => {
  pool.query.mockReset().mockImplementation(async (sql, params) => {
    if (/SELECT session_version[^;]*FROM usuarios/i.test(String(sql))) return [[filaSesion(params)], []];
    if (filaStaff(sql)) return filaStaff(sql);
    if (/FROM staff_permisos/i.test(String(sql))) return [[{ permiso: 'clientes.gestionar' }], []];
    if (/SELECT id FROM clientes/i.test(String(sql))) return [[{ id: 5 }], []];
    return [{ insertId: 1, affectedRows: 1 }, []];
  });
  pool.getConnection.mockReset();
  procesarRegistro.mockReset();
});

// Registro verificado válido de Bomberos: nombre, NIT de la entidad, correo,
// contraseña, aceptaciones y captcha resuelto.
function registroValido(cambios = {}) {
  const { id, respuesta } = crearReto();
  return {
    tipoInstitucion: 'bomberos',
    tipoCuerpo: 'voluntario',
    nombreCompleto: 'Comprador de prueba',
    nit: '999000003-7',
    correo: 'comprador@example.test',
    password: 'ClaveSegura2026!',
    aceptaTerminos: true,
    aceptaTratamiento: true,
    captchaId: id,
    captchaRespuesta: respuesta,
    ...cambios
  };
}

describe('Fase 0 - registro y control de acceso', () => {
  test('el registro no permite vincular la cuenta a un clienteId recibido del navegador', async () => {
    const response = await request(appConRutas())
      .post('/api/auth/registro')
      .send({ correo: 'attacker@example.test', password: 'Password123!', clienteId: 5 });

    expect(response.status).toBe(400);
    expect(pool.query).not.toHaveBeenCalled();
    expect(pool.getConnection).not.toHaveBeenCalled();
  });

  test('el registro rechaza datos ajenos al formulario (teléfono, antecedentes, estado) y exige el NIT', async () => {
    for (const extra of [{ nit: undefined }, { telefono: '3001234567' }, { numeroConsultaAntecedentes: '123' }, { estadoVerificacion: 'aprobado' }]) {
      const response = await request(appConRutas()).post('/api/auth/registro').send(registroValido(extra));
      expect(response.status).toBe(400);
    }
    expect(pool.getConnection).not.toHaveBeenCalled();
  });

  test('el registro exige aceptar los términos y el tratamiento de datos', async () => {
    for (const cambio of [{ aceptaTerminos: false }, { aceptaTratamiento: undefined }]) {
      const response = await request(appConRutas()).post('/api/auth/registro').send(registroValido(cambio));
      expect(response.status).toBe(400);
    }
  });

  test('el autorregistro rechaza cualquier intento de asignar autorización general', async () => {
    const response = await request(appConRutas())
      .post('/api/auth/registro')
      .send(registroValido({ autorizacionGeneral: true }));

    expect(response.status).toBe(400);
    expect(pool.getConnection).not.toHaveBeenCalled();
  });

  test('el registro válido crea una solicitud pendiente y responde 202 genérico', async () => {
    procesarRegistro.mockResolvedValueOnce({ solicitudId: 31, resultado: 'coincide' });
    const response = await request(appConRutas())
      .post('/api/auth/registro')
      .send(registroValido());

    expect(response.status).toBe(202);
    expect(response.body.estado).toBe('solicitud_recibida');
    expect(JSON.stringify(response.body)).not.toMatch(/31|coincide|clienteId|token/);
    const [datos] = procesarRegistro.mock.calls[0];
    expect(datos).not.toHaveProperty('captchaId');
    expect(datos).not.toHaveProperty('autorizacionGeneral');
  });

  test('un correo ya registrado recibe exactamente la misma respuesta', async () => {
    procesarRegistro.mockResolvedValueOnce({ solicitudId: 32, resultado: 'nit_no_existe' });
    const nueva = await request(appConRutas()).post('/api/auth/registro').send(registroValido());
    procesarRegistro.mockResolvedValueOnce({ existente: true });
    const repetida = await request(appConRutas()).post('/api/auth/registro').send(registroValido());

    expect(repetida.status).toBe(nueva.status);
    expect(repetida.body).toEqual(nueva.body);
  });

  test('sin captcha resuelto no se procesa el registro', async () => {
    const response = await request(appConRutas())
      .post('/api/auth/registro')
      .send(registroValido({ captchaRespuesta: 'x' }));

    expect(response.status).toBe(400);
    expect(response.body.code).toBe('CAPTCHA_INVALIDO');
    expect(procesarRegistro).not.toHaveBeenCalled();
  });

  test('POST /api/clientes requiere autenticación y no crea cliente públicamente', async () => {
    const response = await request(appConRutas())
      .post('/api/clientes')
      .send({ nombreUnidad: 'Entidad', nit: '9001', nombreFuncionario: 'Persona', correo: 'p@example.test' });

    expect(response.status).toBe(401);
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('solo un administrador puede crear manualmente un cliente y conceder autorización', async () => {
    const adminToken = jwt.sign({ uid: 1, rol: 'admin', mfa: true }, process.env.JWT_SECRET);
    const response = await request(appConRutas())
      .post('/api/clientes')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        nombreUnidad: 'Entidad',
        nit: '9001',
        nombreFuncionario: 'Persona',
        correo: 'p@example.test',
        autorizacionGeneral: true
      });

    expect(response.status).toBe(201);
    const insercion = pool.query.mock.calls.find(([sql]) => /INSERT INTO clientes/i.test(sql));
    expect(insercion[0]).toMatch(/autorizacion_general\)\s*VALUES\s*\([^)]*FALSE/i);
  });

  test('un usuario autenticado como cliente no puede crear clientes ni asignar autorización', async () => {
    const clientToken = jwt.sign({ uid: 10, clienteId: 5, rol: 'cliente', mfa: true }, process.env.JWT_SECRET);
    const response = await request(appConRutas())
      .post('/api/clientes')
      .set('Authorization', `Bearer ${clientToken}`)
      .send({
        nombreUnidad: 'Entidad',
        nit: '9001',
        nombreFuncionario: 'Persona',
        correo: 'p@example.test',
        autorizacionGeneral: true
      });

    expect(response.status).toBe(403);
    expect(pool.query).toHaveBeenCalledTimes(1);
    expect(pool.query.mock.calls[0][0]).toMatch(/session_version/);
  });

  function mockClienteParaPut({ permisos, estado = 'aprobado' }) {
    pool.query.mockImplementation(async (sql, params) => {
      if (/SELECT session_version[^;]*FROM usuarios/i.test(String(sql))) return [[filaSesion(params)], []];
      if (filaStaff(sql)) return filaStaff(sql);
      if (/FROM clientes WHERE id/i.test(String(sql))) return [[{ id: 5, autorizacion_general: 0, estado_verificacion: estado }], []];
      if (/FROM staff_permisos/i.test(String(sql))) return [permisos.map(permiso => ({ permiso })), []];
      return [{ affectedRows: 1 }, []];
    });
  }

  test('solo el staff con permiso de cumplimiento concede la autorización de restringidos mediante PUT', async () => {
    const adminToken = jwt.sign({ uid: 1, rol: 'admin', mfa: true }, process.env.JWT_SECRET);
    mockClienteParaPut({ permisos: ['clientes.gestionar', 'restringidos.autorizar'] });
    const response = await request(appConRutas())
      .put('/api/clientes/5')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ autorizacionGeneral: true });

    expect(response.status).toBe(200);
    const update = pool.query.mock.calls.find(([sql]) => /UPDATE clientes SET/i.test(sql));
    expect(update[0]).toMatch(/autorizacion_general\s*=\s*COALESCE/i);
    expect(update[1][5]).toBe(true);
  });

  test('un administrador sin el permiso no puede conceder restringidos (escalada vertical)', async () => {
    const adminToken = jwt.sign({ uid: 2, rol: 'admin', mfa: true }, process.env.JWT_SECRET);
    mockClienteParaPut({ permisos: ['clientes.gestionar', 'verificacion.ver'] });
    const response = await request(appConRutas())
      .put('/api/clientes/5')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ autorizacionGeneral: true });

    expect(response.status).toBe(403);
    expect(pool.query.mock.calls.some(([sql]) => /UPDATE clientes SET/i.test(sql))).toBe(false);
  });

  test('no se conceden restringidos a una cuenta que no está aprobada', async () => {
    const adminToken = jwt.sign({ uid: 1, rol: 'admin', mfa: true }, process.env.JWT_SECRET);
    mockClienteParaPut({ permisos: ['clientes.gestionar', 'restringidos.autorizar'], estado: 'pendiente' });
    const response = await request(appConRutas())
      .put('/api/clientes/5')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ autorizacionGeneral: true });

    expect(response.status).toBe(409);
  });

  test('un administrador sin el permiso clientes.gestionar no gestiona clientes (administrador limitado)', async () => {
    const adminToken = jwt.sign({ uid: 3, rol: 'admin', mfa: true }, process.env.JWT_SECRET);
    mockClienteParaPut({ permisos: ['verificacion.ver'] });
    const response = await request(appConRutas())
      .put('/api/clientes/5')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ nombreUnidad: 'Otro nombre' });

    expect(response.status).toBe(403);
    expect(response.body.permisoRequerido).toBe('clientes.gestionar');
    expect(pool.query.mock.calls.some(([sql]) => /UPDATE clientes SET/i.test(sql))).toBe(false);
  });

  test('POST /dato-sensible requiere sesión y no escribe sin autenticación', async () => {
    pool.query.mockResolvedValueOnce([[{ id: 5 }], []]);
    const response = await request(appConRutas())
      .post('/api/clientes/5/dato-sensible')
      .send({ numeroConsultaAntecedentes: 'consulta', autorizacionSensible: true });

    expect(response.status).toBe(401);
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('un cliente no puede enviar datos sensibles a otro cliente', async () => {
    const token = jwt.sign({ uid: 10, clienteId: 4, rol: 'cliente', mfa: true }, process.env.JWT_SECRET);
    const response = await request(appConRutas())
      .post('/api/clientes/5/dato-sensible')
      .set('Authorization', `Bearer ${token}`)
      .send({ numeroConsultaAntecedentes: 'consulta', autorizacionSensible: true });

    expect(response.status).toBe(403);
    expect(pool.query).toHaveBeenCalledTimes(1);
    expect(pool.query.mock.calls[0][0]).toMatch(/session_version/);
  });

  test('el consentimiento para guardar antecedentes no concede autorización de compra restringida', async () => {
    const token = jwt.sign({ uid: 10, clienteId: 5, rol: 'cliente', mfa: true }, process.env.JWT_SECRET);
    let insertado = false;
    pool.query.mockImplementation(async (sql, params) => {
      if (/SELECT session_version[^;]*FROM usuarios/i.test(String(sql))) return [[filaSesion(params)], []];
      if (/SELECT id FROM clientes/i.test(String(sql))) return [[{ id: 5 }], []];
      if (/INSERT INTO datos_sensibles/i.test(String(sql))) {
        insertado = true;
        return [{ insertId: 3 }, []];
      }
      if (/FROM clientes c/i.test(String(sql))) {
        return [[{
          id: 5,
          nombre_unidad: 'Entidad',
          nit: '',
          nombre_funcionario: '',
          correo: '',
          telefono: '',
          direccion_entrega: '',
          autorizacion_restringidos: 0
        }], []];
      }
      return [{ affectedRows: insertado ? 1 : 0 }, []];
    });
    const response = await request(appConRutas())
      .post('/api/clientes/5/dato-sensible')
      .set('Authorization', `Bearer ${token}`)
      .send({ numeroConsultaAntecedentes: 'consulta', autorizacionSensible: true });

    expect(response.status).toBe(201);
    const insercionDato = pool.query.mock.calls.find(([sql]) => /INSERT INTO datos_sensibles/i.test(sql));
    expect(insercionDato[1][2]).toBe(true);
    const perfil = await request(appConRutas())
      .get('/api/checkout/perfil')
      .set('Authorization', `Bearer ${token}`);
    expect(perfil.status).toBe(200);
    expect(perfil.body.autorizacionRestringidos).toBe(false);
  });
});
