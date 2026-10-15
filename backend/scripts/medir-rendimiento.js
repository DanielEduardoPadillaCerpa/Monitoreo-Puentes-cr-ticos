#!/usr/bin/env node
// Mide los tiempos del registro verificado contra la base real configurada en
// .env, con la app en este mismo proceso (sin latencia de red cliente-servidor).
//
//   node scripts/medir-rendimiento.js [--repeticiones 6] [--conservar]
//
// Crea cuentas sintéticas (medicion-*@lab.local) y un administrador temporal,
// mide registro, login paso 1, aprobar y rechazar, y al final borra SOLO lo que
// creó (salvo --conservar). Los correos se descartan (no se imprimen códigos).
//
// Metas: registro y login paso 1 < ~600 ms; aprobar/rechazar < ~300 ms.
// Se informa también la latencia de un viaje a MySQL: desde un equipo lejos de
// la base es lo que domina (en Clever Cloud, app y base están en la misma red).

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

// Correo descartado: la medición no debe imprimir ni enviar códigos.
const nodemailer = require('nodemailer');
nodemailer.createTransport = () => ({ sendMail: async () => ({}) });
process.env.SMTP_HOST = 'medicion.local';
delete process.env.N8N_REGISTRO_WEBHOOK_URL;

const jwt = require('jsonwebtoken');
const { crearApp } = require('../src/app');
const { pool, poolTransacciones } = require('../src/db');
const { secretoJwt } = require('../src/configSegura');
const { crearReto } = require('../src/seguridad/captcha');
const { hashContrasena, hashRelleno } = require('../src/seguridad/contrasenas');

const argumentos = process.argv.slice(2);
const N = Math.max(2, Number(argumentos[argumentos.indexOf('--repeticiones') + 1]) || 6);
const CONSERVAR = argumentos.includes('--conservar');
const MARCA = `medicion-${Date.now()}`;
const PASSWORD = 'MedicionSegura2026!';

// Personas del padrón de laboratorio (la verificación da "coincide").
const PERSONAS = [
  ['Juan Camilo Rodríguez', '999000001-2', 'policia'],
  ['Andrés Felipe Gómez', '999000002-1', 'defensa'],
  ['Carlos Alberto Ramírez', '999000003-7', 'bomberos'],
  ['Felipe Alejandro Vargas', '999000004-4', 'socorro'],
  ['Santiago José Martínez', '999000005-1', 'penitenciario'],
  ['Camilo Esteban Rojas', '999000006-9', 'corporativo']
];

const captcha = () => { const { id, respuesta } = crearReto(); return { captchaId: id, captchaRespuesta: respuesta }; };

async function medir(base, ruta, { metodo = 'POST', cuerpo, token } = {}) {
  const inicio = process.hrtime.bigint();
  const resp = await fetch(base + ruta, {
    method: metodo,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: cuerpo ? JSON.stringify(cuerpo) : undefined
  });
  const datos = await resp.json().catch(() => ({}));
  return { ms: Number(process.hrtime.bigint() - inicio) / 1e6, status: resp.status, datos };
}

function resumen(nombre, muestras, meta) {
  const ms = muestras.map(m => m.ms).sort((a, b) => a - b);
  const p = q => ms[Math.min(ms.length - 1, Math.floor(q * ms.length))];
  return {
    operacion: nombre,
    n: ms.length,
    min: Math.round(ms[0]),
    mediana: Math.round(p(0.5)),
    p95: Math.round(p(0.95)),
    max: Math.round(ms[ms.length - 1]),
    meta: `< ${meta}`,
    cumple: p(0.5) < meta ? 'sí' : 'NO',
    status: [...new Set(muestras.map(m => m.status))].join(',')
  };
}

(async () => {
  const servidor = crearApp().listen(0);
  const base = `http://127.0.0.1:${servidor.address().port}`;
  const creados = { usuarios: [], clientes: [] };
  try {
    await hashRelleno();
    // Latencia de un viaje a MySQL (referencia).
    const rtt = [];
    for (let i = 0; i < 5; i += 1) {
      const t = process.hrtime.bigint();
      await pool.query('SELECT 1');
      rtt.push(Number(process.hrtime.bigint() - t) / 1e6);
    }
    rtt.sort((a, b) => a - b);
    const rttMs = Math.round(rtt[2]);

    // Administrador temporal con el permiso del panel.
    const [admin] = await pool.query(
      "INSERT INTO usuarios (correo, password_hash, rol, estado_cuenta, es_cuenta_prueba) VALUES (?, ?, 'admin', 'activa', TRUE)",
      [`${MARCA}-admin@lab.local`, await hashContrasena(PASSWORD)]
    );
    creados.usuarios.push(admin.insertId);
    await pool.query("INSERT INTO staff_permisos (usuario_id, permiso) VALUES (?, 'clientes.gestionar')", [admin.insertId]);
    const token = jwt.sign({ uid: admin.insertId, rol: 'admin', mfa: true, sv: 0 }, secretoJwt(), { expiresIn: '10m' });

    // Calentamiento: abre las conexiones de ambos pools.
    await medir(base, '/api/admin/solicitudes/contador', { metodo: 'GET', token });
    await (await poolTransacciones.getConnection()).release();

    // 1. Registro
    const registros = [];
    for (let i = 0; i < N; i += 1) {
      const [nombre, nit, tipo] = PERSONAS[i % PERSONAS.length];
      const r = await medir(base, '/api/auth/registro', {
        cuerpo: {
          tipoInstitucion: tipo, nombreCompleto: nombre, nit, correo: `${MARCA}-${i}@lab.local`,
          password: PASSWORD, aceptaTerminos: true, aceptaTratamiento: true, ...captcha()
        }
      });
      registros.push(r);
    }
    const [nuevos] = await pool.query(
      `SELECT u.id AS usuario_id, u.cliente_id, s.id AS solicitud_id
       FROM usuarios u JOIN solicitudes_registro s ON s.usuario_id = u.id
       WHERE u.correo LIKE ? ORDER BY u.id`,
      [`${MARCA}-%@lab.local`]
    );
    for (const n of nuevos) { creados.usuarios.push(n.usuario_id); creados.clientes.push(n.cliente_id); }

    // 2. Aprobar (todas menos dos) y rechazar (las dos últimas)
    const aprobaciones = [];
    const rechazos = [];
    for (const [i, n] of nuevos.entries()) {
      if (i < nuevos.length - 2) {
        aprobaciones.push(await medir(base, `/api/admin/solicitudes/${n.solicitud_id}/aprobar`, { cuerpo: {}, token }));
      } else {
        rechazos.push(await medir(base, `/api/admin/solicitudes/${n.solicitud_id}/rechazar`, { cuerpo: { motivo: 'Medición de rendimiento' }, token }));
      }
    }

    // 3. Login paso 1: cuentas aprobadas, contraseña errónea y correo inexistente.
    const logins = [];
    for (let i = 0; i < nuevos.length - 2; i += 1) {
      logins.push(await medir(base, '/api/auth/login', { cuerpo: { correo: `${MARCA}-${i}@lab.local`, password: PASSWORD, ...captcha() } }));
    }
    const fallidos = [
      await medir(base, '/api/auth/login', { cuerpo: { correo: `${MARCA}-0@lab.local`, password: 'ClaveIncorrecta123', ...captcha() } }),
      await medir(base, '/api/auth/login', { cuerpo: { correo: `${MARCA}-noexiste@lab.local`, password: 'ClaveIncorrecta123', ...captcha() } })
    ];
    const contador = [];
    for (let i = 0; i < 3; i += 1) contador.push(await medir(base, '/api/admin/solicitudes/contador', { metodo: 'GET', token }));

    console.log(`\nLatencia de un viaje a MySQL desde este equipo: ~${rttMs} ms (mediana de 5).`);
    console.log(`Costo de bcrypt: ${process.env.BCRYPT_COST || 10}. Tiempos medidos en el servidor local (sin red cliente-servidor).\n`);
    console.table([
      resumen('Registro (202)', registros, 600),
      resumen('Login paso 1 (202)', logins, 600),
      resumen('Login fallido (401)', fallidos, 600),
      resumen('Aprobar', aprobaciones, 300),
      resumen('Rechazar', rechazos, 300),
      resumen('Contador pendientes', contador, 300)
    ]);
    console.log('Viajes a MySQL por operación: registro 2 (consultas en paralelo + lote transaccional),');
    console.log('login paso 1 2 (usuario + lote del reto MFA); aprobar, rechazar y contador 1 (autorización y UPDATE en el mismo lote).');
    console.log(`Sin la latencia de red a MySQL, cada operación tomaría ≈ total − ${rttMs} ms × viajes.\n`);
  } catch (err) {
    console.error('La medición falló:', err.message);
    process.exitCode = 1;
  } finally {
    if (!CONSERVAR && creados.usuarios.length) {
      // Solo lo creado por esta medición (las FK en cascada limpian solicitudes,
      // retos MFA, permisos e historial asociados).
      await pool.query('DELETE FROM usuarios WHERE id IN (?)', [creados.usuarios]).catch(e => console.error('Limpieza usuarios:', e.code));
      if (creados.clientes.length) {
        await pool.query('DELETE FROM clientes WHERE id IN (?)', [creados.clientes]).catch(e => console.error('Limpieza clientes:', e.code));
      }
      console.log(`Datos sintéticos de la medición eliminados (${creados.usuarios.length} usuarios).`);
    }
    servidor.close();
    await pool.end();
    await poolTransacciones.end();
    process.exit();
  }
})();
