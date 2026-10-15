const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { z } = require('zod');
const { rateLimit } = require('express-rate-limit');
const { pool } = require('../db');
const { cifrar, descifrar } = require('../crypto');
const { hashCodigoMfa, compararHashesMfa, generarCodigoMfa } = require('../mfaCodes');
const { requiereAutenticacion, requiereAdmin } = require('./auth');
const { requierePermiso } = require('../autorizacion');
const { registrarAuditoria, registrarAuditoriaTransaccional } = require('../auditoria');
const { enviarCorreoEnSegundoPlano } = require('../seguridad/correo');

const router = express.Router();
const MFA_VIGENCIA_MINUTOS = 5;
const MFA_INTENTOS_MAXIMOS = 5;

function crearLimitador({ ventanaMs, limite, mensaje }) {
  return rateLimit({
    windowMs: ventanaMs,
    limit: limite,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => res.status(429).json({ error: mensaje })
  });
}

const limitarLecturaEdicion = crearLimitador({
  ventanaMs: 60 * 1000,
  limite: 30,
  mensaje: 'Demasiadas solicitudes de cuenta. Inténtalo nuevamente en un minuto.'
});
const limitarCorreo = crearLimitador({
  ventanaMs: 60 * 60 * 1000,
  limite: 5,
  mensaje: 'Se alcanzó el límite de solicitudes de cambio de correo. Inténtalo más tarde.'
});
const limitarConfirmacionCorreo = crearLimitador({
  ventanaMs: 15 * 60 * 1000,
  limite: 10,
  mensaje: 'Se alcanzó el límite de verificaciones. Inténtalo más tarde.'
});
const limitarPassword = crearLimitador({
  ventanaMs: 60 * 60 * 1000,
  limite: 5,
  mensaje: 'Se alcanzó el límite de cambios de contraseña. Inténtalo más tarde.'
});
const limitarAccionSeguridad = crearLimitador({
  ventanaMs: 60 * 60 * 1000,
  limite: 5,
  mensaje: 'Se alcanzó el límite de acciones de seguridad. Inténtalo más tarde.'
});
const limitarSolicitud = crearLimitador({
  ventanaMs: 60 * 60 * 1000,
  limite: 3,
  mensaje: 'Se alcanzó el límite de solicitudes de privacidad. Inténtalo más tarde.'
});

function textoSeguro(min, max) {
  return z.string()
    .trim()
    .min(min)
    .max(max)
    .refine(valor => !/[<>]/.test(valor) && !/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(valor));
}

function normalizarTelefono(valor) {
  const limpio = String(valor).trim().replace(/[\s().-]/g, '');
  const nacional = limpio.startsWith('+57') ? limpio.slice(3)
    : limpio.startsWith('57') && limpio.length === 12 ? limpio.slice(2)
      : limpio;
  if (!/^(3\d{9}|60[1-9]\d{7})$/.test(nacional)) return null;
  return `+57${nacional}`;
}

const esquemaEdicion = z.object({
  nombreFuncionario: textoSeguro(2, 100).optional(),
  telefono: z.string().trim().min(1).max(30).transform(normalizarTelefono)
    .refine(Boolean, 'Ingresa un teléfono colombiano válido.').optional(),
  direccionEntrega: textoSeguro(1, 255).optional(),
  direccionInstalacion: textoSeguro(1, 255).optional()
}).strict().refine(datos => Object.keys(datos).length > 0);

const esquemaSolicitud = z.object({
  campo: z.enum(['nit', 'nombreUnidad', 'eliminacion', 'correccion']),
  detalle: textoSeguro(10, 2000)
}).strict();
const esquemaDecision = z.object({
  estado: z.enum(['aprobada', 'rechazada']),
  respuesta: textoSeguro(1, 500).optional()
}).strict();

function idClienteAutenticado(req) {
  const id = Number(req.usuario?.clienteId);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function respuestaValidacion(res, resultado, mensaje) {
  if (resultado.success) return resultado.data;
  res.status(400).json({ error: mensaje });
  return null;
}

function serializarEventoCifrado(evento) {
  return JSON.stringify({ contenido: cifrar(JSON.stringify(evento)) });
}

async function encolarEventoCuenta(connection, clave, evento) {
  await connection.query(
    `INSERT IGNORE INTO automation_outbox
      (workflow, dedupe_key, payload, payload_cifrado)
     VALUES ('W8', ?, ?, TRUE)`,
    [clave, serializarEventoCifrado(evento)]
  );
}

async function auditarCuenta(usuario, accion, campos, entidadId = usuario.uid, connection) {
  const auditoria = {
    usuario: { uid: usuario.uid, correo: null },
    accion,
    entidad: 'cuenta',
    entidadId,
    detalle: { campos }
  };
  if (connection) return registrarAuditoriaTransaccional(connection, auditoria);
  return registrarAuditoria(auditoria);
}

async function obtenerCliente(usuarioId, clienteId) {
  const [filas] = await pool.query(
    `SELECT c.id, c.nombre_unidad, c.direccion_instalacion, c.nit,
            c.nombre_funcionario, c.correo, c.telefono, c.direccion_entrega,
            c.autorizacion_general, u.correo AS correo_login
     FROM clientes c
     JOIN usuarios u ON u.cliente_id = c.id
     WHERE c.id = ? AND u.id = ?
     LIMIT 1`,
    [clienteId, usuarioId]
  );
  return filas[0] || null;
}

router.use(requiereAutenticacion);

router.get('/', limitarLecturaEdicion, async (req, res) => {
  try {
    const clienteId = idClienteAutenticado(req);
    if (!clienteId) return res.status(403).json({ error: 'La cuenta no tiene un perfil de cliente.' });
    const cliente = await obtenerCliente(req.usuario.uid, clienteId);
    if (!cliente) return res.status(404).json({ error: 'No se encontró el perfil de la cuenta.' });
    res.set('Cache-Control', 'no-store');
    return res.json({
      nombreFuncionario: descifrar(cliente.nombre_funcionario) || '',
      telefono: descifrar(cliente.telefono) || '',
      direccionEntrega: descifrar(cliente.direccion_entrega) || '',
      direccionInstalacion: cliente.direccion_instalacion || '',
      correo: cliente.correo_login,
      autorizacionGeneral: Boolean(cliente.autorizacion_general)
    });
  } catch (err) {
    console.error('[mi-cuenta] No se pudo consultar el perfil:', err.code || 'ACCOUNT_READ_FAILED');
    return res.status(500).json({ error: 'No fue posible cargar los datos de la cuenta.' });
  }
});

router.patch('/', limitarLecturaEdicion, async (req, res) => {
  const campos = respuestaValidacion(
    res,
    esquemaEdicion.safeParse(req.body || {}),
    'Los datos contienen campos no permitidos o valores inválidos.'
  );
  if (!campos) return;

  const clienteId = idClienteAutenticado(req);
  if (!clienteId) return res.status(403).json({ error: 'La cuenta no tiene un perfil de cliente.' });
  const updates = [];
  const valores = [];
  const columnas = {
    nombreFuncionario: ['nombre_funcionario', cifrar],
    telefono: ['telefono', cifrar],
    direccionEntrega: ['direccion_entrega', cifrar],
    direccionInstalacion: ['direccion_instalacion', valor => valor]
  };
  for (const [campo, valor] of Object.entries(campos)) {
    const [columna, transformar] = columnas[campo];
    updates.push(`${columna} = ?`);
    valores.push(transformar(valor));
  }

  try {
    valores.push(clienteId, req.usuario.uid);
    const [resultado] = await pool.query(
      `UPDATE clientes c
       JOIN usuarios u ON u.cliente_id = c.id
       SET ${updates.join(', ')}
       WHERE c.id = ? AND u.id = ?`,
      valores
    );
    if (resultado.affectedRows !== 1) {
      return res.status(404).json({ error: 'No se encontró el perfil de la cuenta.' });
    }
    await auditarCuenta(req.usuario, 'editar', Object.keys(campos));
    return res.json({ ok: true });
  } catch (err) {
    console.error('[mi-cuenta] No se pudo actualizar el perfil:', err.code || 'ACCOUNT_UPDATE_FAILED');
    return res.status(500).json({ error: 'No fue posible actualizar los datos de la cuenta.' });
  }
});

router.post('/correo/solicitar', limitarCorreo, async (req, res) => {
  if (typeof req.body?.passwordActual !== 'string' || !req.body.passwordActual) {
    return res.status(403).json({ error: 'Confirma tu contraseña actual para solicitar el cambio.' });
  }
  const solicitud = z.object({
    nuevoCorreo: z.string().trim().email().max(255),
    passwordActual: z.string().min(1).max(255)
  }).strict().safeParse(req.body);
  const datos = respuestaValidacion(res, solicitud, 'El correo o los datos de solicitud no son válidos.');
  if (!datos) return;

  const clienteId = idClienteAutenticado(req);
  if (!clienteId) return res.status(403).json({ error: 'La cuenta no tiene un perfil de cliente.' });
  const nuevoCorreo = datos.nuevoCorreo.toLowerCase();
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [usuarios] = await connection.query(
      `SELECT id, correo, password_hash
       FROM usuarios
       WHERE id = ? AND cliente_id = ?
       FOR UPDATE`,
      [req.usuario.uid, clienteId]
    );
    if (!usuarios.length || !await bcrypt.compare(datos.passwordActual, usuarios[0].password_hash)) {
      await connection.rollback();
      return res.status(401).json({ error: 'No fue posible verificar las credenciales.' });
    }
    if (usuarios[0].correo.toLowerCase() === nuevoCorreo) {
      await connection.rollback();
      return res.status(409).json({ error: 'Ese correo no está disponible.' });
    }
    const [ocupado] = await connection.query(
      'SELECT id FROM usuarios WHERE correo = ? AND id <> ? LIMIT 1',
      [nuevoCorreo, req.usuario.uid]
    );
    if (ocupado.length) {
      await connection.rollback();
      return res.status(409).json({ error: 'Ese correo no está disponible.' });
    }

    const retoId = crypto.randomBytes(32).toString('hex');
    const codigo = generarCodigoMfa();
    const codigoHash = hashCodigoMfa(retoId, req.usuario.uid, codigo);
    await connection.query(
      `UPDATE retos_mfa
       SET estado = 'cancelado'
       WHERE usuario_id = ? AND proposito = 'cambio_correo' AND estado = 'pendiente'`,
      [req.usuario.uid]
    );
    await connection.query(
      `INSERT INTO retos_mfa
        (reto_id, usuario_id, codigo_hash, expira_en, proposito, correo_destino_cifrado)
       VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE), 'cambio_correo', ?)`,
      [retoId, req.usuario.uid, codigoHash, MFA_VIGENCIA_MINUTOS, cifrar(nuevoCorreo)]
    );
    await connection.commit();
    // Correo directo (nodemailer): ni el correo nuevo ni el código pasan por n8n.
    enviarCorreoEnSegundoPlano({
      to: nuevoCorreo,
      subject: 'Confirma tu nuevo correo',
      text: `Tu código para confirmar el cambio de correo es: ${codigo}\n\nVence en ${MFA_VIGENCIA_MINUTOS} minutos.`
    });
    return res.status(202).json({
      ok: true,
      challengeId: retoId,
      expiresIn: MFA_VIGENCIA_MINUTOS * 60,
      mensaje: 'Enviamos un código de verificación al nuevo correo.'
    });
  } catch (err) {
    if (connection) await connection.rollback();
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Ese correo no está disponible.' });
    }
    console.error('[mi-cuenta] No se pudo solicitar el cambio de correo:', err.code || 'EMAIL_CHANGE_REQUEST_FAILED');
    return res.status(500).json({ error: 'No fue posible solicitar el cambio de correo.' });
  } finally {
    if (connection) connection.release();
  }
});

router.post('/correo/confirmar', limitarConfirmacionCorreo, async (req, res) => {
  const solicitud = z.object({
    challengeId: z.string().regex(/^[a-f0-9]{64}$/),
    code: z.string().regex(/^\d{6}$/)
  }).strict().safeParse(req.body || {});
  const datos = respuestaValidacion(res, solicitud, 'El código o desafío no son válidos.');
  if (!datos) return;

  const clienteId = idClienteAutenticado(req);
  if (!clienteId) return res.status(403).json({ error: 'La cuenta no tiene un perfil de cliente.' });
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [retos] = await connection.query(
      `SELECT r.usuario_id, r.codigo_hash, r.estado, r.intentos,
              r.correo_destino_cifrado, (r.expira_en > NOW()) AS vigente,
              u.cliente_id, u.correo AS correo_anterior
       FROM retos_mfa r
       JOIN usuarios u ON u.id = r.usuario_id
       WHERE r.reto_id = ? AND r.proposito = 'cambio_correo'
       FOR UPDATE`,
      [datos.challengeId]
    );
    if (!retos.length || retos[0].usuario_id !== req.usuario.uid ||
        retos[0].cliente_id !== clienteId || retos[0].estado !== 'pendiente') {
      await connection.rollback();
      return res.status(401).json({ error: 'El código no es válido o ya no está disponible.' });
    }
    const reto = retos[0];
    if (!reto.vigente) {
      await connection.query("UPDATE retos_mfa SET estado = 'expirado' WHERE reto_id = ?", [datos.challengeId]);
      await connection.commit();
      return res.status(410).json({ error: 'El código expiró. Solicita uno nuevo.' });
    }
    if (Number(reto.intentos) >= MFA_INTENTOS_MAXIMOS) {
      await connection.query("UPDATE retos_mfa SET estado = 'bloqueado' WHERE reto_id = ?", [datos.challengeId]);
      await connection.commit();
      return res.status(429).json({ error: 'Se agotaron los intentos. Solicita un nuevo código.' });
    }
    const codigoEsperado = hashCodigoMfa(datos.challengeId, req.usuario.uid, datos.code);
    if (!compararHashesMfa(reto.codigo_hash, codigoEsperado)) {
      await connection.query(
        `UPDATE retos_mfa
         SET intentos = intentos + 1,
             estado = IF(intentos + 1 >= ?, 'bloqueado', 'pendiente')
         WHERE reto_id = ?`,
        [MFA_INTENTOS_MAXIMOS, datos.challengeId]
      );
      await connection.commit();
      return res.status(401).json({ error: 'El código no es válido.' });
    }

    const nuevoCorreo = descifrar(reto.correo_destino_cifrado);
    if (typeof nuevoCorreo !== 'string' || !nuevoCorreo) {
      throw new Error('EMAIL_CHANGE_DESTINATION_INVALID');
    }
    const [actualizacionUsuario] = await connection.query(
      'UPDATE usuarios SET correo = ?, session_version = session_version + 1 WHERE id = ? AND cliente_id = ?',
      [nuevoCorreo, req.usuario.uid, clienteId]
    );
    if (actualizacionUsuario.affectedRows !== 1) {
      throw new Error('EMAIL_CHANGE_USER_UPDATE_FAILED');
    }
    const [actualizacionCliente] = await connection.query(
      'UPDATE clientes SET correo = ? WHERE id = ?',
      [cifrar(nuevoCorreo), clienteId]
    );
    if (actualizacionCliente.affectedRows !== 1) {
      throw new Error('EMAIL_CHANGE_PROFILE_UPDATE_FAILED');
    }
    await connection.query(
      'UPDATE refresh_tokens SET revocado = TRUE WHERE usuario_id = ? AND revocado = FALSE',
      [req.usuario.uid]
    );
    await connection.query(
      "UPDATE retos_mfa SET estado = 'verificado' WHERE reto_id = ? AND estado = 'pendiente'",
      [datos.challengeId]
    );
    await auditarCuenta(req.usuario, 'editar', ['correo'], req.usuario.uid, connection);
    await connection.commit();
    enviarCorreoEnSegundoPlano({
      to: reto.correo_anterior,
      subject: 'Aviso de seguridad: tu correo cambió',
      text: 'El correo de acceso de tu cuenta fue cambiado. Si no fuiste tú, comunícate de inmediato con el administrador de la plataforma.'
    });
    return res.json({ ok: true, mensaje: 'Correo actualizado. Inicia sesión nuevamente.' });
  } catch (err) {
    if (connection) await connection.rollback();
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Ese correo no está disponible.' });
    }
    console.error('[mi-cuenta] No se pudo confirmar el cambio de correo:', err.code || 'EMAIL_CHANGE_CONFIRM_FAILED');
    return res.status(500).json({ error: 'No fue posible completar el cambio de correo.' });
  } finally {
    if (connection) connection.release();
  }
});

router.post('/password', limitarPassword, async (req, res) => {
  const solicitud = z.object({
    passwordActual: z.string().min(1).max(255),
    passwordNueva: z.string().min(10).max(255)
  }).strict().safeParse(req.body || {});
  if (!req.body?.passwordActual) {
    return res.status(401).json({ error: 'Confirma tu contraseña actual.' });
  }
  const datos = respuestaValidacion(res, solicitud, 'La contraseña nueva debe tener entre 10 y 255 caracteres.');
  if (!datos) return;
  if (datos.passwordActual === datos.passwordNueva) {
    return res.status(400).json({ error: 'La contraseña nueva debe ser distinta de la actual.' });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [usuarios] = await connection.query(
      'SELECT id, correo, password_hash FROM usuarios WHERE id = ? FOR UPDATE',
      [req.usuario.uid]
    );
    if (!usuarios.length || !await bcrypt.compare(datos.passwordActual, usuarios[0].password_hash)) {
      await connection.rollback();
      return res.status(401).json({ error: 'No fue posible verificar las credenciales.' });
    }
    const [mfa] = await connection.query(
      `SELECT id FROM refresh_tokens
       WHERE usuario_id = ? AND revocado = FALSE AND fecha_expiracion > NOW()
         AND mfa_verificado_en >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)
       LIMIT 1`,
      [req.usuario.uid]
    );
    if (!mfa.length) {
      await connection.rollback();
      return res.status(403).json({ error: 'Vuelve a iniciar sesión con MFA para cambiar la contraseña.' });
    }

    const passwordHash = await bcrypt.hash(datos.passwordNueva, 10);
    const [actualizacionUsuario] = await connection.query(
      'UPDATE usuarios SET password_hash = ?, session_version = session_version + 1, debe_cambiar_password = FALSE WHERE id = ?',
      [passwordHash, req.usuario.uid]
    );
    if (actualizacionUsuario.affectedRows !== 1) {
      throw new Error('PASSWORD_CHANGE_USER_UPDATE_FAILED');
    }
    await connection.query(
      'UPDATE refresh_tokens SET revocado = TRUE WHERE usuario_id = ? AND revocado = FALSE',
      [req.usuario.uid]
    );
    await auditarCuenta(req.usuario, 'editar', ['password'], req.usuario.uid, connection);
    await connection.commit();
    enviarCorreoEnSegundoPlano({
      to: usuarios[0].correo,
      subject: 'Aviso de seguridad: tu contraseña cambió',
      text: 'La contraseña de tu cuenta fue cambiada. Si no fuiste tú, comunícate de inmediato con el administrador de la plataforma.'
    });
    return res.json({ ok: true, mensaje: 'Contraseña actualizada. Inicia sesión nuevamente.' });
  } catch (err) {
    if (connection) await connection.rollback();
    console.error('[mi-cuenta] No se pudo cambiar la contraseña:', err.code || 'PASSWORD_CHANGE_FAILED');
    return res.status(500).json({ error: 'No fue posible actualizar la contraseña.' });
  } finally {
    if (connection) connection.release();
  }
});

router.post('/sesiones/cerrar-todas', limitarAccionSeguridad, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    await connection.query(
      'UPDATE refresh_tokens SET revocado = TRUE WHERE usuario_id = ? AND revocado = FALSE',
      [req.usuario.uid]
    );
    await connection.query(
      'UPDATE usuarios SET session_version = session_version + 1 WHERE id = ?',
      [req.usuario.uid]
    );
    await auditarCuenta(req.usuario, 'editar', ['sesiones'], req.usuario.uid, connection);
    await connection.commit();
    return res.json({ ok: true, mensaje: 'Se cerraron todas las sesiones. Inicia sesión nuevamente.' });
  } catch (err) {
    if (connection) await connection.rollback();
    console.error('[mi-cuenta] No se pudieron cerrar las sesiones:', err.code || 'SESSION_REVOCATION_FAILED');
    return res.status(500).json({ error: 'No fue posible cerrar todas las sesiones.' });
  } finally {
    if (connection) connection.release();
  }
});

router.post('/solicitud-cambio', limitarSolicitud, async (req, res) => {
  const datos = respuestaValidacion(
    res,
    esquemaSolicitud.safeParse(req.body || {}),
    'La solicitud debe incluir un tipo y un detalle válido, sin etiquetas HTML.'
  );
  if (!datos) return;
  const clienteId = idClienteAutenticado(req);
  if (!clienteId) return res.status(403).json({ error: 'La cuenta no tiene un perfil de cliente.' });

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [resultado] = await connection.query(
      `INSERT INTO solicitudes_cuenta (usuario_id, cliente_id, campo, detalle)
       VALUES (?, ?, ?, ?)`,
      [req.usuario.uid, clienteId, datos.campo, datos.detalle]
    );
    await encolarEventoCuenta(connection, `account-request:${resultado.insertId}`, {
      evento: 'admin.solicitud_cuenta',
      solicitud_id: Number(resultado.insertId),
      tipo: datos.campo,
      timestamp: new Date().toISOString()
    });
    await auditarCuenta(req.usuario, 'crear', ['solicitud_cambio'], resultado.insertId, connection);
    await connection.commit();
    return res.status(201).json({ ok: true, solicitudId: Number(resultado.insertId) });
  } catch (err) {
    if (connection) await connection.rollback();
    console.error('[mi-cuenta] No se pudo crear la solicitud:', err.code || 'ACCOUNT_REQUEST_FAILED');
    return res.status(500).json({ error: 'No fue posible guardar la solicitud.' });
  } finally {
    if (connection) connection.release();
  }
});

router.get('/solicitudes', requiereAdmin, requierePermiso('clientes.gestionar'), async (req, res) => {
  try {
    const [filas] = await pool.query(
      `SELECT id, cliente_id, campo, detalle, estado, respuesta_admin, creado_en,
              resuelta_en, resuelta_por
       FROM solicitudes_cuenta
       ORDER BY (estado = 'pendiente') DESC, creado_en DESC
       LIMIT 200`
    );
    res.set('Cache-Control', 'no-store');
    return res.json(filas);
  } catch (err) {
    console.error('[mi-cuenta] No se pudieron consultar solicitudes:', err.code || 'ACCOUNT_REQUEST_LIST_FAILED');
    return res.status(500).json({ error: 'No fue posible consultar las solicitudes.' });
  }
});

router.patch('/solicitudes/:id', requiereAdmin, requierePermiso('clientes.gestionar'), async (req, res) => {
  const datos = respuestaValidacion(
    res,
    esquemaDecision.safeParse(req.body || {}),
    'La decisión de administración no es válida.'
  );
  if (!datos) return;
  const solicitudId = Number(req.params.id);
  if (!Number.isSafeInteger(solicitudId) || solicitudId < 1) {
    return res.status(400).json({ error: 'Identificador de solicitud inválido.' });
  }
  try {
    const [resultado] = await pool.query(
      `UPDATE solicitudes_cuenta
       SET estado = ?, respuesta_admin = ?, resuelta_por = ?, resuelta_en = NOW()
       WHERE id = ? AND estado = 'pendiente'`,
      [datos.estado, datos.respuesta || null, req.usuario.uid, solicitudId]
    );
    if (resultado.affectedRows !== 1) {
      return res.status(404).json({ error: 'La solicitud no existe o ya fue resuelta.' });
    }
    await auditarCuenta(req.usuario, 'editar', ['solicitud_cambio_estado'], solicitudId);
    return res.json({ ok: true, estado: datos.estado });
  } catch (err) {
    console.error('[mi-cuenta] No se pudo resolver la solicitud:', err.code || 'ACCOUNT_REQUEST_DECISION_FAILED');
    return res.status(500).json({ error: 'No fue posible guardar la decisión.' });
  }
});

module.exports = router;
