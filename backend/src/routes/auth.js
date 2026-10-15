const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { rateLimit } = require('express-rate-limit');
const { pool } = require('../db');
const { hashCodigoMfa, compararHashesMfa, generarCodigoMfa } = require('../mfaCodes');
const {
  validarRegistro,
  camposEspecificosDe,
  configuracionPublica
} = require('../registroInstitucional');
const { crearReto, verificarCaptcha } = require('../seguridad/captcha');
const { compararContrasena } = require('../seguridad/contrasenas');
const { clavesConfiguradas } = require('../seguridad/cifradoCampos');
const { procesarRegistro, insertarRetoMfa } = require('../seguridad/registroVerificado');
const { enviarCorreoEnSegundoPlano } = require('../seguridad/correo');
const { avisarN8n } = require('../seguridad/avisosN8n');

// La institución del token solo sirve para la apariencia del portal. Las
// decisiones de acceso se toman con autorizacion.obtenerContexto() desde MySQL.
function institucionDeSesion(fila) {
  return fila.estado_verificacion === 'aprobado' ? fila.institucion_aprobada || null : null;
}

function datosVerificacionSesion(fila) {
  if (fila.rol === 'admin' || !fila.cliente_id) return {};
  return {
    estadoVerificacion: fila.estado_verificacion || 'pendiente',
    tipoInstitucion: fila.tipo_institucion || null
  };
}

const { secretoJwt } = require('../configSegura');
const JWT_EXPIRA = process.env.JWT_EXPIRES_IN || '2h';
const REFRESH_DIAS = Number(process.env.REFRESH_EXPIRES_DIAS || 7);

// Genera un refresh token aleatorio, guarda su HASH en la base de datos
// (nunca el valor real) y devuelve el token en texto plano para el cliente.
// mfaVerificadoEn = null significa "ahora" y se toma del reloj de MySQL: las
// comprobaciones de MFA reciente comparan contra NOW() y un Date de Node se
// escribiría en la zona horaria del proceso, no en la de la base.
async function generarRefreshToken(usuarioId, connection = pool, mfaVerificadoEn = null) {
  const tokenPlano = crypto.randomBytes(40).toString('hex');
  const hash = crypto.createHash('sha256').update(tokenPlano).digest('hex');
  const expiracion = new Date(Date.now() + REFRESH_DIAS * 24 * 60 * 60 * 1000);

  await connection.query(
    'INSERT INTO refresh_tokens (usuario_id, token_hash, fecha_expiracion, mfa_verificado_en) VALUES (?, ?, ?, COALESCE(?, NOW()))',
    [usuarioId, hash, expiracion, mfaVerificadoEn]
  );

  return tokenPlano;
}

function firmarAccessToken(payload) {
  return jwt.sign(payload, secretoJwt(), { expiresIn: JWT_EXPIRA });
}

// jwt.decode().exp viene en segundos desde epoch; el frontend necesita ms
function expiraEnMs(accessToken) {
  return jwt.decode(accessToken).exp * 1000;
}

const MFA_CODIGO_VIGENCIA_MINUTOS = 5;
const MFA_INTENTOS_MAXIMOS = 5;
const MFA_REENVIO_ESPERA_SEGUNDOS = 60;
const MFA_REENVIO_MAXIMOS = 5;
const MFA_REINTENTOS_LOGIN_VENTANA_MINUTOS = 15;
const MFA_REINTENTOS_LOGIN_MAXIMOS = 5;

function enmascararCorreo(correo) {
  const [nombre, dominio] = String(correo).split('@');
  if (!dominio) return 'tu correo registrado';
  const prefijo = nombre.length < 3 ? nombre[0] : nombre.slice(0, 2);
  return `${prefijo}${'*'.repeat(Math.max(2, nombre.length - prefijo.length))}@${dominio}`;
}

// El código se envía por correo directo (nodemailer) y en segundo plano: ni
// el correo ni el código pasan por n8n, y el envío no retrasa la respuesta.
function enviarCodigoMfa({ correo, codigo }) {
  enviarCorreoEnSegundoPlano({
    to: correo,
    subject: 'Tu código de acceso',
    text: `Tu código de acceso es: ${codigo}\n\nVence en ${MFA_CODIGO_VIGENCIA_MINUTOS} minutos y sirve una sola vez. Si no intentaste iniciar sesión, ignora este mensaje y cambia tu contraseña.`,
    html: `<p>Tu código de acceso es:</p><p style="font-size:24px;font-weight:700;letter-spacing:4px">${codigo}</p><p>Vence en ${MFA_CODIGO_VIGENCIA_MINUTOS} minutos y sirve una sola vez. Si no intentaste iniciar sesión, ignora este mensaje y cambia tu contraseña.</p>`
  });
}

function crearLimitadorMfa({ ventanaMs, limite, mensaje }) {
  return rateLimit({
    windowMs: ventanaMs,
    limit: limite,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => res.status(429).json({
      code: 'RATE_LIMITED',
      error: mensaje
    })
  });
}

const limitarLogin = crearLimitadorMfa({
  ventanaMs: 15 * 60 * 1000,
  limite: 10,
  mensaje: 'Demasiados intentos desde esta conexión. Espera 15 minutos e inténtalo de nuevo.'
});
const limitarVerificacionMfa = crearLimitadorMfa({
  ventanaMs: 15 * 60 * 1000,
  limite: 15,
  mensaje: 'Demasiadas verificaciones desde esta conexión. Espera 15 minutos e inténtalo de nuevo.'
});
const limitarReenvioMfa = crearLimitadorMfa({
  ventanaMs: 60 * 60 * 1000,
  limite: 10,
  mensaje: 'Se alcanzó el límite temporal de reenvíos desde esta conexión. Inténtalo más tarde.'
});

async function crearRetoMfa(usuario) {
  const retoId = crypto.randomBytes(32).toString('hex');
  const codigo = generarCodigoMfa();
  const creado = await insertarRetoMfa({
    usuarioId: usuario.id,
    retoId,
    codigoHash: hashCodigoMfa(retoId, usuario.id, codigo),
    vigenciaMinutos: MFA_CODIGO_VIGENCIA_MINUTOS,
    ventanaMinutos: MFA_REINTENTOS_LOGIN_VENTANA_MINUTOS,
    maximo: MFA_REINTENTOS_LOGIN_MAXIMOS
  });
  if (!creado) {
    const error = new Error('Demasiados intentos de acceso. Espera unos minutos antes de volver a intentarlo.');
    error.status = 429;
    throw error;
  }
  enviarCodigoMfa({ correo: usuario.correo, codigo });
  return { retoId, correoEnmascarado: enmascararCorreo(usuario.correo) };
}

const limitarRegistro = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: Number(process.env.REGISTRO_LIMITE_POR_HORA || 10),
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => process.env.NODE_ENV === 'test' && process.env.TEST_RATE_LIMITS !== '1',
  handler: (req, res) => res.status(429).json({
    code: 'RATE_LIMITED',
    error: 'Se alcanzó el límite de registros desde esta conexión. Inténtalo más tarde.'
  })
});

const limitarCaptcha = crearLimitadorMfa({
  ventanaMs: 15 * 60 * 1000,
  limite: 120,
  mensaje: 'Demasiadas solicitudes de captcha desde esta conexión. Espera unos minutos.'
});

// GET /api/auth/captcha -> { id, svg }. La respuesta nunca sale del servidor.
router.get('/captcha', limitarCaptcha, (req, res) => {
  const { id, svg } = crearReto();
  res.set('Cache-Control', 'no-store');
  res.json({ id, svg });
});

function captchaValido(body) {
  return verificarCaptcha(body?.captchaId, body?.captchaRespuesta);
}

function sinCamposCaptcha(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return body;
  const { captchaId, captchaRespuesta, ...resto } = body;
  return resto;
}

const ERROR_CAPTCHA = { code: 'CAPTCHA_INVALIDO', error: 'El resultado de la verificación no es correcto o ya venció. Resuelve la nueva operación.', errores: { captcha: 'Resuelve la operación de nuevo.' } };

// GET /api/auth/registro/tipos -> tipos de institución, campos y documentos
// requeridos. El formulario se construye con esta respuesta y el servidor
// vuelve a aplicar las mismas reglas al recibir el registro.
router.get('/registro/tipos', (req, res) => {
  res.set('Cache-Control', 'public, max-age=300');
  res.json({ tipos: configuracionPublica() });
});

const RESPUESTA_REGISTRO = Object.freeze({
  ok: true,
  estado: 'solicitud_recibida',
  mensaje: 'Solicitud recibida. Un administrador la revisará y te avisaremos por correo cuando tu cuenta quede habilitada.'
});

// POST /api/auth/registro -> solicitud de cuenta verificada.
//
// Campos: tipo de institución, nombre completo, NIT, correo, contraseña,
// aceptaciones y captcha. Se verifica la terna NIT + nombre + institución
// contra el padrón cifrado y SIEMPRE se crea una solicitud pendiente: el
// resultado es solo una bandera para el administrador. Al navegador se le
// responde lo mismo (202) exista o no el correo y salga como salga la
// verificación. Sin acceso hasta que un administrador apruebe.
router.post('/registro', limitarRegistro, async (req, res) => {
  if (!captchaValido(req.body)) return res.status(400).json(ERROR_CAPTCHA);
  const validacion = validarRegistro(sinCamposCaptcha(req.body));
  if (!validacion.ok) {
    return res.status(400).json({
      error: validacion.errores._ || 'Revisa los datos marcados del registro.',
      errores: validacion.errores
    });
  }
  if (!clavesConfiguradas()) {
    console.error('[auth] ENC_KEY/HMAC_KEY no configuradas: el registro está deshabilitado.');
    return res.status(503).json({ error: 'El registro no está disponible temporalmente.' });
  }
  const datos = validacion.datos;
  try {
    const resultado = await procesarRegistro(datos, { especificos: camposEspecificosDe(datos.tipoInstitucion, datos) });
    if (resultado.existente) {
      // El titular del correo se entera; quien intenta registrarse, no.
      enviarCorreoEnSegundoPlano({
        to: datos.correo,
        subject: 'Intento de registro con tu correo',
        text: 'Alguien intentó crear una cuenta con este correo, que ya tiene una cuenta o una solicitud en revisión. Si fuiste tú, inicia sesión. Si no, puedes ignorar este mensaje.'
      });
    } else {
      avisarN8n('registro.recibido', resultado.solicitudId, resultado.resultado);
    }
    return res.status(202).json(RESPUESTA_REGISTRO);
  } catch (err) {
    console.error('[auth] No se pudo registrar la solicitud:', err.code || 'REGISTRATION_FAILED');
    return res.status(500).json({ error: 'No se pudo recibir la solicitud. Inténtalo de nuevo.' });
  }
});

const MENSAJES_ESTADO_CUENTA = {
  pendiente: ['CUENTA_PENDIENTE', 'Tu solicitud de cuenta está en revisión. Te avisaremos por correo cuando un administrador la apruebe.'],
  rechazada: ['CUENTA_RECHAZADA', 'Tu solicitud de cuenta no fue aprobada. Revisa el correo que te enviamos; puedes registrarte de nuevo con los datos correctos.'],
  suspendida: ['CUENTA_SUSPENDIDA', 'Tu cuenta está suspendida. Comunícate con el administrador de la plataforma.']
};

// POST /api/auth/login -> paso 1: correo + contraseña + captcha.
// Si el correo no existe se compara contra un hash de relleno (mismo tiempo).
// El estado de la cuenta solo se revela después de validar la contraseña.
router.post('/login', limitarLogin, async (req, res) => {
  try {
    if (!captchaValido(req.body)) return res.status(400).json(ERROR_CAPTCHA);
    const correo = String(req.body?.correo || '').trim().toLowerCase();
    const { password } = req.body || {};
    if (!correo || typeof password !== 'string' || !password || password.length > 72) {
      return res.status(400).json({ error: 'Correo y contraseña son obligatorios' });
    }

    const [filas] = await pool.query(
      'SELECT id, correo, password_hash, estado_cuenta FROM usuarios WHERE correo = ?',
      [correo]
    );
    const usuario = filas[0];
    const coincide = await compararContrasena(password, usuario?.password_hash);
    if (!usuario || !coincide) {
      return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
    }
    if (usuario.estado_cuenta !== 'activa') {
      const [code, error] = MENSAJES_ESTADO_CUENTA[usuario.estado_cuenta] || MENSAJES_ESTADO_CUENTA.suspendida;
      return res.status(403).json({ code, error });
    }

    const reto = await crearRetoMfa(usuario);
    res.status(202).json({
      mfaRequired: true,
      challengeId: reto.retoId,
      expiresIn: MFA_CODIGO_VIGENCIA_MINUTOS * 60,
      correoEnmascarado: reto.correoEnmascarado,
      deliveryUnconfirmed: false
    });
  } catch (err) {
    if (err.status) {
      return res.status(err.status).json({ error: err.message });
    }
    console.error('[auth] Error iniciando el desafío MFA:', err.code || 'MFA_CHALLENGE_FAILED');
    res.status(503).json({ error: 'No fue posible iniciar la verificación de seguridad. Intenta de nuevo más tarde.' });
  }
});

router.post('/mfa/verificar', limitarVerificacionMfa, async (req, res) => {
  const retoId = String(req.body?.challengeId || '');
  const codigo = String(req.body?.code || '');
  if (!/^[a-f0-9]{64}$/.test(retoId) || !/^\d{6}$/.test(codigo)) {
    return res.status(400).json({ error: 'El código de seguridad debe contener seis dígitos.' });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [retos] = await connection.query(
      `SELECT r.usuario_id, r.codigo_hash, r.estado, r.intentos, r.proposito,
              (r.expira_en > NOW()) AS vigente,
              u.correo, u.rol, u.cliente_id, u.session_version, u.debe_cambiar_password, u.estado_cuenta,
              c.estado_verificacion, c.institucion_aprobada, c.tipo_institucion
       FROM retos_mfa r
       JOIN usuarios u ON u.id = r.usuario_id
       LEFT JOIN clientes c ON c.id = u.cliente_id
       WHERE r.reto_id = ? AND r.proposito = 'inicio_sesion'
       FOR UPDATE`,
      [retoId]
    );
    // Una cuenta suspendida entre el paso 1 y el 2 no completa el acceso.
    if (!retos.length || retos[0].estado !== 'pendiente' || retos[0].estado_cuenta !== 'activa') {
      await connection.rollback();
      return res.status(401).json({ error: 'El código no es válido o ya no está disponible. Inicia sesión nuevamente.' });
    }

    const reto = retos[0];
    if (!reto.vigente) {
      await connection.query("UPDATE retos_mfa SET estado = 'expirado' WHERE reto_id = ?", [retoId]);
      await connection.commit();
      return res.status(410).json({ error: 'El código expiró. Inicia sesión nuevamente para recibir otro.' });
    }

    if (Number(reto.intentos) >= MFA_INTENTOS_MAXIMOS) {
      await connection.query("UPDATE retos_mfa SET estado = 'bloqueado' WHERE reto_id = ?", [retoId]);
      await connection.commit();
      return res.status(429).json({ error: 'Se agotaron los intentos. Inicia sesión nuevamente para solicitar otro código.' });
    }

    let codigoCorrecto = false;
    try {
      codigoCorrecto = compararHashesMfa(
        reto.codigo_hash,
        hashCodigoMfa(retoId, reto.usuario_id, codigo)
      );
    } catch (err) {
      await connection.rollback();
      console.error('[auth] La clave de MFA no está configurada correctamente:', err.message);
      return res.status(503).json({ error: 'La verificación de seguridad no está disponible temporalmente.' });
    }

    if (!codigoCorrecto) {
      const intentosRestantes = MFA_INTENTOS_MAXIMOS - Number(reto.intentos) - 1;
      await connection.query(
        `UPDATE retos_mfa
         SET intentos = intentos + 1,
             estado = IF(intentos >= ?, 'bloqueado', 'pendiente')
         WHERE reto_id = ?`,
        [MFA_INTENTOS_MAXIMOS, retoId]
      );
      await connection.commit();
      return res.status(401).json({
        error: intentosRestantes > 0
          ? `El código no coincide. Te quedan ${intentosRestantes} intento(s).`
          : 'Se agotaron los intentos. Inicia sesión nuevamente para solicitar otro código.'
      });
    }

    const token = firmarAccessToken({
      uid: reto.usuario_id,
      correo: reto.correo,
      rol: reto.rol,
      clienteId: reto.cliente_id,
      institucionId: institucionDeSesion(reto),
      sv: Number(reto.session_version || 0),
      mfa: true
    });
    const refreshToken = await generarRefreshToken(reto.usuario_id, connection);
    await connection.query(
      "UPDATE retos_mfa SET estado = 'verificado' WHERE reto_id = ? AND estado = 'pendiente'",
      [retoId]
    );
    // El código llegó al buzón registrado: el correo queda verificado.
    await connection.query(
      'UPDATE usuarios SET correo_verificado_en = COALESCE(correo_verificado_en, NOW()) WHERE id = ?',
      [reto.usuario_id]
    );
    await connection.commit();

    res.json({
      token,
      refreshToken,
      expiraEn: expiraEnMs(token),
      correo: reto.correo,
      id: reto.usuario_id,
      clienteId: reto.cliente_id,
      rol: reto.rol,
      institucionId: institucionDeSesion(reto),
      ...datosVerificacionSesion(reto),
      debeCambiarPassword: Boolean(reto.debe_cambiar_password),
      mfaVerified: true
    });
  } catch (err) {
    if (connection) await connection.rollback();
    console.error('[auth] Error verificando MFA:', err.message);
    res.status(500).json({ error: 'No fue posible completar la verificación de seguridad.' });
  } finally {
    if (connection) connection.release();
  }
});

router.post('/mfa/reenviar', limitarReenvioMfa, async (req, res) => {
  const retoId = String(req.body?.challengeId || '');
  if (!/^[a-f0-9]{64}$/.test(retoId)) {
    return res.status(400).json({ error: 'La solicitud de reenvío no es válida.' });
  }

  try {
    const [retos] = await pool.query(
      `SELECT r.usuario_id, r.estado,
              (r.expira_en > NOW()) AS vigente,
              (TIMESTAMPDIFF(SECOND, r.enviado_en, NOW()) >= ?) AS puede_reenviar,
              (r.reenvios < ?) AS quedan_reenvios,
              u.correo
       FROM retos_mfa r
       JOIN usuarios u ON u.id = r.usuario_id
       WHERE r.reto_id = ? AND r.proposito = 'inicio_sesion'`,
      [MFA_REENVIO_ESPERA_SEGUNDOS, MFA_REENVIO_MAXIMOS, retoId]
    );
    if (!retos.length || retos[0].estado !== 'pendiente' || !retos[0].vigente) {
      return res.status(410).json({ error: 'El desafío expiró. Inicia sesión nuevamente.' });
    }
    if (!retos[0].puede_reenviar) {
      return res.status(429).json({ error: 'Espera un minuto antes de solicitar otro código.' });
    }
    if (!retos[0].quedan_reenvios) {
      return res.status(429).json({ error: 'Se agotaron los reenvíos disponibles. Inicia sesión nuevamente.' });
    }

    const codigo = generarCodigoMfa();
    const codigoHash = hashCodigoMfa(retoId, retos[0].usuario_id, codigo);
    const [actualizacion] = await pool.query(
      `UPDATE retos_mfa
       SET codigo_hash = ?, enviado_en = NOW(),
           expira_en = DATE_ADD(NOW(), INTERVAL ? MINUTE),
           reenvios = reenvios + 1
       WHERE reto_id = ? AND estado = 'pendiente'
         AND TIMESTAMPDIFF(SECOND, enviado_en, NOW()) >= ? AND expira_en > NOW()
         AND reenvios < ?`,
      [codigoHash, MFA_CODIGO_VIGENCIA_MINUTOS, retoId, MFA_REENVIO_ESPERA_SEGUNDOS, MFA_REENVIO_MAXIMOS]
    );
    if (!actualizacion.affectedRows) {
      return res.status(429).json({ error: 'No se pudo reenviar todavía. Intenta de nuevo en un minuto.' });
    }

    enviarCodigoMfa({ correo: retos[0].correo, codigo });
    res.json({
      ok: true,
      expiresIn: MFA_CODIGO_VIGENCIA_MINUTOS * 60,
      correoEnmascarado: enmascararCorreo(retos[0].correo)
    });
  } catch (err) {
    console.error('[auth] Error reenviando MFA:', err.message);
    res.status(503).json({ error: 'No fue posible reenviar el código temporalmente.' });
  }
});

router.post('/mfa/cancelar', async (req, res) => {
  const retoId = String(req.body?.challengeId || '');
  if (!/^[a-f0-9]{64}$/.test(retoId)) {
    return res.status(400).json({ error: 'La solicitud de cancelación no es válida.' });
  }
  try {
    await pool.query(
      "UPDATE retos_mfa SET estado = 'cancelado' WHERE reto_id = ? AND proposito = 'inicio_sesion' AND estado = 'pendiente'",
      [retoId]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('[auth] Error cancelando MFA:', err.message);
    res.status(500).json({ error: 'No fue posible cancelar el desafío temporalmente.' });
  }
});

// POST /api/auth/refresh -> canjea un refresh token válido por un access token nuevo
// Rota el refresh token en cada uso: revoca el usado y entrega uno nuevo,
// así uno robado tiene una sola oportunidad de usarse antes de invalidarse.
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ error: 'Falta el refresh token' });
    }

    const hash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const [filas] = await pool.query(
      `SELECT rt.id, rt.usuario_id, rt.fecha_expiracion, rt.mfa_verificado_en,
              u.correo, u.rol, u.cliente_id, u.session_version, u.estado_cuenta,
              c.estado_verificacion, c.institucion_aprobada, c.tipo_institucion
       FROM refresh_tokens rt
       JOIN usuarios u ON u.id = rt.usuario_id
       LEFT JOIN clientes c ON c.id = u.cliente_id
       WHERE rt.token_hash = ? AND rt.revocado = FALSE`,
      [hash]
    );

    if (!filas.length || filas[0].estado_cuenta !== 'activa') {
      return res.status(401).json({ error: 'Refresh token inválido' });
    }

    const registro = filas[0];
    if (!registro.mfa_verificado_en) {
      await pool.query('UPDATE refresh_tokens SET revocado = TRUE WHERE id = ?', [registro.id]);
      return res.status(401).json({ error: 'Inicia sesión nuevamente para completar la verificación de seguridad.' });
    }
    if (new Date(registro.fecha_expiracion) < new Date()) {
      return res.status(401).json({ error: 'Sesión expirada, inicia sesión de nuevo' });
    }

    // Rotación: invalida el token usado y emite uno nuevo
    await pool.query('UPDATE refresh_tokens SET revocado = TRUE WHERE id = ?', [registro.id]);
    const nuevoRefresh = await generarRefreshToken(registro.usuario_id, pool, registro.mfa_verificado_en);

    const nuevoAccess = firmarAccessToken({
      uid: registro.usuario_id,
      correo: registro.correo,
      rol: registro.rol,
      clienteId: registro.cliente_id,
      institucionId: institucionDeSesion(registro),
      sv: Number(registro.session_version || 0),
      mfa: true
    });

    res.json({
      token: nuevoAccess,
      refreshToken: nuevoRefresh,
      expiraEn: expiraEnMs(nuevoAccess),
      correo: registro.correo,
      clienteId: registro.cliente_id,
      rol: registro.rol,
      institucionId: institucionDeSesion(registro),
      ...datosVerificacionSesion(registro),
      mfaVerified: true
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error renovando la sesión' });
  }
});

// POST /api/auth/logout -> revoca el refresh token para que no se pueda reutilizar
router.post('/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) {
      const hash = crypto.createHash('sha256').update(refreshToken).digest('hex');
      await pool.query('UPDATE refresh_tokens SET revocado = TRUE WHERE token_hash = ?', [hash]);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error cerrando sesión' });
  }
});

const RUTAS_CON_CAMBIO_PENDIENTE = new Set(['GET /api/mi-cuenta/', 'GET /api/mi-cuenta', 'POST /api/mi-cuenta/password']);

// Middleware exportado para proteger otras rutas
async function requiereAutenticacion(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No autenticado' });
  let usuario;
  try {
    usuario = jwt.verify(token, secretoJwt(), { algorithms: ['HS256'] });
  } catch {
    return res.status(401).json({ error: 'Sesión inválida o expirada' });
  }
  if (usuario.mfa !== true) {
    return res.status(401).json({ error: 'Inicia sesión nuevamente para completar la verificación de seguridad.' });
  }

  const usuarioId = Number(usuario.uid);
  const versionToken = Number(usuario.sv || 0);
  if (!Number.isSafeInteger(usuarioId) || usuarioId < 1 ||
      !Number.isSafeInteger(versionToken) || versionToken < 0) {
    return res.status(401).json({ error: 'Sesión inválida o expirada' });
  }

  try {
    // Estado y rol se leen de la base en cada petición: suspender una cuenta o
    // quitarle el rol surte efecto de inmediato, aunque el JWT siga vigente.
    const [filas] = await pool.query(
      'SELECT session_version, debe_cambiar_password, estado_cuenta, rol FROM usuarios WHERE id = ?',
      [usuarioId]
    );
    if (!filas.length || Number(filas[0].session_version || 0) !== versionToken) {
      return res.status(401).json({ error: 'La sesión fue revocada. Inicia sesión nuevamente.' });
    }
    if (filas[0].estado_cuenta !== 'activa') {
      return res.status(403).json({ code: 'CUENTA_NO_ACTIVA', error: 'Tu cuenta no está habilitada.' });
    }
    usuario = { ...usuario, rol: filas[0].rol };
    // Credencial inicial (superadministrador o administrador sembrado): hasta
    // cambiarla solo se permite consultar la cuenta y cambiar la contraseña.
    if (filas[0].debe_cambiar_password && !RUTAS_CON_CAMBIO_PENDIENTE.has(`${req.method} ${req.baseUrl}${req.path}`)) {
      return res.status(403).json({ code: 'PASSWORD_CHANGE_REQUIRED', error: 'Debes cambiar tu contraseña inicial antes de continuar.' });
    }
    req.usuario = usuario;
    return next();
  } catch (err) {
    console.error('[auth] No se pudo validar la versión de sesión:', err.code || 'SESSION_VERSION_CHECK_FAILED');
    return res.status(503).json({ error: 'No fue posible validar la sesión temporalmente.' });
  }
}

function autenticacionOpcional(req, res, next) {
  if (!req.headers.authorization) return next();
  return requiereAutenticacion(req, res, next);
}

function requiereAdmin(req, res, next) {
  if (req.usuario?.rol !== 'admin') {
    return res.status(403).json({ error: 'Acceso restringido: solo administradores' });
  }
  next();
}

module.exports = { router, requiereAutenticacion, autenticacionOpcional, requiereAdmin };