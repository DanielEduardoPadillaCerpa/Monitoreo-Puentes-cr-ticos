const express = require('express');
const jwt = require('jsonwebtoken');
const { pool } = require('../db');
const { secretoJwt } = require('../configSegura');
const { descifrarCampo } = require('../seguridad/cifradoCampos');
const { verificarEnPadron } = require('../seguridad/padron');
const { ejecutarLote } = require('../seguridad/registroVerificado');
const { registrarAuditoria } = require('../auditoria');
const { enviarCorreoEnSegundoPlano, escaparHtml } = require('../seguridad/correo');
const { avisarN8n } = require('../seguridad/avisosN8n');

const router = express.Router();
const PERMISO = 'clientes.gestionar';

// ---------------------------------------------------------------------------
// Autenticación y autorización del panel
// ---------------------------------------------------------------------------
// Requisitos: JWT HS256 con MFA, sesión vigente (session_version), cuenta
// activa, rol admin LEÍDO DE LA BASE, sin contraseña inicial pendiente y con
// el permiso clientes.gestionar (o superadministrador).
//
// Rendimiento: el contador, aprobar y rechazar hacen UN solo viaje a MySQL.
// La fila del administrador se lee en el mismo lote que la operación y, en los
// UPDATE, las mismas condiciones van dentro del WHERE (CONDICION_ADMIN): si el
// administrador no es válido, el UPDATE no cambia nada.

const SQL_ADMIN = `SELECT a.session_version, a.debe_cambiar_password, a.estado_cuenta, a.rol, a.es_superadmin, a.correo,
       EXISTS (SELECT 1 FROM staff_permisos p WHERE p.usuario_id = a.id AND p.permiso = ?) AS tiene_permiso
FROM usuarios a WHERE a.id = ?`;

const CONDICION_ADMIN = `a.session_version = ? AND a.estado_cuenta = 'activa' AND a.rol = 'admin'
  AND a.debe_cambiar_password = FALSE
  AND (a.es_superadmin = TRUE OR EXISTS (SELECT 1 FROM staff_permisos p WHERE p.usuario_id = a.id AND p.permiso = ?))`;

function leerSesion(req) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return { error: [401, { error: 'No autenticado' }] };
  let datos;
  try {
    datos = jwt.verify(token, secretoJwt(), { algorithms: ['HS256'] });
  } catch {
    return { error: [401, { error: 'Sesión inválida o expirada' }] };
  }
  const uid = Number(datos.uid);
  const sv = Number(datos.sv || 0);
  if (datos.mfa !== true || !Number.isSafeInteger(uid) || uid < 1 || !Number.isSafeInteger(sv) || sv < 0) {
    return { error: [401, { error: 'Sesión inválida o expirada' }] };
  }
  return { uid, sv };
}

// Misma regla que CONDICION_ADMIN, evaluada en Node para responder el motivo.
function rechazoAdmin(fila, sv) {
  if (!fila || Number(fila.session_version || 0) !== sv) {
    return [401, { error: 'La sesión fue revocada. Inicia sesión nuevamente.' }];
  }
  if (fila.estado_cuenta !== 'activa' || fila.rol !== 'admin') {
    return [403, { error: 'Acceso restringido: solo administradores.' }];
  }
  if (fila.debe_cambiar_password) {
    return [403, { code: 'PASSWORD_CHANGE_REQUIRED', error: 'Debes cambiar tu contraseña inicial antes de continuar.' }];
  }
  if (!fila.es_superadmin && !Number(fila.tiene_permiso)) {
    return [403, { error: 'Tu rol administrativo no tiene permiso para esta acción.', permisoRequerido: PERMISO }];
  }
  return null;
}

// Solo valida el JWT (sin base): las rutas de un viaje autorizan en su lote.
function requiereSesion(req, res, next) {
  const sesion = leerSesion(req);
  if (sesion.error) return res.status(sesion.error[0]).json(sesion.error[1]);
  req.sesion = sesion;
  return next();
}

// Para lista y detalle: una consulta de autorización antes de leer datos.
async function requiereAdmin(req, res, next) {
  try {
    const [filas] = await pool.query(SQL_ADMIN, [PERMISO, req.sesion.uid]);
    const rechazo = rechazoAdmin(filas[0], req.sesion.sv);
    if (rechazo) return res.status(rechazo[0]).json(rechazo[1]);
    req.usuario = { uid: req.sesion.uid, correo: filas[0].correo, rol: 'admin' };
    return next();
  } catch (err) {
    console.error('[solicitudes] No se pudo validar la sesión:', err.code || 'SESSION_CHECK_FAILED');
    return res.status(503).json({ error: 'No fue posible validar la sesión temporalmente.' });
  }
}

router.use(requiereSesion);

const ESTADOS = new Set(['pendiente', 'aprobada', 'rechazada']);
const idValido = valor => /^\d{1,15}$/.test(String(valor));

// GET /api/admin/solicitudes/contador -> { pendientes }. COUNT sobre el índice
// (estado, creado_en, id), en el mismo viaje que la autorización.
router.get('/contador', async (req, res) => {
  try {
    const [filasAdmin, [conteo]] = await ejecutarLote(
      `${SQL_ADMIN};
       SELECT COUNT(*) AS pendientes FROM solicitudes_registro WHERE estado = 'pendiente'`,
      [PERMISO, req.sesion.uid]
    );
    const rechazo = rechazoAdmin(filasAdmin[0], req.sesion.sv);
    if (rechazo) return res.status(rechazo[0]).json(rechazo[1]);
    res.set('Cache-Control', 'no-store');
    res.json({ pendientes: Number(conteo.pendientes) });
  } catch (err) {
    console.error('[solicitudes] Error contando:', err.code || 'COUNT_FAILED');
    res.status(503).json({ error: 'No disponible temporalmente.' });
  }
});

// GET /api/admin/solicitudes?estado=pendiente -> lista SIN NIT ni nombre:
// correo, institución, estado, bandera de verificación y fecha. No descifra nada.
router.get('/', requiereAdmin, async (req, res) => {
  const estado = ESTADOS.has(req.query.estado) ? req.query.estado : 'pendiente';
  const limite = Math.min(Math.max(Number(req.query.limite) || 100, 1), 200);
  try {
    const [filas] = await pool.query(
      `SELECT s.id, u.correo, s.tipo_institucion, s.estado, s.resultado_verificacion, s.creado_en, s.decidida_en
       FROM solicitudes_registro s
       JOIN usuarios u ON u.id = s.usuario_id
       WHERE s.estado = ?
       ORDER BY s.creado_en DESC, s.id DESC
       LIMIT ?`,
      [estado, limite]
    );
    res.set('Cache-Control', 'no-store');
    res.json({
      solicitudes: filas.map(f => ({
        id: Number(f.id),
        correo: f.correo,
        tipoInstitucion: f.tipo_institucion,
        estado: f.estado,
        resultado: f.resultado_verificacion,
        creadoEn: f.creado_en,
        decididaEn: f.decidida_en
      }))
    });
  } catch (err) {
    console.error('[solicitudes] Error listando:', err.code || 'LIST_FAILED');
    res.status(503).json({ error: 'No disponible temporalmente.' });
  }
});

// GET /api/admin/solicitudes/:id -> detalle descifrado en el servidor, con el
// nombre del padrón al lado y la verificación repetida en este momento.
router.get('/:id', requiereAdmin, async (req, res) => {
  if (!idValido(req.params.id)) return res.status(400).json({ error: 'Solicitud inválida.' });
  try {
    const [filas] = await pool.query(
      `SELECT s.id, s.nit_cifrado, s.nombre_cifrado, s.tipo_institucion, s.estado, s.resultado_verificacion,
              s.motivo_rechazo, s.creado_en, s.decidida_en, u.correo, a.correo AS decidida_por_correo
       FROM solicitudes_registro s
       JOIN usuarios u ON u.id = s.usuario_id
       LEFT JOIN usuarios a ON a.id = s.decidida_por
       WHERE s.id = ?`,
      [req.params.id]
    );
    const fila = filas[0];
    if (!fila) return res.status(404).json({ error: 'Solicitud no encontrada.' });
    const nit = descifrarCampo('solicitud.nit', fila.nit_cifrado);
    const nombre = descifrarCampo('solicitud.nombre', fila.nombre_cifrado);
    const actual = await verificarEnPadron(pool, { nit, nombre, tipoInstitucion: fila.tipo_institucion }, { incluirDetalle: true });
    res.set('Cache-Control', 'no-store');
    res.json({
      id: Number(fila.id),
      correo: fila.correo,
      declarado: { nombre, nit, tipoInstitucion: fila.tipo_institucion },
      padron: actual.coincidencia,
      resultadoAlRegistrar: fila.resultado_verificacion,
      resultadoAhora: actual.resultado,
      estado: fila.estado,
      motivoRechazo: fila.motivo_rechazo,
      creadoEn: fila.creado_en,
      decididaEn: fila.decidida_en,
      decididaPor: fila.decidida_por_correo || null
    });
    registrarAuditoria({ usuario: req.usuario, accion: 'ver_solicitud_registro', entidad: 'solicitud_registro', entidadId: fila.id });
  } catch (err) {
    console.error('[solicitudes] Error en detalle:', err.code || 'DETAIL_FAILED');
    res.status(503).json({ error: 'No disponible temporalmente.' });
  }
});

// Correo del solicitante para avisarle la decisión (fuera de la respuesta).
// Aviso al solicitante por correo, fuera de la respuesta.
function avisarSolicitante(correo, aprobada, motivo) {
  if (!correo) return;
  enviarCorreoEnSegundoPlano(aprobada
    ? {
      to: correo,
      subject: 'Tu cuenta fue aprobada',
      text: 'Tu solicitud de cuenta fue aprobada. Ya puedes iniciar sesión; te enviaremos un código de seguridad a este correo.'
    }
    : {
      to: correo,
      subject: 'Tu solicitud de cuenta no fue aprobada',
      text: `Tu solicitud de cuenta no fue aprobada.\n\nMotivo: ${motivo}\n\nPuedes registrarte de nuevo con los datos correctos.`,
      html: `<p>Tu solicitud de cuenta no fue aprobada.</p><p><strong>Motivo:</strong> ${escaparHtml(motivo)}</p><p>Puedes registrarte de nuevo con los datos correctos.</p>`
    });
}

// Diagnóstico solo cuando la decisión no se aplicó (camino poco frecuente).
async function motivoNoAplicada(id) {
  const [filas] = await pool.query('SELECT estado, resultado_verificacion FROM solicitudes_registro WHERE id = ?', [id]);
  if (!filas[0]) return { status: 404, error: 'Solicitud no encontrada.' };
  if (filas[0].estado !== 'pendiente') {
    return { status: 409, code: 'YA_DECIDIDA', error: `La solicitud ya fue ${filas[0].estado} por otro administrador.`, estado: filas[0].estado };
  }
  return {
    status: 409,
    code: 'CONFIRMACION_REQUERIDA',
    error: 'La verificación contra el padrón no coincide. Confirma explícitamente para aprobar.',
    resultado: filas[0].resultado_verificacion
  };
}

// Aprobar y rechazar: UN solo viaje a MySQL con tres sentencias:
//   1. la fila del administrador (para responder 401/403 con el motivo),
//   2. el UPDATE atómico sobre la solicitud y la cuenta, condicionado a que la
//      solicitud siga pendiente Y a que el administrador sea válido,
//   3. el correo del solicitante, para avisarle sin otra consulta.
// affectedRows = 2 (solicitud + cuenta) indica que la decisión se aplicó.
async function decidir(req, { sqlSet, condicionExtra = '', valoresSet, valoresExtra = [] }) {
  const { uid, sv } = req.sesion;
  const [filasAdmin, actualizacion, filasCorreo] = await ejecutarLote(
    `${SQL_ADMIN};
     UPDATE solicitudes_registro s
     JOIN usuarios u ON u.id = s.usuario_id
     JOIN usuarios a ON a.id = ?
     SET ${sqlSet}, s.decidida_por = a.id, s.decidida_en = NOW()
     WHERE s.id = ? AND s.estado = 'pendiente' AND u.estado_cuenta = 'pendiente'
       ${condicionExtra}
       AND ${CONDICION_ADMIN};
     SELECT u.correo FROM solicitudes_registro s JOIN usuarios u ON u.id = s.usuario_id WHERE s.id = ?`,
    [PERMISO, uid, uid, ...valoresSet, req.params.id, ...valoresExtra, sv, PERMISO, req.params.id]
  );
  return {
    rechazo: rechazoAdmin(filasAdmin[0], sv),
    aplicada: actualizacion.affectedRows === 2,
    admin: filasAdmin[0] ? { uid, correo: filasAdmin[0].correo, rol: 'admin' } : null,
    correoSolicitante: filasCorreo[0]?.correo || null
  };
}

// POST /api/admin/solicitudes/:id/aprobar  { confirmar?: true }
// Si la verificación no dio "coincide", aprobar exige confirmar: true.
router.post('/:id/aprobar', async (req, res) => {
  if (!idValido(req.params.id)) return res.status(400).json({ error: 'Solicitud inválida.' });
  const confirmar = req.body?.confirmar === true;
  try {
    const r = await decidir(req, {
      sqlSet: "s.estado = 'aprobada', u.estado_cuenta = 'activa'",
      valoresSet: [],
      condicionExtra: "AND (s.resultado_verificacion = 'coincide' OR ? = 1)",
      valoresExtra: [confirmar ? 1 : 0]
    });
    if (r.rechazo) return res.status(r.rechazo[0]).json(r.rechazo[1]);
    if (!r.aplicada) {
      const motivo = await motivoNoAplicada(req.params.id);
      return res.status(motivo.status).json(motivo);
    }
    res.json({ ok: true, id: Number(req.params.id), estado: 'aprobada' });
    registrarAuditoria({
      usuario: r.admin, accion: 'aprobar_registro', entidad: 'solicitud_registro', entidadId: req.params.id,
      detalle: { confirmacionExplicita: confirmar }
    });
    avisarN8n('registro.aprobado', req.params.id, 'aprobada');
    avisarSolicitante(r.correoSolicitante, true);
  } catch (err) {
    console.error('[solicitudes] Error aprobando:', err.code || 'APPROVE_FAILED');
    if (!res.headersSent) res.status(503).json({ error: 'No fue posible aprobar temporalmente.' });
  }
});

// POST /api/admin/solicitudes/:id/rechazar  { motivo }
router.post('/:id/rechazar', async (req, res) => {
  if (!idValido(req.params.id)) return res.status(400).json({ error: 'Solicitud inválida.' });
  const motivo = typeof req.body?.motivo === 'string' ? req.body.motivo.trim() : '';
  if (motivo.length < 5 || motivo.length > 500) {
    return res.status(400).json({ error: 'Escribe el motivo del rechazo (entre 5 y 500 caracteres).' });
  }
  try {
    const r = await decidir(req, {
      sqlSet: "s.estado = 'rechazada', s.motivo_rechazo = ?, u.estado_cuenta = 'rechazada'",
      valoresSet: [motivo]
    });
    if (r.rechazo) return res.status(r.rechazo[0]).json(r.rechazo[1]);
    if (!r.aplicada) {
      const diagnostico = await motivoNoAplicada(req.params.id);
      return res.status(diagnostico.status).json(diagnostico.code === 'CONFIRMACION_REQUERIDA'
        ? { error: 'No se pudo rechazar: la cuenta asociada no está pendiente.' }
        : diagnostico);
    }
    res.json({ ok: true, id: Number(req.params.id), estado: 'rechazada' });
    // El motivo no va a la auditoría: puede contener datos personales.
    registrarAuditoria({ usuario: r.admin, accion: 'rechazar_registro', entidad: 'solicitud_registro', entidadId: req.params.id });
    avisarN8n('registro.rechazado', req.params.id, 'rechazada');
    avisarSolicitante(r.correoSolicitante, false, motivo);
  } catch (err) {
    console.error('[solicitudes] Error rechazando:', err.code || 'REJECT_FAILED');
    if (!res.headersSent) res.status(503).json({ error: 'No fue posible rechazar temporalmente.' });
  }
});

module.exports = router;
