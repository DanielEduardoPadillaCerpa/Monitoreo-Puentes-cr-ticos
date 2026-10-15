const { pool, poolTransacciones } = require('../db');
const { cifrar } = require('../crypto');
const { cifrarCampo, indiceCiego } = require('./cifradoCampos');
const { normalizarNit } = require('./normalizacion');
const { verificarEnPadron } = require('./padron');
const { hashContrasena } = require('./contrasenas');

// Ejecuta un lote "START TRANSACTION … COMMIT; SELECT …" en un solo viaje.
// Si una sentencia falla, MySQL detiene el lote con la transacción abierta:
// se revierte antes de devolver la conexión.
async function loteTransaccional(sql, valores) {
  const conexion = await poolTransacciones.getConnection();
  try {
    const [resultados] = await conexion.query(sql, valores);
    const ultimo = resultados[resultados.length - 1];
    return Array.isArray(ultimo) ? ultimo[0] || {} : {};
  } catch (err) {
    await conexion.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    conexion.release();
  }
}

// Varias sentencias independientes en un solo viaje (sin transacción).
// Devuelve el resultado de cada sentencia, en orden.
async function ejecutarLote(sql, valores) {
  const conexion = await poolTransacciones.getConnection();
  try {
    const [resultados] = await conexion.query(sql, valores);
    return resultados;
  } finally {
    conexion.release();
  }
}

const SQL_CUENTA_NUEVA = `
START TRANSACTION;
INSERT INTO clientes
  (nombre_funcionario, correo, tipo_institucion, estado_verificacion,
   dominio_verificado, datos_registro_cifrados, autorizacion_general, acepta_terminos_en)
VALUES (?, ?, ?, 'borrador', FALSE, ?, FALSE, NOW());
SET @cliente := LAST_INSERT_ID();
INSERT INTO usuarios (correo, password_hash, cliente_id, rol, estado_cuenta)
VALUES (?, ?, @cliente, 'cliente', 'pendiente');
SET @usuario := LAST_INSERT_ID();
INSERT INTO verificacion_historial (cliente_id, estado_anterior, estado_nuevo, evento, actor_usuario_id, actor_tipo)
VALUES (@cliente, NULL, 'borrador', 'registro', @usuario, 'cliente');
INSERT INTO solicitudes_registro
  (usuario_id, cliente_id, nit_hash, nit_cifrado, nombre_cifrado, tipo_institucion, resultado_verificacion)
VALUES (@usuario, @cliente, ?, ?, ?, ?, ?);
SET @solicitud := LAST_INSERT_ID();
COMMIT;
SELECT @solicitud AS solicitud_id;`;

// Una cuenta rechazada puede volver a solicitar con datos corregidos. Las
// cuentas pendientes o activas nunca se tocan desde el registro público.
const SQL_NUEVA_SOLICITUD = `
START TRANSACTION;
UPDATE usuarios SET password_hash = ?, estado_cuenta = 'pendiente'
WHERE id = ? AND estado_cuenta = 'rechazada';
SET @ok := ROW_COUNT();
UPDATE clientes SET nombre_funcionario = ?, tipo_institucion = ? WHERE id = ? AND @ok = 1;
INSERT INTO solicitudes_registro
  (usuario_id, cliente_id, nit_hash, nit_cifrado, nombre_cifrado, tipo_institucion, resultado_verificacion)
SELECT ?, ?, ?, ?, ?, ?, ? FROM DUAL WHERE @ok = 1;
SET @solicitud := IF(@ok = 1, LAST_INSERT_ID(), NULL);
COMMIT;
SELECT @solicitud AS solicitud_id;`;

// Registro verificado. Devuelve { solicitudId, resultado } o, si el correo ya
// tiene una cuenta pendiente o activa, { existente: true } sin modificar nada.
// La respuesta HTTP es idéntica en todos los casos.
async function procesarRegistro(datos, { especificos = {} } = {}) {
  const nit = normalizarNit(datos.nit);
  const [hash, [usuarios], verificacion] = await Promise.all([
    hashContrasena(datos.password),
    pool.query('SELECT id, cliente_id, estado_cuenta FROM usuarios WHERE correo = ?', [datos.correo]),
    verificarEnPadron(pool, { nit, nombre: datos.nombreCompleto, tipoInstitucion: datos.tipoInstitucion })
  ]);
  const existente = usuarios[0];
  if (existente && (existente.estado_cuenta !== 'rechazada' || !existente.cliente_id)) {
    return { existente: true };
  }

  const solicitud = [
    indiceCiego('nit', nit),
    cifrarCampo('solicitud.nit', nit),
    cifrarCampo('solicitud.nombre', datos.nombreCompleto),
    datos.tipoInstitucion,
    verificacion.resultado
  ];
  try {
    const fila = existente
      ? await loteTransaccional(SQL_NUEVA_SOLICITUD, [
        hash, existente.id,
        cifrar(datos.nombreCompleto), datos.tipoInstitucion, existente.cliente_id,
        existente.id, existente.cliente_id, ...solicitud
      ])
      : await loteTransaccional(SQL_CUENTA_NUEVA, [
        cifrar(datos.nombreCompleto),
        cifrar(datos.correo),
        datos.tipoInstitucion,
        Object.keys(especificos).length ? cifrar(JSON.stringify(especificos)) : null,
        datos.correo,
        hash,
        ...solicitud
      ]);
    if (!fila.solicitud_id) return { existente: true };
    return { solicitudId: Number(fila.solicitud_id), resultado: verificacion.resultado };
  } catch (err) {
    // Carrera con otro registro del mismo correo: misma respuesta que "existente".
    if (err.code === 'ER_DUP_ENTRY') return { existente: true };
    throw err;
  }
}

// Reto MFA de inicio de sesión en un solo viaje: limita a 5 retos por usuario
// cada 15 minutos, crea el nuevo y cancela los pendientes anteriores.
const SQL_RETO_MFA = `
START TRANSACTION;
SELECT id FROM usuarios WHERE id = ? FOR UPDATE;
INSERT INTO retos_mfa (reto_id, usuario_id, codigo_hash, expira_en)
SELECT ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE) FROM DUAL
WHERE (SELECT COUNT(*) FROM retos_mfa
       WHERE usuario_id = ? AND proposito = 'inicio_sesion'
         AND creado_en >= DATE_SUB(NOW(), INTERVAL ? MINUTE)) < ?;
SET @creado := ROW_COUNT();
UPDATE retos_mfa SET estado = 'cancelado'
WHERE usuario_id = ? AND proposito = 'inicio_sesion' AND estado = 'pendiente'
  AND reto_id <> ? AND @creado = 1;
COMMIT;
SELECT @creado AS creado;`;

async function insertarRetoMfa({ usuarioId, retoId, codigoHash, vigenciaMinutos, ventanaMinutos, maximo }) {
  const fila = await loteTransaccional(SQL_RETO_MFA, [
    usuarioId,
    retoId, usuarioId, codigoHash, vigenciaMinutos,
    usuarioId, ventanaMinutos, maximo,
    usuarioId, retoId
  ]);
  return Number(fila.creado) === 1;
}

module.exports = { procesarRegistro, insertarRetoMfa, loteTransaccional, ejecutarLote };
