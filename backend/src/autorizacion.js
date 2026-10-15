const { pool } = require('./db');
const { datosPublicosInvitado } = require('./tenancy');

// Servicio central de autorización del comprador.
//
// El JWT solo identifica a la persona (uid + versión de sesión). Estado de la
// cuenta, verificación vigente, institución verificada y autorización de
// restringidos se leen de MySQL en cada decisión, de modo que aprobar, vencer,
// rechazar o suspender surte efecto en la siguiente petición.
//
// Separación de conceptos:
//   autenticación    → sesión con MFA (routes/auth.js)
//   cuenta activa    → correo verificado y no suspendida: compra de uso general
//   verificación     → identidad y vínculo institucional comprobados y vigentes
//   autorización     → decisión por producto (evaluarProducto) y, para
//                      restringidos, autorización de compra por operación

const PERMISOS_STAFF = Object.freeze({
  'verificacion.ver': 'Consultar solicitudes de verificación y sus datos',
  'verificacion.decidir': 'Registrar la revisión documental y aprobar, rechazar o pedir información',
  'verificacion.confirmar_institucion': 'Registrar la confirmación institucional por canal oficial (segunda comprobación)',
  'documentos.ver': 'Descargar documentos de acreditación',
  'identificadores.ver': 'Ver el número completo de un documento de identidad (acceso excepcional, con justificación)',
  'cuentas.suspender': 'Suspender y reactivar cuentas',
  'restringidos.autorizar': 'Conceder o revocar la autorización de productos restringidos',
  'productos.cumplimiento': 'Configurar elegibilidad, restricción y revisión legal de productos',
  'catalogo.gestionar': 'Crear, editar y retirar productos y categorías',
  'pedidos.gestionar': 'Consultar y actualizar pedidos de todos los clientes',
  'clientes.gestionar': 'Consultar y gestionar fichas de clientes y solicitudes de cuenta',
  'auditoria.ver': 'Consultar el registro de auditoría',
  'staff.permisos': 'Crear personal administrativo y asignar permisos'
});

// Acceso a datos personales: ni siquiera el superadministrador los tiene por
// defecto; se conceden de forma explícita y quedan auditados.
const PERMISOS_DATOS_PERSONALES = new Set(['documentos.ver', 'identificadores.ver']);

// Solo un superadministrador puede conceder o retirar estos permisos.
const PERMISOS_RESERVADOS_SUPERADMIN = new Set(['staff.permisos', 'identificadores.ver']);

const ESTADOS_VERIFICACION = Object.freeze([
  'borrador', 'pendiente', 'requiere_informacion', 'aprobado', 'rechazado', 'suspendido'
]);

const REVISION_QUE_BLOQUEA_VENTA = new Set(['pendiente', 'bloqueada']);

const CONTEXTO_INVITADO = Object.freeze({
  autenticado: false,
  staff: false,
  cuentaActiva: false,
  aprobado: false,
  institucion: null,
  autorizadoRestringidos: false,
  estado: null
});

async function obtenerPermisosStaff(usuarioId, db = pool, { superadmin = false } = {}) {
  const [filas] = await db.query('SELECT permiso FROM staff_permisos WHERE usuario_id = ?', [usuarioId]);
  const permisos = new Set(filas.map(fila => fila.permiso).filter(p => Object.prototype.hasOwnProperty.call(PERMISOS_STAFF, p)));
  if (superadmin) {
    for (const permiso of Object.keys(PERMISOS_STAFF)) {
      if (!PERMISOS_DATOS_PERSONALES.has(permiso)) permisos.add(permiso);
    }
  }
  return permisos;
}

function verificacionVigente(fila, ahora = new Date()) {
  return !fila.verificado_hasta || new Date(fila.verificado_hasta) > ahora;
}

// Construye el contexto a partir de la base de datos. `bloquear` se usa dentro
// de transacciones (checkout) para leer la fila con FOR UPDATE.
async function obtenerContexto(usuarioToken, { db = pool, bloquear = false } = {}) {
  if (!usuarioToken) return CONTEXTO_INVITADO;
  const usuarioId = Number(usuarioToken.uid);
  if (!Number.isSafeInteger(usuarioId) || usuarioId < 1) return CONTEXTO_INVITADO;

  const [filas] = await db.query(
    `SELECT u.id, u.rol, u.cliente_id, u.correo_verificado_en, u.es_superadmin, u.es_cuenta_prueba, u.estado_cuenta,
            c.estado_verificacion, c.institucion_aprobada, c.tipo_institucion,
            c.autorizacion_general, c.verificado_hasta
     FROM usuarios u
     LEFT JOIN clientes c ON c.id = u.cliente_id
     WHERE u.id = ?${bloquear ? ' FOR UPDATE' : ''}`,
    [usuarioId]
  );
  const fila = filas[0];
  if (!fila || !fila.id) return CONTEXTO_INVITADO;

  if (fila.rol === 'admin') {
    const superadmin = Boolean(fila.es_superadmin);
    return {
      autenticado: true,
      staff: true,
      superadmin,
      usuarioId,
      permisos: await obtenerPermisosStaff(usuarioId, db, { superadmin }),
      cuentaActiva: false,
      aprobado: false,
      institucion: null,
      autorizadoRestringidos: false,
      estado: null
    };
  }

  const estado = fila.cliente_id ? fila.estado_verificacion || 'borrador' : null;
  const correoVerificado = Boolean(fila.correo_verificado_en);
  // Cuenta aprobada por un administrador (registro verificado), correo
  // confirmado con MFA y sin suspensión.
  const cuentaActiva = Boolean(fila.cliente_id) && fila.estado_cuenta === 'activa' && correoVerificado && estado !== 'suspendido';
  const aprobadoEnBase = cuentaActiva && estado === 'aprobado' && Boolean(fila.institucion_aprobada);
  const vigente = verificacionVigente(fila);
  const aprobado = aprobadoEnBase && vigente;
  return {
    autenticado: true,
    staff: false,
    usuarioId,
    clienteId: fila.cliente_id ? Number(fila.cliente_id) : null,
    estado,
    tipoInstitucion: fila.tipo_institucion || null,
    correoVerificado,
    cuentaActiva,
    cuentaPrueba: Boolean(fila.es_cuenta_prueba),
    aprobado,
    verificacionVencida: aprobadoEnBase && !vigente,
    verificadoHasta: fila.verificado_hasta || null,
    institucion: aprobado ? fila.institucion_aprobada : null,
    // Institución que rige el catálogo de uso general: la verificada o, si no
    // la hay, la declarada en el registro (la declaración no es acreditación).
    institucionCatalogo: aprobado ? fila.institucion_aprobada : (cuentaActiva ? fila.tipo_institucion || null : null),
    autorizadoRestringidos: aprobado && Boolean(fila.autorizacion_general)
  };
}

function leerMetadatos(producto) {
  if (!producto.metadatos) return null;
  if (typeof producto.metadatos === 'object') return producto.metadatos;
  try {
    return JSON.parse(producto.metadatos);
  } catch {
    return null;
  }
}

function institucionesElegibles(producto) {
  const extra = Array.isArray(producto.instituciones_elegibles)
    ? producto.instituciones_elegibles
    : String(producto.instituciones_elegibles || '').split(',').filter(Boolean);
  return new Set([producto.institucion_id, ...extra]);
}

// Sin institución solo es elegible lo de uso general.
function esElegible(producto, institucion) {
  const elegibles = institucionesElegibles(producto);
  return elegibles.has('general') || (Boolean(institucion) && elegibles.has(institucion));
}

function esRestringido(producto) {
  return producto.restringido === true || Number(producto.restringido) === 1;
}

function compraBloqueadaPorEntorno(ctx) {
  // Las cuentas sintéticas de prueba nunca compran en producción.
  return ctx.cuentaPrueba && process.env.NODE_ENV === 'production';
}

// Decide qué puede hacer el contexto con un producto.
//   visible:     si el producto existe para este usuario (si no: 404 / omitido)
//   nivel:       'completo' (precio, inventario) o 'vitrina' (nombre e imagen)
//   puedeComprar y motivo: para el carrito, el checkout y los mensajes de UI
//   requiereAutorizacionCompra: el checkout exigirá una autorización por operación
function evaluarProducto(producto, ctx) {
  const oculto = { visible: false, nivel: null, puedeComprar: false, motivo: 'no_disponible' };
  if (!producto) return oculto;
  if (ctx.staff) return { visible: true, nivel: 'completo', puedeComprar: false, motivo: 'personal_administrativo' };
  if (producto.estado !== 'activo') return oculto;

  const revision = producto.revision_legal || 'no_requerida';
  const restringido = esRestringido(producto);

  // Un producto restringido solo existe para cuentas con verificación vigente
  // de una institución elegible: no aparece en listados, búsquedas, asistente
  // ni detalle para nadie más (la declaración del registro no basta).
  if (restringido && !(ctx.aprobado && esElegible(producto, ctx.institucion))) return oculto;
  if (revision === 'bloqueada') return oculto;

  if (!ctx.autenticado) return { visible: true, nivel: 'vitrina', puedeComprar: false, motivo: 'requiere_login' };
  if (!ctx.cuentaActiva) {
    return {
      visible: true,
      nivel: 'vitrina',
      puedeComprar: false,
      motivo: ctx.estado === 'suspendido' ? 'cuenta_suspendida' : 'cuenta_no_activa'
    };
  }
  if (!esElegible(producto, ctx.institucionCatalogo)) return oculto;

  let motivo = null;
  if (REVISION_QUE_BLOQUEA_VENTA.has(revision)) motivo = 'revision_legal_pendiente';
  else if (restringido && !ctx.autorizadoRestringidos) motivo = 'requiere_autorizacion_restringidos';
  else if (leerMetadatos(producto)?.cotizacion_requerida === true) motivo = 'cotizacion_requerida';
  else if (compraBloqueadaPorEntorno(ctx)) motivo = 'cuenta_de_prueba';
  return {
    visible: true,
    nivel: 'completo',
    puedeComprar: motivo === null,
    motivo,
    requiereAutorizacionCompra: restringido
  };
}

// Forma de un producto que viaja al navegador según la decisión anterior.
function presentarProducto(producto, decision) {
  const { instituciones_elegibles: _extra, ...resto } = producto;
  const base = decision.nivel === 'vitrina' ? datosPublicosInvitado(resto) : resto;
  if (decision.nivel === 'vitrina') delete base.revision_legal;
  return {
    ...base,
    acceso: {
      nivel: decision.nivel,
      puedeComprar: decision.puedeComprar,
      motivo: decision.motivo,
      requiereAutorizacionCompra: Boolean(decision.requiereAutorizacionCompra)
    }
  };
}

function claveCache(ctx) {
  if (ctx.staff) return 'staff';
  if (!ctx.autenticado) return 'invitado';
  if (!ctx.cuentaActiva) return `inactiva:${ctx.estado === 'suspendido' ? 's' : 'n'}`;
  const prueba = compraBloqueadaPorEntorno(ctx) ? ':prueba' : '';
  if (!ctx.aprobado) return `activa:${ctx.institucionCatalogo || 'general'}${prueba}`;
  return `aprobado:${ctx.institucion}:${ctx.autorizadoRestringidos ? 'r' : 'nr'}${prueba}`;
}

// Middleware: exige el permiso administrativo indicado, leído de la base de
// datos (no del token). Debe ir después de requiereAutenticacion.
function requierePermiso(...permisos) {
  return async (req, res, next) => {
    try {
      const ctx = await obtenerContexto(req.usuario);
      if (!ctx.staff) return res.status(403).json({ error: 'Acceso restringido: solo personal administrativo.' });
      const faltante = permisos.find(permiso => !ctx.permisos.has(permiso));
      if (faltante) {
        return res.status(403).json({ error: 'Tu rol administrativo no tiene permiso para esta acción.', permisoRequerido: faltante });
      }
      req.contextoStaff = ctx;
      return next();
    } catch (err) {
      console.error('[autorizacion] No se pudo verificar el permiso:', err.code || 'PERMISSION_CHECK_FAILED');
      return res.status(503).json({ error: 'No fue posible verificar tus permisos temporalmente.' });
    }
  };
}

function requiereSuperadmin() {
  return async (req, res, next) => {
    try {
      const ctx = await obtenerContexto(req.usuario);
      if (!ctx.staff || !ctx.superadmin) {
        return res.status(403).json({ error: 'Acción reservada al superadministrador.' });
      }
      req.contextoStaff = ctx;
      return next();
    } catch (err) {
      console.error('[autorizacion] No se pudo verificar el superadministrador:', err.code || 'PERMISSION_CHECK_FAILED');
      return res.status(503).json({ error: 'No fue posible verificar tus permisos temporalmente.' });
    }
  };
}

module.exports = {
  PERMISOS_STAFF,
  PERMISOS_DATOS_PERSONALES,
  PERMISOS_RESERVADOS_SUPERADMIN,
  ESTADOS_VERIFICACION,
  CONTEXTO_INVITADO,
  obtenerContexto,
  obtenerPermisosStaff,
  evaluarProducto,
  presentarProducto,
  esElegible,
  esRestringido,
  claveCache,
  requierePermiso,
  requiereSuperadmin
};
