const mysql = require('mysql2/promise');
const { cifrarCampo, descifrarCampo, indiceCiego, igualesTiempoConstante } = require('./cifradoCampos');
const { normalizarNit, normalizarNombre } = require('./normalizacion');

// Padrón institucional cifrado (copia local de la fuente oficial).
//
// En el laboratorio la "fuente oficial" es la base MySQL que simula la del
// Estado (PADRON_DB_URI, tabla personas_institucionales_prueba). Se copia a
// padron_institucional con:
//   nit_hash       HMAC del NIT normalizado (índice ciego, buscable)
//   nombre_cifrado AES-256-GCM, AAD "padron.nombre" (solo se descifra en memoria)
//   entidad_cifrada AES-256-GCM, AAD "padron.entidad"
//   tipo_institucion en claro: es una categoría (policia, defensa…), no un dato personal
// El NIT nunca se guarda en claro en nuestra base.
//
// La fuente no se modifica nunca (solo SELECT): borrar su texto plano
// equivaldría a borrar el registro del Estado.

const RESULTADOS = Object.freeze([
  'coincide',
  'nit_no_existe',
  'nombre_no_coincide',
  'institucion_no_coincide',
  'persona_inactiva',
  'padron_no_disponible'
]);

// Verificación de una terna (NIT, nombre, institución).
//
// 1. Busca por índice ciego del NIT (una sola consulta con índice).
// 2. Descifra en memoria el nombre de cada funcionario de ese NIT y lo compara
//    en tiempo constante contra el nombre normalizado (se recorren todas las
//    filas aunque haya coincidencia temprana).
// 3. Con el funcionario identificado, revisa que la institución declarada sea
//    la del padrón y que esté activo.
//
// Devuelve { resultado, coincidencia } donde coincidencia (solo para el panel
// del administrador) trae el nombre y la entidad del padrón descifrados.
async function verificarEnPadron(db, { nit, nombre, tipoInstitucion }, { incluirDetalle = false } = {}) {
  const nitNormalizado = normalizarNit(nit);
  if (!nitNormalizado) return { resultado: 'nit_no_existe', coincidencia: null };
  let filas;
  try {
    [filas] = await db.query(
      `SELECT id, nombre_cifrado, entidad_cifrada, tipo_institucion, estado
       FROM padron_institucional WHERE nit_hash = ?`,
      [indiceCiego('nit', nitNormalizado)]
    );
  } catch (err) {
    console.error('[padron] Consulta no disponible:', err.code || 'PADRON_QUERY_FAILED');
    return { resultado: 'padron_no_disponible', coincidencia: null };
  }
  if (!filas.length) return { resultado: 'nit_no_existe', coincidencia: null };

  const nombreBuscado = normalizarNombre(nombre);
  let encontrada = null;
  for (const fila of filas) {
    let nombrePadron;
    try {
      nombrePadron = descifrarCampo('padron.nombre', fila.nombre_cifrado);
    } catch {
      continue;
    }
    const igual = igualesTiempoConstante(normalizarNombre(nombrePadron), nombreBuscado);
    if (igual && !encontrada) encontrada = { fila, nombrePadron };
  }

  const detalle = fila => (incluirDetalle ? {
    padronId: Number(fila.fila.id),
    nombre: fila.nombrePadron,
    entidad: (() => { try { return descifrarCampo('padron.entidad', fila.fila.entidad_cifrada); } catch { return null; } })(),
    tipoInstitucion: fila.fila.tipo_institucion,
    estado: fila.fila.estado
  } : null);

  if (!encontrada) {
    // Para el administrador: a qué institución pertenece ese NIT según el padrón.
    const tiposDelNit = [...new Set(filas.map(f => f.tipo_institucion))];
    return {
      resultado: 'nombre_no_coincide',
      coincidencia: incluirDetalle ? { tiposDelNit, funcionariosConEseNit: filas.length } : null
    };
  }
  if (encontrada.fila.tipo_institucion !== tipoInstitucion) {
    return { resultado: 'institucion_no_coincide', coincidencia: detalle(encontrada) };
  }
  if (encontrada.fila.estado !== 'activa') {
    return { resultado: 'persona_inactiva', coincidencia: detalle(encontrada) };
  }
  return { resultado: 'coincide', coincidencia: detalle(encontrada) };
}

// ---------------------------------------------------------------------------
// Sincronización desde la fuente (base que simula la del Estado)
// ---------------------------------------------------------------------------
function uriFuente() {
  return process.env.PADRON_DB_URI || process.env.MYSQL_ADDON_URI || '';
}

function fuenteConfigurada() {
  return /^mysql:\/\//.test(uriFuente());
}

// Huella con la clave HMAC secreta: detecta cambios sin permitir confirmar
// por diccionario un NIT o un nombre a quien solo tenga la base de datos.
function huellaDe(fila) {
  return indiceCiego('huella', JSON.stringify([fila.nit, fila.nombre_funcionario, fila.nombre_entidad, fila.tipo_institucion, fila.estado]));
}

// Copia la fuente al padrón cifrado. Idempotente: solo reescribe las filas
// cuya huella cambió y marca como inactivas las que ya no están en la fuente.
async function sincronizarPadron(db, { log = () => {} } = {}) {
  if (!fuenteConfigurada()) throw Object.assign(new Error('PADRON_DB_URI no está configurado.'), { code: 'PADRON_SOURCE_MISSING' });
  const fuente = await mysql.createConnection({ uri: uriFuente(), connectTimeout: 15000 });
  let filasFuente;
  try {
    [filasFuente] = await fuente.query(
      `SELECT id, nit, nombre_funcionario, nombre_entidad, tipo_institucion, estado
       FROM personas_institucionales_prueba`
    );
  } finally {
    await fuente.end().catch(() => {});
  }

  const [actuales] = await db.query('SELECT fuente_id, huella, estado FROM padron_institucional');
  const huellas = new Map(actuales.map(f => [Number(f.fuente_id), f.huella]));
  const resumen = { fuente: filasFuente.length, nuevas: 0, actualizadas: 0, sinCambios: 0, invalidas: 0, desactivadas: 0 };

  const valores = [];
  for (const fila of filasFuente) {
    const nit = normalizarNit(fila.nit);
    const tipo = String(fila.tipo_institucion || '').trim().toLowerCase();
    if (!nit || !fila.nombre_funcionario || !/^[a-z_]{2,32}$/.test(tipo)) {
      resumen.invalidas += 1;
      continue;
    }
    const huella = huellaDe(fila);
    const previa = huellas.get(Number(fila.id));
    if (previa === huella) {
      resumen.sinCambios += 1;
      continue;
    }
    resumen[previa ? 'actualizadas' : 'nuevas'] += 1;
    valores.push([
      Number(fila.id),
      indiceCiego('nit', nit),
      cifrarCampo('padron.nombre', String(fila.nombre_funcionario)),
      fila.nombre_entidad ? cifrarCampo('padron.entidad', String(fila.nombre_entidad)) : null,
      tipo,
      fila.estado === 'activa' ? 'activa' : 'inactiva',
      huella
    ]);
  }
  // Un solo INSERT … ON DUPLICATE KEY por lote de 200 filas: sin N+1.
  for (let i = 0; i < valores.length; i += 200) {
    await db.query(
      `INSERT INTO padron_institucional
        (fuente_id, nit_hash, nombre_cifrado, entidad_cifrada, tipo_institucion, estado, huella)
       VALUES ?
       ON DUPLICATE KEY UPDATE nit_hash = VALUES(nit_hash), nombre_cifrado = VALUES(nombre_cifrado),
         entidad_cifrada = VALUES(entidad_cifrada), tipo_institucion = VALUES(tipo_institucion),
         estado = VALUES(estado), huella = VALUES(huella)`,
      [valores.slice(i, i + 200)]
    );
  }

  const idsFuente = filasFuente.map(f => Number(f.id));
  if (idsFuente.length) {
    const [desactivacion] = await db.query(
      "UPDATE padron_institucional SET estado = 'inactiva', huella = '' WHERE estado = 'activa' AND fuente_id NOT IN (?)",
      [idsFuente]
    );
    resumen.desactivadas = desactivacion.affectedRows;
  }
  log(resumen);
  return resumen;
}

let temporizador = null;
function iniciarSincronizacionPeriodica(db) {
  if (!fuenteConfigurada() || temporizador) return;
  const minutos = Math.max(1, Number(process.env.PADRON_SYNC_MINUTOS || 10));
  const ejecutar = () => sincronizarPadron(db, {
    log: r => console.log(`[padron] Sincronizado: ${r.fuente} en la fuente, ${r.nuevas} nuevas, ${r.actualizadas} actualizadas, ${r.desactivadas} desactivadas, ${r.invalidas} inválidas.`)
  }).catch(err => console.error('[padron] No se pudo sincronizar:', err.code || 'PADRON_SYNC_FAILED'));
  ejecutar();
  temporizador = setInterval(ejecutar, minutos * 60 * 1000);
  temporizador.unref();
}

module.exports = { RESULTADOS, verificarEnPadron, sincronizarPadron, iniciarSincronizacionPeriodica, fuenteConfigurada };
