// Ejecutor de migraciones versionadas. Cada migración se aplica una sola vez y
// queda registrada en schema_migraciones. Las migraciones históricas del
// proyecto (CREATE TABLE IF NOT EXISTS / ALTER tolerantes en db.js) siguen
// ejecutándose antes que estas.

const MIGRACIONES = [
  require('./001_verificacion_institucional'),
  require('./002_verificacion_en_compra'),
  require('./003_registro_verificado')
];

async function asegurarTablaControl(db) {
  await db.query(`
    CREATE TABLE IF NOT EXISTS schema_migraciones (
      version VARCHAR(100) PRIMARY KEY,
      descripcion VARCHAR(255) NOT NULL,
      aplicada_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);
}

async function versionesAplicadas(db) {
  await asegurarTablaControl(db);
  const [filas] = await db.query('SELECT version FROM schema_migraciones');
  return new Set(filas.map(fila => fila.version));
}

async function aplicarMigraciones(db) {
  // Permisos que la migración 001 concede a los administradores existentes
  // (fijos: los permisos agregados después tienen su propia migración).
  const permisosStaff = ['verificacion.ver', 'verificacion.decidir', 'documentos.ver', 'cuentas.suspender',
    'restringidos.autorizar', 'productos.cumplimiento', 'staff.permisos'];
  const aplicadas = await versionesAplicadas(db);
  for (const migracion of MIGRACIONES) {
    if (aplicadas.has(migracion.version)) continue;
    console.log(`[migraciones] Aplicando ${migracion.version}...`);
    await migracion.up(db, { permisosStaff });
    await db.query('INSERT INTO schema_migraciones (version, descripcion) VALUES (?, ?)', [migracion.version, migracion.descripcion]);
    console.log(`[migraciones] ${migracion.version} aplicada.`);
  }
}

async function estadoMigraciones(db) {
  const aplicadas = await versionesAplicadas(db);
  return MIGRACIONES.map(m => ({ version: m.version, descripcion: m.descripcion, aplicada: aplicadas.has(m.version) }));
}

async function revertirMigracion(db, version) {
  const migracion = MIGRACIONES.find(m => m.version === version);
  if (!migracion) throw new Error(`Migración desconocida: ${version}`);
  await migracion.down(db);
  await db.query('DELETE FROM schema_migraciones WHERE version = ?', [version]);
}

module.exports = { MIGRACIONES, aplicarMigraciones, estadoMigraciones, revertirMigracion };
