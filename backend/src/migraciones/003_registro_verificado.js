// Registro verificado: solo personas del padrón institucional pueden tener
// cuenta, y siempre con aprobación de un administrador.
//
// - usuarios.estado_cuenta: las cuentas nuevas nacen 'pendiente'. Las que ya
//   existían quedan 'activa' (no se bloquea a nadie ni se borran datos).
// - padron_institucional: copia cifrada del padrón (NIT solo como índice HMAC).
// - solicitudes_registro: NIT y nombre declarados, cifrados, con la bandera de
//   verificación para el administrador.
// La auditoría de aprobaciones usa la tabla `auditoria` existente.
// SQL equivalente para ejecutar a mano: backend/sql/003_registro_verificado.sql

const version = '003_registro_verificado';
const descripcion = 'Estado de cuenta, padrón institucional cifrado y solicitudes de registro con aprobación';

async function agregarColumna(db, tabla, columna, definicion) {
  try {
    await db.query(`ALTER TABLE ${tabla} ADD COLUMN ${columna} ${definicion}`);
  } catch (err) {
    if (err.code !== 'ER_DUP_FIELDNAME' && !/duplicate column/i.test(err.message)) throw err;
  }
}

async function up(db) {
  await agregarColumna(db, 'usuarios', 'estado_cuenta',
    "ENUM('pendiente','activa','rechazada','suspendida') NOT NULL DEFAULT 'activa'");

  await db.query(`
    CREATE TABLE IF NOT EXISTS padron_institucional (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      fuente_id BIGINT UNSIGNED NOT NULL,
      nit_hash CHAR(64) NOT NULL,
      nombre_cifrado TEXT NOT NULL,
      entidad_cifrada TEXT NULL,
      tipo_institucion VARCHAR(32) NOT NULL,
      estado ENUM('activa','inactiva') NOT NULL DEFAULT 'activa',
      huella CHAR(64) NOT NULL DEFAULT '',
      sincronizado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uq_padron_fuente (fuente_id),
      INDEX idx_padron_nit (nit_hash)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS solicitudes_registro (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      usuario_id INT NOT NULL,
      cliente_id INT NOT NULL,
      nit_hash CHAR(64) NOT NULL,
      nit_cifrado TEXT NOT NULL,
      nombre_cifrado TEXT NOT NULL,
      tipo_institucion VARCHAR(32) NOT NULL,
      resultado_verificacion ENUM('coincide','nit_no_existe','nombre_no_coincide','institucion_no_coincide','persona_inactiva','padron_no_disponible') NOT NULL,
      estado ENUM('pendiente','aprobada','rechazada') NOT NULL DEFAULT 'pendiente',
      motivo_rechazo VARCHAR(500) NULL,
      decidida_por INT NULL,
      decidida_en DATETIME NULL,
      creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_solreg_estado (estado, creado_en, id),
      INDEX idx_solreg_usuario (usuario_id, estado),
      INDEX idx_solreg_nit (nit_hash),
      FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
      FOREIGN KEY (cliente_id) REFERENCES clientes(id) ON DELETE CASCADE,
      FOREIGN KEY (decidida_por) REFERENCES usuarios(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);
}

async function down(db) {
  await db.query('DROP TABLE IF EXISTS solicitudes_registro');
  await db.query('DROP TABLE IF EXISTS padron_institucional');
  try {
    await db.query('ALTER TABLE usuarios DROP COLUMN estado_cuenta');
  } catch (err) {
    if (err.code !== 'ER_CANT_DROP_FIELD_OR_KEY') throw err;
  }
}

module.exports = { version, descripcion, up, down };
