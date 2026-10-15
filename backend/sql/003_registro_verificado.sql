-- Registro verificado (equivale a src/migraciones/003_registro_verificado.js).
-- Idempotente: puede ejecutarse varias veces. No borra ni modifica filas.
-- El servidor lo aplica solo al arrancar; este archivo es para revisión o
-- para aplicarlo a mano (mysql < 003_registro_verificado.sql).

-- usuarios.estado_cuenta (MySQL 8 no tiene ADD COLUMN IF NOT EXISTS).
SET @existe := (SELECT COUNT(*) FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'usuarios' AND COLUMN_NAME = 'estado_cuenta');
SET @sql := IF(@existe = 0,
  "ALTER TABLE usuarios ADD COLUMN estado_cuenta ENUM('pendiente','activa','rechazada','suspendida') NOT NULL DEFAULT 'activa'",
  'SELECT 1');
PREPARE paso FROM @sql;
EXECUTE paso;
DEALLOCATE PREPARE paso;

CREATE TABLE IF NOT EXISTS padron_institucional (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  fuente_id BIGINT UNSIGNED NOT NULL,
  nit_hash CHAR(64) NOT NULL,                 -- HMAC-SHA256(HMAC_KEY, "nit:<dígitos>")
  nombre_cifrado TEXT NOT NULL,               -- AES-256-GCM, AAD "padron.nombre"
  entidad_cifrada TEXT NULL,                  -- AES-256-GCM, AAD "padron.entidad"
  tipo_institucion VARCHAR(32) NOT NULL,
  estado ENUM('activa','inactiva') NOT NULL DEFAULT 'activa',
  huella CHAR(64) NOT NULL DEFAULT '',
  sincronizado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_padron_fuente (fuente_id),
  INDEX idx_padron_nit (nit_hash)            -- no es UNIQUE: varios funcionarios comparten el NIT de su entidad
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS solicitudes_registro (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  usuario_id INT NOT NULL,
  cliente_id INT NOT NULL,
  nit_hash CHAR(64) NOT NULL,
  nit_cifrado TEXT NOT NULL,                  -- AAD "solicitud.nit"
  nombre_cifrado TEXT NOT NULL,               -- AAD "solicitud.nombre"
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO schema_migraciones (version, descripcion)
VALUES ('003_registro_verificado', 'Estado de cuenta, padrón institucional cifrado y solicitudes de registro con aprobación');
