#!/usr/bin/env node
// Copia el padrón de la fuente (PADRON_DB_URI; en el laboratorio, la base que
// simula la del Estado) a la tabla cifrada padron_institucional.
//
//   node scripts/importar-padron.js
//
// - El NIT se guarda solo como índice HMAC; nombre y entidad, cifrados.
// - Es idempotente: solo reescribe filas que cambiaron.
// - No borra NADA de la fuente: es el registro oficial y la fuente de verdad.
//   Las filas que desaparecen de la fuente quedan 'inactiva' en la copia.
// - El servidor ya sincroniza solo al arrancar y cada PADRON_SYNC_MINUTOS;
//   este script sirve para forzarlo después de cargar datos nuevos.

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const { pool } = require('../src/db');
const { aplicarMigraciones } = require('../src/migraciones');
const { sincronizarPadron } = require('../src/seguridad/padron');
const { claves } = require('../src/seguridad/cifradoCampos');

(async () => {
  try {
    claves();
    await aplicarMigraciones(pool);
    const inicio = Date.now();
    const r = await sincronizarPadron(pool);
    console.log(`Padrón sincronizado en ${Date.now() - inicio} ms`);
    console.table([r]);
    const [[total]] = await pool.query("SELECT COUNT(*) AS activas FROM padron_institucional WHERE estado = 'activa'");
    console.log(`Funcionarios activos en la copia cifrada: ${total.activas}`);
  } catch (err) {
    console.error('No se pudo importar el padrón:', err.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
    process.exit();
  }
})();
