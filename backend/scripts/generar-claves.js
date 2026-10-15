#!/usr/bin/env node
// Genera las claves del registro verificado.
//
//   node scripts/generar-claves.js            -> solo las muestra en pantalla
//   node scripts/generar-claves.js --escribir -> agrega a backend/.env las que
//                                                FALTEN (nunca reemplaza una
//                                                existente) y guarda un respaldo
//
// ENC_KEY y HMAC_KEY: 32 bytes aleatorios en hex, distintas entre sí.
// JWT_SECRET: 48 bytes aleatorios en hex (96 caracteres).
// Las claves van solo en .env (excluido de git). Nunca en el repo, en la base
// ni en n8n. Si se pierde ENC_KEY, los datos cifrados con ella no se recuperan.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const RUTA_ENV = path.join(__dirname, '..', '.env');
const generar = bytes => crypto.randomBytes(bytes).toString('hex');

const nuevas = {
  ENC_KEY: generar(32),
  ENC_KEY_VERSION: '1',
  HMAC_KEY: generar(32),
  JWT_SECRET: generar(48),
  N8N_REGISTRO_SECRET: generar(32)
};

if (!process.argv.includes('--escribir')) {
  console.log('# Copia estas líneas en backend/.env (o ejecuta con --escribir):');
  for (const [k, v] of Object.entries(nuevas)) console.log(`${k}=${v}`);
  process.exit(0);
}

const actual = fs.existsSync(RUTA_ENV) ? fs.readFileSync(RUTA_ENV, 'utf8') : '';
const definidas = new Set(actual.split(/\r?\n/).map(l => /^([A-Z0-9_]+)=(.+)$/.exec(l.trim())).filter(Boolean).map(m => m[1]));
const faltantes = Object.entries(nuevas).filter(([k]) => !definidas.has(k));

if (!faltantes.length) {
  console.log('No falta ninguna clave: .env no se modificó.');
  process.exit(0);
}
if (actual) {
  const respaldo = `${RUTA_ENV}.respaldo-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  fs.copyFileSync(RUTA_ENV, respaldo);
  console.log(`Respaldo: ${path.basename(respaldo)}`);
}
const bloque = [
  '',
  `# --- Registro verificado (generado ${new Date().toISOString().slice(0, 10)} con scripts/generar-claves.js) ---`,
  ...faltantes.map(([k, v]) => `${k}=${v}`),
  ''
].join('\n');
fs.appendFileSync(RUTA_ENV, (actual.endsWith('\n') || !actual ? '' : '\n') + bloque);
console.log(`Agregadas a .env: ${faltantes.map(([k]) => k).join(', ')} (los valores no se muestran).`);
