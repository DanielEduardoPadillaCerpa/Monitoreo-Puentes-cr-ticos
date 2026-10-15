// CAMBIO 1: path primero y ruta explícita del .env
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const { crearApp } = require('./src/app');
const { migrar, pool } = require('./src/db');
const { getPaymentProvider } = require('./src/paymentProviderInstance');
const { iniciarWorkerEmail } = require('./src/emailOutbox');
const { iniciarWorkerAutomatizaciones } = require('./src/automationOutbox');
const { iniciarJobExpiracionPedidos } = require('./src/paymentJobs');
const { validarConfiguracionCorreo } = require('./src/seguridad/correo');
const { iniciarSincronizacionPeriodica } = require('./src/seguridad/padron');
const { hashRelleno } = require('./src/seguridad/contrasenas');
const { iniciarRefrescoIndice } = require('./src/assistant/indiceCatalogo');
const { validarConfiguracionSegura } = require('./src/configSegura');
const { iniciarJobVerificaciones } = require('./src/verificacionJobs');

const app = crearApp();

const PORT = process.env.PORT || 8080;

async function iniciar() {
  try {
    const modoAsistente = process.env.ASSISTANT_MODE || 'rules';
    if (!['rules', 'llm'].includes(modoAsistente)) {
      throw new Error('ASSISTANT_MODE debe ser rules o llm');
    }
    validarConfiguracionSegura();
    getPaymentProvider();
    validarConfiguracionCorreo();
    await migrar(); // crea tablas si no existen
    iniciarRefrescoIndice();
    iniciarWorkerEmail();
    iniciarWorkerAutomatizaciones();
    iniciarJobExpiracionPedidos();
    iniciarJobVerificaciones();
    // Copia cifrada del padrón desde la fuente (PADRON_DB_URI), al arrancar y
    // cada PADRON_SYNC_MINUTOS; nunca bloquea el arranque.
    iniciarSincronizacionPeriodica(pool);
    hashRelleno();

    // No registrar valores de configuración ni información sensible.
    console.log('[env] Archivo .env:', path.join(__dirname, '.env'));

    // CAMBIO 3: avisa si el puerto ya está ocupado por otro backend
    const servidor = app.listen(PORT, () => {
      console.log(`[server] Backend corriendo en http://localhost:${PORT}`);
    });
    servidor.on('error', err => {
      if (err.code === 'EADDRINUSE') {
        console.error(`[server] El puerto ${PORT} ya está en uso: hay OTRO backend corriendo. Ciérralo y vuelve a iniciar.`);
      } else {
        console.error('[server] Error del servidor:', err.message);
      }
      process.exit(1);
    });
  } catch (err) {
    console.error('[server] No se pudo iniciar (revisa tu .env y la conexión a la base de datos):', err.message);
    process.exit(1);
  }
}

iniciar();