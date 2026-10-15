const path = require('path');
const express = require('express');
const cors = require('cors');

// Construye la aplicación Express sin abrir el puerto ni ejecutar migraciones,
// para que server.js y las pruebas de integración usen exactamente la misma app.
function crearApp() {
  const app = express();
  const saltosProxy = Number(process.env.TRUST_PROXY_HOPS || 0);
  if (!Number.isSafeInteger(saltosProxy) || saltosProxy < 0) {
    throw new Error('TRUST_PROXY_HOPS debe ser un entero no negativo.');
  }
  app.set('trust proxy', saltosProxy);
  app.disable('x-powered-by');
  const origenesPermitidos = new Set(
    (process.env.CORS_ORIGINS ||
      'http://localhost:5500,http://127.0.0.1:5500,http://localhost:5501,http://127.0.0.1:5501,http://localhost:8765,http://127.0.0.1:8765,http://localhost:8081,http://127.0.0.1:8081')
      .split(',')
      .map(origen => origen.trim())
      .filter(Boolean)
  );
  if (process.env.NODE_ENV === 'production' && !process.env.CORS_ORIGINS) {
    throw new Error('CORS_ORIGINS debe configurarse con los dominios del frontend en producción.');
  }
  app.use(cors({
    origin: (origen, callback) => callback(null, !origen || origenesPermitidos.has(origen)),
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Idempotency-Key'],
    maxAge: 600
  }));
  // Cabeceras de seguridad básicas. Sin HSTS ni upgrade-insecure-requests:
  // el laboratorio no tiene HTTPS (activarlas sería un pendiente de producción).
  app.use((req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'same-origin',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
    });
    next();
  });
  app.use('/api/pagos/webhook', express.raw({ type: 'application/json', limit: '64kb' }));
  // Registro, inicio de sesión y panel de solicitudes: cuerpo máximo de 10 kb.
  app.use(['/api/auth', '/api/admin/solicitudes'], express.json({ limit: '10kb' }));
  app.use(express.json({ limit: '100kb' }));
  app.use('/img', express.static(path.join(__dirname, '..', 'img')));

  app.get('/', (req, res) => {
    if (req.accepts(['html', 'json']) === 'html') {
      return res.redirect('/landing.html');
    }
    res.json({ status: 'ok', servicio: 'Suministros Institucionales - Backend' });
  });
  app.get('/favicon.ico', (req, res) => res.status(204).end());

  // Rutas
  app.use('/api/clientes', require('./routes/clientes'));
  app.use('/api/atencion', require('./routes/atencion'));
  app.use('/api/asistente', require('./routes/asistente').router);
  app.use('/api/checkout', require('./routes/checkout'));
  app.use('/api/pagos', require('./routes/pagos').router);
  app.use('/api/comprobantes', require('./routes/comprobantes'));
  app.use('/api/automatizaciones', require('./routes/automatizaciones'));
  app.use('/api/mi-cuenta', require('./routes/miCuenta'));
  app.use('/api/reportes', require('./routes/reportes'));
  app.use('/api/auth', require('./routes/auth').router);
  app.use('/api/admin/solicitudes', require('./routes/solicitudesRegistro'));
  app.use('/api/verificacion', require('./routes/verificacion'));
  app.use('/api/pedidos', require('./routes/pedidos'));
  app.use('/api/productos', require('./routes/productos'));
  app.use('/api/categorias', require('./routes/categorias'));
  app.use('/api/mis-reportes', require('./routes/misreportes'));
  app.use('/api/auditoria', require('./routes/auditoria'));
  app.use(express.static(path.join(__dirname, '..', '..', 'frontend'), { index: false }));

  // JSON mal formado u otros errores de parseo: respuesta genérica, sin trazas.
  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON inválido.' });
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'La solicitud es demasiado grande.' });
    console.error('[server] Error no controlado:', err.code || err.message);
    return res.status(500).json({ error: 'Error interno.' });
  });
  return app;
}

module.exports = { crearApp };
