# Changelog

## 2026-10-15: registro verificado, aprobación del administrador y MFA sin n8n

### Agregado
- Registro con nombre completo, NIT, institución, correo, contraseña y captcha propio (SVG con trazos, un solo uso). La terna NIT + nombre + institución se verifica contra el padrón y la solicitud queda pendiente; la respuesta es siempre 202 genérica.
- Padrón cifrado `padron_institucional` (NIT como índice HMAC, nombre y entidad con AES-256-GCM y AAD), sincronizado desde `PADRON_DB_URI` al arrancar y cada 10 minutos (`npm run padron:importar`).
- Panel **Solicitudes** (`admin-solicitudes.html`): lista sin NIT ni nombre, detalle con el padrón al lado y verificación repetida, aprobación atómica (confirmación explícita si no coincide) y rechazo con motivo; contador en el menú de todos los paneles.
- Migración `003_registro_verificado` (`usuarios.estado_cuenta`, `padron_institucional`, `solicitudes_registro`) y SQL idempotente en `backend/sql/`.
- Scripts `generar-claves.js`, `importar-padron.js` y `medir-rendimiento.js`; workflow n8n W12 (avisos firmados `{evento, solicitud_id, resultado}`).
- Pruebas `test/registro-verificado.test.js` (cifrado, normalización, padrón, captcha, firma n8n y flujo completo).

### Cambiado
- Sin acceso hasta que un administrador apruebe. El login compara contra un hash de relleno si el correo no existe e informa el estado de la cuenta solo tras validar la contraseña.
- El middleware lee `estado_cuenta` y `rol` de la base en cada petición.
- Los códigos MFA, de autorización de compra y de cambio de correo, los comprobantes y los avisos de seguridad se envían con nodemailer (consola en laboratorio sin SMTP); ya no pasan por n8n (W5 y W9 quedan sin uso).
- Registro, login, aprobar y rechazar agrupados en lotes de un solo viaje a MySQL; pool de 3 conexiones; límite de cuerpo de 10 kb en autenticación y panel; cabeceras de seguridad (sin HSTS).
- Banner de la portada y fondo de los paneles con la imagen de todas las instituciones.

### Pendiente
- Ver `docs/REGISTRO_VERIFICADO.md` §8: HTTPS, captcha y SMTP reales, gestor de secretos, decidir sobre el NIT que W11 envía a n8n y rotar la contraseña de la base del padrón.

## 2026-10-13 (tarde): registro mínimo y verificación en la compra

### Agregado
- Registro mínimo: tipo de institución, nombre, correo, contraseña, aceptación de términos y del tratamiento de datos. El campo específico del tipo es opcional.
- Verificación diferida en *Mi verificación* (datos de la entidad, documento de identidad cifrado, evidencia) solo cuando una compra la requiere. Tiene vigencia de 365 días y se renueva.
- Doble comprobación: revisión documental, canal independiente (correo institucional o confirmación oficial por otra persona) y entidad en datos.gov.co, con tabla de decisión en el servidor y cuatro ojos.
- Autorización por compra para productos restringidos: código al correo, ligada al carrito, de un solo uso.
- n8n W11 (`n8n/workflows/W11-verificacion-compra.json`, generador `n8n/generar-w11.js`): consulta de RUES y CHIP, avisos y mantenimiento. Respuestas con HMAC propio y nonce.
- Superadministrador (`scripts/crear-superadmin.js`), cambio obligatorio de la contraseña inicial (`cambiar-password.html`), diagnóstico y permisos reservados.
- Cuentas de prueba sintéticas (`scripts/crear-cuentas-prueba.js`).
- Cifrado versionado (`CRYPTO_KEYS`), índice HMAC (`IDENT_HMAC_KEY`) y validación de secretos al arrancar (`configSegura.js`).
- Migración `002_verificacion_en_compra`.
- Documentación: viabilidad SIGEP y datos abiertos, arquitectura y política de verificación, matriz FP/FN, flujo n8n, superusuario, tratamiento de datos y documentos de auditoría.

### Cambiado
- Una cuenta con el correo verificado y no suspendida compra productos de uso general sin verificación institucional (antes debía estar aprobada para todo).
- Las rutas administrativas heredadas exigen permisos: `catalogo.gestionar`, `pedidos.gestionar`, `clientes.gestionar` y `auditoria.ver` (los administradores existentes los reciben en la migración).
- Aprobar una verificación exige la doble comprobación completa. Suspender cancela las solicitudes y revoca las autorizaciones.
- `JWT_SECRET` ya no tiene valor por defecto y el JWT se verifica solo con HS256.
- El personal creado desde el panel debe cambiar su contraseña temporal.

### Corregido
- La marca de MFA reciente se guardaba en hora local y se comparaba con la hora UTC de MySQL, lo que rompía el cambio de contraseña.

### Pendiente
- Ver la clasificación final en `RESULTADOS_PRUEBAS.md`: rotación de los secretos débiles del `.env` actual, importar W11, convenios externos, validación jurídica, recifrado de datos heredados, `nodemailer`, CSP/HSTS, cookie `HttpOnly` y antivirus.

## 2026-10-13 — Verificación institucional de compradores

### Agregado
- Registro por pasos con tipo de institución y campos condicionales validados en el servidor (`registroInstitucional.js`, `GET /api/auth/registro/tipos`, `frontend/js/registro-wizard.js`).
- Estados de verificación (borrador, pendiente, requiere información, aprobado, rechazado, suspendido), historial y auditoría de cada transición.
- Documentos de acreditación privados, validados por contenido y cifrados en disco.
- Servicio central de autorización (`autorizacion.js`) aplicado a catálogo, detalle, asistente y checkout.
- Elegibilidad de productos muchos-a-muchos y revisión legal preventiva (`revision_legal`).
- Siete permisos de staff diferenciados, alta de personal y gestión de permisos.
- Páginas `mi-verificacion.html` y `admin-verificaciones.html`; tarjeta "Verificaciones pendientes" en el dashboard.
- Migraciones versionadas (`schema_migraciones`) y `scripts/migraciones.js` (estado / revertir).
- Pruebas: integración contra MySQL (24) e interfaz con jsdom (32 verificaciones).
- Documentación en `docs/` y matrices normativa y de elegibilidad.

### Cambiado
- `POST /api/auth/registro` exige `tipoInstitucion` y los campos del tipo; contraseña de 10 a 72 caracteres; límite de 10 registros por IP y hora.
- La institución ya no se deduce del dominio del correo: la fija un revisor. El JWT solo identifica a la persona.
- Visitantes y cuentas no aprobadas ven vitrina sin precios ni productos restringidos.
- Conceder productos restringidos exige el permiso `restringidos.autorizar` y una cuenta aprobada.
- Cambiar restricción o institución de un producto exige `productos.cumplimiento`.
- `server.js` usa `src/app.js` (misma app para el servidor y las pruebas).

### Corregido
- `restringido = "false"` enviado por FormData marcaba el producto como restringido.
- El administrador inicial se creaba con una contraseña conocida y se imprimía en consola.
- `backend/.env` no estaba en `.gitignore`.

### Pendiente
- Actualizar `nodemailer` (vulnerabilidad alta preexistente).
- Antivirus para documentos; CSP/HSTS; sesión en cookie `HttpOnly`.
- Traducción de las páginas nuevas.
- Decisión sobre las cuentas heredadas en la base de producción (ver `AUDITORIA_TECNICA.md` §7).
