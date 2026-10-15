# Registro verificado: padrón, aprobación del administrador y MFA

Solo personas del padrón institucional pueden tener cuenta. Cada registro se compara contra el padrón (NIT + nombre + institución), queda **pendiente** y un administrador lo aprueba o rechaza. El inicio de sesión exige contraseña, captcha y un código de un solo uso enviado por correo.

Entorno: **laboratorio** (sin HTTPS, sin servicios de pago). Todo lo usado es gratuito.

## 1. Flujo

```
registro.html ──► POST /api/auth/registro  (captcha, nombre, NIT, institución, correo, contraseña)
                    │  en paralelo: bcrypt · ¿existe el correo? · verificación en el padrón
                    │  un solo lote transaccional: clientes + usuarios(pendiente) + solicitudes_registro
                    └─► 202 "Solicitud recibida"   (idéntico exista o no el correo y salga como salga)

admin-solicitudes.html ──► lista (sin NIT ni nombre) ──► detalle (descifrado + padrón al lado
                           + verificación repetida) ──► Aprobar / Rechazar (con motivo)
                           UPDATE atómico … WHERE estado='pendiente' (affectedRows = 2)

login.html ──► paso 1: correo + contraseña + captcha
                 · correo inexistente → se compara contra un hash de relleno (mismo tiempo)
                 · cuenta pendiente/rechazada/suspendida → se informa SOLO tras validar la contraseña
           ──► paso 2: código de 6 dígitos (crypto.randomInt), se guarda solo su HMAC,
                 vence en 5 min, máximo 5 intentos, un solo uso → JWT HS256 de 2 h
```

En cada petición autenticada, `requiereAutenticacion` lee de MySQL `session_version`, `estado_cuenta` y `rol`. Suspender una cuenta o quitarle el rol surte efecto en la siguiente petición, aunque el JWT siga vigente.

### Resultado de la verificación (bandera para el administrador)

| Resultado | Significado |
|---|---|
| `coincide` | El NIT existe, una persona de ese NIT tiene ese nombre y su institución es la declarada |
| `nit_no_existe` | El NIT no está en el padrón |
| `nombre_no_coincide` | El NIT existe, pero ningún funcionario de esa entidad tiene ese nombre |
| `institucion_no_coincide` | La persona está en el padrón, pero en otra institución |
| `persona_inactiva` | La persona figura como inactiva |
| `padron_no_disponible` | No se pudo consultar el padrón en ese momento |

Si el resultado no es `coincide`, aprobar exige marcar una confirmación explícita (`{ "confirmar": true }`). Un rechazo nunca se toma automáticamente.

### Normalización

- **NIT:** solo dígitos y sin dígito de verificación. `999.000.001-2`, `999000001-2` y `999000001` son el mismo NIT.
- **Nombre:** sin tildes, en mayúsculas, solo letras y con las palabras ordenadas. Así, `Rodríguez Juan Camilo` coincide con `Juan Camilo Rodríguez`. Se exigen al menos dos palabras.

## 2. Padrón

En el laboratorio la "base del Estado" es `PADRON_DB_URI` (o `MYSQL_ADDON_URI`), tabla `personas_institucionales_prueba`. El backend **solo la lee** y la copia cifrada a `padron_institucional`:

| Columna | Contenido |
|---|---|
| `nit_hash` | HMAC-SHA256(`HMAC_KEY`, `"nit:<dígitos>"`): índice ciego, buscable por igualdad |
| `nombre_cifrado`, `entidad_cifrada` | AES-256-GCM (AAD `padron.nombre` / `padron.entidad`) |
| `tipo_institucion` | En claro: es una categoría (policia, defensa…), no un dato personal |
| `huella` | HMAC con clave secreta del contenido, para no reescribir filas sin cambios |

La copia se sincroniza al arrancar y cada `PADRON_SYNC_MINUTOS` (10 por defecto). Para forzarla: `npm run padron:importar`. Las filas que desaparecen de la fuente quedan `inactiva`. **Nunca se borra la fuente**: es el registro oficial.

## 3. Cifrado y claves

- Formato `v<versión>:<iv>:<tag>:<cifrado>` (base64url), IV aleatorio de 12 bytes y AAD igual al nombre del campo. Un valor copiado a otra columna no se descifra.
- `ENC_KEY` (cifrado) y `HMAC_KEY` (índices ciegos y comparación en tiempo constante): 32 bytes en hex, distintas entre sí. `JWT_SECRET`: al menos 32 caracteres. Si falta alguna o es inválida, el servidor **no arranca**.
- Generarlas: `npm run claves:generar`. Solo agrega a `.env` las que falten y guarda un respaldo antes.
- Rotación: se pone una `ENC_KEY` nueva con `ENC_KEY_VERSION=2` y la anterior en `ENC_KEY_V1`. Los datos viejos se siguen descifrando.
- Las claves viven solo en `.env` (excluido de git): nunca en el repositorio, en la base ni en n8n.
- Se guardan cifrados el NIT y el nombre de la solicitud (`solicitud.nit`, `solicitud.nombre`). La lista del administrador no descifra nada.

## 4. n8n (solo avisos)

Hallazgos de la auditoría (todos corregidos):

| Flujo | Enviaba a n8n | Ahora |
|---|---|---|
| Código MFA de inicio de sesión (W5) | correo + código | nodemailer directo |
| Comprobante de compra (W9) | correo + enlace firmado | nodemailer directo |
| Código de autorización de compra | correo + código | nodemailer directo |
| Cambio de correo y avisos de seguridad (W8) | correo + código | nodemailer directo |

W5 y W9 quedaron sin uso. W8 sigue recibiendo solo `admin.solicitud_cuenta`, que lleva el id y el tipo, sin datos personales.

**Contradicción pendiente de decisión:** W11 (verificación en la compra) envía a n8n el **NIT de la entidad** (solo personas jurídicas, nunca una cédula) para consultar RUES. El prompt pide no enviar nunca el NIT. No lo cambié porque W11 está inactivo, el padrón lo reemplaza en el laboratorio y quitarlo cambia la verificación de compra. Decide si se elimina o se mantiene.

**W12 – avisos de registro** (`n8n/workflows/W12-avisos-registro.json`, generado con `node n8n/generar-w12.js`):

- **Cuerpo:** exactamente `{ "evento": "registro.recibido|registro.aprobado|registro.rechazado", "solicitud_id": 14, "resultado": "coincide" }`.
- **Cabeceras:**
  - `X-Timestamp`: segundos Unix.
  - `X-Signature`: `hex(HMAC-SHA256(N8N_REGISTRO_SECRET, "<timestamp>.<evento>.<solicitud_id>"))`.
- **Comportamiento:** el aviso nunca bloquea la respuesta (va en segundo plano, con 3 s de tiempo límite) y un fallo de n8n solo queda en el log.

El nodo **Code "Verificar firma"** valida la ventana de 5 minutos, la forma exacta del cuerpo y la firma en tiempo constante. Su código está en `n8n/generar-w12.js` y se prueba en `backend/test/registro-verificado.test.js`. Requiere en `n8n/.env`:

```
NODE_FUNCTION_ALLOW_BUILTIN=crypto
N8N_BLOCK_ENV_ACCESS_IN_NODE=false
N8N_REGISTRO_SECRET=<mismo valor que en backend/.env>
```

Nota: la firma no cubre `resultado`, porque así lo definió el prompt. Es solo informativo; si n8n llegara a tomar decisiones con él, conviene incluirlo en la firma.

## 5. Rendimiento

Se mide con `npm run medir`. Usa la base real, cuentas sintéticas que borra al terminar y descarta los correos.

**Diseño:**

- Las consultas usan solo columnas con índice: `usuarios.correo` UNIQUE, `padron_institucional.nit_hash`, `solicitudes_registro(estado, creado_en, id)`.
- No hay consultas N+1 y la lista no descifra nada.
- **Registro:** bcrypt, búsqueda del correo y verificación en el padrón van en paralelo (`Promise.all`). Luego **un solo lote** `START TRANSACTION … COMMIT` con todas las inserciones.
- **Login, paso 1:** consulta del usuario + un lote con el límite, la creación del reto y la cancelación de los anteriores.
- **Aprobar, rechazar y contador:** **un solo viaje**. La autorización del administrador va dentro del mismo lote y, en los UPDATE, dentro del `WHERE`.
- Auditoría, avisos a n8n y correos van en segundo plano.
- Pool principal de 3 conexiones + 1 para los lotes. El plan gratuito de Clever Cloud permite 5.

**Tiempos medidos el 2026-10-15** desde el equipo de laboratorio, con **~150 ms por viaje a MySQL** (la base está en Clever Cloud). bcrypt con costo 10:

| Operación | Mediana | p95 | Meta |
|---|---|---|---|
| Registro (202) | 360 ms | 863 ms* | < 600 ms ✔ |
| Login paso 1 (202) | 421 ms | 423 ms | < 600 ms ✔ |
| Login fallido (401) | 246 ms | 246 ms | < 600 ms ✔ |
| Aprobar | 192 ms | 193 ms | < 300 ms ✔ |
| Rechazar | 176 ms | 176 ms | < 300 ms ✔ |
| Contador de pendientes | 161 ms | 167 ms | < 300 ms ✔ |

\* El primer registro tras arrancar incluye la apertura de conexiones.

Casi todo el tiempo es la latencia hasta la base. Con el backend desplegado en Clever Cloud, junto a la base, cada viaje baja a ~1 ms.

**Panel:**

- El contador se refresca cada 12 s mientras la pestaña está visible.
- Aprobar y rechazar quitan la fila y bajan el contador al instante. Si el servidor responde error, se restaura.

## 6. Cómo probar

```bash
cd backend
npm install
npm run claves:generar       # solo la primera vez
npm start                    # aplica la migración 003 y sincroniza el padrón
```

1. Registro: entra a `http://localhost:8081/registro.html` y elige **Policía Nacional**. Usa el nombre `Juan Camilo Rodríguez`, el NIT `999000001-2`, un correo cualquiera y una contraseña de 10 o más caracteres. Resuelve la operación.
2. Login: entra a `http://localhost:8081/login.html` con esa cuenta. Debe decir que está en revisión.
3. Panel: entra con un administrador que tenga el permiso `clientes.gestionar` y abre `http://localhost:8081/admin-solicitudes.html`. Abre la solicitud y apruébala.
4. Login con MFA: vuelve a iniciar sesión. El código llega a Mailpit (`http://localhost:8025`) o, si no está encendido, se imprime en la consola del servidor.
5. Casos de prueba sugeridos:
   - Mismo nombre y NIT con institución **Defensa**: el resultado es `institucion_no_coincide`.
   - Nombre `Juan Rodríguez`: el resultado es `nombre_no_coincide`.
   - NIT `123456789`: el resultado es `nit_no_existe`.

Pruebas automáticas: `npm test` (Jest, 107 pruebas, y `node:test`, 51). `test/registro-verificado.test.js` cubre:

- cifrado, índice ciego y normalización;
- verificación contra el padrón, captcha y firma de n8n;
- el flujo HTTP registro → aprobación → login con MFA.

## 7. Decisiones y diferencias con el prompt

- **NIT no es UNIQUE:** el padrón tiene una fila por funcionario y el NIT es el de la entidad; varios funcionarios comparten NIT. El índice `nit_hash` no es único. La unicidad está en `usuarios.correo`.
- **Se verifica la terna** NIT + nombre + institución, como pediste: "si en la página puso Policía, en la base debe salir Policía".
- **Sin tablas `seg_*`:** me integré con `usuarios` (nueva columna `estado_cuenta`), `clientes` y la tabla `auditoria` existente. Las tablas nuevas son `padron_institucional` y `solicitudes_registro`.
- **Cuentas existentes:** quedan `activa`, para no bloquear a nadie ni borrar datos. Si quieres que pasen por revisión, hay que marcarlas `pendiente`.
- **Institución autorizada:** al aprobar, la cuenta queda activa con su catálogo institucional. Los productos **restringidos** siguen exigiendo la verificación de compra existente: documentos, doble comprobación y código por compra.
- **Una cuenta rechazada puede volver a solicitar** con datos corregidos. Se crea una nueva solicitud pendiente.
- **Correo en consola:** el prompt pide imprimir en consola sin SMTP y, a la vez, no registrar códigos en logs. Se imprime solo fuera de producción, marcado como `[correo-laboratorio]`. En producción, sin SMTP es un error.
- **Captcha propio:** una suma dibujada con trazos, no con texto, para que un bot no la lea del SVG. Es un reto de un solo uso que vence en 5 minutos y vive en memoria (un solo proceso).
- **Carpeta `seguridad-registro/`:** no existía ni junto al repo ni en el zip, así que todo se construyó desde cero.

## 8. Pendientes para producción (fuera de alcance)

- HTTPS, y con él HSTS, cookies `Secure`/`HttpOnly` para la sesión (hoy está en `localStorage`) y una CSP estricta.
- Captcha gestionado (Cloudflare Turnstile es gratuito) o un almacén compartido de retos si hay varias instancias.
- SMTP real (correo institucional o un proveedor transaccional).
- Gestor de secretos en la nube para `ENC_KEY`, `HMAC_KEY` y `JWT_SECRET`, más un respaldo seguro de `ENC_KEY`.
- Conexión con la fuente oficial real en lugar de la base de laboratorio.
- Pasarelas de pago.
- **Rotar la contraseña de la base del padrón**, que se compartió en texto plano durante el desarrollo.
- Los límites de intentos (`express-rate-limit`) y el captcha viven en memoria del proceso: con varias instancias se necesita un almacén compartido.
