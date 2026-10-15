/* ============================================================
   Registro mínimo por pasos: tipo de institución, datos de acceso y
   aceptaciones. Los datos de la entidad, el documento de identidad y la
   evidencia se piden después, solo si una compra lo requiere.
   Las reglas vienen de GET /api/auth/registro/tipos y el servidor las
   vuelve a aplicar: esta validación solo mejora la experiencia.
   ============================================================ */
(function () {
  const raiz = document.getElementById('registro-wizard');
  if (!raiz) return;

  const PASOS = ['Tipo de institución', 'Tus datos', 'Confirmar'];
  const ULTIMO = PASOS.length - 1;
  const CLAVE_BORRADOR = 'si_registro_borrador';
  // Nunca se guardan en el navegador: contraseñas ni NIT.
  const CAMPOS_NO_PERSISTIBLES = new Set(['password', 'passwordConfirmacion', 'nit']);
  const CAMPOS_POR_PASO = {
    1: ['nombreCompleto', 'nit', 'correo', 'password', 'passwordConfirmacion'],
    2: ['aceptaTerminos', 'aceptaTratamiento']
  };
  let captcha = null;

  let tipos = [];
  let paso = 0;
  const estado = { tipoInstitucion: null };

  const $ = sel => raiz.querySelector(sel);
  const apiBase = () => (typeof API_BASE !== 'undefined' ? API_BASE : 'http://localhost:8081').replace(/\/$/, '');
  const tipoActual = () => tipos.find(t => t.id === estado.tipoInstitucion) || null;

  function escapar(texto) {
    const span = document.createElement('span');
    span.textContent = texto == null ? '' : String(texto);
    return span.innerHTML;
  }

  // ---- Borrador local (sin secretos) --------------------------------------
  function guardarBorrador() {
    try {
      const datos = { tipoInstitucion: estado.tipoInstitucion };
      raiz.querySelectorAll('[data-campo]').forEach(el => {
        if (CAMPOS_NO_PERSISTIBLES.has(el.dataset.campo) || el.type === 'checkbox') return;
        datos[el.dataset.campo] = el.value;
      });
      sessionStorage.setItem(CLAVE_BORRADOR, JSON.stringify(datos));
    } catch { /* almacenamiento no disponible: se continúa sin borrador */ }
  }

  function leerBorrador() {
    try { return JSON.parse(sessionStorage.getItem(CLAVE_BORRADOR)) || {}; } catch { return {}; }
  }

  function borrarBorrador() {
    try { sessionStorage.removeItem(CLAVE_BORRADOR); } catch { /* sin acción */ }
  }

  // ---- Progreso ------------------------------------------------------------
  function pintarProgreso() {
    $('#vf-progreso').innerHTML = PASOS.map((nombre, i) =>
      `<li class="${i === paso ? 'activo' : i < paso ? 'hecho' : ''}" ${i === paso ? 'aria-current="step"' : ''}>${nombre}</li>`
    ).join('');
    raiz.querySelectorAll('[data-paso]').forEach(seccion => {
      seccion.hidden = Number(seccion.dataset.paso) !== paso;
    });
    $('#vf-anterior').hidden = paso === 0 || paso > ULTIMO;
    $('#vf-siguiente').hidden = paso >= ULTIMO;
    $('#vf-enviar').hidden = paso !== ULTIMO;
    $('#vf-acciones').hidden = paso > ULTIMO;
  }

  function irA(nuevo) {
    paso = nuevo;
    if (paso === 1) pintarCamposEspecificos();
    if (paso === ULTIMO) pintarResumen();
    pintarProgreso();
    const encabezado = raiz.querySelector(`[data-paso="${paso}"] h2`);
    if (encabezado) {
      encabezado.setAttribute('tabindex', '-1');
      encabezado.focus({ preventScroll: true });
    }
    raiz.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // ---- Paso 1: tipo --------------------------------------------------------
  function pintarTipos() {
    $('#vf-tipos').innerHTML = tipos.map(t => `
      <label class="vf-tipo">
        <input type="radio" name="tipoInstitucion" value="${escapar(t.id)}" ${estado.tipoInstitucion === t.id ? 'checked' : ''}>
        <strong>${escapar(t.etiqueta)}</strong>
        <span>${escapar(t.descripcion)}</span>
      </label>`).join('');
    raiz.querySelectorAll('input[name="tipoInstitucion"]').forEach(radio => {
      radio.addEventListener('change', () => cambiarTipo(radio.value));
    });
  }

  function cambiarTipo(nuevo) {
    estado.tipoInstitucion = nuevo;
    $('#vf-error-tipo').textContent = '';
    pintarCamposEspecificos(true);
    guardarBorrador();
  }

  // ---- Paso 2: datos de acceso + campo específico opcional -----------------
  function pintarCamposEspecificos(limpiar = false) {
    const tipo = tipoActual();
    const contenedor = $('#vf-campos-especificos');
    if (!tipo) { contenedor.innerHTML = ''; return; }
    const previos = limpiar ? {} : leerBorrador();
    contenedor.innerHTML = tipo.camposEspecificos.map(c => `
      <div class="col-md-6 mb-3">
        <label class="form-label" for="vf-${c.campo}">${escapar(c.etiqueta)} <span class="text-muted small">(opcional)</span></label>
        <select class="form-select" id="vf-${c.campo}" data-campo="${c.campo}">
          <option value="">Prefiero indicarlo después</option>
          ${c.opciones.map(o => `<option value="${escapar(o.valor)}" ${previos[c.campo] === o.valor ? 'selected' : ''}>${escapar(o.etiqueta)}</option>`).join('')}
        </select>
        <div class="vf-error-campo" data-error="${c.campo}"></div>
      </div>`).join('');
    const ayudaCorreo = tipo.dominiosInstitucionales.length
      ? `Si tienes un correo institucional (${tipo.dominiosInstitucionales.map(d => '@' + d).join(', ')}), úsalo: agiliza una futura verificación.`
      : 'Usa el correo desde el que gestionas las compras.';
    $('#vf-ayuda-correo').textContent = ayudaCorreo;
  }

  // ---- Validación cliente --------------------------------------------------
  function valor(campo) {
    const el = $(`[data-campo="${campo}"]`);
    if (!el) return undefined;
    return el.type === 'checkbox' ? el.checked : el.value.trim();
  }

  function marcarError(campo, mensaje) {
    const el = $(`[data-campo="${campo}"]`);
    const error = $(`[data-error="${campo}"]`);
    if (el) {
      el.classList.toggle('is-invalid', Boolean(mensaje));
      el.setAttribute('aria-invalid', mensaje ? 'true' : 'false');
      if (error) {
        error.id = error.id || `vf-error-${campo}`;
        el.setAttribute('aria-describedby', error.id);
      }
    }
    if (error) error.textContent = mensaje || '';
  }

  function validarPaso(n) {
    let valido = true;
    const fallar = (campo, mensaje) => { marcarError(campo, mensaje); valido = false; };
    if (n === 0 && !estado.tipoInstitucion) {
      $('#vf-error-tipo').textContent = 'Selecciona el tipo de institución para continuar.';
      return false;
    }
    if (n === 1) {
      CAMPOS_POR_PASO[1].forEach(c => marcarError(c, ''));
      const palabras = (valor('nombreCompleto') || '').normalize('NFD').replace(/[̀-ͯ]/g, '')
        .replace(/[^A-Za-z]+/g, ' ').trim().split(' ').filter(p => p.length >= 2);
      if (palabras.length < 2) fallar('nombreCompleto', 'Escribe al menos un nombre y un apellido.');
      const baseNit = (valor('nit') || '').split('-')[0].replace(/[\s.]/g, '');
      if (!/^\d{6,15}$/.test(baseNit)) fallar('nit', 'Escribe el NIT de tu entidad: solo números, con o sin dígito de verificación.');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(valor('correo') || '')) fallar('correo', 'Escribe un correo válido.');
      const password = $('[data-campo="password"]').value;
      if (password.length < 10 || password.length > 72) fallar('password', 'Usa entre 10 y 72 caracteres.');
      const usuario = (valor('correo') || '').split('@')[0].toLowerCase();
      if (usuario.length >= 4 && password.toLowerCase().includes(usuario)) fallar('password', 'La contraseña no puede contener tu usuario de correo.');
      if (password !== $('[data-campo="passwordConfirmacion"]').value) fallar('passwordConfirmacion', 'Las contraseñas no coinciden.');
    }
    if (n === 2) {
      CAMPOS_POR_PASO[2].forEach(c => marcarError(c, ''));
      if (!valor('aceptaTerminos')) fallar('aceptaTerminos', 'Debes aceptar los términos para crear la cuenta.');
      if (!valor('aceptaTratamiento')) fallar('aceptaTratamiento', 'Debes autorizar el tratamiento de datos para crear la cuenta.');
      captcha?.marcarError('');
      if (captcha && !captcha.completo()) {
        captcha.marcarError('Resuelve la operación.');
        if (valido) captcha.enfocar();
        valido = false;
      }
    }
    if (!valido) raiz.querySelector('.is-invalid')?.focus();
    return valido;
  }

  // ---- Paso 3: resumen -----------------------------------------------------
  function pintarResumen() {
    const tipo = tipoActual();
    const filas = [
      ['Tipo de institución', tipo?.etiqueta],
      ...(tipo?.camposEspecificos || []).filter(c => valor(c.campo)).map(c => [c.etiqueta, c.opciones.find(o => o.valor === valor(c.campo))?.etiqueta]),
      ['Nombre', valor('nombreCompleto')],
      ['NIT', valor('nit')],
      ['Correo', valor('correo')]
    ];
    $('#vf-resumen').innerHTML = filas.map(([k, v]) => `<dt>${escapar(k)}</dt><dd>${escapar(v || '—')}</dd>`).join('');
  }

  // ---- Envío ---------------------------------------------------------------
  function construirPayload() {
    const tipo = tipoActual();
    const payload = {
      tipoInstitucion: tipo.id,
      nombreCompleto: valor('nombreCompleto'),
      nit: valor('nit'),
      correo: valor('correo').toLowerCase(),
      password: $('[data-campo="password"]').value,
      aceptaTerminos: valor('aceptaTerminos') === true,
      aceptaTratamiento: valor('aceptaTratamiento') === true,
      ...(captcha ? captcha.leer() : {})
    };
    // Solo se envían los campos del tipo elegido: el servidor rechaza los ajenos.
    for (const c of tipo.camposEspecificos) if (valor(c.campo)) payload[c.campo] = valor(c.campo);
    return payload;
  }

  function pasoDeCampo(campo) {
    if (campo === 'tipoInstitucion') return 0;
    for (const [n, campos] of Object.entries(CAMPOS_POR_PASO)) if (campos.includes(campo)) return Number(n);
    return 1;
  }

  async function enviar() {
    if (!validarPaso(ULTIMO)) return;
    const boton = $('#vf-enviar');
    const mensaje = $('#vf-mensaje');
    boton.disabled = true;
    boton.textContent = 'Enviando solicitud…';
    mensaje.hidden = true;
    try {
      const resp = await fetch(apiBase() + '/api/auth/registro', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(construirPayload())
      });
      const datos = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        // Cada operación del captcha sirve una sola vez: tras cualquier error se pide otra.
        captcha?.recargar();
        if (datos.errores) {
          Object.entries(datos.errores).forEach(([campo, texto]) => {
            if (campo === 'captcha') captcha?.marcarError(texto);
            else marcarError(campo, texto);
          });
          const primero = Object.keys(datos.errores).find(c => c !== '_' && c !== 'captcha');
          if (primero) irA(pasoDeCampo(primero));
        }
        throw new Error(resp.status === 429
          ? 'Se alcanzó el límite de registros desde esta conexión. Inténtalo más tarde.'
          : datos.error || 'No se pudo completar el registro.');
      }
      borrarBorrador();
      mostrarConfirmacion(datos);
    } catch (err) {
      mensaje.className = 'alert alert-danger mt-3';
      mensaje.textContent = err.message === 'Failed to fetch'
        ? 'No hay comunicación con el servidor. Revisa tu conexión e inténtalo de nuevo.'
        : err.message;
      mensaje.hidden = false;
    } finally {
      boton.disabled = false;
      boton.textContent = 'Enviar solicitud';
    }
  }

  function mostrarConfirmacion() {
    paso = ULTIMO + 1;
    pintarProgreso();
    $('#vf-progreso').querySelectorAll('li').forEach(li => { li.className = 'hecho'; });
    const seccion = raiz.querySelector(`[data-paso="${ULTIMO + 1}"]`);
    seccion.hidden = false;
    seccion.querySelector('h2').focus();
  }

  // ---- Inicio --------------------------------------------------------------
  async function iniciar() {
    raiz.hidden = false;
    try {
      const resp = await fetch(apiBase() + '/api/auth/registro/tipos');
      if (!resp.ok) throw new Error();
      tipos = (await resp.json()).tipos || [];
    } catch {
      $('#vf-tipos').innerHTML = '<div class="alert alert-danger">No se pudieron cargar los tipos de institución. Verifica que el servidor esté en funcionamiento y recarga la página.</div>';
      $('#vf-acciones').hidden = true;
      return;
    }
    const borrador = leerBorrador();
    if (borrador.tipoInstitucion && tipos.some(t => t.id === borrador.tipoInstitucion)) estado.tipoInstitucion = borrador.tipoInstitucion;
    raiz.querySelectorAll('[data-campo]').forEach(el => {
      if (borrador[el.dataset.campo] && !CAMPOS_NO_PERSISTIBLES.has(el.dataset.campo) && el.type !== 'checkbox') el.value = borrador[el.dataset.campo];
      el.addEventListener('change', guardarBorrador);
    });
    pintarTipos();
    pintarCamposEspecificos();
    pintarProgreso();
    if (window.Captcha && $('#vf-captcha')) captcha = window.Captcha.montar($('#vf-captcha'), { idInput: 'vf-captcha-respuesta' });

    $('#vf-siguiente').addEventListener('click', () => { if (validarPaso(paso)) irA(paso + 1); });
    $('#vf-anterior').addEventListener('click', () => irA(paso - 1));
    $('#vf-enviar').addEventListener('click', enviar);
    $('#vf-campos-especificos').addEventListener('change', guardarBorrador);
  }

  window.registroWizardIniciar = iniciar;
})();
