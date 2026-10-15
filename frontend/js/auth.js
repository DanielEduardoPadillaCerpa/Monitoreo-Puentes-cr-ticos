/* ============================================================
   Autenticación — prototipo front-end
   Guarda el JWT (access token) + refresh token en localStorage
   tras login/registro. Antes de cada compra, renueva el access
   token automáticamente si está por vencer, usando el refresh
   token — sin pedirle al usuario que vuelva a loguearse.
   ============================================================ */

// URL única del backend, compartida por todas las páginas (cart.js, index.html, etc.)
const API_BASE = 'http://localhost:8081';

const AUTH_KEY = 'si_auth';
let authRenovacionEnCurso = null;

function portalToastStack() {
  let stack = document.getElementById('portal-toast-stack');
  if (!stack) {
    stack = document.createElement('div');
    stack.id = 'portal-toast-stack';
    stack.className = 'portal-toast-stack';
    stack.setAttribute('aria-live', 'polite');
    document.body.appendChild(stack);
  }
  return stack;
}

function mostrarNotificacion(mensaje, tipo = 'info', duracion = 3000) {
  const toast = document.createElement('div');
  toast.className = `portal-toast portal-toast--${tipo}`;
  toast.setAttribute('role', 'status');
  const contenido = document.createElement('span');
  contenido.textContent = String(mensaje);
  const cerrarBtn = document.createElement('button');
  cerrarBtn.type = 'button';
  cerrarBtn.className = 'portal-toast__close';
  cerrarBtn.setAttribute('aria-label', 'Cerrar');
  cerrarBtn.textContent = '×';
  toast.append(contenido, cerrarBtn);
  const cerrar = () => toast.remove();
  cerrarBtn.addEventListener('click', cerrar);
  portalToastStack().appendChild(toast);
  window.setTimeout(cerrar, duracion);
  return toast;
}

function confirmarAccion(mensaje) {
  return new Promise(resolve => {
    const toast = mostrarNotificacion('', 'info', 10000);
    const contenido = toast.querySelector('span');
    contenido.textContent = String(mensaje);
    const acciones = document.createElement('div');
    acciones.className = 'portal-confirm__actions';
    acciones.innerHTML = '<button type="button" class="btn btn-sm btn-dark" data-confirmar>Sí, continuar</button><button type="button" class="btn btn-sm btn-outline-secondary" data-cancelar>Cancelar</button>';
    contenido.appendChild(acciones);
    const terminar = resultado => { toast.remove(); resolve(resultado); };
    toast.querySelector('[data-confirmar]').addEventListener('click', () => terminar(true));
    toast.querySelector('[data-cancelar]').addEventListener('click', () => terminar(false));
  });
}

function authMigrarCarritoInvitado(correo) {
  if (!correo) return;
  try {
    const kInv = 'si_carrito:invitado';
    const kUsr = 'si_carrito:' + String(correo).toLowerCase();
    const inv = JSON.parse(localStorage.getItem(kInv)) || [];
    if (!inv.length) return;
    const usr = JSON.parse(localStorage.getItem(kUsr)) || [];
    inv.forEach(it => {
      const ya = usr.find(x => x.id === it.id);
      if (ya) ya.cantidad += it.cantidad; else usr.push(it);
    });
    localStorage.setItem(kUsr, JSON.stringify(usr));
    localStorage.removeItem(kInv);
  } catch {}
}

function authGuardar(datos) {
  localStorage.setItem(AUTH_KEY, JSON.stringify(datos));
  authMigrarCarritoInvitado(datos?.correo);
  authRenderNavbar();
}

function authLeer() {
  try {
    return JSON.parse(localStorage.getItem(AUTH_KEY));
  } catch {
    return null;
  }
}

function authEstaLogueado() {
  const sesion = authLeer();
  return !!sesion?.token && sesion.mfaVerified === true;
}

// Cierra sesión localmente y avisa al backend para revocar el refresh token
// (best-effort: si falla la petición, igual se limpia la sesión local).
function authCerrarSesion() {
  const sesion = authLeer();
  if (sesion?.refreshToken) {
    fetch(API_BASE + '/api/auth/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: sesion.refreshToken })
    }).catch(() => {});
  }
  localStorage.removeItem('si_carrito:invitado');
  localStorage.removeItem(AUTH_KEY);
  localStorage.removeItem('si_carrito:' + (sesion?.correo || '').toLowerCase());
  authRenderNavbar();
  window.location.href = 'landing.html';
}

function authRenderNavbar() {
  const temaSesion = authLeer();
  const institucion = temaSesion?.mfaVerified === true
    ? temaSesion.institucionId || 'corporativo'
    : 'general';
  document.body.dataset.institution = institucion;
  document.body.dataset.authenticated = String(temaSesion?.mfaVerified === true);
  document.body.dataset.rol = temaSesion?.mfaVerified === true ? (temaSesion.rol || '') : '';
  const imagenesTenant = {
    policia: 'image_ab9291c8.jpg',
    defensa: 'defensa-unsplash.jpg',
    bomberos: 'bomberos-dominio-publico.jpg',
    socorro: 'socorro-unsplash.jpg',
    penitenciario: 'penitenciario-unsplash.jpg',
    corporativo: 'corporativo-unsplash.jpg',
    general: 'corporativo-unsplash.jpg'
  };
  const imagenTenant = imagenesTenant[institucion];
  if (imagenTenant) {
    document.body.style.setProperty('--tenant-panel-image', `url("${API_BASE}/img/${imagenTenant}")`);
  } else {
    document.body.style.removeProperty('--tenant-panel-image');
  }
  const slot = document.getElementById('auth-nav-slot');
  const sesion = authLeer();
  const logueado = !!sesion?.correo && sesion?.mfaVerified === true;
  const esAdmin = !!(logueado && sesion?.rol === 'admin' &&
    (!sesion.expiraEn || Number(sesion.expiraEn) > Date.now()));

  const pathname = window.location.pathname.split('/').pop() || '';
  const params = new URLSearchParams(window.location.search);
  const esDashboardAdmin = pathname === 'admin-dashboard.html';
  const esVistaAdmin = /^admin-.+\.html$/.test(pathname) ||
    pathname === 'reportes.html' ||
    (pathname === 'registro.html' && (params.get('modo') === 'admin' || esAdmin));

  if (slot) {
    const icoUser = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/></svg>';
    const icoChev = '<svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>';
    const boton = '<button class="nav-account-btn dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">' + icoUser + '<span>Mi cuenta</span>' + icoChev + '</button>';
    if (logueado) {
      const correoSeguro = document.createElement('span');
      correoSeguro.textContent = sesion.correo;
      slot.innerHTML = '<div class="dropdown nav-account">' + boton +
        '<ul class="dropdown-menu dropdown-menu-end">' +
        '<li><h6 class="dropdown-header">' + correoSeguro.innerHTML + '</h6></li>' +
        (sesion.rol === 'admin'
          ? '<li><a class="dropdown-item" href="admin-verificaciones.html">Verificaciones</a></li>'
          : '<li><a class="dropdown-item" href="mi-verificacion.html">Mi verificación</a></li>') +
        '<li><a class="dropdown-item" href="historial.html">Historial</a></li>' +
        '<li><a class="dropdown-item" href="mis-reportes.html">Mis reportes</a></li>' +
        '<li><hr class="dropdown-divider"></li>' +
        '<li><button type="button" class="dropdown-item" onclick="authCerrarSesion()">Cerrar sesión</button></li>' +
        '</ul></div>';
    } else {
      slot.innerHTML = '<div class="dropdown nav-account">' + boton +
        '<ul class="dropdown-menu dropdown-menu-end">' +
        '<li><a class="dropdown-item" href="login.html">Iniciar sesión</a></li>' +
        '<li><a class="dropdown-item" href="registro.html">Crear cuenta</a></li>' +
        '</ul></div>';
    }
  }

  // "Registro de cliente" solo tiene sentido si todavía no hay cuenta.
  document.querySelectorAll('.nav-registro-link').forEach(el => {
    el.style.display = logueado ? 'none' : '';
  });

  // Historial y Mis reportes solo tienen sentido si ya hay sesión.
  document.querySelectorAll('.nav-cliente-link').forEach(el => {
    el.style.display = logueado ? '' : 'none';
  });

  const navbar = document.querySelector('.navbar .navbar-nav');
  // Los paneles con el menú administrativo unificado (Dashboard, Clientes,
  // Verificaciones, Productos, Alertas de stock, Pedidos) conservan el logo y
  // todo el menú; el modo "Regresar al panel principal" queda para las demás vistas.
  const tieneMenuAdmin = Boolean(document.querySelector('.navbar .nav-alertas-stock'));
  if (navbar && esVistaAdmin && esAdmin && !tieneMenuAdmin) {
    const brand = document.querySelector('.navbar .navbar-brand');
    const toggler = document.querySelector('.navbar .navbar-toggler');
    const navbarCollapse = navbar.closest('.navbar-collapse');
    if (brand) brand.style.display = 'none';
    if (toggler) toggler.style.display = 'none';
    if (navbarCollapse) navbarCollapse.classList.add('show');

    if (esDashboardAdmin) {
      Array.from(navbar.children).forEach(item => {
        const dashboardLink = item.querySelector('a[href="admin-dashboard.html"], a[data-i18n="nav_dashboard"], a.active');
        item.style.display = dashboardLink ? '' : 'none';
      });
    } else {
      let backLink = navbar.querySelector('a[href="admin-dashboard.html"], #nav-regresar-admin-global, #nav-regresar-admin')
        || document.getElementById('nav-regresar-admin');
      if (!backLink) {
        const li = document.createElement('li');
        li.className = 'nav-item';
        backLink = document.createElement('a');
        backLink.id = 'nav-regresar-admin-global';
        backLink.className = 'nav-link';
        li.appendChild(backLink);
        navbar.insertBefore(li, navbar.firstChild);
      }

      backLink.href = 'admin-dashboard.html';
      backLink.textContent = '← Regresar al panel principal';
      backLink.style.display = 'inline-flex';

      Array.from(navbar.children).forEach(item => {
        item.style.display = item.contains(backLink) ? '' : 'none';
      });
      const backItem = backLink.closest('li');
      if (backItem) backItem.style.display = '';
    }
  }

  if (esAdmin) {
    if (!tieneMenuAdmin) {
      document.querySelectorAll('.navbar a[href="admin-dashboard.html"]').forEach(el => {
        el.textContent = '← Regresar al panel principal';
      });
    }
    document.querySelectorAll('.navbar a[href="historial.html"]').forEach(el => {
      el.textContent = 'Historial de clientes';
      el.href = 'admin-pedidos.html';
    });
    document.querySelectorAll('.navbar a[href="mis-reportes.html"]').forEach(el => {
      el.textContent = 'Reportes de clientes';
      el.href = 'reportes.html';
    });
    document.querySelectorAll('.navbar a[href="registro.html"]').forEach(el => {
      el.textContent = 'Nuevo cliente';
      el.href = 'registro.html?modo=admin';
    });
    document.querySelectorAll('.nav-registro-link').forEach(el => {
      el.style.display = '';
    });

    const navList = document.querySelector('.navbar .navbar-nav');
    const esCatalogo = /(^|\/)index\.html$/.test(window.location.pathname) || window.location.pathname.endsWith('/');
    if (esCatalogo && navList) {
      const enlacesAdmin = [
        ['admin-clientes.html', 'Clientes'],
        ['admin-productos.html', 'Productos'],
        ['admin-pedidos.html', 'Pedidos'],
        ['admin-verificaciones.html', 'Verificaciones'],
        ['reportes.html', 'Reportes']
      ];
      enlacesAdmin.forEach(([href, label]) => {
        if (navList.querySelector(`a[href="${href}"]`)) return;
        const li = document.createElement('li');
        li.className = 'nav-item';
        const link = document.createElement('a');
        link.className = 'nav-link';
        link.href = href;
        link.textContent = label;
        li.appendChild(link);
        const authItem = navList.querySelector('#auth-nav-slot')?.parentElement;
        navList.insertBefore(li, authItem || null);
      });
    }

    const tieneDashboard = navbar && Array.from(navbar.querySelectorAll('a'))
      .some(link => link.getAttribute('href') === 'admin-dashboard.html');
    const modoRegistroAdmin = document.body.classList.contains('modo-admin-registro');
    const esDashboard = window.location.pathname.endsWith('admin-dashboard.html');
    if (navbar && !tieneDashboard && !esDashboard && !modoRegistroAdmin && !document.getElementById('nav-regresar-admin-global')) {
      const li = document.createElement('li');
      li.className = 'nav-item';
      const link = document.createElement('a');
      link.id = 'nav-regresar-admin-global';
      link.className = 'nav-link';
      link.href = 'admin-dashboard.html';
      link.textContent = '← Regresar al panel principal';
      li.appendChild(link);
      navbar.insertBefore(li, navbar.firstChild);
    }
  }

  // Inicializar tooltips de Bootstrap
  const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
  tooltipTriggerList.map(el => new bootstrap.Tooltip(el));
}


// Llama esto antes de dejar avanzar al checkout. Si no hay sesión,
// redirige a login.html y recuerda a dónde volver.
function authRequerirParaComprar(destinoSiLogueado) {
  if (authEstaLogueado()) {
    window.location.href = destinoSiLogueado;
    return;
  }
  window.location.href = 'login.html?redirect=' + encodeURIComponent(destinoSiLogueado);
}

// Verifica que el access token siga siendo válido antes de una acción
// sensible (como confirmar una compra). Si está vencido o a punto de
// vencer, lo renueva en silencio usando el refresh token.
// Devuelve true si hay una sesión válida lista para usar, false si no
// (y ya se encargó de cerrar la sesión / redirigir si corresponde).
async function authAsegurarTokenValido() {
  const sesion = authLeer();
  if (!sesion?.token) return false;
  if (sesion.mfaVerified !== true) {
    localStorage.removeItem(AUTH_KEY);
    authRenderNavbar();
    return false;
  }
  if (authRenovacionEnCurso) return authRenovacionEnCurso;

  let expiraEn = Number(sesion.expiraEn) || 0;
  if (!expiraEn) {
    try {
      const payload = sesion.token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      expiraEn = Number(JSON.parse(atob(payload)).exp) * 1000;
    } catch {
      expiraEn = 0;
    }
  }

  const margenMs = 60 * 1000;
  const vencidoOPorVencer = !expiraEn || (expiraEn - Date.now()) < margenMs;

  if (!vencidoOPorVencer) return true;

  if (!sesion.refreshToken) {
    localStorage.removeItem(AUTH_KEY);
    authRenderNavbar();
    return false;
  }

  authRenovacionEnCurso = (async () => {
    try {
      const resp = await fetch(API_BASE + '/api/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: sesion.refreshToken })
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) throw new Error(data.error || 'No se pudo renovar la sesión');

      authGuardar(data);
      return true;
    } catch (err) {
      console.error('[auth] Error renovando sesión:', err);
      localStorage.removeItem(AUTH_KEY);
      authRenderNavbar();
      return false;
    } finally {
      authRenovacionEnCurso = null;
    }
  })();
  return authRenovacionEnCurso;
}

document.addEventListener('DOMContentLoaded', authRenderNavbar);

function authEnsureChatbot() {
  if (document.getElementById('chatbot-toggle') || document.getElementById('chatbot-panel')) return;
  const wrapper = document.createElement('div');
  wrapper.innerHTML = `
    <button id="chatbot-toggle" type="button" onclick="cbToggle()" title="Asistente del catálogo" aria-label="Abrir asistente del catálogo" aria-expanded="false">💬</button>
    <section id="chatbot-panel" aria-label="Asistente del catálogo">
      <div class="cb-header"><span>Asistente del catálogo</span><button type="button" onclick="cbToggle()" aria-label="Cerrar">×</button></div>
      <div class="cb-body" id="cb-body" aria-live="polite" aria-relevant="additions text"><div class="cb-msg bot">Hola. Puedo ayudarte con el catálogo, precios y disponibilidad.</div></div>
      <div class="cb-quick cb-quick-start">
        <button type="button" data-q="¿Qué productos tienen disponibles?">Productos disponibles</button>
        <button type="button" data-q="¿Qué productos están restringidos?">Productos restringidos</button>
      </div>
      <button class="cb-human-button" type="button">Hablar con una persona</button>
      <div class="cb-input"><input type="text" id="cb-input-text" maxlength="500" placeholder="Pregunta sobre productos..." aria-label="Pregunta sobre el catálogo"><button id="cb-send-button" type="button" onclick="cbEnviar()">Enviar</button></div>
    </section>`;
  document.body.appendChild(wrapper);
  if (!document.querySelector('script[src$="js/chatbot.js"]')) {
    const script = document.createElement('script');
    script.src = 'js/chatbot.js';
    document.body.appendChild(script);
  }
}

document.addEventListener('DOMContentLoaded', authEnsureChatbot);