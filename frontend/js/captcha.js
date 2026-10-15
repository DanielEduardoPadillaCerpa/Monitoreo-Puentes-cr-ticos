/* ============================================================
   Captcha propio (sin servicios externos): una suma dibujada por el
   servidor. Cada operación sirve para un solo intento; tras cualquier
   error del formulario se pide una nueva.
   Uso: const c = Captcha.montar(elemento); c.leer(); c.recargar();
   ============================================================ */
(function () {
  const apiBase = () => (typeof API_BASE !== 'undefined' ? API_BASE : 'http://localhost:8081').replace(/\/$/, '');

  function montar(contenedor, { idInput = 'captchaRespuesta' } = {}) {
    contenedor.classList.add('captcha-caja');
    contenedor.innerHTML = `
      <label class="form-label small mb-1" for="${idInput}">Verificación: resuelve la operación *</label>
      <div class="d-flex align-items-center gap-2 flex-wrap">
        <img class="captcha-imagen border rounded" width="170" height="56" alt="Operación matemática de verificación">
        <button type="button" class="btn btn-sm btn-outline-secondary captcha-recargar" title="Otra operación" aria-label="Cargar otra operación">↻</button>
        <input type="text" class="form-control" id="${idInput}" inputmode="numeric" autocomplete="off" maxlength="3" style="max-width:6rem" required>
      </div>
      <div class="vf-error-campo small text-danger" data-error="captcha"></div>`;
    const imagen = contenedor.querySelector('img');
    const input = contenedor.querySelector('input');
    let id = null;

    async function recargar() {
      id = null;
      input.value = '';
      imagen.removeAttribute('src');
      try {
        const resp = await fetch(apiBase() + '/api/auth/captcha', { cache: 'no-store' });
        if (!resp.ok) throw new Error();
        const datos = await resp.json();
        id = datos.id;
        imagen.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(datos.svg);
      } catch {
        imagen.alt = 'No se pudo cargar la verificación. Pulsa ↻ para reintentar.';
      }
    }

    input.addEventListener('input', () => { input.value = input.value.replace(/\D/g, '').slice(0, 3); });
    contenedor.querySelector('.captcha-recargar').addEventListener('click', recargar);
    recargar();

    return {
      recargar,
      leer: () => ({ captchaId: id, captchaRespuesta: input.value.trim() }),
      completo: () => Boolean(id && input.value.trim()),
      enfocar: () => input.focus(),
      marcarError: mensaje => { contenedor.querySelector('[data-error="captcha"]').textContent = mensaje || ''; }
    };
  }

  window.Captcha = { montar };
})();
