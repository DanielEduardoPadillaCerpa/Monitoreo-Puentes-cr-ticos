/* ============================================================
   Contador de solicitudes de cuenta pendientes en el menú admin.
   Consulta GET /api/admin/solicitudes/contador (COUNT con índice) cada
   12 segundos mientras la pestaña está visible, y pinta el número en
   todos los elementos .badge-solicitudes.
   ============================================================ */
(function () {
  const INTERVALO_MS = 12000;
  let pendientes = null;
  const oyentes = [];

  function pintar() {
    document.querySelectorAll('.badge-solicitudes').forEach(badge => {
      badge.textContent = pendientes > 0 ? String(pendientes) : '';
      badge.hidden = !(pendientes > 0);
      badge.setAttribute('aria-label', `${pendientes || 0} solicitudes pendientes`);
    });
  }

  function fijar(valor) {
    const anterior = pendientes;
    pendientes = Math.max(0, valor);
    pintar();
    if (anterior !== null && anterior !== pendientes) oyentes.forEach(fn => fn(pendientes));
    if (anterior === null) oyentes.forEach(fn => fn(pendientes));
  }

  async function refrescar() {
    if (typeof authLeer !== 'function') return;
    const sesion = authLeer();
    if (!sesion || sesion.rol !== 'admin' || !sesion.token) return;
    if (typeof authAsegurarTokenValido === 'function' && !await authAsegurarTokenValido()) return;
    try {
      const resp = await fetch(API_BASE + '/api/admin/solicitudes/contador', {
        headers: { Authorization: 'Bearer ' + authLeer().token },
        cache: 'no-store'
      });
      if (!resp.ok) return;
      const datos = await resp.json();
      fijar(Number(datos.pendientes) || 0);
    } catch { /* sin conexión: se reintenta en el siguiente ciclo */ }
  }

  setInterval(() => { if (document.visibilityState === 'visible') refrescar(); }, INTERVALO_MS);
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') refrescar(); });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', refrescar);
  else refrescar();

  window.ContadorSolicitudes = {
    refrescar,
    // Actualización optimista al aprobar o rechazar (sin esperar al servidor).
    ajustar: delta => { if (pendientes !== null) { pendientes = Math.max(0, pendientes + delta); pintar(); } },
    alCambiar: fn => oyentes.push(fn)
  };
})();
