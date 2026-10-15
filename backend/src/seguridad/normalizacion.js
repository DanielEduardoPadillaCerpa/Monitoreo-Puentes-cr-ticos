// Normalización de los datos que se comparan contra el padrón.

// NIT: solo dígitos y sin dígito de verificación (lo que va tras el guion).
// "900.123.456-7" → "900123456"; "900123456" → "900123456".
// Devuelve null si no quedan entre 6 y 15 dígitos.
function normalizarNit(valor) {
  const texto = String(valor ?? '').trim();
  if (!texto || texto.length > 30) return null;
  // Base con puntos o espacios y, opcionalmente, "-" y un solo dígito de verificación.
  const partes = /^([\d.\s]+?)\s*(?:-\s*\d)?$/.exec(texto);
  if (!partes) return null;
  const digitos = partes[1].replace(/\D/g, '');
  return /^\d{6,15}$/.test(digitos) ? digitos : null;
}

// Nombre: sin tildes, mayúsculas, solo letras y palabras ordenadas
// alfabéticamente, para tolerar "Apellidos Nombres" y espacios extra.
// "Rodríguez  Juan-Camilo" → "CAMILO JUAN RODRIGUEZ".
function palabrasNombre(valor) {
  return String(valor ?? '')
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toUpperCase()
    .replace(/[^A-Z]+/g, ' ')
    .trim()
    .split(' ')
    .filter(Boolean);
}

function normalizarNombre(valor) {
  return palabrasNombre(valor).sort().join(' ');
}

// Mínimo dos palabras de al menos dos letras (nombre y apellido).
function nombreCompletoValido(valor) {
  const texto = String(valor ?? '');
  if (texto.trim().length > 150) return false;
  return palabrasNombre(texto).filter(p => p.length >= 2).length >= 2;
}

module.exports = { normalizarNit, normalizarNombre, nombreCompletoValido };
