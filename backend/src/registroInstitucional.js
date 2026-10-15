const { z } = require('zod');
const { INSTITUCIONES } = require('./tenancy');
const { normalizarNit: normalizarNitRegistro, nombreCompletoValido } = require('./seguridad/normalizacion');

// Tipos de comprador admitidos en el autorregistro. Reutilizan los
// identificadores de tenancy.js (y por tanto productos.institucion_id); 'general'
// es un ámbito de producto, no un tipo de comprador.
//
// - dominios: correos cuyo dominio coincide con el tipo. Una coincidencia,
//   sumada al MFA por correo, prueba el control del buzón institucional y exime
//   del documento de vinculación; NO aprueba la cuenta: siempre decide un revisor.
// - documentos: evidencia que el solicitante adjunta tras verificar su correo.
//   obligatorio: 'siempre' | 'sin_dominio' (solo si el dominio no coincide) |
//   función (datos) => boolean | false (opcional).
const DOC_VINCULACION = {
  tipo: 'acreditacion_vinculacion',
  etiqueta: 'Certificado laboral, acto de designación u oficio que acredite que gestionas compras para la dependencia',
  obligatorio: 'sin_dominio'
};

const TIPOS_COMPRADOR = Object.freeze({
  policia: {
    etiqueta: INSTITUCIONES.policia.nombre,
    descripcion: 'Unidades, estaciones y dependencias de la Policía Nacional de Colombia.',
    dominios: ['policia.gov.co', 'policia.mil.co'],
    camposEspecificos: {},
    documentos: [DOC_VINCULACION]
  },
  defensa: {
    etiqueta: 'Fuerzas Militares y sector Defensa',
    descripcion: 'Ejército, Armada, Fuerza Aérea, Ministerio de Defensa y entidades adscritas.',
    dominios: ['ejercito.mil.co', 'armada.mil.co', 'fac.mil.co', 'dimar.mil.co', 'mindefensa.gov.co'],
    camposEspecificos: {
      fuerza: {
        etiqueta: 'Fuerza o entidad',
        opciones: {
          ejercito: 'Ejército Nacional',
          armada: 'Armada de Colombia',
          fuerza_aerea: 'Fuerza Aérea Colombiana',
          mindefensa: 'Ministerio de Defensa Nacional',
          dimar: 'Dirección General Marítima',
          otra: 'Otra entidad del sector Defensa'
        }
      }
    },
    documentos: [DOC_VINCULACION]
  },
  bomberos: {
    etiqueta: INSTITUCIONES.bomberos.nombre,
    descripcion: 'Cuerpos de bomberos oficiales, voluntarios y aeronáuticos.',
    dominios: ['dnbc.gov.co', 'bomberos.gov.co'],
    camposEspecificos: {
      tipoCuerpo: {
        etiqueta: 'Clase de cuerpo de bomberos',
        opciones: { oficial: 'Oficial', voluntario: 'Voluntario', aeronautico: 'Aeronáutico' }
      }
    },
    documentos: [
      {
        tipo: 'acreditacion_entidad',
        etiqueta: 'Documento que acredite la existencia legal del cuerpo de bomberos (acto de creación, reconocimiento o certificado vigente)',
        obligatorio: 'siempre'
      },
      DOC_VINCULACION
    ]
  },
  socorro: {
    etiqueta: INSTITUCIONES.socorro.nombre,
    descripcion: 'Defensa Civil, Cruz Roja y otros organismos de socorro y rescate.',
    dominios: ['defensacivil.gov.co', 'defensacivil.org.co'],
    camposEspecificos: {
      organismo: {
        etiqueta: 'Organismo',
        opciones: { defensa_civil: 'Defensa Civil Colombiana', cruz_roja: 'Cruz Roja Colombiana', otro: 'Otro organismo de socorro' }
      }
    },
    documentos: [
      {
        tipo: 'acreditacion_entidad',
        etiqueta: 'Documento que acredite la existencia legal del organismo o de la seccional',
        obligatorio: 'sin_dominio'
      },
      DOC_VINCULACION
    ]
  },
  penitenciario: {
    etiqueta: INSTITUCIONES.penitenciario.nombre,
    descripcion: 'INPEC, USPEC y establecimientos de reclusión.',
    dominios: ['inpec.gov.co', 'uspec.gov.co'],
    camposEspecificos: {
      entidadPenitenciaria: {
        etiqueta: 'Entidad',
        opciones: { inpec: 'INPEC', uspec: 'USPEC', territorial: 'Establecimiento de orden territorial' }
      }
    },
    documentos: [DOC_VINCULACION]
  },
  corporativo: {
    etiqueta: 'Empresas e instituciones privadas',
    descripcion: 'Empresas de seguridad privada, salud, industria, construcción y otras organizaciones privadas.',
    dominios: [],
    camposEspecificos: {
      sector: {
        etiqueta: 'Sector',
        opciones: {
          seguridad_privada: 'Vigilancia y seguridad privada',
          salud: 'Salud y atención de emergencias',
          industria: 'Industria y construcción',
          comercio_servicios: 'Comercio y servicios',
          otro: 'Otro'
        }
      }
    },
    documentos: [
      {
        tipo: 'certificado_existencia',
        etiqueta: 'Certificado de existencia y representación legal (Cámara de Comercio)',
        obligatorio: 'siempre'
      },
      {
        tipo: 'licencia_supervigilancia',
        etiqueta: 'Licencia de funcionamiento vigente expedida por la Superintendencia de Vigilancia y Seguridad Privada',
        obligatorio: datos => datos?.sector === 'seguridad_privada'
      },
      { tipo: 'rut', etiqueta: 'RUT de la empresa', obligatorio: false },
      DOC_VINCULACION
    ]
  }
});

const TIPOS_DOCUMENTO = new Set(
  Object.values(TIPOS_COMPRADOR).flatMap(tipo => tipo.documentos.map(doc => doc.tipo))
);

function tipoCompradorValido(tipo) {
  return typeof tipo === 'string' && Object.prototype.hasOwnProperty.call(TIPOS_COMPRADOR, tipo);
}

function dominioDeCorreo(correo) {
  return String(correo || '').trim().toLowerCase().split('@').pop();
}

function dominioCoincide(tipo, correo) {
  return tipoCompradorValido(tipo) && TIPOS_COMPRADOR[tipo].dominios.includes(dominioDeCorreo(correo));
}

// Dígito de verificación del NIT (algoritmo módulo 11 publicado por la DIAN).
function calcularDvNit(base) {
  const pesos = [3, 7, 13, 17, 19, 23, 29, 37, 41, 43, 47, 53, 59, 67, 71];
  const digitos = String(base).split('').reverse();
  const suma = digitos.reduce((total, digito, i) => total + Number(digito) * pesos[i], 0);
  const residuo = suma % 11;
  return residuo > 1 ? 11 - residuo : residuo;
}

// Acepta "900123456-7", "900.123.456-7" o "9001234567"; devuelve "900123456-7"
// o null si el formato o el dígito de verificación no son válidos.
function normalizarNit(valor) {
  const limpio = String(valor || '').replace(/[\s.]/g, '');
  const coincidencia = /^(\d{6,15})-?(\d)$/.exec(limpio);
  if (!coincidencia) return null;
  const [, base, dv] = coincidencia;
  return calcularDvNit(base) === Number(dv) ? `${base}-${dv}` : null;
}

const texto = (min, max) => z.string().trim().min(min).max(max);
const CAMPOS_COMUNES = {
  tipoInstitucion: z.string(),
  nombreEntidad: texto(3, 200),
  nit: z.string().max(25),
  dependencia: texto(2, 200),
  cargo: texto(2, 120),
  departamento: texto(2, 80),
  municipio: texto(2, 80),
  direccionInstalacion: texto(5, 255),
  nombreFuncionario: texto(5, 150),
  correo: z.string().trim().toLowerCase().max(254).regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/),
  telefono: z.string().trim().regex(/^\+?[0-9 ()-]{7,20}$/),
  direccionEntrega: z.string().trim().max(255).optional(),
  password: z.string().min(10).max(72),
  aceptaTratamiento: z.literal(true),
  numeroConsultaAntecedentes: z.string().trim().max(100).optional(),
  autorizacionSensible: z.boolean().optional()
};

const MENSAJES_CAMPO = {
  tipoInstitucion: 'Selecciona un tipo de institución válido.',
  nombreEntidad: 'Indica el nombre de la entidad u organización (mínimo 3 caracteres).',
  nit: 'El NIT no es válido. Escríbelo con su dígito de verificación, por ejemplo 900123456-7.',
  dependencia: 'Indica la unidad, sede o dependencia.',
  cargo: 'Indica tu cargo o función.',
  departamento: 'Indica el departamento.',
  municipio: 'Indica el municipio.',
  direccionInstalacion: 'Indica la dirección de la sede.',
  nombreFuncionario: 'Indica tu nombre completo.',
  correo: 'El correo electrónico no es válido.',
  telefono: 'El teléfono no es válido.',
  direccionEntrega: 'La dirección de entrega es demasiado larga.',
  password: 'La contraseña debe tener entre 10 y 72 caracteres.',
  aceptaTratamiento: 'Debes autorizar el tratamiento de datos personales para continuar.',
  numeroConsultaAntecedentes: 'El número de consulta no es válido.',
  autorizacionSensible: 'La autorización de tratamiento no es válida.'
};

for (const tipo of Object.values(TIPOS_COMPRADOR)) {
  for (const [campo, def] of Object.entries(tipo.camposEspecificos)) {
    MENSAJES_CAMPO[campo] = MENSAJES_CAMPO[campo] || `Selecciona: ${def.etiqueta.toLowerCase()}.`;
  }
}

// Registro mínimo: solo lo indispensable para crear y proteger la cuenta. Los
// datos de la organización, el documento de identidad y la evidencia se piden
// después, únicamente si una compra lo requiere. El campo específico del tipo
// (fuerza, organismo, clase de cuerpo, sector) es opcional y no sensible.
MENSAJES_CAMPO.nombreCompleto = 'Escribe tu nombre completo: al menos un nombre y un apellido.';
MENSAJES_CAMPO.nitRegistro = 'Escribe el NIT de tu entidad (solo números; el dígito de verificación es opcional).';
MENSAJES_CAMPO.aceptaTerminos = 'Debes aceptar los términos y condiciones para crear la cuenta.';
function esquemaRegistroMinimo(tipo) {
  const especificos = {};
  for (const [campo, def] of Object.entries(TIPOS_COMPRADOR[tipo].camposEspecificos)) {
    especificos[campo] = z.enum(Object.keys(def.opciones)).optional();
  }
  // strict: cualquier campo de otro tipo, o intentos de fijar rol, clienteId,
  // estado o autorizaciones, hacen fallar la validación.
  return z.object({
    tipoInstitucion: z.string(),
    nombreCompleto: texto(5, 150),
    nit: z.string().trim().min(1).max(30),
    correo: CAMPOS_COMUNES.correo,
    password: CAMPOS_COMUNES.password,
    aceptaTerminos: z.literal(true),
    aceptaTratamiento: z.literal(true),
    ...especificos
  }).strict();
}

const ESQUEMAS = Object.fromEntries(Object.keys(TIPOS_COMPRADOR).map(tipo => [tipo, esquemaRegistroMinimo(tipo)]));

function contrasenaContieneUsuario(password, correo) {
  const usuario = correo.split('@')[0];
  return usuario.length >= 4 && password.toLowerCase().includes(usuario);
}

// Valida el registro según el tipo elegido. El servidor decide qué campos son
// obligatorios: el navegador solo elige el tipo.
function validarRegistro(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, errores: { _: 'Solicitud inválida.' } };
  }
  if (!tipoCompradorValido(body.tipoInstitucion)) {
    return { ok: false, errores: { tipoInstitucion: MENSAJES_CAMPO.tipoInstitucion } };
  }
  const resultado = ESQUEMAS[body.tipoInstitucion].safeParse(body);
  const errores = {};
  if (!resultado.success) {
    for (const issue of resultado.error.issues) {
      if (issue.code === 'unrecognized_keys') {
        errores._ = 'El registro contiene campos no permitidos para este tipo de institución.';
        continue;
      }
      const campo = String(issue.path[0] ?? '_');
      if (!errores[campo]) errores[campo] = (campo === 'nit' ? MENSAJES_CAMPO.nitRegistro : MENSAJES_CAMPO[campo]) || 'Valor no válido.';
    }
    return { ok: false, errores };
  }
  const datos = resultado.data;
  if (!nombreCompletoValido(datos.nombreCompleto)) {
    return { ok: false, errores: { nombreCompleto: MENSAJES_CAMPO.nombreCompleto } };
  }
  if (!normalizarNitRegistro(datos.nit)) {
    return { ok: false, errores: { nit: MENSAJES_CAMPO.nitRegistro } };
  }
  if (contrasenaContieneUsuario(datos.password, datos.correo)) {
    return { ok: false, errores: { password: 'La contraseña no puede contener tu usuario de correo.' } };
  }
  return { ok: true, datos };
}

// Campos específicos del tipo que se capturaron en el registro (opcionales).
function camposEspecificosDe(tipo, datos) {
  const salida = {};
  for (const campo of Object.keys(TIPOS_COMPRADOR[tipo].camposEspecificos)) {
    if (datos[campo]) salida[campo] = datos[campo];
  }
  return salida;
}

// Solo los datos de la organización (sin credenciales ni datos personales del
// titular): reclasificar una cuenta heredada o solicitar un cambio de tipo.
const CAMPOS_ORGANIZACION = ['tipoInstitucion', 'nombreEntidad', 'nit', 'dependencia', 'cargo', 'departamento', 'municipio', 'direccionInstalacion'];
const ESQUEMAS_ORGANIZACION = Object.fromEntries(Object.keys(TIPOS_COMPRADOR).map(tipo => {
  const base = Object.fromEntries(CAMPOS_ORGANIZACION.map(campo => [campo, CAMPOS_COMUNES[campo]]));
  const especificos = Object.fromEntries(Object.entries(TIPOS_COMPRADOR[tipo].camposEspecificos)
    .map(([campo, def]) => [campo, z.enum(Object.keys(def.opciones))]));
  return [tipo, z.object({ ...base, ...especificos }).strict()];
}));

function validarDatosOrganizacion(body) {
  if (!body || typeof body !== 'object' || !tipoCompradorValido(body.tipoInstitucion)) {
    return { ok: false, errores: { tipoInstitucion: MENSAJES_CAMPO.tipoInstitucion } };
  }
  const resultado = ESQUEMAS_ORGANIZACION[body.tipoInstitucion].safeParse(body);
  if (!resultado.success) {
    const errores = {};
    for (const issue of resultado.error.issues) {
      const campo = issue.code === 'unrecognized_keys' ? '_' : String(issue.path[0] ?? '_');
      if (!errores[campo]) errores[campo] = campo === '_' ? 'La solicitud contiene campos no permitidos para este tipo de institución.' : MENSAJES_CAMPO[campo] || 'Valor no válido.';
    }
    return { ok: false, errores };
  }
  const nit = normalizarNit(resultado.data.nit);
  if (!nit) return { ok: false, errores: { nit: MENSAJES_CAMPO.nit } };
  return { ok: true, datos: { ...resultado.data, nit } };
}

// Campos que se guardan cifrados en clientes.datos_registro_cifrados.
function datosInstitucionales(tipo, datos) {
  const salida = {
    dependencia: datos.dependencia,
    cargo: datos.cargo,
    departamento: datos.departamento,
    municipio: datos.municipio
  };
  for (const campo of Object.keys(TIPOS_COMPRADOR[tipo].camposEspecificos)) salida[campo] = datos[campo];
  return salida;
}

// Lista de documentos con su obligatoriedad resuelta para una solicitud concreta.
function requisitosDocumentales(tipo, { dominioVerificado = false, datos = {} } = {}) {
  if (!tipoCompradorValido(tipo)) return [];
  return TIPOS_COMPRADOR[tipo].documentos.map(doc => {
    let obligatorio = false;
    if (doc.obligatorio === 'siempre') obligatorio = true;
    else if (doc.obligatorio === 'sin_dominio') obligatorio = !dominioVerificado;
    else if (typeof doc.obligatorio === 'function') obligatorio = Boolean(doc.obligatorio(datos));
    return { tipo: doc.tipo, etiqueta: doc.etiqueta, obligatorio };
  });
}

function documentosFaltantes(requisitos, documentosVigentes) {
  const presentes = new Set(documentosVigentes.map(doc => doc.tipo_documento || doc.tipo));
  return requisitos.filter(req => req.obligatorio && !presentes.has(req.tipo));
}

// Configuración pública para construir el formulario (sin reglas internas).
function configuracionPublica() {
  return Object.entries(TIPOS_COMPRADOR).map(([id, tipo]) => ({
    id,
    etiqueta: tipo.etiqueta,
    descripcion: tipo.descripcion,
    dominiosInstitucionales: tipo.dominios,
    camposEspecificos: Object.entries(tipo.camposEspecificos).map(([campo, def]) => ({
      campo,
      etiqueta: def.etiqueta,
      opciones: Object.entries(def.opciones).map(([valor, etiqueta]) => ({ valor, etiqueta }))
    })),
    documentos: tipo.documentos.map(doc => ({
      tipo: doc.tipo,
      etiqueta: doc.etiqueta,
      obligatorio: doc.obligatorio === 'siempre'
        ? 'siempre'
        : doc.obligatorio === 'sin_dominio'
          ? 'si_el_correo_no_es_institucional'
          : typeof doc.obligatorio === 'function' ? 'segun_datos' : 'opcional'
    }))
  }));
}

module.exports = {
  TIPOS_COMPRADOR,
  TIPOS_DOCUMENTO,
  tipoCompradorValido,
  dominioCoincide,
  calcularDvNit,
  normalizarNit,
  validarRegistro,
  camposEspecificosDe,
  validarDatosOrganizacion,
  datosInstitucionales,
  requisitosDocumentales,
  documentosFaltantes,
  configuracionPublica
};
