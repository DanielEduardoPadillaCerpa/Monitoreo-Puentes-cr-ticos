const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

const configuredConnectionLimit = Number(process.env.DB_CONNECTION_LIMIT);
const connectionLimit = Number.isSafeInteger(configuredConnectionLimit) && configuredConnectionLimit > 0
  ? Math.min(configuredConnectionLimit, 4)
  : 3;

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit,
  connectTimeout: 20000,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000,
  idleTimeout: 60000,
});

// Pool de una conexión para las transacciones del registro y del inicio de
// sesión, que se envían como un solo lote (START TRANSACTION … COMMIT) para
// hacer un solo viaje a MySQL. Las sentencias son fijas y los valores van
// siempre como parámetros escapados por mysql2: ningún texto del usuario se
// concatena al SQL. Con el pool principal (3) suma 4 de las 5 conexiones del
// plan gratuito de Clever Cloud.
const poolTransacciones = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 1,
  multipleStatements: true,
  connectTimeout: 20000,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000,
  idleTimeout: 60000,
});

const CATEGORIAS_SEED = [
  ['Dotación', 'Uniformes y dotación básica'],
  ['Equipo táctico', 'Equipos especializados para operaciones'],
  ['Papelería oficial', 'Material oficial de oficina'],
  ['Oficina', 'Equipos y suministros de oficina'],
  ['Uniformidad', 'Prendas técnicas y calzado'],
  ['Protección personal', 'Elementos de protección pasiva'],
  ['Seguridad industrial', 'Elementos de protección y seguridad para el trabajo'],
  ['Emergencias y rescate', 'Equipos para respuesta a emergencias y rescate'],
  ['Salud y primeros auxilios', 'Insumos de atención prehospitalaria y primeros auxilios'],
  ['Archivo y papelería', 'Insumos de archivo, impresión y gestión documental'],
  ['Comunicaciones', 'Equipos y accesorios de comunicación institucional'],
  ['Tráfico y medición', 'Instrumentos de control vial'],
  ['Herramientas', 'Accesorios y herramientas tácticas'],
  ['Fundas y portas', 'Fundas y sistemas de sujeción'],
  ['Tecnología', 'Comunicaciones y registro de evidencias'],
  ['Primeros auxilios', 'IFAK y soporte vital'],
  ['Criminalística', 'Policía científica y evidencias'],
];  
const USUARIOS_SEED = [
  ['admin@empresa.com', '$2b$12$y1boqSHiF9TnjNRcAUCmMubnGqRrNSBJN1oLl1ICM2HQx0FO1KSrW', 'admin'],
];
// [id, nombre, descripcion, precio, cantidad_disponible, restringido, nombreCategoria]
const PRODUCTOS_SEED = [
  ['Uniforme operativo — tela ripstop', 'Camisa y pantalón reglamentario, resistente a abrasión, disponible en tallas S a XXL.', 186000, 50, false, 'Dotación'],
  [ 'Chaleco portaequipo modular', 'Sistema MOLLE, ajuste lateral, compatible con placas de protección estándar.', 312500, 20, true, 'Equipo táctico'],
  ['Talonario de comparendos (x50)', 'Papel numerado consecutivo, formato oficial vigente, empaque sellado.', 41900, 100, false, 'Papelería oficial'],
  ['Botas tácticas antideslizantes', 'Suela de goma reforzada, punta reforzada, tallas 36 a 45.', 228000, 40, false, 'Dotación'],
  ['Kit de sellos institucionales', 'Set de 3 sellos personalizados con escudo de la unidad, entintado automático.', 97300, 30, false, 'Oficina'],
  ['Linterna operativa recargable', '1200 lúmenes, resistente a agua IP67, montaje compatible con arma larga.', 154200, 25, true, 'Equipo táctico'],
  ['Botas tácticas policiales Gore-Tex', 'Calzado con suela antideslizante, membrana impermeable y plantilla anticlavo.', 245000, 35, false, 'Uniformidad'],
  ['Pantalón táctico de dotación', 'Tratamiento de teflón, fuelles elásticos y bolsillos de carga ocultos.', 132000, 60, false, 'Uniformidad'],
  ['Polo técnico antibacterial', 'Camiseta transpirable con propiedades antibacteriales y tratamiento ignífugo.', 78500, 80, false, 'Uniformidad'],
  [ 'Chaquetón de alta visibilidad', 'Chaleco reflectante y chaquetón impermeable homologado para control de tráfico.', 96000, 40, false, 'Uniformidad'],
  [ 'Cinturón interior/exterior de dotación', 'Sistema de doble cinturón (velcro interior y rígido exterior) para fijar el equipo.', 64000, 50, false, 'Uniformidad'],
  [ 'Chaleco balístico y anticuchillo', 'Paneles de fibras de aramida (Kevlar/Twaron) con funda lavable.', 890000, 10, true, 'Protección personal'],
  [ 'Placas balísticas traumáticas', 'Placas rígidas adicionales para absorber energía de impacto en el pecho.', 410000, 15, true, 'Protección personal'],
  [ 'Guantes anticorte y antipinchazo', 'Guantes técnicos con nivel de protección certificado (nivel 5).', 58000, 70, false, 'Protección personal'],
  [ 'Gafas tácticas de protección', 'Lentes policarbonadas resistentes a impacto de fragmentos y protección UV.', 45000, 90, false, 'Protección personal'],
  [ 'Casco de protección urbana', 'Casco ligero con visera antidisturbios y protección contra impactos.', 312000, 12, true, 'Protección personal'],
  [ 'Alcoholímetro digital evidencial', 'Dispositivo portátil de cribado y pruebas judiciales.', 680000, 8, false, 'Tráfico y medición'],
  [ 'Kit de detección de drogas (salival)', 'Análisis salival cualitativo para detección de estupefacientes.', 215000, 20, false, 'Tráfico y medición'],
  [ 'Sonómetro digital', 'Medición de contaminación acústica y decibelios de vehículos o locales.', 189000, 15, false, 'Tráfico y medición'],
  [ 'Cinemómetro láser de tránsito', 'Pistola láser de medición de velocidad vehicular.', 1250000, 5, false, 'Tráfico y medición'],
  [ 'Kit de croquis vial (cinta y odómetro)', 'Rueda de medición y cinta métrica para levantamiento de accidentes.', 76000, 25, false, 'Tráfico y medición'],
  [ 'Cono de señalización con linterna', 'Cono de polímero acoplable a linterna para dirigir tráfico nocturno.', 38500, 60, false, 'Tráfico y medición'],
  [ 'Grilletes metálicos de bisagra', 'Esposas de dotación estándar con llaves de seguridad.', 92000, 40, true, 'Herramientas'],
  [ 'Lazos de retención plásticos (x50)', 'Bridas de seguridad de un solo uso para detenciones múltiples.', 28000, 100, true, 'Herramientas'],
  [ 'Llave universal de grilletes', 'Llave alargada táctica para apertura rápida.', 19500, 50, false, 'Herramientas'],
  [ 'Herramienta multifunción táctica', 'Alicates multitarea para corte de cables o reparaciones de emergencia.', 87000, 30, false, 'Herramientas'],
  [ 'Navaja de rescate', 'Herramienta con rompecristales y cortacinturones integrada.', 54000, 45, false, 'Herramientas'],
  [ 'Cizalla portátil de apertura forzada', 'Equipamiento ligero para aperturas forzadas en entradas tácticas.', 325000, 10, true, 'Herramientas'],
  [ 'Funda de pistola nivel III', 'Funda rígida (Kydex/polímero) con sistema de seguridad mecánico.', 158000, 20, true, 'Fundas y portas'],
  [ 'Portagrilletes técnico', 'Funda de extracción rápida en polímero o cordura de alta resistencia.', 42000, 30, true, 'Fundas y portas'],
  [ 'Portacargadores dobles', 'Compartimentos con retención por presión para munición de reserva.', 61000, 25, true, 'Fundas y portas'],
  [ 'Tahalí portadefensa', 'Soporte rotatorio para defensa de polímero o bastón extensible.', 49500, 20, true, 'Fundas y portas'],
  [ 'Kit de anclajes MOLLE', 'Sistema de cintas entrelazadas para acoplar bolsillos al chaleco táctico.', 33000, 50, false, 'Fundas y portas'],
  [ 'Radio portátil digital (TETRA)', 'Terminal con encriptación digital para comunicaciones operativas.', 1480000, 5, false, 'Tecnología'],
  [ 'Micrófono de solapa', 'Extensión de audio manos libres conectada a la radio.', 65000, 40, false, 'Tecnología'],
  [ 'Cámara corporal (Bodycam)', 'Sistema de grabación de audio y video con activación automática por eventos.', 520000, 15, false, 'Tecnología'],
  [ 'Baliza de localización GPS', 'Sistema portátil para seguimiento de flotas o activos en operaciones.', 340000, 10, false, 'Tecnología'],
  [ 'Torniquete táctico (tipo CAT)', 'Dispositivo de compresión para frenar hemorragias masivas en extremidades.', 68000, 60, false, 'Primeros auxilios'],
  [ 'Vendaje israelí de emergencia', 'Vendaje con barra de presión integrada para heridas profundas.', 34500, 80, false, 'Primeros auxilios'],
  [ 'Agente hemostático (gasa)', 'Gasa impregnada en sustancias que aceleran la coagulación sanguínea.', 52000, 40, false, 'Primeros auxilios'],
  [ 'Tijeras de rescate reforzadas', 'Tijeras capaces de cortar ropa gruesa, cuero o cinturones.', 31000, 50, false, 'Primeros auxilios'],
  [ 'Parche torácico oclusivo', 'Apósito con válvula para el tratamiento de neumotórax abierto.', 46500, 30, false, 'Primeros auxilios'],
  [ 'Kit de revelado de huellas', 'Polvos magnéticos, brochas de fibra de vidrio y cintas de trasplante.', 128000, 15, false, 'Criminalística'],
  [ 'Linterna forense UV (Luz de Wood)', 'Detección de fluidos biológicos y fibras en escena.', 215000, 10, false, 'Criminalística'],
  [ 'Kit de bolsas de evidencia', 'Envases con cierre hermético numerado y precintos de seguridad.', 47000, 60, false, 'Criminalística'],
  [ 'Testigos métricos numerados', 'Tarjetas plásticas L-shaped para fotografiar indicios a escala.', 22500, 40, false, 'Criminalística'],
  [ 'Kit de recolección de ADN', 'Hisopos estériles y tubos de ensayo para muestras biológicas.', 89000, 20, false, 'Criminalística'],
];

const PRODUCTOS_INSTITUCIONALES_SEED = [
  ['defensa', 'Uniforme de campaña institucional', 'Conjunto de camisa y pantalón de campaña. Tela, patrón, insignias, tallas y requisitos sujetos a especificación de la entidad.', 'Uniformidad', 'camufajeSelva.jpg'],
  ['defensa', 'Botas de campaña', 'Calzado de servicio para terreno. Suela, materiales, tallaje y pruebas de desempeño se confirman en la ficha técnica y cotización.', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
  ['defensa', 'Chaqueta impermeable de campaña', 'Prenda exterior para lluvia y clima variable; configuración, color y niveles de protección sujetos a requerimiento institucional.', 'Uniformidad', 'chaqueton de alta visibilidad.jpg'],
  ['defensa', 'Morral de campaña modular', 'Morral de servicio con compartimentos y puntos de sujeción; capacidad y materiales por definir en la solicitud de cotización.', 'Dotación', 'Chaleco porta Echipos.jpg'],
  ['defensa', 'Casco de protección para servicio', 'Casco de protección no balística; nivel de protección y compatibilidad requieren validación técnica previa.', 'Protección personal', 'Casco de proteccion.png'],
  ['defensa', 'Radio portátil institucional', 'Terminal portátil de comunicaciones; banda, interoperabilidad, cifrado y homologación sujetos a aprobación de la entidad.', 'Comunicaciones', 'Radio portatil digital.jpg'],
  ['defensa', 'Kit de primeros auxilios de campo', 'Suministros básicos para atención inicial; contenido y dispositivos médicos se definen con el área de sanidad.', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
  ['defensa', 'Papelería y carpetas para archivo operativo', 'Carpetas, separadores y consumibles para gestión documental; formatos sujetos a especificación de la unidad.', 'Archivo y papelería', 'image_1c9f64f8.jpg'],

  ['bomberos', 'Chaquetón estructural para bombero', 'Prenda de protección para intervención estructural. La certificación aplicable, diseño multicapa y compatibilidad se deben verificar en la ficha técnica antes de contratar.', 'Protección personal', 'bomberos-dominio-publico.jpg'],
  ['bomberos', 'Pantalón estructural para bombero', 'Pantalón de protección térmica para servicio de bomberos; tallas, certificación y elementos reflectivos sujetos a validación técnica.', 'Protección personal', 'bomberos-dominio-publico.jpg'],
  ['bomberos', 'Casco de intervención contra incendios', 'Casco de protección para respuesta a incendios. Tipo de casco, accesorios y normas aplicables deben definirse en el proceso de compra.', 'Protección personal', 'bomberos-dominio-publico.jpg'],
  ['bomberos', 'Guantes de protección para bombero', 'Guantes para labores de intervención y rescate; resistencia térmica, destreza y certificación sujetas a ficha técnica.', 'Protección personal', 'Guantes anticorte y antipinchazo.jpg'],
  ['bomberos', 'Botas de intervención estructural', 'Botas de protección para bomberos; resistencia térmica, puntera, suela y certificación a especificar por la entidad.', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
  ['bomberos', 'Manguera contra incendios', 'Manguera para conducción de agua en operaciones; diámetro, presión de trabajo, acoples y ensayos se definen con el cuerpo de bomberos.', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
  ['bomberos', 'Boquilla regulable para manguera', 'Boquilla para control de caudal y patrón de descarga; conexión y desempeño deben coincidir con el equipo del organismo.', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
  ['bomberos', 'Kit de trauma y primeros auxilios', 'Insumos para atención inicial de incidentes; composición, registro sanitario y vigencia se especifican antes de cotizar.', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],

  ['socorro', 'Chaleco de alta visibilidad para socorrista', 'Prenda de identificación y visibilidad para equipos de respuesta; color, bandas reflectivas e identificación institucional a confirmar.', 'Seguridad industrial', 'chaqueton de alta visibilidad.jpg'],
  ['socorro', 'Casco para búsqueda y rescate', 'Casco de protección para operaciones de rescate; norma, accesorios y compatibilidad con comunicaciones sujetos a la evaluación técnica.', 'Emergencias y rescate', 'Casco de proteccion.png'],
  ['socorro', 'Botas para búsqueda y rescate', 'Calzado de protección para desplazamiento en terrenos variables; suela, impermeabilidad y tallaje bajo cotización.', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
  ['socorro', 'Camilla plegable de evacuación', 'Camilla portátil para traslado de pacientes; carga nominal, materiales y dimensiones se definen de acuerdo con el protocolo del organismo.', 'Emergencias y rescate', 'Tijeras de rescate reforzadas.jpg'],
  ['socorro', 'Cuerda semiestática para rescate', 'Cuerda para maniobras de rescate; diámetro, longitud, carga y certificación se establecen en la ficha técnica del requerimiento.', 'Emergencias y rescate', 'navaja de rescate.jpg'],
  ['socorro', 'Kit de inmovilización y trauma', 'Elementos de inmovilización y atención prehospitalaria; contenido y requisitos sanitarios por validar con el comprador.', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
  ['socorro', 'Linterna recargable para emergencias', 'Linterna portátil para brigadas; autonomía, resistencia ambiental y accesorios sujetos a cotización.', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
  ['socorro', 'Megáfono portátil para evacuación', 'Equipo de amplificación para coordinación y alertas; alcance, potencia y alimentación se confirman según el escenario operativo.', 'Comunicaciones', 'Radio portatil digital.jpg'],

  ['penitenciario', 'Uniforme de servicio institucional', 'Prendas de dotación para personal de servicio; diseño, distintivos, tela y tallas se deben aprobar por la entidad.', 'Uniformidad', 'Uniforme operativo.jpg'],
  ['penitenciario', 'Botas de servicio institucional', 'Calzado de uso operativo para jornadas prolongadas; tallas, materiales y características antideslizantes sujetos a ficha técnica.', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
  ['penitenciario', 'Chaleco reflectivo para mantenimiento', 'Prenda de alta visibilidad para actividades de mantenimiento y logística; color y bandas reflectivas por especificar.', 'Seguridad industrial', 'chaqueton de alta visibilidad.jpg'],
  ['penitenciario', 'Guantes de protección para mantenimiento', 'Guantes de protección para labores generales; material y nivel de protección según análisis de riesgos del establecimiento.', 'Seguridad industrial', 'Guantes anticorte y antipinchazo.jpg'],
  ['penitenciario', 'Kit de primeros auxilios para sede', 'Insumos para atención inicial en instalaciones; inventario, registro sanitario y reposición sujetos a revisión del área responsable.', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
  ['penitenciario', 'Archivadores y carpetas institucionales', 'Carpetas, cajas y separadores para organización de expedientes y documentación administrativa; tamaños por confirmar.', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
  ['penitenciario', 'Linterna recargable de inspección', 'Linterna de uso institucional para inspección de instalaciones; características, certificaciones y accesorios bajo cotización.', 'Herramientas', 'Linterna operativa recargable.jpg'],
  ['penitenciario', 'Radio portátil de coordinación', 'Equipo de comunicación para coordinación interna; frecuencias, homologación y compatibilidad sujetos a autorización técnica.', 'Comunicaciones', 'Radio portatil digital.jpg'],

  ['corporativo', 'Resma de papel tamaño carta', 'Papel para impresión y fotocopiado institucional. Gramaje, blancura, certificaciones y presentación se confirman al cotizar.', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
  ['corporativo', 'Carpetas y cajas de archivo', 'Suministros para organización y conservación documental; dimensiones y materiales sujetos a requerimiento.', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
  ['corporativo', 'Kit de escritura y papelería', 'Bolígrafos, marcadores, notas y consumibles de oficina; marcas equivalentes y cantidades bajo cotización.', 'Papelería oficial', 'image_1c9f64f8.jpg'],
  ['corporativo', 'Chaleco de alta visibilidad', 'Elemento de protección para personal de campo y logística; clase, color y certificación se determinan según actividad.', 'Seguridad industrial', 'chaqueton de alta visibilidad.jpg'],
  ['corporativo', 'Guantes de protección laboral', 'Guantes para labores generales; material y nivel de protección de acuerdo con la matriz de riesgos del cliente.', 'Seguridad industrial', 'Guantes anticorte y antipinchazo.jpg'],
  ['corporativo', 'Botiquín institucional', 'Suministros de primeros auxilios para oficina o sede; contenido y cumplimiento sanitario se definen según uso y normativa aplicable.', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
  ['corporativo', 'Radio portátil para coordinación', 'Equipo de comunicación para operación y logística; cobertura, permisos y compatibilidad sujetos a evaluación.', 'Comunicaciones', 'Radio portatil digital.jpg'],
  ['corporativo', 'Linterna recargable para mantenimiento', 'Iluminación portátil para inspección y mantenimiento; autonomía y resistencia requeridas a validar en la solicitud.', 'Herramientas', 'Linterna operativa recargable.jpg'],
];

const PRODUCTOS_INSTITUCIONALES_ADICIONALES_SEED = [
  ...[
    ['Lámpara frontal LED recargable', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Lámpara frontal LED con batería reemplazable', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Linterna angular para casco', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Linterna de mano para intervención', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Linterna intrínsecamente segura para atmósferas peligrosas', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Faro portátil recargable de escena', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Torre de iluminación portátil', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Lámpara de área para rescate nocturno', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Lámpara de casco con montaje universal', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Baliza luminosa portátil de señalización', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Martillo de bombero de cabeza plana', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de bombero tipo pico', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Hacha plana de bombero', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Hacha tipo pico para rescate', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Hacha de bombero con mango aislante', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Hacha de bombero con mango de fibra', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Hacha compacta para vehículo de respuesta', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Hacha de corte para rescate técnico', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Hacha de brecha con cabeza combinada', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Hacha forestal para control de vegetación', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Hacha pulaski para brigada forestal', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Hacha tipo Halligan para entrada y rescate', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Hacha de bombero con funda de transporte', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo demoledor manual para rescate', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de golpe muerto para rescate', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Mazo de rescate de cabeza reforzada', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de entrada con cabeza de acero', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de rescate con mango largo', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de rescate con mango corto', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de rescate con mango de fibra', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de bombero con mango aislante', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de golpe controlado para estructuras', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de rescate para lámina y carrocería', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de bola para mantenimiento de equipos', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de uña para labores de estación', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de goma para estabilización y ajuste', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de nylon para mantenimiento técnico', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Mazo de demolición de dos caras', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Mazo de rescate con mango antideslizante', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo combinado con extractor de clavos', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo para trabajo en madera de apuntalamiento', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo compacto para kit de rescate vehicular', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de emergencia con rompevidrios', 'Herramientas', 'navaja de rescate.jpg'],
    ['Martillo de cabeza blanda para rescate técnico', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de inspección y mantenimiento de estación', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Barreta Halligan para apertura y rescate', 'Herramientas', 'Cizalla portatil de apertura forzada.jpg'],
    ['Barreta de uña para trabajo pesado', 'Herramientas', 'Cizalla portatil de apertura forzada.jpg'],
    ['Pata de cabra compacta para rescate', 'Herramientas', 'Cizalla portatil de apertura forzada.jpg'],
    ['Herramienta de apertura tipo hooligan', 'Herramientas', 'Cizalla portatil de apertura forzada.jpg'],
    ['Kit combinado de hacha y herramienta Halligan', 'Herramientas', 'Cizalla portatil de apertura forzada.jpg'],
    ['Bota forestal para incendios de vegetación', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota impermeable para inundación y rescate acuático', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota de protección para rescate técnico', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota dieléctrica para intervención', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota de intervención para alta temperatura', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota para operación en hielo y baja temperatura', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota de goma para inundación', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota de rescate con protección de metatarso', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota para brigada forestal con polaina', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota de estación para bomberos', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Gafas panorámicas para humo y partículas', 'Protección personal', 'Gafas tacticas de proteccion.jpg'],
    ['Monogafas de protección contra salpicaduras', 'Protección personal', 'Gafas tacticas de proteccion.jpg'],
    ['Gafas de seguridad para rescate técnico', 'Protección personal', 'Gafas tacticas de proteccion.jpg'],
    ['Pantalla facial para casco de bombero', 'Protección personal', 'Casco de proteccion urbana.jpg'],
    ['Capucha de protección para bombero', 'Protección personal', 'bomberos-dominio-publico.jpg'],
    ['Guantes estructurales de intervención', 'Protección personal', 'Guantes anticorte y antipinchazo.jpg'],
    ['Guantes para rescate vehicular', 'Protección personal', 'Guantes anticorte y antipinchazo.jpg'],
    ['Guantes para incendio forestal', 'Protección personal', 'Guantes anticorte y antipinchazo.jpg'],
    ['Guantes dieléctricos para respuesta técnica', 'Protección personal', 'Guantes anticorte y antipinchazo.jpg'],
    ['Guantes de rescate acuático', 'Protección personal', 'Guantes anticorte y antipinchazo.jpg'],
    ['Casco para rescate técnico', 'Protección personal', 'Casco de proteccion.png'],
    ['Casco para incendio forestal', 'Protección personal', 'Casco de proteccion.png'],
    ['Casco para rescate acuático', 'Protección personal', 'Casco de proteccion.png'],
    ['Casco estructural con visor y accesorios', 'Protección personal', 'Casco de proteccion.png'],
    ['Chaqueta de protección para incendio forestal', 'Protección personal', 'bomberos-dominio-publico.jpg'],
    ['Overol de protección para materiales peligrosos', 'Protección personal', 'bomberos-dominio-publico.jpg'],
    ['Traje de protección química encapsulado', 'Protección personal', 'bomberos-dominio-publico.jpg'],
    ['Traje de protección contra salpicaduras químicas', 'Protección personal', 'bomberos-dominio-publico.jpg'],
    ['Equipo de respiración autónoma para bombero', 'Protección personal', 'bomberos-dominio-publico.jpg'],
    ['Cilindro de repuesto para equipo respiratorio', 'Protección personal', 'bomberos-dominio-publico.jpg'],
    ['Máscara facial para equipo respiratorio', 'Protección personal', 'bomberos-dominio-publico.jpg'],
    ['Detector portátil multigás para espacios confinados', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Manguera de ataque contra incendios', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Manguera de suministro para bomba contra incendios', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Manguera forestal para incendio de vegetación', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Manguera de succión para motobomba', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Manguera plana de descarga para inundaciones', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Manguera de alta presión para unidad de respuesta', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Acople y adaptador para manguera contra incendios', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Boquilla de caudal regulable para ataque', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Boquilla de niebla para manguera', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Boquilla de chorro sólido para manguera', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Lanza para manguera de incendio forestal', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Divisor de líneas para mangueras', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Recolector y distribuidor de agua para líneas', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Cono vial reflectivo para atención de incidentes', 'Emergencias y rescate', 'cono-senalizacion-linterna.jpg'],
    ['Cono plegable para vehículo de emergencia', 'Emergencias y rescate', 'cono-senalizacion-linterna.jpg'],
    ['Cono luminoso recargable para señalización', 'Emergencias y rescate', 'cono-senalizacion-linterna.jpg'],
    ['Barrera extensible para perímetro de seguridad', 'Emergencias y rescate', 'cono-senalizacion-linterna.jpg'],
    ['Cinta de señalización para acordonamiento', 'Emergencias y rescate', 'cono-senalizacion-linterna.jpg'],
    ['Baliza LED magnética para vehículo', 'Emergencias y rescate', 'cono-senalizacion-linterna.jpg'],
    ['Kit de rompevidrios y cortacinturones', 'Herramientas', 'navaja de rescate.jpg'],
    ['Punzón rompevidrios de emergencia', 'Herramientas', 'navaja de rescate.jpg'],
    ['Cortacinturones para rescate vehicular', 'Herramientas', 'navaja de rescate.jpg'],
    ['Cizalla manual para rescate vehicular', 'Herramientas', 'Cizalla portatil de apertura forzada.jpg'],
    ['Cizalla hidráulica para rescate vehicular', 'Herramientas', 'Cizalla portatil de apertura forzada.jpg'],
    ['Separador hidráulico para rescate vehicular', 'Herramientas', 'Cizalla portatil de apertura forzada.jpg'],
    ['Cilindro hidráulico de expansión para rescate', 'Herramientas', 'Cizalla portatil de apertura forzada.jpg'],
    ['Sierra sable para rescate técnico', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Sierra circular para rescate y ventilación', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Motosierra para brigada forestal', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Pértiga dieléctrica de rescate', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Escalera de extensión para bomberos', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Escalera de gancho para intervención', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Cuerda semiestática para rescate vertical', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Cuerda dinámica para rescate técnico', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Cuerda de seguridad para brigada forestal', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Arnés integral para rescate en alturas', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Descensor para rescate técnico', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Polea de rescate de alta resistencia', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Trípode para rescate en espacios confinados', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Ventilador de presión positiva para incendio', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Extractor de humo portátil', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Motobomba portátil para control de inundaciones', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Bomba sumergible para achique', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Detector térmico para operaciones de incendio', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Cámara termográfica para búsqueda y rescate', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Hidrante portátil para unidad de respuesta', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Extintor portátil para vehículo de respuesta', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Manta ignífuga para atención de emergencias', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Camilla tipo canastilla para rescate', 'Emergencias y rescate', 'Tijeras de rescate reforzadas.jpg'],
    ['Camilla plegable para evacuación', 'Emergencias y rescate', 'Tijeras de rescate reforzadas.jpg'],
    ['Inmovilizador espinal para atención prehospitalaria', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Kit de oxigenoterapia portátil', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Desfibrilador externo automático', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Botiquín de trauma para unidad bomberil', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Tabla espinal para rescate', 'Salud y primeros auxilios', 'Tijeras de rescate reforzadas.jpg'],
    ['Chaleco de flotación para rescate acuático', 'Protección personal', 'bomberos-dominio-publico.jpg'],
    ['Traje de protección para rescate en agua fría', 'Protección personal', 'bomberos-dominio-publico.jpg'],
    ['Aletas para rescate acuático', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Casco para rescate en aguas rápidas', 'Protección personal', 'Casco de proteccion.png'],
    ['Rastrillo y herramienta forestal tipo McLeod', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Pulaski forestal para brigada de incendios', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Batefuego para incendio forestal', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Mochila extintora para brigada forestal', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Kit de iluminación perimetral de emergencia', 'Emergencias y rescate', 'Linterna operativa recargable.jpg']
  ].map(([nombre, categoria, imagen]) => ['bomberos', nombre, categoria, imagen]),

  ...[
    ['Casco de protección para búsqueda urbana', 'Emergencias y rescate', 'Casco de proteccion.png'],
    ['Casco de rescate para inundación', 'Emergencias y rescate', 'Casco de proteccion.png'],
    ['Casco de rescate en alturas', 'Emergencias y rescate', 'Casco de proteccion.png'],
    ['Casco de protección para brigada forestal', 'Emergencias y rescate', 'Casco de proteccion.png'],
    ['Gafas de seguridad para escombros y polvo', 'Protección personal', 'Gafas tacticas de proteccion.jpg'],
    ['Monogafas contra salpicaduras', 'Protección personal', 'Gafas tacticas de proteccion.jpg'],
    ['Gafas para rescate acuático', 'Protección personal', 'Gafas tacticas de proteccion.jpg'],
    ['Guantes de rescate con protección mecánica', 'Protección personal', 'Guantes anticorte y antipinchazo.jpg'],
    ['Guantes de rescate acuático', 'Protección personal', 'Guantes anticorte y antipinchazo.jpg'],
    ['Guantes para búsqueda entre escombros', 'Protección personal', 'Guantes anticorte y antipinchazo.jpg'],
    ['Guantes de protección para brigada forestal', 'Protección personal', 'Guantes anticorte y antipinchazo.jpg'],
    ['Bota de rescate urbano antideslizante', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota para operación de inundaciones', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota para rescate en terreno rocoso', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota impermeable para búsqueda rural', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota de protección para voluntariado de emergencia', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota para rescate técnico en alturas', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Linterna frontal para búsqueda nocturna', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Linterna de mano para brigada de rescate', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Faro portátil para puesto de mando', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Baliza portátil recargable de emergencia', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Torre de iluminación para zona de desastre', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Cono reflectivo para control de incidentes', 'Emergencias y rescate', 'cono-senalizacion-linterna.jpg'],
    ['Cono plegable para vehículo de socorro', 'Emergencias y rescate', 'cono-senalizacion-linterna.jpg'],
    ['Cono luminoso para trabajo nocturno', 'Emergencias y rescate', 'cono-senalizacion-linterna.jpg'],
    ['Cinta de acordonamiento de zona de riesgo', 'Emergencias y rescate', 'cono-senalizacion-linterna.jpg'],
    ['Manguera de descarga para motobomba', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Manguera plana para evacuación de agua', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Manguera de succión para bomba portátil', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Acoples y adaptadores para motobomba', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Motobomba portátil para inundaciones', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Bomba sumergible para achique y drenaje', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Bomba manual para evacuación de agua', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Rompevidrios de emergencia para vehículo', 'Herramientas', 'navaja de rescate.jpg'],
    ['Cortacinturones de seguridad para rescate', 'Herramientas', 'navaja de rescate.jpg'],
    ['Martillo rompevidrios con punzón', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Hacha de rescate liviana', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de rescate con uña', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Barreta para búsqueda y rescate', 'Herramientas', 'Cizalla portatil de apertura forzada.jpg'],
    ['Palanca de apertura para estructuras colapsadas', 'Herramientas', 'Cizalla portatil de apertura forzada.jpg'],
    ['Cizalla manual de rescate vehicular', 'Herramientas', 'Cizalla portatil de apertura forzada.jpg'],
    ['Sierra manual para rescate en estructuras', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Kit de cuñas y puntales de estabilización', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Gato mecánico para estabilización de vehículos', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Detector acústico para búsqueda de víctimas', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Cámara de búsqueda para espacios confinados', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Geófono para localización bajo escombros', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Cuerda semiestática para rescate en alturas', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Cuerda dinámica para maniobras técnicas', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Cuerda flotante para rescate acuático', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Cuerda de evacuación para brigadas', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Arnés integral de rescate', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Trípode para rescate en espacios confinados', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Poleas y bloqueadores para rescate vertical', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Camilla canastilla para rescate en terreno', 'Emergencias y rescate', 'Tijeras de rescate reforzadas.jpg'],
    ['Camilla plegable de evacuación médica', 'Emergencias y rescate', 'Tijeras de rescate reforzadas.jpg'],
    ['Camilla tipo cuchara para trauma', 'Salud y primeros auxilios', 'Tijeras de rescate reforzadas.jpg'],
    ['Inmovilizador cervical para atención prehospitalaria', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Inmovilizador lateral de cabeza', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Tabla espinal larga para rescate', 'Salud y primeros auxilios', 'Tijeras de rescate reforzadas.jpg'],
    ['Kit de férulas de inmovilización', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Kit de oxígeno portátil para brigada', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Desfibrilador externo automático para respuesta', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Botiquín de trauma para equipo de socorro', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Manta térmica para atención de víctimas', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Chaleco de alta visibilidad para coordinación', 'Seguridad industrial', 'chaqueton de alta visibilidad.jpg'],
    ['Chaleco de identificación para puesto de mando', 'Seguridad industrial', 'chaqueton de alta visibilidad.jpg'],
    ['Megáfono portátil para evacuación', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Radio portátil para brigada de emergencias', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Radio base para puesto de comando', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Batería y cargador para radio de emergencia', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Pizarra de coordinación para puesto de mando', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Carpeta impermeable para registro de incidentes', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Linterna UV para identificación de fluidos', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Detector portátil multigás para rescate', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Generador portátil para zona de emergencia', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Extensión eléctrica para iluminación de escena', 'Emergencias y rescate', 'Linterna operativa recargable.jpg'],
    ['Motosierra para despeje de vías', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Machete y herramienta de despeje rural', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Hacha forestal para despeje de ruta', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Pala plegable para operación de campo', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Batefuego para apoyo en incendios forestales', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Mochila extintora para brigada forestal', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Traje de protección para rescate acuático', 'Protección personal', 'bomberos-dominio-publico.jpg'],
    ['Chaleco de flotación para socorrista', 'Protección personal', 'bomberos-dominio-publico.jpg'],
    ['Aletas de rescate acuático', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg'],
    ['Casco para rescate en aguas rápidas', 'Protección personal', 'Casco de proteccion.png'],
    ['Botiquín de campo para brigada rural', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Carpa de atención y clasificación de víctimas', 'Emergencias y rescate', 'bomberos-dominio-publico.jpg']
  ].map(([nombre, categoria, imagen]) => ['socorro', nombre, categoria, imagen]),

  ...[
    ['Uniforme de servicio para personal administrativo', 'Uniformidad', 'Uniforme operativo.jpg'],
    ['Uniforme de servicio para personal operativo', 'Uniformidad', 'Uniforme operativo.jpg'],
    ['Camisa institucional de manga larga', 'Uniformidad', 'Uniforme operativo.jpg'],
    ['Camisa institucional de manga corta', 'Uniformidad', 'Uniforme operativo.jpg'],
    ['Pantalón institucional de servicio', 'Uniformidad', 'Pantalon tactico de dotacion.jpg'],
    ['Chaqueta institucional para clima frío', 'Uniformidad', 'chaqueton de alta visibilidad.jpg'],
    ['Buzo institucional para clima frío', 'Uniformidad', 'Uniforme operativo.jpg'],
    ['Camiseta interior de dotación', 'Uniformidad', 'polo tecnico antibacterial.jpeg'],
    ['Gorra institucional de servicio', 'Uniformidad', 'Uniforme operativo.jpg'],
    ['Cinturón de servicio institucional', 'Uniformidad', 'cinturon de dotacion.jpg'],
    ['Botas de servicio de uso diario', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Botas impermeables para mantenimiento', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Botas con puntera de protección para taller', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Zapato institucional para personal administrativo', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Chaleco reflectivo para mantenimiento', 'Seguridad industrial', 'chaqueton de alta visibilidad.jpg'],
    ['Casco de seguridad industrial para obra', 'Seguridad industrial', 'Casco de proteccion.png'],
    ['Casco de seguridad para mantenimiento eléctrico', 'Seguridad industrial', 'Casco de proteccion.png'],
    ['Gafas de seguridad para mantenimiento', 'Seguridad industrial', 'Gafas tacticas de proteccion.jpg'],
    ['Monogafas contra polvo y salpicaduras', 'Seguridad industrial', 'Gafas tacticas de proteccion.jpg'],
    ['Guantes anticorte para mantenimiento', 'Seguridad industrial', 'Guantes anticorte y antipinchazo.jpg'],
    ['Guantes de nitrilo para aseo y servicios', 'Seguridad industrial', 'Guantes anticorte y antipinchazo.jpg'],
    ['Guantes de carnaza para manejo general', 'Seguridad industrial', 'Guantes anticorte y antipinchazo.jpg'],
    ['Guantes dieléctricos para personal calificado', 'Seguridad industrial', 'Guantes anticorte y antipinchazo.jpg'],
    ['Protección auditiva tipo copa', 'Seguridad industrial', 'Gafas tacticas de proteccion.jpg'],
    ['Protección auditiva tipo inserción', 'Seguridad industrial', 'Gafas tacticas de proteccion.jpg'],
    ['Respirador reutilizable para mantenimiento', 'Seguridad industrial', 'Gafas tacticas de proteccion.jpg'],
    ['Filtros de repuesto para respirador', 'Seguridad industrial', 'Gafas tacticas de proteccion.jpg'],
    ['Arnés para trabajo seguro en alturas', 'Seguridad industrial', 'navaja de rescate.jpg'],
    ['Línea de vida y accesorios certificados', 'Seguridad industrial', 'navaja de rescate.jpg'],
    ['Botiquín institucional para área administrativa', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Botiquín portátil para vehículo institucional', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Camilla plegable para evacuación de sede', 'Salud y primeros auxilios', 'Tijeras de rescate reforzadas.jpg'],
    ['Desfibrilador externo automático para sede', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Tensiómetro digital para enfermería', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Estetoscopio para atención primaria', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Termómetro digital clínico', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Insumos de curación para enfermería', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Silla de ruedas para atención de usuarios', 'Salud y primeros auxilios', 'Tijeras de rescate reforzadas.jpg'],
    ['Resma de papel tamaño carta', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Resma de papel tamaño oficio', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Carpeta de archivo con gancho legajador', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Carpeta colgante para archivo', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Caja de archivo para gestión documental', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Archivador de palanca tamaño oficio', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Sobre de seguridad para documentos', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Libro foliado para registro institucional', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Tóner para impresora institucional', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Cartucho de tinta para impresora', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Kit de mantenimiento para impresora', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Impresora multifuncional para oficina', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Escáner documental de escritorio', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Destructora de documentos para oficina', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Computador de escritorio para área administrativa', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Computador portátil institucional', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Monitor para puesto de trabajo', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Teclado y mouse para estación de trabajo', 'Oficina', 'image_1c9f64f8.jpg'],
    ['UPS para equipo de oficina', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Teléfono IP de escritorio', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Diadema para atención telefónica', 'Comunicaciones', 'Microfono de solapa.jpg'],
    ['Radio portátil para brigada institucional', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Punto de acceso inalámbrico para sede', 'Comunicaciones', 'image_1c9f64f8.jpg'],
    ['Proyector para sala de capacitación', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Pantalla de proyección para sala', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Silla ergonómica para puesto administrativo', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Escritorio de trabajo institucional', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Archivador metálico para oficina', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Mesa de reunión institucional', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Dispensador de agua para sede', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Aspiradora para mantenimiento de instalaciones', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Carro de aseo institucional', 'Herramientas', 'image_1c9f64f8.jpg'],
    ['Señal de piso húmedo para instalaciones', 'Seguridad industrial', 'cono-senalizacion-linterna.jpg'],
    ['Extintor para oficina según evaluación de riesgo', 'Seguridad industrial', 'bomberos-dominio-publico.jpg'],
    ['Linterna recargable para inspección de sede', 'Herramientas', 'Linterna operativa recargable.jpg'],
    ['Kit de herramientas para mantenimiento locativo', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Escalera multipropósito para mantenimiento', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Conos para señalización de mantenimiento', 'Seguridad industrial', 'cono-senalizacion-linterna.jpg'],
    ['Cinta de demarcación para áreas de trabajo', 'Seguridad industrial', 'cono-senalizacion-linterna.jpg'],
    ['Papelera para separación de residuos', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Contenedor con pedal para residuos biosanitarios', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Botiquín de primeros auxilios para planta', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Chaleco reflectivo para logística y transporte', 'Seguridad industrial', 'chaqueton de alta visibilidad.jpg']
  ].map(([nombre, categoria, imagen]) => ['corporativo', nombre, categoria, imagen]),

  ...[
    ['Uniforme de campaña para clima cálido', 'Uniformidad', 'camufajeSelva.jpg'],
    ['Uniforme de campaña para clima frío', 'Uniformidad', 'camufajeSelva.jpg'],
    ['Camisa de campaña de manga larga', 'Uniformidad', 'camufajeSelva.jpg'],
    ['Pantalón de campaña reforzado', 'Uniformidad', 'Pantalon tactico de dotacion.jpg'],
    ['Chaqueta impermeable de campaña', 'Uniformidad', 'chaqueton de alta visibilidad.jpg'],
    ['Chaqueta térmica para clima frío', 'Uniformidad', 'chaqueton de alta visibilidad.jpg'],
    ['Camiseta interior de servicio', 'Uniformidad', 'polo tecnico antibacterial.jpeg'],
    ['Gorra de campaña institucional', 'Uniformidad', 'camufajeSelva.jpg'],
    ['Morral de campaña de gran capacidad', 'Dotación', 'Chaleco porta Echipos.jpg'],
    ['Morral de patrulla modular', 'Dotación', 'Chaleco porta Echipos.jpg'],
    ['Bolso de hidratación para campaña', 'Dotación', 'Chaleco porta Echipos.jpg'],
    ['Bolso de primeros auxilios de campo', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Bota de campaña para selva', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota de campaña para terreno húmedo', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota de servicio para clima frío', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota impermeable para operaciones de campo', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota de servicio para personal administrativo', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Bota para marcha y desplazamiento prolongado', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Casco de protección para servicio de campo', 'Protección personal', 'Casco de proteccion.png'],
    ['Casco de protección para comunicaciones', 'Protección personal', 'Casco de proteccion.png'],
    ['Gafas de protección balística para servicio', 'Protección personal', 'Gafas tacticas de proteccion.jpg'],
    ['Gafas de protección contra polvo y partículas', 'Protección personal', 'Gafas tacticas de proteccion.jpg'],
    ['Guantes de protección para campaña', 'Protección personal', 'Guantes anticorte y antipinchazo.jpg'],
    ['Guantes de protección para mantenimiento', 'Protección personal', 'Guantes anticorte y antipinchazo.jpg'],
    ['Chaleco de alta visibilidad para vía y logística', 'Protección personal', 'chaqueton de alta visibilidad.jpg'],
    ['Impermeable de campaña de dos piezas', 'Uniformidad', 'chaqueton de alta visibilidad.jpg'],
    ['Linterna frontal recargable de campaña', 'Herramientas', 'Linterna operativa recargable.jpg'],
    ['Linterna angular para casco de servicio', 'Herramientas', 'Linterna operativa recargable.jpg'],
    ['Linterna de mano para puesto de guardia', 'Herramientas', 'Linterna operativa recargable.jpg'],
    ['Faro portátil para puesto de campaña', 'Herramientas', 'Linterna operativa recargable.jpg'],
    ['Radio portátil de campaña', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Radio vehicular para unidad móvil', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Batería de repuesto para radio portátil', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Cargador múltiple para radios', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Micrófono remoto para radio portátil', 'Comunicaciones', 'Microfono de solapa.jpg'],
    ['Antena de repuesto para radio de campaña', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Megáfono portátil para coordinación', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Botiquín de campaña para unidad', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Kit de trauma individual para campo', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Torniquete de primeros auxilios para campo', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Vendaje compresivo para primeros auxilios', 'Salud y primeros auxilios', 'Vendaje israeli de emergencia.jpg'],
    ['Manta térmica de emergencia para campo', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Camilla plegable para evacuación de campo', 'Salud y primeros auxilios', 'Tijeras de rescate reforzadas.jpg'],
    ['Cuerda de uso general para campaña', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Mosquetones para equipo de rescate institucional', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Arnés de seguridad para trabajo en alturas', 'Seguridad industrial', 'navaja de rescate.jpg'],
    ['Pala plegable de campaña', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Hacha de campaña para despeje', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Martillo de campaña para mantenimiento', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Herramienta multifunción para mantenimiento', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Cizalla manual para mantenimiento de campo', 'Herramientas', 'Cizalla portatil de apertura forzada.jpg'],
    ['Kit de reparación de calzado de campaña', 'Herramientas', 'Botas Tacticas antideslizantes.jpg'],
    ['Cantimplora de campaña', 'Dotación', 'Chaleco porta Echipos.jpg'],
    ['Sistema de hidratación tipo mochila', 'Dotación', 'Chaleco porta Echipos.jpg'],
    ['Carpa modular para alojamiento temporal', 'Emergencias y rescate', 'camufajeSelva.jpg'],
    ['Lona impermeable para campamento', 'Emergencias y rescate', 'camufajeSelva.jpg'],
    ['Saco de dormir para clima frío', 'Dotación', 'camufajeSelva.jpg'],
    ['Colchoneta aislante de campaña', 'Dotación', 'camufajeSelva.jpg'],
    ['Linterna de señalización para vehículo', 'Herramientas', 'cono-senalizacion-linterna.jpg'],
    ['Conos de señalización para unidad de transporte', 'Seguridad industrial', 'cono-senalizacion-linterna.jpg'],
    ['Kit de señalización para control de vía', 'Seguridad industrial', 'cono-senalizacion-linterna.jpg'],
    ['Archivador de campaña para documentos', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Carpeta impermeable para órdenes y mapas', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Libro de registro de novedades', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Mapa topográfico impreso para área operativa', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Brújula de navegación terrestre', 'Tráfico y medición', 'Linterna operativa recargable.jpg'],
    ['GPS portátil para navegación de campo', 'Tráfico y medición', 'Baliza de localizacion GPS.jpg'],
    ['Binoculares para observación de campo', 'Tecnología', 'Linterna operativa recargable.jpg'],
    ['Batería externa para equipos de campaña', 'Tecnología', 'Radio portatil digital.jpg'],
    ['Panel solar portátil para recarga de equipos', 'Tecnología', 'Radio portatil digital.jpg'],
    ['Generador portátil para puesto de campaña', 'Tecnología', 'Radio portatil digital.jpg'],
    ['Herramientas manuales para mantenimiento de unidad', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Kit de limpieza y mantenimiento de equipo', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Protección auditiva para polígono y mantenimiento', 'Protección personal', 'Gafas tacticas de proteccion.jpg'],
    ['Protección respiratoria para polvo y partículas', 'Protección personal', 'Gafas tacticas de proteccion.jpg'],
    ['Chaleco salvavidas para operación acuática', 'Protección personal', 'bomberos-dominio-publico.jpg'],
    ['Casco de rescate para operación acuática', 'Protección personal', 'Casco de proteccion.png'],
    ['Bota de agua para operación fluvial', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Cuerda flotante para rescate acuático', 'Emergencias y rescate', 'navaja de rescate.jpg'],
    ['Kit de señalización para operación nocturna', 'Seguridad industrial', 'cono-senalizacion-linterna.jpg'],
    ['Linterna de inspección para mantenimiento vehicular', 'Herramientas', 'Linterna operativa recargable.jpg']
  ].map(([nombre, categoria, imagen]) => ['defensa', nombre, categoria, imagen]),

  ...[
    ['Uniforme institucional para personal administrativo', 'Uniformidad', 'Uniforme operativo.jpg'],
    ['Uniforme de servicio para personal de custodia', 'Uniformidad', 'Uniforme operativo.jpg'],
    ['Camisa institucional de manga larga', 'Uniformidad', 'Uniforme operativo.jpg'],
    ['Camisa institucional de manga corta', 'Uniformidad', 'Uniforme operativo.jpg'],
    ['Pantalón institucional de servicio', 'Uniformidad', 'Pantalon tactico de dotacion.jpg'],
    ['Chaqueta institucional para clima frío', 'Uniformidad', 'chaqueton de alta visibilidad.jpg'],
    ['Buzo institucional para clima frío', 'Uniformidad', 'Uniforme operativo.jpg'],
    ['Camiseta interior de dotación', 'Uniformidad', 'polo tecnico antibacterial.jpeg'],
    ['Gorra institucional', 'Uniformidad', 'Uniforme operativo.jpg'],
    ['Cinturón institucional de servicio', 'Uniformidad', 'cinturon de dotacion.jpg'],
    ['Botas institucionales de servicio', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Botas impermeables para mantenimiento', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Botas con puntera para talleres y almacenes', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Zapatos institucionales para personal administrativo', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Chaleco reflectivo para mantenimiento locativo', 'Seguridad industrial', 'chaqueton de alta visibilidad.jpg'],
    ['Casco de seguridad para mantenimiento', 'Seguridad industrial', 'Casco de proteccion.png'],
    ['Gafas de protección para mantenimiento', 'Seguridad industrial', 'Gafas tacticas de proteccion.jpg'],
    ['Monogafas contra polvo y salpicaduras', 'Seguridad industrial', 'Gafas tacticas de proteccion.jpg'],
    ['Guantes de protección anticorte', 'Seguridad industrial', 'Guantes anticorte y antipinchazo.jpg'],
    ['Guantes de nitrilo para labores de aseo', 'Seguridad industrial', 'Guantes anticorte y antipinchazo.jpg'],
    ['Guantes de carnaza para almacén y taller', 'Seguridad industrial', 'Guantes anticorte y antipinchazo.jpg'],
    ['Protección auditiva para talleres', 'Seguridad industrial', 'Gafas tacticas de proteccion.jpg'],
    ['Respirador reutilizable para mantenimiento', 'Seguridad industrial', 'Gafas tacticas de proteccion.jpg'],
    ['Filtros de repuesto para respirador', 'Seguridad industrial', 'Gafas tacticas de proteccion.jpg'],
    ['Arnés para mantenimiento en alturas', 'Seguridad industrial', 'navaja de rescate.jpg'],
    ['Línea de vida para trabajo en alturas', 'Seguridad industrial', 'navaja de rescate.jpg'],
    ['Botiquín institucional para área administrativa', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Botiquín portátil para brigada institucional', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Camilla plegable para evacuación de sede', 'Salud y primeros auxilios', 'Tijeras de rescate reforzadas.jpg'],
    ['Silla de ruedas para atención en sede', 'Salud y primeros auxilios', 'Tijeras de rescate reforzadas.jpg'],
    ['Tensiómetro digital para enfermería', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Estetoscopio para enfermería institucional', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Termómetro digital clínico', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Insumos de curación para atención primaria', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Desfibrilador externo automático para sede', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Resma de papel tamaño carta', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Resma de papel tamaño oficio', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Carpeta de archivo con gancho legajador', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Carpeta colgante para gestión documental', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Caja para archivo institucional', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Archivador de palanca tamaño oficio', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Libro foliado de registro institucional', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Sobre de seguridad para documentos', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Tóner para impresora institucional', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Cartucho de tinta para impresora', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Impresora multifuncional para oficina', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Escáner documental de escritorio', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Destructora de documentos para oficina', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Computador de escritorio para oficina', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Computador portátil para área administrativa', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Monitor para puesto de trabajo', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Teclado y mouse para estación de trabajo', 'Oficina', 'image_1c9f64f8.jpg'],
    ['UPS para equipo administrativo', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Silla ergonómica para oficina', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Escritorio para puesto administrativo', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Archivador metálico para documentación', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Teléfono IP para oficina administrativa', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Diadema para atención telefónica', 'Comunicaciones', 'Microfono de solapa.jpg'],
    ['Radio portátil para coordinación institucional', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Batería y cargador para radio portátil', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Megáfono portátil para evacuación de sede', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Proyector para sala de capacitación', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Pantalla de proyección para capacitación', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Carro de aseo institucional', 'Herramientas', 'image_1c9f64f8.jpg'],
    ['Señal de piso húmedo para mantenimiento', 'Seguridad industrial', 'cono-senalizacion-linterna.jpg'],
    ['Conos de señalización para obras locativas', 'Seguridad industrial', 'cono-senalizacion-linterna.jpg'],
    ['Cinta de demarcación para mantenimiento', 'Seguridad industrial', 'cono-senalizacion-linterna.jpg'],
    ['Linterna recargable para inspección de instalaciones', 'Herramientas', 'Linterna operativa recargable.jpg'],
    ['Kit de herramientas para mantenimiento locativo', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Escalera multipropósito para mantenimiento', 'Herramientas', 'Herramienta multifuncion tactica.jpg'],
    ['Extintor portátil según evaluación de riesgo', 'Seguridad industrial', 'bomberos-dominio-publico.jpg'],
    ['Papelera para separación de residuos', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Contenedor para residuos biosanitarios', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Dispensador de agua para sede', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Aspiradora para mantenimiento de áreas', 'Oficina', 'image_1c9f64f8.jpg'],
    ['Kit de papelería para oficina de atención', 'Papelería oficial', 'image_1c9f64f8.jpg'],
    ['Bolígrafos para dotación administrativa (caja)', 'Papelería oficial', 'image_1c9f64f8.jpg'],
    ['Marcadores permanentes para inventario', 'Papelería oficial', 'image_1c9f64f8.jpg'],
    ['Etiquetas para archivo e inventario', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Carpeta impermeable para documentos de servicio', 'Archivo y papelería', 'image_1c9f64f8.jpg'],
    ['Lámpara de emergencia recargable para pasillos', 'Herramientas', 'Linterna operativa recargable.jpg'],
    ['Kit de señalización para evacuación de instalaciones', 'Seguridad industrial', 'cono-senalizacion-linterna.jpg'],
    ['Guantes resistentes a químicos para aseo', 'Seguridad industrial', 'Guantes anticorte y antipinchazo.jpg'],
    ['Delantal de protección para labores de aseo', 'Seguridad industrial', 'chaqueton de alta visibilidad.jpg'],
    ['Botas de caucho para aseo y mantenimiento', 'Dotación', 'Botas Tacticas antideslizantes.jpg'],
    ['Botiquín de primeros auxilios para área común', 'Salud y primeros auxilios', 'Torniquete tactico.jpg'],
    ['Camilla de evacuación para áreas comunes', 'Salud y primeros auxilios', 'Tijeras de rescate reforzadas.jpg'],
    ['Radio base para coordinación de servicios generales', 'Comunicaciones', 'Radio portatil digital.jpg'],
    ['Lámpara portátil para mantenimiento nocturno', 'Herramientas', 'Linterna operativa recargable.jpg']
  ].map(([nombre, categoria, imagen]) => ['penitenciario', nombre, categoria, imagen])
];

const IMAGENES_POR_PRODUCTO = [
  ['uniforme|camuflaje|gala', 'Uniforme operativo.jpg'],
  ['bota', 'Botas Tacticas antideslizantes.jpg'],
  ['chaleco|aramida|armana', 'chaleco balistico.jpg'],
  ['casco|antidisturbios', 'Casco de proteccion urbana.jpg'],
  ['pantalon', 'Pantalon tactico de dotacion.jpg'],
  ['polo', 'polo tecnico antibacterial.jpeg'],
  ['chaqueton', 'chaqueton de alta visibilidad.jpg'],
  ['cinturon', 'cinturon de dotacion.jpg'],
  ['placa', 'placas balisticas traumaticas.jpg'],
  ['guante', 'Guantes anticorte y antipinchazo.jpg'],
  ['gafa', 'Gafas tacticas de proteccion.jpg'],
  ['alcohol', 'Alcoholimetro digital evidencial.jpg'],
  ['drogas', 'kit de detecion de drogas.jpg'],
  ['sonometro', 'Sonometro digital.jpg'],
  ['cinemometro', 'Cinemometro laser.jpg'],
  ['cono', 'cono-senalizacion-linterna.jpg'],
  ['grillete', 'Grillete Metalicos de bisagra.jpg'],
  ['lazo', 'Lazos de retencion plastico.jpg'],
  ['llave', 'Llave universal de grilletes.jpg'],
  ['multifuncion', 'Herramienta multifuncion tactica.jpg'],
  ['navaja', 'navaja de rescate.jpg'],
  ['cizalla', 'Cizalla portatil de apertura forzada.jpg'],
  ['funda', 'Funda pistola nivel III.jpg'],
  ['portagrilletes', 'portagrilletes tecnico.webp'],
  ['portacargadores', 'portacargadores dobles.jpg'],
  ['tahali', 'Tahali portadefensa.jpg'],
  ['anclajes', 'Kit de anclajes MOLLE.webp'],
  ['radio', 'Radio portatil digital.jpg'],
  ['microfono', 'Microfono de solapa.jpg'],
  ['camara', 'camara corporal.jpg'],
  ['baliza', 'Baliza de localizacion GPS.jpg'],
  ['torniquete', 'Torniquete tactico.jpg'],
  ['vendaje', 'Vendaje israeli de emergencia.jpg'],
  ['hemostatico', 'Agente Hemostatico.jpg'],
  ['tijera', 'Tijeras de rescate reforzadas.jpg'],
  ['parche', 'parche toracico oclusivo.jpg'],
  ['revelado', 'kit de revelado de huellas.jpg'],
  ['forense', 'Linterna forence UV.jpg'],
  ['bolsas', 'Kit de bolsas de evidencia.jpg'],
  ['testigos', 'testigos metricos numerados.jpg'],
  ['adn', 'kit de recoleccion de adn.jpg'],
];

function imagenProductoPorNombre(nombre) {
  const nombreNormalizado = String(nombre || '').toLowerCase();
  const coincidencia = IMAGENES_POR_PRODUCTO.find(([patron]) => new RegExp(patron).test(nombreNormalizado));
  return coincidencia ? coincidencia[1] : null;
}



async function migrar() {
  // Clientes
  await pool.query(`
    CREATE TABLE IF NOT EXISTS clientes (
      id INT AUTO_INCREMENT PRIMARY KEY,
      nombre_unidad VARCHAR(255),
      direccion_instalacion VARCHAR(255),
      nit VARCHAR(100),
      nombre_funcionario TEXT,
      correo TEXT,
      telefono TEXT,
      direccion_entrega TEXT,
      autorizacion_general BOOLEAN DEFAULT FALSE,
      fecha_registro DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  // Datos sensibles
  await pool.query(`
    CREATE TABLE IF NOT EXISTS datos_sensibles (
      id INT AUTO_INCREMENT PRIMARY KEY,
      cliente_id INT NOT NULL,
      numero_consulta_antecedentes TEXT,
      autorizacion_sensible BOOLEAN DEFAULT FALSE,
      fecha_autorizacion DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (cliente_id) REFERENCES clientes(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);
  // Categorías
  await pool.query(`
    CREATE TABLE IF NOT EXISTS categorias (
      id INT AUTO_INCREMENT PRIMARY KEY,
      nombre VARCHAR(100) NOT NULL UNIQUE,
      descripcion TEXT
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  // Productos
  await pool.query(`
    CREATE TABLE IF NOT EXISTS productos (
      id INT AUTO_INCREMENT PRIMARY KEY,
      nombre VARCHAR(255) NOT NULL,
      descripcion TEXT,
      precio DECIMAL(10,2) NOT NULL,
      imagen VARCHAR(255),
      cantidad_disponible INT DEFAULT 0,
      estado ENUM('activo','inactivo') DEFAULT 'activo',
      fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
      restringido BOOLEAN DEFAULT FALSE,
      categoria_id INT,
      macrocategoria ENUM('general','vestimenta','herramientas') DEFAULT 'general',
      institucion_id VARCHAR(32) NOT NULL DEFAULT 'policia',
      metadatos JSON NULL,
      FOREIGN KEY (categoria_id) REFERENCES categorias(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS solicitudes_contacto (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      tipo_solicitud ENUM('pqrs','soporte','cotizacion') NOT NULL,
      tipo_entidad ENUM('publica','privada') NOT NULL,
      entidad VARCHAR(255) NOT NULL,
      nit_cifrado TEXT NOT NULL,
      correo_cifrado TEXT NOT NULL,
      criticidad ENUM('baja','media','alta','urgente') NOT NULL,
      mensaje TEXT NOT NULL,
      estado ENUM('recibida','en_gestion','cerrada') NOT NULL DEFAULT 'recibida',
      fecha_creacion DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_solicitudes_contacto_estado_fecha (estado, fecha_creacion)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  // Atenciones
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atenciones (
      id INT AUTO_INCREMENT PRIMARY KEY,
      conversacion_id VARCHAR(100),
      calificacion INT,
      comentario TEXT,
      escalado_a_humano BOOLEAN DEFAULT FALSE,
      fecha DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  // Usuarios
  await pool.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INT AUTO_INCREMENT PRIMARY KEY,
      correo VARCHAR(255) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      cliente_id INT,
      session_version INT UNSIGNED NOT NULL DEFAULT 0,
      rol ENUM('cliente','admin') DEFAULT 'cliente',
      fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (cliente_id) REFERENCES clientes(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

    // Refresh tokens (para renovar la sesión sin volver a pedir login)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INT AUTO_INCREMENT PRIMARY KEY,
      usuario_id INT NOT NULL,
      token_hash VARCHAR(255) NOT NULL,
      fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
      fecha_expiracion DATETIME NOT NULL,
      mfa_verificado_en DATETIME NULL,
      revocado BOOLEAN DEFAULT FALSE,
      FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS retos_mfa (
      reto_id CHAR(64) PRIMARY KEY,
      usuario_id INT NOT NULL,
      codigo_hash CHAR(64) NOT NULL,
      estado ENUM('pendiente','verificado','expirado','cancelado','bloqueado') NOT NULL DEFAULT 'pendiente',
      intentos TINYINT UNSIGNED NOT NULL DEFAULT 0,
      reenvios TINYINT UNSIGNED NOT NULL DEFAULT 0,
      creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      enviado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      expira_en DATETIME NOT NULL,
      proposito ENUM('inicio_sesion','cambio_correo') NOT NULL DEFAULT 'inicio_sesion',
      correo_destino_cifrado TEXT NULL,
      INDEX idx_retos_mfa_usuario_estado (usuario_id, estado, expira_en),
      FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);
  
  // Pedidos
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pedidos (
      id INT AUTO_INCREMENT PRIMARY KEY,
      cliente_id INT NOT NULL,
      fecha_pedido DATETIME DEFAULT CURRENT_TIMESTAMP,
      items JSON NOT NULL,
      total DECIMAL(10,2) NOT NULL,
      estado ENUM('pendiente','pendiente_pago','pagado','expirado','rechazado','confirmado','preparado','enviado','entregado','cancelado') DEFAULT 'pendiente',
      datos_comprador_cifrados TEXT NULL,
      direccion_entrega_cifrada TEXT NULL,
      enviar_comprobante BOOLEAN NOT NULL DEFAULT FALSE,
      FOREIGN KEY (cliente_id) REFERENCES clientes(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS pagos (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      pedido_id INT NOT NULL,
      proveedor VARCHAR(32) NOT NULL,
      referencia_externa VARCHAR(191) NULL UNIQUE,
      idempotency_key VARCHAR(128) NOT NULL UNIQUE,
      request_hash CHAR(64) NOT NULL,
      widget_token VARCHAR(191) NULL,
      widget_url TEXT NULL,
      estado ENUM('creado','pendiente','aprobado','rechazado','expirado','reembolsado') NOT NULL DEFAULT 'creado',
      monto_centavos BIGINT UNSIGNED NOT NULL,
      moneda CHAR(3) NOT NULL DEFAULT 'COP',
      metodo VARCHAR(32) NULL,
      expira_en DATETIME NOT NULL,
      creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      actualizado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_pagos_pedido_estado (pedido_id, estado),
      FOREIGN KEY (pedido_id) REFERENCES pedidos(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS eventos_pago (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      evento_id VARCHAR(191) NOT NULL UNIQUE,
      proveedor VARCHAR(32) NOT NULL,
      pago_id BIGINT UNSIGNED NOT NULL,
      payload_hash CHAR(64) NOT NULL,
      recibido_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (pago_id) REFERENCES pagos(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS comprobantes (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      pedido_id INT NOT NULL UNIQUE,
      numero VARCHAR(40) NOT NULL UNIQUE,
      enviar_correo BOOLEAN NOT NULL DEFAULT FALSE,
      enviado_cliente_en DATETIME NULL,
      enviado_admin_en DATETIME NULL,
      token_hash CHAR(64) NULL,
      expira_en DATETIME NULL,
      creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (pedido_id) REFERENCES pedidos(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS correo_outbox (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      comprobante_id BIGINT UNSIGNED NOT NULL,
      tipo ENUM('cliente','admin') NOT NULL,
      estado ENUM('pendiente','procesando','enviado','fallido') NOT NULL DEFAULT 'pendiente',
      intentos TINYINT UNSIGNED NOT NULL DEFAULT 0,
      disponible_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      ultimo_error_code VARCHAR(64) NULL,
      creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      actualizado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      enviado_en DATETIME NULL,
      INDEX idx_correo_outbox_pendiente (estado, disponible_en, id),
      INDEX idx_correo_outbox_comprobante (comprobante_id, tipo, estado),
      FOREIGN KEY (comprobante_id) REFERENCES comprobantes(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS solicitudes_reenvio_comprobante (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      comprobante_id BIGINT UNSIGNED NOT NULL,
      usuario_id INT NOT NULL,
      creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_reenvio_comprobante_usuario_fecha (comprobante_id, usuario_id, creado_en),
      FOREIGN KEY (comprobante_id) REFERENCES comprobantes(id) ON DELETE CASCADE,
      FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS automation_outbox (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      workflow ENUM('W1','W3','W6','W8','W11') NOT NULL,
      dedupe_key VARCHAR(191) NOT NULL UNIQUE,
      payload JSON NOT NULL,
      payload_cifrado BOOLEAN NOT NULL DEFAULT FALSE,
      estado ENUM('pendiente','procesando','enviado','fallido') NOT NULL DEFAULT 'pendiente',
      intentos TINYINT UNSIGNED NOT NULL DEFAULT 0,
      disponible_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      ultimo_error_code VARCHAR(64) NULL,
      creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      actualizado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_automation_outbox_pendiente (estado, disponible_en, id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(
    "ALTER TABLE automation_outbox MODIFY workflow ENUM('W1','W3','W6','W8','W11') NOT NULL"
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS faq_asistente (
      id INT AUTO_INCREMENT PRIMARY KEY,
      palabras_clave VARCHAR(500) NOT NULL,
      pregunta VARCHAR(255) NOT NULL UNIQUE,
      respuesta TEXT NOT NULL,
      activo BOOLEAN NOT NULL DEFAULT TRUE,
      creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      actualizado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_faq_asistente_activo (activo)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS asistente_pendientes (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      conversacion_id VARCHAR(100) NOT NULL,
      texto_normalizado VARCHAR(500) NOT NULL,
      creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      atendido BOOLEAN NOT NULL DEFAULT FALSE,
      INDEX idx_asistente_pendientes_fecha (atendido, creado_en)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    INSERT IGNORE INTO faq_asistente (palabras_clave, pregunta, respuesta, activo)
    VALUES
      ('envio entrega domicilio', '¿Cuáles son los tiempos y zonas de envío?', '[COMPLETAR: política de envíos aprobada]', TRUE),
      ('garantia producto', '¿Qué garantía tienen los productos?', '[COMPLETAR: política de garantías aprobada]', TRUE),
      ('devolucion cambio', '¿Cómo puedo solicitar una devolución o cambio?', '[COMPLETAR: política de devoluciones aprobada]', TRUE),
      ('horario atencion', '¿Cuál es el horario de atención?', '[COMPLETAR: horario oficial de atención]', TRUE),
      ('pago metodos medios', '¿Qué métodos de pago están habilitados?', '[COMPLETAR: medios de pago habilitados]', TRUE),
      ('datos privacidad habeas', '¿Cómo se tratan mis datos personales?', '[COMPLETAR: aviso de privacidad y canal de Habeas Data aprobados]', TRUE)
  `);

  // Detalle de pedidos
  await pool.query(`
    CREATE TABLE IF NOT EXISTS detalle_pedido (
      id INT AUTO_INCREMENT PRIMARY KEY,
      pedido_id INT NOT NULL,
      producto_id INT NOT NULL,
      cantidad INT NOT NULL,
      precio_unitario DECIMAL(10,2) NOT NULL,
      FOREIGN KEY (pedido_id) REFERENCES pedidos(id) ON DELETE CASCADE,
      FOREIGN KEY (producto_id) REFERENCES productos(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  // Reportes / sugerencias de clientes (módulo 4 - vista del cliente)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS reportes_cliente (
      id INT AUTO_INCREMENT PRIMARY KEY,
      cliente_id INT NOT NULL,
      comentario TEXT NOT NULL,
      calificacion INT NOT NULL,
      fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
      fecha_actualizacion DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (cliente_id) REFERENCES clientes(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  // Auditoría de acciones administrativas (crear / editar / eliminar)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS auditoria (
      id INT AUTO_INCREMENT PRIMARY KEY,
      usuario_id INT,
      correo VARCHAR(255),
      accion ENUM('crear','editar','eliminar') NOT NULL,
      entidad VARCHAR(50) NOT NULL,
      entidad_id VARCHAR(50),
      detalle TEXT,
      fecha DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  console.log('[db] Tablas verificadas/creadas correctamente.');

  await migrarColumnasFaltantes();
  await migrarAutenticacionMfa();
  await migrarCuentaSegura();
  await sembrarCategoriasYProductos();
  await require('./migraciones').aplicarMigraciones(pool);
  // Después de las migraciones: así recibe permisos y el cambio obligatorio de contraseña.
  await sembrarAdminPorDefecto();
}

async function migrarAutenticacionMfa() {
  try {
    await pool.query('ALTER TABLE refresh_tokens ADD COLUMN mfa_verificado_en DATETIME NULL');
  } catch (err) {
    if (!/duplicate column/i.test(err.message)) {
      throw err;
    }
  }

  try {
    await pool.query('ALTER TABLE retos_mfa ADD COLUMN reenvios TINYINT UNSIGNED NOT NULL DEFAULT 0');
  } catch (err) {
    if (!/duplicate column/i.test(err.message)) {
      throw err;
    }
  }

}

async function migrarCuentaSegura() {
  for (const [tabla, columna, definicion] of [
    ['usuarios', 'session_version', 'INT UNSIGNED NOT NULL DEFAULT 0'],
    ['retos_mfa', 'proposito', "ENUM('inicio_sesion','cambio_correo') NOT NULL DEFAULT 'inicio_sesion'"],
    ['retos_mfa', 'correo_destino_cifrado', 'TEXT NULL'],
    ['automation_outbox', 'payload_cifrado', 'BOOLEAN NOT NULL DEFAULT FALSE']
  ]) {
    try {
      await pool.query(`ALTER TABLE ${tabla} ADD COLUMN ${columna} ${definicion}`);
    } catch (err) {
      if (!/duplicate column/i.test(err.message)) throw err;
    }
  }

  await pool.query(
    "ALTER TABLE automation_outbox MODIFY workflow ENUM('W1','W3','W6','W8','W11') NOT NULL"
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS solicitudes_cuenta (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      usuario_id INT NOT NULL,
      cliente_id INT NOT NULL,
      campo ENUM('nit','nombreUnidad','eliminacion','correccion') NOT NULL,
      detalle TEXT NOT NULL,
      estado ENUM('pendiente','aprobada','rechazada') NOT NULL DEFAULT 'pendiente',
      resuelta_por INT NULL,
      respuesta_admin VARCHAR(500) NULL,
      creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      resuelta_en DATETIME NULL,
      INDEX idx_solicitudes_cuenta_estado (estado, creado_en, id),
      INDEX idx_solicitudes_cuenta_cliente (cliente_id, creado_en),
      FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
      FOREIGN KEY (cliente_id) REFERENCES clientes(id) ON DELETE CASCADE,
      FOREIGN KEY (resuelta_por) REFERENCES usuarios(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);
}

// Ajustes a instalaciones ya existentes (creadas antes de agregar estas
// columnas/valores). Cada ALTER va en su propio try/catch: si la base ya
// tiene el cambio aplicado, MySQL lanza error y simplemente se ignora.
async function migrarColumnasFaltantes() {
  // Mantiene compatibles las instalaciones antiguas con el timeline operativo.
  await pool.query(
    "ALTER TABLE pedidos MODIFY estado ENUM('pendiente','pendiente_pago','pagado','expirado','rechazado','confirmado','preparado','enviado','entregado','cancelado') DEFAULT 'pendiente'"
  );

  for (const [columna, definicion] of [
    ['datos_comprador_cifrados', 'TEXT NULL'],
    ['direccion_entrega_cifrada', 'TEXT NULL'],
    ['enviar_comprobante', 'BOOLEAN NOT NULL DEFAULT FALSE']
  ]) {
    try {
      await pool.query(`ALTER TABLE pedidos ADD COLUMN ${columna} ${definicion}`);
    } catch (err) {
      if (!/duplicate column/i.test(err.message)) {
        throw err;
      }
    }
  }

  try {
    await pool.query("ALTER TABLE productos ADD COLUMN macrocategoria ENUM('general','vestimenta','herramientas') DEFAULT 'general'");
  } catch (err) {
    if (err.code !== 'ER_DUP_FIELDNAME') {
      console.warn('[db] No se pudo agregar macrocategoria a productos:', err.message);
    }
  }

  try {
    await pool.query("ALTER TABLE productos ADD COLUMN metadatos JSON NULL");
  } catch (err) {
    if (err.code !== 'ER_DUP_FIELDNAME') {
      console.warn('[db] No se pudo agregar metadatos a productos:', err.message);
    }
  }

  try {
    await pool.query("ALTER TABLE productos ADD COLUMN institucion_id VARCHAR(32) NOT NULL DEFAULT 'policia'");
  } catch (err) {
    if (err.code !== 'ER_DUP_FIELDNAME') {
      console.error('[db] No se pudo agregar institucion_id a productos:', err.code || err.message);
      throw err;
    }
  }

  const indices = [
    ['pedidos', 'idx_pedidos_cliente_fecha', 'cliente_id, fecha_pedido'],
    ['reportes_cliente', 'idx_reportes_cliente_fecha', 'cliente_id, fecha'],
    ['productos', 'idx_productos_estado_stock', 'estado, cantidad_disponible'],
    ['productos', 'idx_productos_institucion_estado', 'institucion_id, estado']
  ];
  for (const [tabla, indice, columnas] of indices) {
    try {
      const [existente] = await pool.query(
        'SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ? LIMIT 1',
        [tabla, indice]
      );
      if (!existente.length) {
        await pool.query(`CREATE INDEX ${indice} ON ${tabla} (${columnas})`);
      }
    } catch (err) {
      console.warn(`[db] No se pudo verificar/crear el índice ${indice}:`, err.message);
    }
  }
}

// Inserta las categorías y productos de ejemplo SOLO la primera vez
// (si la tabla ya tiene datos, no hace nada — evita duplicar en cada reinicio).
async function sembrarCategoriasYProductos() {
  const [[{ total }]] = await pool.query('SELECT COUNT(*) AS total FROM categorias');
  for (const [nombre, descripcion] of CATEGORIAS_SEED) {
    await pool.query(
      'INSERT IGNORE INTO categorias (nombre, descripcion) VALUES (?, ?)',
      [nombre, descripcion]
    );
  }

  if (total === 0) {
    const [categorias] = await pool.query('SELECT id, nombre FROM categorias');
    const idPorNombre = Object.fromEntries(categorias.map(c => [c.nombre, c.id]));
    for (const [nombre, descripcion, precio, cantidad, restringido, nombreCategoria] of PRODUCTOS_SEED) {
      await pool.query(
        `INSERT INTO productos (nombre, descripcion, precio, imagen, cantidad_disponible, estado, restringido, categoria_id)
         VALUES (?, ?, ?, ?, ?, 'activo', ?, ?)`,
        [nombre, descripcion, precio, imagenProductoPorNombre(nombre), cantidad, restringido, idPorNombre[nombreCategoria] || null]
      );
    }
    console.log(`[db] Sembradas ${CATEGORIAS_SEED.length} categorías y ${PRODUCTOS_SEED.length} productos de ejemplo.`);
  }

  const referenciasInstitucionales = [
    ...PRODUCTOS_INSTITUCIONALES_SEED,
    ...PRODUCTOS_INSTITUCIONALES_ADICIONALES_SEED.map(([institucion, nombre, categoria, imagen]) => [
      institucion,
      nombre,
      `Referencia institucional para cotización. La marca, el modelo, las especificaciones, certificaciones, precio y disponibilidad deben confirmarse con la entidad antes de ofertar.`,
      categoria,
      imagen
    ])
  ];
  const instituciones = [...new Set(referenciasInstitucionales.map(([institucion]) => institucion))];
  const [categorias] = await pool.query('SELECT id, nombre FROM categorias');
  const idPorNombre = Object.fromEntries(categorias.map(c => [c.nombre, c.id]));
  const [existentes] = await pool.query(
    `SELECT institucion_id, nombre FROM productos WHERE institucion_id IN (${instituciones.map(() => '?').join(',')})`,
    instituciones
  );
  const clavesExistentes = new Set(existentes.map(p => `${p.institucion_id}:${p.nombre}`));
  let insertados = 0;
  for (const [institucion, nombre, descripcion, categoria, imagen] of referenciasInstitucionales) {
    if (clavesExistentes.has(`${institucion}:${nombre}`)) continue;
    await pool.query(
      `INSERT INTO productos
         (nombre, descripcion, precio, imagen, cantidad_disponible, estado, restringido, categoria_id, institucion_id, metadatos)
       VALUES (?, ?, 0, ?, 0, 'activo', FALSE, ?, ?, ?)`,
      [
        nombre,
        descripcion,
        `/img/${imagen}`,
        idPorNombre[categoria] || null,
        institucion,
        JSON.stringify({ cotizacion_requerida: true, precio_referencial: false, origen: 'catalogo_institucional_base' })
      ]
    );
    clavesExistentes.add(`${institucion}:${nombre}`);
    insertados += 1;
  }
  if (insertados) {
    console.log(`[db] Añadidas ${insertados} referencias institucionales para cotización.`);
  }

  const [productosSinImagen] = await pool.query('SELECT id, nombre FROM productos WHERE imagen IS NULL OR imagen = ""');
  for (const producto of productosSinImagen) {
    const imagen = imagenProductoPorNombre(producto.nombre);
    if (imagen) await pool.query('UPDATE productos SET imagen = ? WHERE id = ?', [imagen, producto.id]);
  }
}

// Crea una cuenta de administrador la primera vez que se arranca el backend,
// si todavía no existe ninguna. La contraseña se imprime UNA sola vez en la
// consola del servidor — cámbiala apenas inicies sesión.
async function sembrarAdminPorDefecto() {
  const [[{ total }]] = await pool.query("SELECT COUNT(*) AS total FROM usuarios WHERE rol = 'admin'");
  if (total > 0) return;

  const correo = process.env.ADMIN_EMAIL || 'admin@suministros.local';
  const passwordTemporal = process.env.ADMIN_PASSWORD || '';
  // Sin contraseña propia no se crea una cuenta con una clave conocida públicamente.
  if (passwordTemporal.length < 12 || passwordTemporal.startsWith('replace_')) {
    console.warn('[db] No hay administradores. Define ADMIN_EMAIL y ADMIN_PASSWORD (mínimo 12 caracteres) en .env y reinicia para crear el primero.');
    return;
  }
  const hash = await bcrypt.hash(passwordTemporal, 10);

  const [admin] = await pool.query(
    "INSERT INTO usuarios (correo, password_hash, rol) VALUES (?, ?, 'admin')",
    [correo, hash]
  );
  // Si la verificación institucional ya está instalada, el administrador
  // inicial recibe todos los permisos de staff (si no, los otorga la migración).
  const [tablaPermisos] = await pool.query(
    "SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'staff_permisos' LIMIT 1"
  );
  if (tablaPermisos.length) {
    const { PERMISOS_STAFF, PERMISOS_DATOS_PERSONALES } = require('./autorizacion');
    for (const permiso of Object.keys(PERMISOS_STAFF).filter(p => !PERMISOS_DATOS_PERSONALES.has(p) || p === 'documentos.ver')) {
      await pool.query('INSERT IGNORE INTO staff_permisos (usuario_id, permiso) VALUES (?, ?)', [admin.insertId, permiso]);
    }
  }

  // La contraseña vino de una variable de entorno: debe cambiarse en el primer acceso.
  try {
    await pool.query('UPDATE usuarios SET debe_cambiar_password = TRUE WHERE id = ?', [admin.insertId]);
  } catch (err) {
    if (err.code !== 'ER_BAD_FIELD_ERROR') throw err;
  }
  console.log('==============================================================');
  console.log('[db] Cuenta de administrador creada automáticamente:');
  console.log(`      correo:    ${correo}`);
  console.log('      password:  la definida en ADMIN_PASSWORD (no se escribe en registros)');
  console.log('==============================================================');
}

module.exports = { pool, poolTransacciones, migrar, migrarCuentaSegura, sembrarCategoriasYProductos };
