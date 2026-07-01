# -*- coding: utf-8 -*-
"""
checks_data.py
--------------
Definiciones de comprobaciones (endpoints) y categorías, portadas del script
original auditor_wp_v5.py. El formato de cada dict es IDÉNTICO al de tu
`endpoints_maestros`, por lo que puedes pegar aquí cualquier check adicional
de tu script sin tocar el motor (auditor_core.py).

Cada endpoint admite las claves:
    path, nombre, tipo, gravedad, puntos, desc, imp
    match  -> solo para tipo="texto"
    rapido -> True si debe incluirse en el modo rápido (pantalla)
"""

# ---------------------------------------------------------------------------
# LISTA MAESTRA DE ENDPOINTS (modo "completo" = todos; modo "rapido" = rapido=True)
# NOTA: incluye el subconjunto crítico verificado. Puedes añadir el resto de
# entradas de tu `endpoints_maestros` original aquí con el mismo formato.
# ---------------------------------------------------------------------------
ENDPOINTS_MAESTROS = [
    # --- Accesos y paneles (Media) ---
    {"path": "/wp-admin/", "nombre": "Panel de administración expuesto (/wp-admin/)",
     "tipo": "admin", "gravedad": "Media", "puntos": 4,
     "desc": "La ruta de administración redirige o muestra directamente la interfaz de acceso.",
     "imp": "Permite ataques continuados de fuerza bruta sobre las credenciales de gestión."},
    {"path": "/wp-login.php", "nombre": "Formulario de acceso expuesto (/wp-login.php)",
     "tipo": "admin", "gravedad": "Media", "puntos": 4, "rapido": True,
     "desc": "El formulario de acceso por defecto de WordPress se encuentra totalmente accesible.",
     "imp": "Vía de ataque masiva y predecible explotada diariamente por botnets globales."},

    # --- XML-RPC (Alta) ---
    {"path": "/xmlrpc.php", "nombre": "Protocolo XML-RPC activo (/xmlrpc.php)",
     "tipo": "xmlrpc", "gravedad": "Alta", "puntos": 7, "rapido": True,
     "desc": "La puerta de enlace XML-RPC responde activamente a peticiones del exterior.",
     "imp": "Permite validar miles de contraseñas en un único paquete (multicall) y ataques DDoS."},

    # --- Enumeración de usuarios REST (Alta / Media) ---
    {"path": "/wp-json/wp/v2/users", "nombre": "Enumeración de usuarios general por REST API (/wp-json/wp/v2/users)",
     "tipo": "json_users", "gravedad": "Alta", "puntos": 7, "rapido": True,
     "desc": "La API REST devuelve en formato estructurado el listado completo de usuarios reales.",
     "imp": "Regala el 50% de los datos necesarios para secuestrar el acceso del negocio."},
    {"path": "/wp-json/wp/v2/users/1", "nombre": "Exposición de datos de Usuario ID 1 (/wp-json/wp/v2/users/1)",
     "tipo": "json_users", "gravedad": "Alta", "puntos": 7,
     "desc": "Filtración selectiva del usuario con identificador único 1.",
     "imp": "El ID 1 suele pertenecer al perfil de administración maestro."},

    # --- Redirección de autor (Media) ---
    {"path": "/?author=1", "nombre": "Enumeración de usuarios por Redirección de Autor (?author=1)",
     "tipo": "author", "gravedad": "Media", "puntos": 4,
     "desc": "El parámetro por ID numérico desvela el alias directo del administrador maestro.",
     "imp": "Facilita la recolección de los nombres de usuario con mayor rango."},

    # --- Config maestra (Crítica) ---
    {"path": "/wp-config.php", "nombre": "Acceso directo a archivo de producción: wp-config.php",
     "tipo": "status", "gravedad": "Crítica", "puntos": 10, "rapido": True,
     "desc": "El archivo de configuración maestro responde de manera anómala (200 OK).",
     "imp": "CRÍTICO. Puede volcar los secretos de base de datos directamente al navegador."},
    {"path": "/wp-config.php.bak", "nombre": "Copia residual expuesta: wp-config.php.bak",
     "tipo": "status", "gravedad": "Crítica", "puntos": 10,
     "desc": "Respaldo manual del archivo clave de WordPress expuesto en la raíz pública.",
     "imp": "CRÍTICO. Descarga inmediata de las contraseñas e identificadores de la base de datos."},
    {"path": "/wp-config.php.old", "nombre": "Copia residual expuesta: wp-config.php.old",
     "tipo": "status", "gravedad": "Crítica", "puntos": 10,
     "desc": "Fichero de configuración antiguo accesible públicamente.",
     "imp": "CRÍTICO. Entrega las llaves de seguridad internas y credenciales del servidor SQL."},
    {"path": "/wp-config.php.save", "nombre": "Copia de editor expuesta: wp-config.php.save",
     "tipo": "status", "gravedad": "Crítica", "puntos": 10,
     "desc": "Archivo guardado automáticamente por editores Linux disponible.",
     "imp": "CRÍTICO. Expone de manera íntegra los secretos de conectividad de la web."},
    {"path": "/wp-config.php~", "nombre": "Copia por guardado de emergencia: wp-config.php~",
     "tipo": "status", "gravedad": "Crítica", "puntos": 10,
     "desc": "Archivo de respaldo temporal visible en la raíz.",
     "imp": "CRÍTICO. El servidor lo trata como descarga, saltándose la ejecución PHP."},

    # --- Entorno .env (Crítica) ---
    {"path": "/.env", "nombre": "Archivo de entorno expuesto: .env",
     "tipo": "status", "gravedad": "Crítica", "puntos": 10, "rapido": True,
     "desc": "Fichero maestro de variables de entorno expuesto de forma pública.",
     "imp": "CRÍTICO. Custodia claves de pasarelas de pago, credenciales cloud y contraseñas de producción."},
    {"path": "/.env.production", "nombre": "Archivo de entorno de producción expuesto: .env.production",
     "tipo": "status", "gravedad": "Crítica", "puntos": 10,
     "desc": "Variables maestras del entorno en vivo desprotegidas.",
     "imp": "CRÍTICO. Compromiso masivo e inmediato de la infraestructura."},

    # --- Volcados SQL (Crítica) ---
    {"path": "/wp.sql", "nombre": "Volcado SQL en la raíz: wp.sql",
     "tipo": "status", "gravedad": "Crítica", "puntos": 10,
     "desc": "Copia física de la Base de Datos al alcance de cualquiera.",
     "imp": "CRÍTICO. Descarga de contraseñas cifradas, ventas y datos personales."},
    {"path": "/backup.sql", "nombre": "Volcado SQL en la raíz: backup.sql",
     "tipo": "status", "gravedad": "Crítica", "puntos": 10,
     "desc": "Respaldo SQL desprotegido en la raíz pública.",
     "imp": "CRÍTICO. Acceso absoluto al corazón de los datos de la corporación."},

    # --- Control de versiones (Crítica / Alta) ---
    {"path": "/.git/HEAD", "nombre": "Control de versiones Git expuesto públicamente (/.git/HEAD)",
     "tipo": "texto", "match": "ref:", "gravedad": "Crítica", "puntos": 10, "rapido": True,
     "desc": "La carpeta oculta de Git está desprotegida y accesible en producción.",
     "imp": "CRÍTICO. Permite reconstruir todo el historial del código de la plataforma."},
    {"path": "/.git/config", "nombre": "Configuración de Git expuesta (/.git/config)",
     "tipo": "status", "gravedad": "Crítica", "puntos": 10,
     "desc": "El archivo de configuración de Git es accesible en línea.",
     "imp": "CRÍTICO. Puede revelar tokens de acceso o credenciales de despliegue."},

    # --- Listado de directorios (Alta) ---
    {"path": "/wp-content/uploads/", "nombre": "Listado de directorios abierto: /wp-content/uploads/",
     "tipo": "texto", "match": "Index of", "gravedad": "Alta", "puntos": 7,
     "desc": "Indexación pública de todos los contenidos multimedia y ficheros cargados.",
     "imp": "Riesgo extremo de privacidad: filtra PDFs, facturas, contratos o DNI de clientes."},
    {"path": "/wp-content/plugins/", "nombre": "Listado de directorios abierto: /wp-content/plugins/",
     "tipo": "texto", "match": "Index of", "gravedad": "Alta", "puntos": 7,
     "desc": "Navegación visual abierta sobre la suite de plugins instalados.",
     "imp": "Permite identificar todos los complementos para cruzar con vulnerabilidades conocidas."},

    # --- Logs (Alta) ---
    {"path": "/wp-content/debug.log", "nombre": "Registro de depuración expuesto: /wp-content/debug.log",
     "tipo": "status", "gravedad": "Alta", "puntos": 7,
     "desc": "El archivo de recolección de fallos PHP se encuentra activo y visible.",
     "imp": "Almacena trazas de errores, rutas absolutas del servidor y a veces datos personales."},

    # --- Documentos de fábrica (Baja) ---
    {"path": "/readme.html", "nombre": "Archivo instructivo de fábrica expuesto (readme.html)",
     "tipo": "status", "gravedad": "Baja", "puntos": 2,
     "desc": "El manual instructivo por defecto de WordPress se mantiene activo.",
     "imp": "Delata la presencia y versión del CMS a herramientas automatizadas."},

    # --- Rendimiento (Baja) ---
    {"path": "/wp-cron.php", "nombre": "Sistema de tareas programadas accesible (/wp-cron.php)",
     "tipo": "cron", "gravedad": "Baja", "puntos": 2,
     "desc": "El disparador de tareas en segundo plano responde libremente (200 OK).",
     "imp": "Un atacante puede invocarlo de forma masiva para sobrecargar el servidor (DDoS)."},

    # >>> PEGA AQUÍ el resto de entradas de tu `endpoints_maestros` original <<<
    # (mismo formato de dict; añade "rapido": True solo a las 2-3 más críticas
    #  que quieras mostrar en pantalla).
]


# ---------------------------------------------------------------------------
# Cabeceras HTTP de seguridad evaluadas sobre la respuesta de la raíz.
# (nombre, desc_si_falta, imp, gravedad, puntos, rapido)
# ---------------------------------------------------------------------------
CABECERAS_SEGURIDAD = {
    "Strict-Transport-Security": (
        "Ausencia de cabecera HSTS (Strict-Transport-Security)",
        "El servidor no obliga a los navegadores a conectar solo por HTTPS.",
        "Permite ataques de degradación SSL (SSL Stripping) y Man-in-the-Middle.",
        "Baja", 2, False),
    "Content-Security-Policy": (
        "Ausencia de cabecera CSP (Content-Security-Policy)",
        "No hay política que restrinja qué scripts y recursos externos se ejecutan.",
        "Facilita ataques Cross-Site Scripting (XSS) e inyección de malware.",
        "Media", 4, True),
    "X-Frame-Options": (
        "Ausencia de cabecera X-Frame-Options (Protección contra Clickjacking)",
        "El servidor no prohíbe que la web sea incrustada en iframes ajenos.",
        "Permite ataques de Clickjacking sobre botones invisibles.",
        "Media", 4, True),
    "X-Content-Type-Options": (
        "Ausencia de cabecera X-Content-Type-Options",
        "No se previene el sniffing del tipo MIME por parte de los navegadores.",
        "Permite que archivos subidos se ejecuten como scripts maliciosos.",
        "Baja", 2, False),
}


# ---------------------------------------------------------------------------
# Mapeo de categorías (para agrupar en el informe y el PDF)
# ---------------------------------------------------------------------------
MAPEO_CATEGORIAS = {
    "1. CONFIGURACIÓN DE TRANSPORTE Y CABECERAS DE SEGURIDAD HTTP": [
        "Ausencia de Redirección SSL forzosa (HTTP a HTTPS)",
        "Ausencia de cabecera HSTS (Strict-Transport-Security)",
        "Ausencia de cabecera CSP (Content-Security-Policy)",
        "Ausencia de cabecera X-Frame-Options (Protección contra Clickjacking)",
        "Ausencia de cabecera X-Content-Type-Options",
        "Fuga de versión del Servidor Web (Cabecera Server)",
        "Fuga de tecnología / lenguaje backend (Cabecera X-Powered-By)",
        "Versión de PHP obsoleta e insegura (Detección en cabeceras)",
    ],
    "2. ENUMERACIÓN DE USUARIOS, AUTORES Y FUENTES (REST API / FEEDS)": [
        "Enumeración de usuarios general por REST API (/wp-json/wp/v2/users)",
        "Exposición de datos de Usuario ID 1 (/wp-json/wp/v2/users/1)",
        "Enumeración de usuarios por Redirección de Autor (?author=1)",
    ],
    "3. ACCESO A PANELES DE GESTIÓN Y PROTOCOLOS DE ENLACE": [
        "Panel de administración expuesto (/wp-admin/)",
        "Formulario de acceso expuesto (/wp-login.php)",
        "Protocolo XML-RPC activo (/xmlrpc.php)",
        "Sistema de tareas programadas accesible (/wp-cron.php)",
    ],
    "4. ARCHIVOS DE CONFIGURACIÓN MAESTRA Y ENTORNOS (.ENV)": [
        "Acceso directo a archivo de producción: wp-config.php",
        "Copia residual expuesta: wp-config.php.bak",
        "Copia residual expuesta: wp-config.php.old",
        "Copia de editor expuesta: wp-config.php.save",
        "Copia por guardado de emergencia: wp-config.php~",
        "Archivo de entorno expuesto: .env",
        "Archivo de entorno de producción expuesto: .env.production",
    ],
    "5. RESPALDOS COMPRIMIDOS Y VOLCADOS DE BASES DE DATOS (DUMPS)": [
        "Volcado SQL en la raíz: wp.sql",
        "Volcado SQL en la raíz: backup.sql",
    ],
    "6. EXPOSICIÓN DE REPOSITORIOS, REGISTROS DE ERROR Y DIRECTORIOS": [
        "Control de versiones Git expuesto públicamente (/.git/HEAD)",
        "Configuración de Git expuesta (/.git/config)",
        "Listado de directorios abierto: /wp-content/uploads/",
        "Listado de directorios abierto: /wp-content/plugins/",
        "Registro de depuración expuesto: /wp-content/debug.log",
    ],
    "7. HIGIENE DIGITAL Y RECONOCIMIENTO PASIVO DE VERSIONES": [
        "Configuración e higiene de /robots.txt",
        "Archivo instructivo de fábrica expuesto (readme.html)",
        'Etiqueta Meta "generator" expuesta en Código Fuente HTML',
    ],
}

CATEGORIA_POR_DEFECTO = "7. HIGIENE DIGITAL Y RECONOCIMIENTO PASIVO DE VERSIONES"
