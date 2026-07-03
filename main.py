"""
auditor_wp.py — Motor de auditoría de seguridad WordPress (versión servidor).

Refactor de `auditor_wp_v5.py` para ejecutarse en un microservicio (Render/FastAPI)
en lugar de como CLI interactiva. Cambios estructurales frente al original:

  1. CLI interactiva (input()/while True/menú)  ->  run_audit(dominio) -> dict
     Un servidor no tiene stdin; ahora es una función pura invocable por HTTP.

  2. Peticiones 100% secuenciales (~78 GET en serie)  ->  ThreadPoolExecutor + Session
     El escaneo es I/O-bound: los hilos liberan el GIL mientras esperan red, y la
     Session reutiliza la conexión TCP/TLS (elimina ~78 handshakes contra el host).
     Wall-time típico: ~90 s  ->  ~12-15 s.

  3. Escritura de CSV a ~/Documents  ->  devuelve JSON en memoria
     Render tiene filesystem efímero (lo escrito a disco desaparece en el próximo
     deploy). El CSV sigue disponible como export OPCIONAL para ejecución local.

  4. + Guard anti-SSRF antes de escanear (bloquea IPs privadas/loopback/link-local).
  5. + 429/503 se marcan "Inconcluso" (no falsean un "Correcto") y se excluyen del
       cálculo de nota para no diluir la puntuación.
  6. + Logging estructurado en lugar de print / barras ANSI.

Uso local (para depurar en VS Code):
    python auditor_wp.py ejemplo.com
    python auditor_wp.py ejemplo.com --csv salida.csv
"""

from __future__ import annotations

import csv
import ipaddress
import json
import logging
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable

import requests
import urllib3
from requests.adapters import HTTPAdapter

# El auditor escanea sitios de terceros que pueden tener certificados rotos.
# Desactivamos la verificación TLS de forma CONSCIENTE (ver `verificar_ssl` abajo)
# y silenciamos el ruido de warnings para no contaminar los logs.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("auditor_wp")

# User-Agent de navegador real: muchos WAF bloquean clientes sin UA "humano",
# lo que falsearía los resultados devolviendo 403 en rutas que sí existen.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Concurrencia deliberadamente BAJA: golpear un único host con demasiados hilos
# paralelos dispara WAFs (Wordfence, Sucuri, Cloudflare) devolviendo 429 en masa,
# lo que convierte la mayoría de checks en "Inconcluso".
# 4 hilos + throttle inter-petición mantienen la ráfaga por debajo del umbral
# típico de Wordfence (~20 req / 10s) mientras siguen dando un speedup de ~3-4x
# frente a secuencial. Ajustable por objetivo si hace falta.
MAX_WORKERS_DEFECTO = 4

# Timeouts por fase (segundos). Cortos a propósito: una ruta que cuelga no debe
# arrastrar toda la auditoría.
TIMEOUT_ENDPOINT = 4
TIMEOUT_GENERAL = 6
TIMEOUT_ROBOTS = 5

# Retry + backoff exponencial para respuestas 429 / 503. Cuando el WAF rate-limitea
# una petición, esperamos y reintentamos en vez de marcar "Inconcluso" directamente.
# 3 reintentos con backoff 2s -> 4s -> 8s = 14s máx por petición (aceptable en un
# escaneo de ~30s; y solo aplica a las que el WAF corte, no a todas).
RETRY_MAX = 3
RETRY_BACKOFF_BASE = 2.0  # segundos; cada intento espera base * 2^intento

# Pausa inter-petición por hilo (segundos). Espacia las ráfagas dentro de cada
# worker para no saturar la ventana del rate-limiter. 0.3s × 4 hilos = ~13 req/s
# máximo, por debajo del umbral de la mayoría de WAFs.
THROTTLE_INTER_REQUEST = 0.3


# ---------------------------------------------------------------------------
# Excepciones de dominio
# ---------------------------------------------------------------------------
class AuditoriaError(Exception):
    """Error irrecuperable durante la auditoría (p. ej. host inalcanzable)."""


class ObjetivoInvalido(AuditoriaError):
    """El objetivo no es válido o está bloqueado por política de seguridad (SSRF)."""


# ---------------------------------------------------------------------------
# Catálogo de vulnerabilidades (idéntico al original, elevado a constante de módulo
# para no reconstruirlo en cada request).
# ---------------------------------------------------------------------------
ENDPOINTS_MAESTROS: list[dict[str, Any]] = [
    # --- Accesos y Paneles (Media - 4 pts) ---
    {"path": "/wp-admin/", "nombre": "Panel de administración expuesto (/wp-admin/)", "tipo": "admin", "gravedad": "Media", "puntos": 4, "desc": "La ruta de administración redirige o muestra directamente la interfaz de acceso.", "imp": "Permite que cualquier atacante realice ataques continuados de fuerza bruta sobre las credenciales de gestión de la empresa."},
    {"path": "/wp-login.php", "nombre": "Formulario de acceso expuesto (/wp-login.php)", "tipo": "admin", "gravedad": "Media", "puntos": 4, "desc": "El formulario de acceso por defecto de WordPress se encuentra totalmente accesible.", "imp": "Vía de ataque masiva y predecible explotada diariamente por redes de botnets globales."},
    {"path": "/login/", "nombre": "Alias de login activo (/login/)", "tipo": "admin", "gravedad": "Media", "puntos": 4, "desc": "Un alias complementario de inicio de sesión responde de forma activa.", "imp": "Multiplica los vectores predecibles de ataque que buscan paneles expuestos."},
    {"path": "/admin/", "nombre": "Alias de administración activo (/admin/)", "tipo": "admin", "gravedad": "Media", "puntos": 4, "desc": "La ruta genérica de administración responde sin bloqueos del servidor.", "imp": "Incrementa la superficie de exposición del panel administrativo."},
    {"path": "/wp-admin/upgrade.php", "nombre": "Script de actualización expuesto (/wp-admin/upgrade.php)", "tipo": "status", "gravedad": "Baja", "puntos": 2, "desc": "La herramienta interna de actualización de base de datos del core está visible.", "imp": "Puede propiciar la filtración de estructuras lógicas del CMS y la alteración de parámetros tras parches de versión."},
    # --- Canales de Comunicación (Alta - 7 pts) ---
    {"path": "/xmlrpc.php", "nombre": "Protocolo XML-RPC activo (/xmlrpc.php)", "tipo": "xmlrpc", "gravedad": "Alta", "puntos": 7, "desc": "La puerta de enlace XML-RPC responde activamente a peticiones del exterior.", "imp": "Peligro severo de rendimiento y seguridad. Permite validar miles de combinaciones de contraseñas en un único paquete (multicall) y perpetrar ataques masivos de denegación de servicio (DDoS)."},
    # --- Usuarios REST API (Alta - 7 pts) ---
    {"path": "/wp-json/wp/v2/users", "nombre": "Enumeración de usuarios general por REST API (/wp-json/wp/v2/users)", "tipo": "json_users", "gravedad": "Alta", "puntos": 7, "desc": "La API rest corporativa escupe en formato estructurado el listado completo de usuarios reales.", "imp": "Regala a un posible delincuente informático el 50% de los datos necesarios para secuestrar el acceso del negocio."},
    {"path": "/wp-json/wp/v2/users/1", "nombre": "Exposición de datos de Usuario ID 1 (/wp-json/wp/v2/users/1)", "tipo": "json_users", "gravedad": "Alta", "puntos": 7, "desc": "Filtración selectiva del usuario con identificador único 1.", "imp": "El ID 1 suele pertenecer al perfil de administración maestro y creador de la plataforma."},
    {"path": "/wp-json/wp/v2/users/2", "nombre": "Exposición de datos de Usuario ID 2 (/wp-json/wp/v2/users/2)", "tipo": "json_users", "gravedad": "Media", "puntos": 4, "desc": "Filtración selectiva del usuario con identificador único 2.", "imp": "Aporta credenciales adicionales para refinar vectores de ataque dirigidos."},
    {"path": "/wp-json/wp/v2/users/3", "nombre": "Exposición de datos de Usuario ID 3 (/wp-json/wp/v2/users/3)", "tipo": "json_users", "gravedad": "Media", "puntos": 4, "desc": "Filtración de perfiles internos de la compañía.", "imp": "Permite mapear la plantilla de administradores o editores del sitio web."},
    {"path": "/wp-json/wp/v2/users/4", "nombre": "Exposición de datos de Usuario ID 4 (/wp-json/wp/v2/users/4)", "tipo": "json_users", "gravedad": "Media", "puntos": 4, "desc": "Filtración de perfiles internos de la compañía.", "imp": "Permite mapear la plantilla de administradores o editores del sitio web."},
    {"path": "/wp-json/wp/v2/users/5", "nombre": "Exposición de datos de Usuario ID 5 (/wp-json/wp/v2/users/5)", "tipo": "json_users", "gravedad": "Media", "puntos": 4, "desc": "Filtración de perfiles internos de la compañía.", "imp": "Permite mapear la plantilla de administradores o editores del sitio web."},
    # --- Redirecciones de Autor (Media - 4 pts) ---
    {"path": "/?author=1", "nombre": "Enumeración de usuarios por Redirección de Autor (?author=1)", "tipo": "author", "gravedad": "Media", "puntos": 4, "desc": "El parámetro por ID numérico desvela el alias directo del administrador maestro.", "imp": "Facilita la recolección de los nombres de usuario con mayor rango de la corporación."},
    {"path": "/?author=2", "nombre": "Enumeración de usuarios por Redirección de Autor (?author=2)", "tipo": "author", "gravedad": "Media", "puntos": 4, "desc": "Filtra el nombre real del segundo usuario registrado.", "imp": "Expone la identidad de los gestores del portal."},
    {"path": "/?author=3", "nombre": "Enumeración de usuarios por Redirección de Autor (?author=3)", "tipo": "author", "gravedad": "Media", "puntos": 4, "desc": "Filtra el nombre real del tercer usuario registrado.", "imp": "Expone la identidad de los gestores del portal."},
    # --- Sitemaps y Feeds ---
    {"path": "/wp-sitemap-users-1.xml", "nombre": "Fuga de usuarios mediante Sitemap nativo XML (/wp-sitemap-users-1.xml)", "tipo": "status", "gravedad": "Media", "puntos": 4, "desc": "El sitemap de perfiles indexable se encuentra activo y desprotegido.", "imp": "Es un descuido recurrentes; los firewalls suelen capar la API rest pero olvidan deshabilitar el sitemap de autores."},
    {"path": "/?feed=rss2", "nombre": "Fuga de autores en Feed de Noticias RSS (/?feed=rss2)", "tipo": "texto", "match": "<dc:creator>", "gravedad": "Baja", "puntos": 2, "desc": "El agregador de noticias incluye metadatos que revelan el usuario de publicación.", "imp": "Permite a los atacantes cosechar credenciales mediante raspado de metadatos de los posts."},
    {"path": "/author/admin/feed/", "nombre": "Existencia activa del usuario nativo 'admin' (/author/admin/feed/)", "tipo": "status", "gravedad": "Media", "puntos": 4, "desc": "La URL responde con éxito validando la existencia de la cuenta por defecto 'admin'.", "imp": "Mantener el usuario de fábrica 'admin' es altamente peligroso, ya que es el patrón por defecto en millones de ataques automáticos."},
    # --- Configuración maestra (Crítica - 10 pts) ---
    {"path": "/wp-config.php", "nombre": "Acceso directo a archivo de producción: wp-config.php", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "El archivo de configuración maestro responde de manera anómala (200 OK).", "imp": "CRÍTICO. Si el servidor no procesa correctamente el PHP, puede volcar los secretos de base de datos directamente al navegador."},
    {"path": "/wp-config.php.bak", "nombre": "Copia residual expuesta: wp-config.php.bak", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Respaldo manual del archivo clave de WordPress expuesto en la raíz pública.", "imp": "CRÍTICO. Descarga inmediata de las contraseñas e identificadores de la base de datos central."},
    {"path": "/wp-config.php.old", "nombre": "Copia residual expuesta: wp-config.php.old", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Fichero de configuración antiguo accesible públicamente.", "imp": "CRÍTICO. Entrega las llaves de seguridad internas y credenciales del servidor SQL."},
    {"path": "/wp-config.php.save", "nombre": "Copia de editor expuesta: wp-config.php.save", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Archivo guardado automáticamente por editores Linux disponible.", "imp": "CRÍTICO. Expone de manera íntegra los secretos de conectividad de la web."},
    {"path": "/wp-config.php.txt", "nombre": "Configuración expuesta en formato plano: wp-config.php.txt", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "El archivo de configuración fue transformado o copiado con extensión .txt.", "imp": "CRÍTICO. Los ficheros de texto no se procesan en el backend; se imprimen en bruto con todas las claves legibles en pantalla."},
    {"path": "/wp-config.bak", "nombre": "Archivo crítico residual: wp-config.bak", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Copia desprotegida en formato residual.", "imp": "CRÍTICO. Acceso ilegítimo directo a la base de datos del negocio."},
    {"path": "/wp-config.old", "nombre": "Archivo crítico residual: wp-config.old", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Fichero remanente de migraciones desprotegido.", "imp": "CRÍTICO. Pérdida completa de confidencialidad en las claves del sistema."},
    {"path": "/wp-config.txt", "nombre": "Archivo crítico residual: wp-config.txt", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Copia en texto plano de los parámetros de configuración.", "imp": "CRÍTICO. Revela contraseñas críticas sin requerir autenticación."},
    {"path": "/.wp-config.php.swp", "nombre": "Archivo de intercambio volátil: .wp-config.php.swp", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Fichero temporal surgido de un error en consola Linux.", "imp": "CRÍTICO. Permite reconstruir con herramientas sencillas el archivo original wp-config con todas sus claves."},
    {"path": "/wp-config.php~", "nombre": "Copia por guardado de emergencia: wp-config.php~", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Archivo de respaldo temporal visible en la raíz.", "imp": "CRÍTICO. Al contener el caracter '~', los servidores web lo tratan como descarga, saltándose la ejecución PHP."},
    # --- Entornos .env (Crítica - 10 pts) ---
    {"path": "/.env", "nombre": "Archivo de entorno expuesto: .env", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Fichero maestro de variables de entorno expuesto de forma pública.", "imp": "CRÍTICO. Custodia claves de pasarelas bancarias (Stripe, PayPal), credenciales de servidores en la nube y contraseñas de producción."},
    {"path": "/.env.local", "nombre": "Archivo de entorno local expuesto: .env.local", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Variables de configuración de desarrollo expuestas.", "imp": "CRÍTICO. Filtración de parámetros internos del entorno de trabajo."},
    {"path": "/.env.production", "nombre": "Archivo de entorno de producción expuesto: .env.production", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Variables maestras del entorno en vivo desprotegidas.", "imp": "CRÍTICO. Compromiso masivo e inmediato de la infraestructura del cliente."},
    # --- Volcados SQL (Crítica - 10 pts) ---
    {"path": "/wp.sql", "nombre": "Volcado SQL en la raíz: wp.sql", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Copia física de la Base de Datos al alcance de cualquiera.", "imp": "CRÍTICO. El atacante descarga toda la información del negocio: contraseñas cifradas, registros de ventas y datos personales."},
    {"path": "/wordpress.sql", "nombre": "Volcado SQL en la raíz: wordpress.sql", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Respaldo SQL con nombre nativo desprotegido.", "imp": "CRÍTICO. Acceso absoluto al corazón de los datos de la corporación."},
    {"path": "/backup.sql", "nombre": "Volcado SQL en la raíz: backup.sql", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Copia de seguridad de la estructura y tablas desprotegida.", "imp": "CRÍTICO. Infracción severa de normativas internacionales de privacidad de datos (RGPD) y pérdida de secretos comerciales."},
    {"path": "/dump.sql", "nombre": "Volcado SQL en la raíz: dump.sql", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Archivo de volcado genérico accesible para su descarga.", "imp": "CRÍTICO. Facilita la exfiltración íntegra de tablas corporativas."},
    {"path": "/data.sql", "nombre": "Volcado SQL en la raíz: data.sql", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Fichero de datos estructurado desprotegido.", "imp": "CRÍTICO. Robo automatizado de bases de datos por parte de atacantes externos."},
    {"path": "/db.sql", "nombre": "Volcado SQL en la raíz: db.sql", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Respaldo de Base de Datos expuesto de forma pública.", "imp": "CRÍTICO. Descarga directa de toda la información confidencial de la web."},
    {"path": "/dbdump.sql", "nombre": "Volcado SQL en la raíz: dbdump.sql", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Fichero residual de volcado de tablas expuesto.", "imp": "CRÍTICO. Compromiso total de la confidencialidad de la información guardada."},
    {"path": "/mysql.sql", "nombre": "Volcado SQL en la raíz: mysql.sql", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Archivo SQL con nombre del motor de base de datos expuesto.", "imp": "CRÍTICO. Acceso directo a configuraciones y registros sensibles."},
    {"path": "/bd.sql", "nombre": "Volcado SQL en la raíz: bd.sql", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Copia física de la base de datos expuesta.", "imp": "CRÍTICO. Exfiltración y potencial secuestro de datos comerciales."},
    {"path": "/local.sql", "nombre": "Volcado SQL en la raíz: local.sql", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Archivo SQL del entorno local expuesto en el servidor en vivo.", "imp": "CRÍTICO. Revela configuraciones internas y datos de desarrollo."},
    {"path": "/site.sql", "nombre": "Volcado SQL en la raíz: site.sql", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Copia de seguridad de las tablas del sitio web desprotegida.", "imp": "CRÍTICO. Robo masivo de información de usuarios y configuraciones."},
    # --- Comprimidos completos (Crítica - 10 pts) ---
    {"path": "/backup.zip", "nombre": "Archivo comprimido completo: backup.zip", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Copia de seguridad íntegra de la web ejecutable y descargable.", "imp": "CRÍTICO. Un atacante se descarga el sitio web entero para auditarlo en su equipo en busca de fallos o para robar la propiedad intelectual de la empresa."},
    {"path": "/wp-backup.zip", "nombre": "Archivo comprimido completo: wp-backup.zip", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Copia de respaldo en formato ZIP expuesta de manera pública.", "imp": "CRÍTICO. Clonación total del ecosistema digital de la compañía con un solo clic."},
    {"path": "/site.zip", "nombre": "Archivo comprimido completo: site.zip", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Compreso de los ficheros de producción de la web expuesto.", "imp": "CRÍTICO. Exposición del código fuente íntegro, incluyendo configuraciones y temas."},
    {"path": "/wordpress.zip", "nombre": "Archivo comprimido completo: wordpress.zip", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Copia comprimida de la instalación desprotegida.", "imp": "CRÍTICO. Fuga masiva de archivos del core, plantillas y plugins."},
    {"path": "/public.zip", "nombre": "Archivo comprimido completo: public.zip", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Compreso de la carpeta pública del servidor expuesto.", "imp": "CRÍTICO. Descarga sin restricciones de toda la estructura de producción."},
    {"path": "/html.zip", "nombre": "Archivo comprimido completo: html.zip", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "Compreso de la raíz web expuesto de forma pública.", "imp": "CRÍTICO. Acceso ilegítimo al árbol completo de carpetas del negocio."},
    # --- Indexación de carpetas (Alta - 7 pts) ---
    {"path": "/wp-content/", "nombre": "Listado de directorios abierto: /wp-content/", "tipo": "texto", "match": "Index of", "gravedad": "Alta", "puntos": 7, "desc": "El servidor permite listar de forma visual la carpeta raíz de contenidos.", "imp": "Muestra públicamente la estructura interna del CMS, facilitando la identificación de activos."},
    {"path": "/wp-content/plugins/", "nombre": "Listado de directorios abierto: /wp-content/plugins/", "tipo": "texto", "match": "Index of", "gravedad": "Alta", "puntos": 7, "desc": "Navegación visual abierta sobre la suite de plugins instalados.", "imp": "Permite identificar todos los complementos del sitio para cruzar datos con vulnerabilidades conocidas y explotarlas."},
    {"path": "/wp-content/themes/", "nombre": "Listado de directorios abierto: /wp-content/themes/", "tipo": "texto", "match": "Index of", "gravedad": "Alta", "puntos": 7, "desc": "Navegación abierta en la carpeta de plantillas visuales.", "imp": "Permite auditar las plantillas en busca de debilidades de inyección o vulnerabilidades estructurales."},
    {"path": "/wp-content/uploads/", "nombre": "Listado de directorios abierto: /wp-content/uploads/", "tipo": "texto", "match": "Index of", "gravedad": "Alta", "puntos": 7, "desc": "Indexación pública de todos los contenidos multimedia y ficheros cargados.", "imp": "Riesgo extremo de privacidad. Filtra PDFs confidenciales, facturas, contratos, DNI o cualquier elemento subido por clientes."},
    {"path": "/wp-includes/", "nombre": "Listado de directorios abierto: /wp-includes/", "tipo": "texto", "match": "Index of", "gravedad": "Alta", "puntos": 7, "desc": "La carpeta con las funciones principales del núcleo está expuesta visualmente.", "imp": "Revela la arquitectura de archivos lógicos nativos del CMS, facilitando ataques de denegación de servicio o explotación orientada."},
    # --- Control de versiones ---
    {"path": "/.git/HEAD", "nombre": "Control de versiones Git expuesto públicamente (/.git/HEAD)", "tipo": "texto", "match": "ref:", "gravedad": "Crítica", "puntos": 10, "desc": "La carpeta oculta de Git está desprotegida y accesible en producción.", "imp": "CRÍTICO. Permite reconstruir y descargar bloque a bloque todo el historial del código de la plataforma, exponiendo cambios y notas de desarrollo."},
    {"path": "/.git/config", "nombre": "Configuración de Git expuesta (/.git/config)", "tipo": "status", "gravedad": "Crítica", "puntos": 10, "desc": "El archivo de configuración de Git es accesible en línea.", "imp": "CRÍTICO. Puede revelar rutas de repositorios privados, tokens de acceso o credenciales de despliegue del programador."},
    {"path": "/.svn/entries", "nombre": "Control de versiones SVN expuesto (/.svn/entries)", "tipo": "status", "gravedad": "Alta", "puntos": 7, "desc": "Estructuras del repositorio Subversion visibles.", "imp": "Alto riesgo. Filtra nombres de archivos internos y rutas del árbol de desarrollo."},
    # --- Logs (Alta - 7 pts) ---
    {"path": "/wp-content/debug.log", "nombre": "Registro de depuración expuesto: /wp-content/debug.log", "tipo": "status", "gravedad": "Alta", "puntos": 7, "desc": "El archivo de recolección de fallos PHP se encuentra activo y visible.", "imp": "Riesgo alto. Almacena trazas de errores, rutas absolutas del servidor, variables de memoria y, en ocasiones, datos personales."},
    {"path": "/wp-content/uploads/wp-errors.log", "nombre": "Registro de errores expuesto: /wp-content/uploads/wp-errors.log", "tipo": "status", "gravedad": "Alta", "puntos": 7, "desc": "Fichero de fallos alternativo expuesto.", "imp": "Fuga de información técnica valiosa que facilita la preparación de ciberataques dirigidos."},
    {"path": "/error_log", "nombre": "Archivo de registro expuesto: /error_log", "tipo": "status", "gravedad": "Alta", "puntos": 7, "desc": "Historial de fallos del servidor visible en la raíz de producción.", "imp": "Revela fallos lógicos y de infraestructura del servidor web."},
    {"path": "/error.log", "nombre": "Archivo de registro expuesto: /error.log", "tipo": "status", "gravedad": "Alta", "puntos": 7, "desc": "Historial de fallos del servidor expuesto públicamente.", "imp": "Expone las debilidades y advertencias del sistema operativo y sus intérpretes."},
    {"path": "/php_errors.log", "nombre": "Archivo de registro expuesto: /php_errors.log", "tipo": "status", "gravedad": "Alta", "puntos": 7, "desc": "Log específico de errores de PHP accesible.", "imp": "Fuga de datos operativos internos que compromete la seguridad estructural de los scripts."},
    # --- Documentos informativos (Baja - 2 pts) ---
    {"path": "/readme.html", "nombre": "Archivo instructivo de fábrica expuesto (readme.html)", "tipo": "status", "gravedad": "Baja", "puntos": 2, "desc": "El manual instructivo por defecto de WordPress se mantiene activo.", "imp": "Delata la presencia del CMS y asiste a herramientas automatizadas en el análisis inicial del sitio."},
    {"path": "/license.txt", "nombre": "Archivo de licencia de fábrica expuesto (license.txt)", "tipo": "status", "gravedad": "Baja", "puntos": 2, "desc": "El documento legal de fábrica de WordPress se encuentra visible.", "imp": "Aporta información complementaria sobre la instalación original del sistema."},
    {"path": "/wp-links-opml.php", "nombre": "Script de exportación activo (wp-links-opml.php)", "tipo": "status", "gravedad": "Baja", "puntos": 2, "desc": "El script de exportación de enlaces de WordPress responde de forma pública.", "imp": "Fuga de datos menor que permite extraer listas estructuradas de enlaces gestionados por el CMS."},
    # --- Rendimiento (Baja - 2 pts) ---
    {"path": "/wp-cron.php", "nombre": "Sistema de tareas programadas accesible (/wp-cron.php)", "tipo": "cron", "gravedad": "Baja", "puntos": 2, "desc": "El disparador de tareas en segundo plano de WordPress responde libremente a peticiones externas (200 OK).", "imp": "Problema grave de rendimiento. Al estar expuesto de forma pública, un atacante puede invocar este archivo de manera masiva para sobrecargar el procesador del servidor, provocando lentitud extrema o la caída total de la página (Ataque DDoS)."},
]

# Cabeceras de seguridad evaluadas: nombre_cabecera -> (nombre, desc_error, imp, gravedad, puntos)
CABECERAS_SEGURIDAD: dict[str, tuple[str, str, str, str, int]] = {
    "Strict-Transport-Security": ("Ausencia de cabecera HSTS (Strict-Transport-Security)", "El servidor no obliga a los navegadores a recordar que solo deben conectar por HTTPS.", "Permite ataques de degradación de SSL (SSL Striping) y ataques Man-in-the-Middle.", "Baja", 2),
    "Content-Security-Policy": ("Ausencia de cabecera CSP (Content-Security-Policy)", "No hay una política que restrinja qué scripts y recursos externos pueden ejecutarse.", "Facilita drásticamente el éxito de ataques Cross-Site Scripting (XSS) e inyección de malware.", "Media", 4),
    "X-Frame-Options": ("Ausencia de cabecera X-Frame-Options (Protección contra Clickjacking)", "El servidor no prohíbe que la web sea incrustada dentro de marcos (iframes) de páginas ajenas.", "Permite ataques de Clickjacking, donde un hacker engaña al usuario para que pulse en botones invisibles.", "Media", 4),
    "X-Content-Type-Options": ("Ausencia de cabecera X-Content-Type-Options", "No se previene el sniffing del tipo MIME por parte de los navegadores.", "Permite que archivos de texto o imágenes subidos por usuarios se procesen y ejecuten como scripts maliciosos.", "Baja", 2),
}

CATEGORIAS_ORDENADAS = [
    "1. CONFIGURACIÓN DE TRANSPORTE Y CABECERAS DE SEGURIDAD HTTP",
    "2. ENUMERACIÓN DE USUARIOS, AUTORES Y FUENTES (REST API / FEEDS)",
    "3. ACCESO A PANELES DE GESTIÓN Y PROTOCOLOS DE ENLACE",
    "4. ARCHIVOS DE CONFIGURACIÓN MAESTRA Y ENTORNOS (.ENV)",
    "5. RESPALDOS COMPRIMIDOS Y VOLCADOS DE BASES DE DATOS (DUMPS)",
    "6. EXPOSICIÓN DE REPOSITORIOS, REGISTROS DE ERROR Y DIRECTORIOS",
    "7. HIGIENE DIGITAL Y RECONOCIMIENTO PASIVO DE VERSIONES",
]

MAPEO_CATEGORIAS: dict[str, list[str]] = {
    CATEGORIAS_ORDENADAS[0]: [
        "Ausencia de Redirección SSL forzosa (HTTP a HTTPS)",
        "Ausencia de cabecera HSTS (Strict-Transport-Security)",
        "Ausencia de cabecera CSP (Content-Security-Policy)",
        "Ausencia de cabecera X-Frame-Options (Protección contra Clickjacking)",
        "Ausencia de cabecera X-Content-Type-Options",
        "Fuga de versión del Servidor Web (Cabecera Server)",
        "Fuga de tecnología / lenguaje backend (Cabecera X-Powered-By)",
        "Versión de PHP obsoleta e insegura (Detección en cabeceras)",
    ],
    CATEGORIAS_ORDENADAS[1]: [
        "Enumeración de usuarios general por REST API (/wp-json/wp/v2/users)",
        "Exposición de datos de Usuario ID 1 (/wp-json/wp/v2/users/1)",
        "Exposición de datos de Usuario ID 2 (/wp-json/wp/v2/users/2)",
        "Exposición de datos de Usuario ID 3 (/wp-json/wp/v2/users/3)",
        "Exposición de datos de Usuario ID 4 (/wp-json/wp/v2/users/4)",
        "Exposición de datos de Usuario ID 5 (/wp-json/wp/v2/users/5)",
        "Enumeración de usuarios por Redirección de Autor (?author=1)",
        "Enumeración de usuarios por Redirección de Autor (?author=2)",
        "Enumeración de usuarios por Redirección de Autor (?author=3)",
        "Fuga de usuarios mediante Sitemap nativo XML (/wp-sitemap-users-1.xml)",
        "Fuga de autores en Feed de Noticias RSS (/?feed=rss2)",
        "Existencia activa del usuario nativo 'admin' (/author/admin/feed/)",
    ],
    CATEGORIAS_ORDENADAS[2]: [
        "Panel de administración expuesto (/wp-admin/)",
        "Formulario de acceso expuesto (/wp-login.php)",
        "Alias de login activo (/login/)",
        "Alias de administración activo (/admin/)",
        "Protocolo XML-RPC activo (/xmlrpc.php)",
        "Script de actualización expuesto (/wp-admin/upgrade.php)",
        "Sistema de tareas programadas accesible (/wp-cron.php)",
    ],
    CATEGORIAS_ORDENADAS[3]: [
        "Acceso directo a archivo de producción: wp-config.php",
        "Copia residual expuesta: wp-config.php.bak",
        "Copia residual expuesta: wp-config.php.old",
        "Copia de editor expuesta: wp-config.php.save",
        "Configuración expuesta en formato plano: wp-config.php.txt",
        "Archivo crítico residual: wp-config.bak",
        "Archivo crítico residual: wp-config.old",
        "Archivo crítico residual: wp-config.txt",
        "Archivo de intercambio volátil: .wp-config.php.swp",
        "Copia por guardado de emergencia: wp-config.php~",
        "Archivo de entorno expuesto: .env",
        "Archivo de entorno local expuesto: .env.local",
        "Archivo de entorno de producción expuesto: .env.production",
    ],
    CATEGORIAS_ORDENADAS[4]: [
        "Volcado SQL en la raíz: wp.sql",
        "Volcado SQL en la raíz: wordpress.sql",
        "Volcado SQL en la raíz: backup.sql",
        "Volcado SQL en la raíz: dump.sql",
        "Volcado SQL en la raíz: data.sql",
        "Volcado SQL en la raíz: db.sql",
        "Volcado SQL en la raíz: dbdump.sql",
        "Volcado SQL en la raíz: mysql.sql",
        "Volcado SQL en la raíz: bd.sql",
        "Volcado SQL en la raíz: local.sql",
        "Volcado SQL en la raíz: site.sql",
        "Archivo comprimido completo: backup.zip",
        "Archivo comprimido completo: wp-backup.zip",
        "Archivo comprimido completo: site.zip",
        "Archivo comprimido completo: wordpress.zip",
        "Archivo comprimido completo: public.zip",
        "Archivo comprimido completo: html.zip",
    ],
    CATEGORIAS_ORDENADAS[5]: [
        "Control de versiones Git expuesto públicamente (/.git/HEAD)",
        "Configuración de Git expuesta (/.git/config)",
        "Control de versiones SVN expuesto (/.svn/entries)",
        "Registro de depuración expuesto: /wp-content/debug.log",
        "Registro de errores expuesto: /wp-content/uploads/wp-errors.log",
        "Archivo de registro expuesto: /error_log",
        "Archivo de registro expuesto: /error.log",
        "Archivo de registro expuesto: /php_errors.log",
        "Listado de directorios abierto: /wp-content/",
        "Listado de directorios abierto: /wp-content/plugins/",
        "Listado de directorios abierto: /wp-content/themes/",
        "Listado de directorios abierto: /wp-content/uploads/",
        "Listado de directorios abierto: /wp-includes/",
    ],
    CATEGORIAS_ORDENADAS[6]: [
        "Archivo instructivo de fábrica expuesto (readme.html)",
        "Archivo de licencia de fábrica expuesto (license.txt)",
        "Script de exportación activo (wp-links-opml.php)",
        "Configuración e higiene de /robots.txt",
        'Etiqueta Meta "generator" expuesta en Código Fuente HTML',
        "Versiones expuestas en archivos estáticos mediante parámetro '?ver=' (CSS/JS)",
    ],
}


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------
def limpiar_dominio(dominio_raw: str) -> str:
    """Normaliza el dominio: sin esquema, sin barra final, en minúsculas."""
    dominio = dominio_raw.strip().lower()
    if dominio.startswith("http://"):
        dominio = dominio[7:]
    elif dominio.startswith("https://"):
        dominio = dominio[8:]
    return dominio.rstrip("/")


def _es_ip_publica(ip_str: str) -> bool:
    """True solo si la IP es enrutable en Internet (no privada/loopback/reservada)."""
    ip = ipaddress.ip_address(ip_str)
    return ip.is_global and not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def validar_objetivo_publico(dominio: str) -> None:
    """
    Guard anti-SSRF. Resuelve el host y aborta si apunta a red interna.

    Sin esto, un usuario podría pasar `169.254.169.254` (metadata del cloud) o
    `192.168.x.x` y usar nuestro microservicio para escanear infraestructura
    privada. Residual conocido: DNS rebinding (la IP podría cambiar entre esta
    validación y la conexión real). Para blindarlo del todo habría que fijar la
    IP resuelta en el adaptador; para un MVP de agencia, la validación en resolución
    cubre el 80/20.
    """
    host = dominio.split("/")[0].split(":")[0]
    if not host:
        raise ObjetivoInvalido("Dominio vacío.")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ObjetivoInvalido(f"No se pudo resolver el dominio: {host}") from exc
    for info in infos:
        ip = info[4][0]
        if not _es_ip_publica(ip):
            raise ObjetivoInvalido(
                f"El objetivo '{host}' resuelve a una IP no pública ({ip}); "
                "bloqueado por seguridad (SSRF)."
            )


def crear_session(verificar_ssl: bool, max_workers: int) -> requests.Session:
    """
    Session compartida por todos los hilos. Reutiliza conexiones TCP/TLS (pool)
    en lugar de rehacer el handshake en cada una de las ~78 peticiones.
    """
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    session.verify = verificar_ssl
    # Pool dimensionado al nº de hilos para no serializar por falta de conexiones.
    adapter = HTTPAdapter(pool_connections=max_workers, pool_maxsize=max_workers)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _item(ep: dict[str, Any], estado: str, desc: str, url: str) -> dict[str, Any]:
    """Construye un item de resultado homogéneo."""
    return {
        "nombre": ep["nombre"], "gravedad": ep["gravedad"], "puntos": ep["puntos"],
        "url": url, "imp": ep["imp"], "estado": estado, "desc": desc,
    }


def _leer_parcial(res: requests.Response) -> tuple[str, bool, int]:
    """
    Lee como máximo 150 KB del cuerpo (streaming) para inspección de texto.
    Devuelve (texto_parcial, es_archivo_gigante, content_length).
    Evita cargar en RAM ficheros grandes (backups, dumps) — solo nos interesa
    saber que EXISTEN, no descargarlos enteros.
    """
    content_length = int(res.headers.get("Content-Length", 0) or 0)
    if content_length > 3 * 1024 * 1024:  # > 3 MB: fichero real y grande
        return "", True, content_length

    bytes_leidos = b""
    es_gigante = False
    for chunk in res.iter_content(chunk_size=4096):
        bytes_leidos += chunk
        if len(bytes_leidos) > 150 * 1024:
            es_gigante = True
            break
    return bytes_leidos.decode("utf-8", errors="ignore"), es_gigante, content_length


def _get_con_retry(session: requests.Session, url: str, **kwargs) -> requests.Response:
    """
    GET con retry + backoff exponencial para 429/503 y throttle inter-petición.

    Lógica: si el WAF rate-limitea (429) o el servidor está temporalmente saturado
    (503), esperamos y reintentamos en vez de rendirse. Si el header Retry-After
    viene en la respuesta, lo respetamos (capeado a 15s para no colgar el audit).
    Tras agotar reintentos, devolvemos la última respuesta 429/503 tal cual para
    que el caller la marque como "Inconcluso".

    El throttle (THROTTLE_INTER_REQUEST) se aplica ANTES de cada petición (incluida
    la primera) para espaciar las ráfagas entre los N hilos del pool. Es una pausa
    corta (~0.3s) que baja la tasa global de ~30 req/s a ~13 req/s, por debajo del
    umbral de Wordfence.
    """
    ultimo_response: requests.Response | None = None
    for intento in range(1 + RETRY_MAX):  # 1 intento original + RETRY_MAX reintentos
        time.sleep(THROTTLE_INTER_REQUEST)  # throttle inter-petición

        try:
            resp = session.get(url, **kwargs)
        except requests.RequestException:
            if intento < RETRY_MAX:
                time.sleep(RETRY_BACKOFF_BASE * (2 ** intento))
                continue
            raise  # último intento: dejamos que suba la excepción

        if resp.status_code not in (429, 503):
            return resp  # respuesta limpia -> salimos

        # WAF/rate-limit: guardar y esperar antes de reintentar
        ultimo_response = resp
        if intento < RETRY_MAX:
            # Respetar Retry-After si viene, capeado a 15s
            espera = RETRY_BACKOFF_BASE * (2 ** intento)
            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                try:
                    espera = min(float(retry_after), 15.0)
                except ValueError:
                    pass
            logger.debug("429/503 en %s | intento %d/%d | esperando %.1fs",
                         url, intento + 1, RETRY_MAX, espera)
            time.sleep(espera)

    return ultimo_response  # agotados los reintentos: devolvemos el 429/503


# ---------------------------------------------------------------------------
# Checks individuales (cada uno devuelve una lista de items para poder paralelizar)
# ---------------------------------------------------------------------------
def obtener_plugins_desde_api(session: requests.Session, target: str) -> list[str]:
    """Extrae slugs de plugins analizando los namespaces de la REST API."""
    plugins: set[str] = set()
    try:
        r = session.get(f"{target}/wp-json", timeout=TIMEOUT_ROBOTS, allow_redirects=True)
        if r.status_code == 200:
            for ns in r.json().get("namespaces", []):
                if ns in ("wp/v2", "oembed/1.0", "wp-site-health/v1", "akismet/v1"):
                    continue
                if "/" in ns:
                    slug = ns.split("/")[0]
                    if slug and not slug.startswith("wp"):
                        plugins.add(slug)
    except (requests.RequestException, ValueError):
        pass
    return sorted(plugins)


def calibrar_baseline(session: requests.Session, target: str) -> tuple[int, int]:
    """
    Pide una ruta inexistente para conocer cómo responde el servidor a un 404.
    Sirve para descartar 'Soft-404' (servidores que devuelven 200 en todo).
    """
    try:
        r = session.get(
            f"{target}/archivo_inexistente_de_prueba_9988.php",
            timeout=TIMEOUT_GENERAL, allow_redirects=True,
        )
        return r.status_code, len(r.text)
    except requests.RequestException as exc:
        raise AuditoriaError("No se puede establecer conexión estable con la web.") from exc


def check_ssl(session: requests.Session, target_http: str) -> list[dict[str, Any]]:
    ep = {"nombre": "Ausencia de Redirección SSL forzosa (HTTP a HTTPS)", "gravedad": "Baja",
          "puntos": 2, "imp": "Si la web permite navegar en HTTP sin cifrar, un atacante en la misma red pública puede interceptar las contraseñas de los usuarios y administradores en texto plano."}
    try:
        r = session.get(target_http, timeout=TIMEOUT_GENERAL, allow_redirects=True)
        if r.url.startswith("https://"):
            return [_item(ep, "Correcto", "El sitio web fuerza correctamente todo su tráfico hacia la versión segura HTTPS.", target_http)]
        return [_item(ep, "Error", "La web permite la navegación bajo HTTP inseguro sin redirigir de forma automática a HTTPS.", target_http)]
    except requests.RequestException:
        return [_item(ep, "Error", "Fallo al intentar determinar el comportamiento de redirección del protocolo HTTP.", target_http)]


def check_cabeceras_y_fuente(session: requests.Session, target: str) -> list[dict[str, Any]]:
    """Cabeceras de seguridad + fugas (Server, X-Powered-By, PHP) + meta generator + ?ver=."""
    items: list[dict[str, Any]] = []
    try:
        r = session.get(target, timeout=TIMEOUT_GENERAL, allow_redirects=True)
    except requests.RequestException:
        return items  # sin conexión no podemos evaluar cabeceras; se omite el bloque

    headers = r.headers
    html = r.text

    for cabecera, (nombre, desc, imp, grav, pts) in CABECERAS_SEGURIDAD.items():
        ep = {"nombre": nombre, "gravedad": grav, "puntos": pts, "imp": imp}
        if cabecera in headers:
            items.append(_item(ep, "Correcto", f"La cabecera {cabecera} está activa en el servidor.", "Cabeceras HTTP"))
        else:
            items.append(_item(ep, "Error", desc, "Cabeceras HTTP"))

    srv = headers.get("Server", "")
    ep_srv = {"nombre": "Fuga de versión del Servidor Web (Cabecera Server)", "gravedad": "Media", "puntos": 4,
              "imp": "Da pistas directas a atacantes automatizados para lanzar exploits diseñados para esa versión exacta del servidor."}
    if any(c.isdigit() for c in srv):
        items.append(_item(ep_srv, "Error", f"La cabecera 'Server' expone software corporativo y versiones explícitas: {srv}", "Cabeceras HTTP"))
    else:
        items.append(_item(ep_srv, "Correcto", "El servidor web mantiene oculta su versión específica o software interno.", "Cabeceras HTTP"))

    xpb = headers.get("X-Powered-By", "")
    ep_xpb = {"nombre": "Fuga de tecnología / lenguaje backend (Cabecera X-Powered-By)", "gravedad": "Baja", "puntos": 2,
              "imp": "Muestra las tecnologías instaladas en el backend facilitando el reconocimiento pasivo."}
    if xpb:
        items.append(_item(ep_xpb, "Error", f"La cabecera revela el lenguaje de ejecución del servidor: {xpb}", "Cabeceras HTTP"))
    else:
        items.append(_item(ep_xpb, "Correcto", "La cabecera X-Powered-By se encuentra correctamente oculta.", "Cabeceras HTTP"))

    # PHP obsoleto (< 8.2) detectado en X-Powered-By o Server
    ep_php = {"nombre": "Versión de PHP obsoleta e insegura (Detección en cabeceras)", "gravedad": "Alta", "puntos": 7,
              "imp": "Las versiones de PHP antiguas contienen vulnerabilidades críticas conocidas que exponen al servidor a ejecuciones de código remoto y hackeos directos."}
    version_php, php_antiguo = "", False
    for cadena in (xpb, srv):
        m = re.search(r"PHP\/([0-9.]+)", cadena, re.IGNORECASE)
        if m:
            version_php = m.group(1)
            try:
                if float(".".join(version_php.split(".")[:2])) < 8.2:
                    php_antiguo = True
            except ValueError:
                pass
    if php_antiguo:
        items.append(_item(ep_php, "Error", f"El servidor ejecuta una versión desactualizada de PHP ({version_php}) que ya no recibe parches de seguridad.", "Cabeceras HTTP"))
    elif version_php:
        items.append(_item(ep_php, "Correcto", f"El servidor utiliza una versión de PHP moderna ({version_php}).", "Cabeceras HTTP"))
    else:
        items.append(_item(ep_php, "Correcto", "No se detecta exposición pública de la versión de PHP.", "Cabeceras HTTP"))

    # Meta generator
    ep_gen = {"nombre": 'Etiqueta Meta "generator" expuesta en Código Fuente HTML', "gravedad": "Media", "puntos": 4,
              "imp": "Si la versión instalada sufre algún bug público, el sitio se convierte inmediatamente en un blanco fácil para ciberataques."}
    if '<meta name="generator" content="WordPress' in html:
        m = re.search(r'<meta name="generator" content="WordPress\s?([^"]+)"', html)
        items.append(_item(ep_gen, "Error", f"El código HTML filtra la versión precisa de WordPress instalada: {m.group(1) if m else 'Detectada'}", "Código Fuente HTML"))
    else:
        items.append(_item(ep_gen, "Correcto", "No se localiza la versión de WordPress en las etiquetas meta principales.", "Código Fuente HTML"))

    # Parámetro ?ver= en estáticos
    ep_ver = {"nombre": "Versiones expuestas en archivos estáticos mediante parámetro '?ver=' (CSS/JS)", "gravedad": "Baja", "puntos": 2,
              "imp": "Permite deducir de forma pasiva qué versiones de componentes internos utiliza la plataforma."}
    if "?ver=" in html:
        items.append(_item(ep_ver, "Error", "Las solicitudes de scripts y hojas de estilo adjuntan el parámetro '?ver=', filtrando versiones del core o plugins.", "Código Fuente HTML"))
    else:
        items.append(_item(ep_ver, "Correcto", "No se aprecian parámetros de versión en las URL de estilos o scripts estáticos.", "Código Fuente HTML"))

    return items


def check_robots(session: requests.Session, target: str) -> list[dict[str, Any]]:
    ep = {"nombre": "Configuración e higiene de /robots.txt", "gravedad": "Baja", "puntos": 2,
          "imp": "El archivo robots.txt debe existir y contener directrices de seguridad (como restringir el acceso a directorios administrativos) para evitar indexaciones no deseadas."}
    url = f"{target}/robots.txt"
    try:
        r = session.get(url, timeout=TIMEOUT_ROBOTS)
        texto = r.text.lower()
        if r.status_code == 200 and "disallow" in texto:
            if "/wp-admin/" in r.text:
                return [_item(ep, "Correcto", "El archivo robots.txt existe y restringe adecuadamente rutas críticas como /wp-admin/.", url)]
            return [_item(ep, "Error", "El archivo robots.txt existe pero no declara restricciones de seguridad para la administración de WordPress.", url)]
        return [_item(ep, "Error", "El archivo robots.txt no existe o se encuentra completamente vacío.", url)]
    except requests.RequestException:
        return [_item(ep, "Error", "Error al conectar o localizar el archivo robots.txt.", url)]


def check_plugin_dir(session: requests.Session, target: str, slug: str) -> dict[str, Any]:
    ep = {"nombre": f"Listado de directorio abierto en plugin: {slug}", "gravedad": "Alta", "puntos": 7,
          "imp": "Riesgo alto de ingeniería inversa y descubrimiento de archivos sensibles o archivos vulnerables no protegidos dentro del plugin."}
    url = f"{target}/wp-content/plugins/{slug}/"
    try:
        r = _get_con_retry(session, url, timeout=TIMEOUT_ROBOTS, allow_redirects=False)
        if r.status_code in (429, 503):
            return _item(ep, "Inconcluso", "El servidor limitó la petición (rate-limit); no se pudo comprobar.", url)
        if r.status_code == 200 and "index of" in r.text.lower():
            return _item(ep, "Error", f"El directorio del plugin '{slug}' está expuesto y permite listar sus ficheros.", url)
        return _item(ep, "Correcto", f"El directorio del plugin '{slug}' está adecuadamente protegido contra listados.", url)
    except requests.RequestException:
        return _item(ep, "Correcto", f"El directorio del plugin '{slug}' no es accesible.", url)


def check_endpoint(session: requests.Session, target: str, ep: dict[str, Any],
                   baseline_status: int, baseline_len: int) -> dict[str, Any]:
    """Comprueba un endpoint del catálogo aplicando la detección según su `tipo`."""
    url = f"{target}{ep['path']}"
    evitar_redir = ep["tipo"] in ("admin", "author")
    try:
        res = _get_con_retry(session, url, timeout=TIMEOUT_ENDPOINT,
                             allow_redirects=not evitar_redir, stream=True)

        # Rate-limit / servicio no disponible -> no podemos afirmar nada (correctness).
        if res.status_code in (429, 503):
            res.close()
            return _item(ep, "Inconcluso", "El servidor limitó la petición (rate-limit); no se pudo comprobar de forma fiable.", url)

        texto_parcial, es_gigante, content_length = "", False, 0
        # Fix vs original: incluimos 405 para que la firma de XML-RPC se lea del cuerpo
        # (WP suele responder 405 a un GET /xmlrpc.php). Solo afecta al tipo 'xmlrpc';
        # los demás tipos exigen 200 para marcar error, así que no cambia su resultado.
        if res.status_code in (200, 405):
            texto_parcial, es_gigante, content_length = _leer_parcial(res)

        vulnerable, detalle = False, ""
        tipo = ep["tipo"]

        if tipo == "admin":
            loc = res.headers.get("Location", "")
            if res.status_code in (301, 302) and ("wp-login" in loc or "wp-admin" in loc):
                vulnerable, detalle = True, f"La ruta redirige directamente exponiendo la pantalla de login en: {loc}"
            elif res.status_code == 200 and ("user_login" in texto_parcial or "wp-submit" in texto_parcial):
                vulnerable, detalle = True, "La URL carga directamente el formulario de inicio de sesión."

        elif tipo == "author":
            loc = res.headers.get("Location", "")
            if res.status_code in (301, 302) and "author/" in loc:
                vulnerable, detalle = True, f"El parámetro desvela de forma explícita el nombre de usuario del administrador en la URL: {loc}"

        elif tipo == "xmlrpc":
            if res.status_code in (200, 405) and "xml-rpc" in texto_parcial.lower():
                vulnerable, detalle = True, "El archivo se encuentra operativo y responde: 'XML-RPC server accepts POST requests only.'"

        elif tipo == "json_users":
            # Fix vs original: parseamos el texto ya leído en vez de res.json() (el stream
            # ya está consumido tras _leer_parcial, y res.json() fallaría silenciosamente).
            if res.status_code == 200 and not es_gigante and "slug" in texto_parcial:
                try:
                    data = json.loads(texto_parcial)
                    if (isinstance(data, list) and data) or (isinstance(data, dict) and "slug" in data):
                        vulnerable, detalle = True, "La API REST está totalmente abierta y devuelve las estructuras con los nombres de usuario en texto plano."
                except ValueError:
                    pass

        elif tipo == "cron":
            if res.status_code == 200:
                vulnerable, detalle = True, "El archivo está expuesto públicamente (devuelve una página en blanco con código de estado exitoso 200 OK)."

        else:  # status / texto
            if res.status_code == 200:
                vulnerable, detalle = True, ep["desc"]
                if es_gigante:
                    detalle = f"{ep['desc']} (Fichero masivo detectado e identificado correctamente)."
                else:
                    # Anti Soft-404: si el servidor responde 200 a todo y este cuerpo
                    # mide casi lo mismo que un 404 real, es un falso positivo.
                    longitud = content_length if content_length > 0 else len(texto_parcial.encode("utf-8", "ignore"))
                    if baseline_status == 200 and abs(longitud - baseline_len) < 150:
                        vulnerable = False
                    # Para 'texto' exigimos además la firma concreta en el cuerpo.
                    if vulnerable and tipo == "texto" and ep.get("match", "") not in texto_parcial:
                        vulnerable = False

        res.close()  # libera el socket del stream de inmediato

        if vulnerable:
            return _item(ep, "Error", detalle or ep["desc"], url)
        return _item(ep, "Correcto", "Ruta protegida, inaccesible o camuflada por completo mediante restricciones del servidor.", url)

    except requests.RequestException:
        return _item(ep, "Correcto", "No accesible o tiempo de respuesta del servidor excedido.", url)


# ---------------------------------------------------------------------------
# Clasificación y scoring
# ---------------------------------------------------------------------------
def _clasificar(resultados: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    por_categoria: dict[str, list[dict[str, Any]]] = {cat: [] for cat in MAPEO_CATEGORIAS}
    for item in resultados:
        nombre = item["nombre"]
        if "Listado de directorio abierto en plugin:" in nombre:
            por_categoria[CATEGORIAS_ORDENADAS[5]].append(item)
            continue
        for cat, vulns in MAPEO_CATEGORIAS.items():
            if nombre in vulns:
                por_categoria[cat].append(item)
                break
        else:
            # Fallback: cualquier item no mapeado va a Higiene Digital.
            por_categoria[CATEGORIAS_ORDENADAS[6]].append(item)
    return por_categoria


def _nota(items: list[dict[str, Any]]) -> float:
    """
    Nota /10. Correctness vs original: 'Inconcluso' se excluye del máximo para no
    diluir la puntuación (un check no realizado no debe contar como aprobado).
    """
    evaluables = [it for it in items if it["estado"] in ("Error", "Correcto")]
    maximo = sum(it["puntos"] for it in evaluables)
    penalizacion = sum(it["puntos"] for it in evaluables if it["estado"] == "Error")
    if maximo == 0:
        return 10.0
    return round(10.0 * (1.0 - penalizacion / maximo), 1)


def _nivel(nota: float) -> str:
    if nota >= 8.5:
        return "Excelente (Riesgo Bajo)"
    if nota >= 6.0:
        return "Aceptable (Riesgo Medio)"
    if nota >= 3.5:
        return "Inseguro (Riesgo Alto)"
    return "Crítico (Peligro de Secuestro)"


def _ordenar_categoria(items: list[dict[str, Any]], orden: list[str]) -> list[dict[str, Any]]:
    def prioridad(item: dict[str, Any]) -> int:
        nombre = item["nombre"]
        if "Listado de directorio abierto en plugin:" in nombre:
            return len(orden)
        try:
            return orden.index(nombre)
        except ValueError:
            return len(orden) + 1
    return sorted(items, key=prioridad)


def construir_resultado(dominio: str, resultados: list[dict[str, Any]],
                        duracion: float) -> dict[str, Any]:
    """Ensambla el diccionario final JSON-serializable (para API / PDF / frontend)."""
    por_categoria = _clasificar(resultados)

    nota_final = _nota(resultados)
    tiene_critico = any(it["estado"] == "Error" and it["gravedad"] == "Crítica" for it in resultados)
    if tiene_critico:
        nota_final = min(nota_final, 2.0)  # cap: una fuga crítica hunde la nota

    categorias_payload = []
    for cat in CATEGORIAS_ORDENADAS:
        items = _ordenar_categoria(por_categoria[cat], MAPEO_CATEGORIAS[cat])
        categorias_payload.append({
            "categoria": cat,
            "nota": _nota(items),
            "items": [{
                "nombre": it["nombre"], "estado": it["estado"], "gravedad": it["gravedad"],
                "puntos": it["puntos"],
                "puntos_aplicados": it["puntos"] if it["estado"] == "Error" else 0,
                "url": it["url"], "desc": it["desc"], "imp": it["imp"],
            } for it in items],
        })

    evaluables = [it for it in resultados if it["estado"] in ("Error", "Correcto")]
    return {
        "dominio": dominio,
        "generado_en": datetime.now(timezone.utc).isoformat(),
        "duracion_segundos": round(duracion, 2),
        "nota_final": nota_final,
        "nivel_seguridad": _nivel(nota_final),
        "tiene_fallo_critico": tiene_critico,
        "resumen": {
            "total_checks": len(resultados),
            "evaluados": len(evaluables),
            "errores": sum(1 for it in resultados if it["estado"] == "Error"),
            "criticos": sum(1 for it in resultados if it["estado"] == "Error" and it["gravedad"] == "Crítica"),
            "inconclusos": sum(1 for it in resultados if it["estado"] == "Inconcluso"),
            "puntos_penalizacion": sum(it["puntos"] for it in evaluables if it["estado"] == "Error"),
            "puntos_maximos": sum(it["puntos"] for it in evaluables),
        },
        "categorias": categorias_payload,
    }


# ---------------------------------------------------------------------------
# Punto de entrada principal
# ---------------------------------------------------------------------------
def run_audit(dominio_input: str, *, max_workers: int = MAX_WORKERS_DEFECTO,
              verificar_ssl: bool = False) -> dict[str, Any]:
    """
    Ejecuta la auditoría completa y devuelve un dict JSON-serializable.

    Lanza ObjetivoInvalido si el dominio apunta a red interna (SSRF) o no resuelve,
    y AuditoriaError si el host está caído.
    """
    inicio = time.perf_counter()
    dominio = limpiar_dominio(dominio_input)
    if not dominio:
        raise ObjetivoInvalido("Debes indicar un dominio.")

    validar_objetivo_publico(dominio)  # <- barrera SSRF antes de tocar la red de escaneo

    target_https = f"https://{dominio}"
    target_http = f"http://{dominio}"
    session = crear_session(verificar_ssl, max_workers)

    try:
        # --- Fase secuencial: dependencias del resto de checks ---
        slugs = obtener_plugins_desde_api(session, target_https)
        baseline_status, baseline_len = calibrar_baseline(session, target_https)
        logger.info("Auditando %s | plugins detectados: %d | baseline: %s/%d bytes",
                    dominio, len(slugs), baseline_status, baseline_len)

        # --- Fase paralela: todo lo independiente en un solo pool ---
        # Cada tarea es un callable sin argumentos que devuelve un item o lista de items.
        tareas: list[Callable[[], Any]] = [
            lambda: check_ssl(session, target_http),
            lambda: check_cabeceras_y_fuente(session, target_https),
            lambda: check_robots(session, target_https),
        ]
        tareas += [lambda s=s: check_plugin_dir(session, target_https, s) for s in slugs]
        tareas += [lambda e=ep: check_endpoint(session, target_https, e, baseline_status, baseline_len)
                   for ep in ENDPOINTS_MAESTROS]

        resultados: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            for salida in pool.map(lambda t: t(), tareas):
                if isinstance(salida, list):
                    resultados.extend(salida)
                else:
                    resultados.append(salida)
    finally:
        session.close()

    duracion = time.perf_counter() - inicio
    resultado = construir_resultado(dominio, resultados, duracion)
    logger.info("Auditoría de %s completada en %.2fs | nota %.1f (%s)",
                dominio, duracion, resultado["nota_final"], resultado["nivel_seguridad"])
    return resultado


# ---------------------------------------------------------------------------
# Export CSV opcional (solo para ejecución local; NO usar en Render por disco efímero)
# ---------------------------------------------------------------------------
def exportar_csv(resultado: dict[str, Any], ruta: str) -> None:
    columnas = [
        "grupo", "dominio", "url de comprobación", "nombre vulnerabilidad",
        "estado (error o no)", "gravedad de la vulnerabilidad", "puntos de penalización",
        "descripción del error",
        "explicación de porqué es importante solventar esa vulnerabilidad concreta",
    ]
    with open(ruta, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=columnas, delimiter=";")
        writer.writeheader()
        for cat in resultado["categorias"]:
            for it in cat["items"]:
                writer.writerow({
                    "grupo": cat["categoria"],
                    "dominio": resultado["dominio"],
                    "url de comprobación": it["url"],
                    "nombre vulnerabilidad": it["nombre"],
                    "estado (error o no)": it["estado"],
                    "gravedad de la vulnerabilidad": it["gravedad"],
                    "puntos de penalización": it["puntos_aplicados"],
                    "descripción del error": it["desc"],
                    "explicación de porqué es importante solventar esa vulnerabilidad concreta": it["imp"],
                })


def _cli() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    args = sys.argv[1:]
    if not args:
        print("Uso: python auditor_wp.py <dominio> [--csv salida.csv]", file=sys.stderr)
        return 2

    dominio = args[0]
    ruta_csv = None
    if "--csv" in args:
        idx = args.index("--csv")
        if idx + 1 < len(args):
            ruta_csv = args[idx + 1]

    try:
        resultado = run_audit(dominio)
    except ObjetivoInvalido as exc:
        print(f"[objetivo inválido] {exc}", file=sys.stderr)
        return 1
    except AuditoriaError as exc:
        print(f"[error de auditoría] {exc}", file=sys.stderr)
        return 1

    print(json.dumps(resultado, ensure_ascii=False, indent=2))
    if ruta_csv:
        exportar_csv(resultado, ruta_csv)
        print(f"\nCSV escrito en: {ruta_csv}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())