# -*- coding: utf-8 -*-
"""
auditor_core.py
---------------
Motor de auditoría de seguridad WordPress refactorizado a partir de
auditor_wp_v5.py. Cambios clave frente al original:

  * SIN input()/print()/colores ANSI/CSV en disco  -> apto para servicio web.
  * Peticiones CONCURRENTES (ThreadPoolExecutor)     -> 30 checks en serie
    (peor caso ~2-3 min) pasan a ~15-25s en modo completo, ~2-5s en rápido.
  * Devuelve un dict JSON-serializable con nota, categorías y hallazgos.
  * Conserva FIELMENTE tu lógica: calibración soft-404, evaluación por `tipo`,
    y nota global capada a 2.0 si hay cualquier hallazgo Crítico.

Uso:
    from auditor_core import run_audit
    resultado = run_audit("cliente.com", modo="rapido")   # o "completo"
"""

import concurrent.futures
import re

import requests

from checks_data import (
    ENDPOINTS_MAESTROS,
    CABECERAS_SEGURIDAD,
    MAPEO_CATEGORIAS,
    CATEGORIA_POR_DEFECTO,
)

_UA = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
}

# Timeouts cortos: cada check es independiente y corre en paralelo.
_TIMEOUT = 5
_MAX_WORKERS = 10
_MAX_READ = 150 * 1024        # leemos como mucho 150 KB para inspección de texto
_GIGANTE = 3 * 1024 * 1024    # >3 MB => archivo real (no soft-404)


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------
def limpiar_dominio(raw: str) -> str:
    d = (raw or "").strip().lower()
    d = re.sub(r"^https?://", "", d)
    return d.rstrip("/")


def _res(nombre, gravedad, puntos, url, imp, estado, desc):
    return {
        "nombre": nombre, "gravedad": gravedad, "puntos": puntos,
        "url": url, "imp": imp, "estado": estado, "desc": desc,
    }


# ---------------------------------------------------------------------------
# Checks "de setup" (derivan de 2-3 peticiones base)
# ---------------------------------------------------------------------------
def _calibrar_soft404(base_https):
    """Pide un archivo inexistente para detectar servidores que responden 200 a todo."""
    try:
        r = requests.get(
            f"{base_https}/archivo_inexistente_de_prueba_9988.php",
            headers=_UA, timeout=6, verify=False,
        )
        return r.status_code, len(r.text)
    except Exception:
        return 404, 0


def _check_ssl(base_http):
    item = dict(nombre="Ausencia de Redirección SSL forzosa (HTTP a HTTPS)",
                gravedad="Baja", puntos=2, url=base_http,
                imp="En HTTP sin cifrar un atacante puede interceptar contraseñas en texto plano.")
    try:
        r = requests.get(base_http, headers=_UA, timeout=6, verify=False)
        if not r.url.startswith("https://"):
            return _res(**item, estado="Error",
                        desc="La web permite navegación HTTP sin redirigir automáticamente a HTTPS.")
        return _res(**item, estado="Correcto",
                    desc="El sitio fuerza correctamente todo su tráfico hacia HTTPS.")
    except Exception:
        return _res(**item, estado="Error",
                    desc="Fallo al determinar el comportamiento de redirección HTTP.")


def _checks_desde_raiz(root_resp, rapido):
    """Cabeceras de seguridad, fuga de Server/X-Powered-By/PHP y meta generator."""
    salida = []
    if root_resp is None:
        return salida
    headers = root_resp.headers
    html = root_resp.text or ""

    for cab, (nombre, desc, imp, grav, pts, es_rapido) in CABECERAS_SEGURIDAD.items():
        if rapido and not es_rapido:
            continue
        if cab not in headers:
            salida.append(_res(nombre, grav, pts, "Cabeceras HTTP", imp, "Error", desc))
        else:
            salida.append(_res(nombre, grav, pts, "Cabeceras HTTP", imp, "Correcto",
                               f"La cabecera {cab} está activa en el servidor."))

    if not rapido:
        srv = headers.get("Server", "")
        salida.append(_res(
            "Fuga de versión del Servidor Web (Cabecera Server)", "Media", 4, "Cabeceras HTTP",
            "Da pistas directas a atacantes para lanzar exploits de esa versión exacta.",
            "Error" if any(c.isdigit() for c in srv) else "Correcto",
            f"La cabecera 'Server' expone versiones explícitas: {srv}" if any(c.isdigit() for c in srv)
            else "El servidor mantiene oculta su versión específica."))

        xpb = headers.get("X-Powered-By", "")
        salida.append(_res(
            "Fuga de tecnología / lenguaje backend (Cabecera X-Powered-By)", "Baja", 2, "Cabeceras HTTP",
            "Muestra las tecnologías del backend facilitando el reconocimiento pasivo.",
            "Error" if xpb else "Correcto",
            f"La cabecera X-Powered-By expone el backend: {xpb}" if xpb
            else "No se expone la tecnología del backend."))

        gen = re.search(r'<meta name="generator" content="WordPress\s?([^"]+)"', html)
        salida.append(_res(
            'Etiqueta Meta "generator" expuesta en Código Fuente HTML', "Media", 4, "Código Fuente HTML",
            "Si la versión instalada tiene un bug público, el sitio se vuelve blanco fácil.",
            "Error" if gen else "Correcto",
            f"El HTML filtra la versión de WordPress: {gen.group(1)}" if gen
            else "No se localiza la versión de WordPress en las meta etiquetas."))

    return salida


def _check_robots(base_https):
    item = dict(nombre="Configuración e higiene de /robots.txt", gravedad="Baja", puntos=2,
                url=f"{base_https}/robots.txt",
                imp="robots.txt debe existir y restringir rutas administrativas.")
    try:
        r = requests.get(f"{base_https}/robots.txt", headers=_UA, timeout=5, verify=False)
        if r.status_code == 200 and "disallow" in r.text.lower():
            if "/wp-admin/" in r.text:
                return _res(**item, estado="Correcto",
                            desc="robots.txt existe y restringe rutas críticas como /wp-admin/.")
            return _res(**item, estado="Error",
                        desc="robots.txt existe pero no declara restricciones de administración.")
        return _res(**item, estado="Error", desc="robots.txt no existe o está vacío.")
    except Exception:
        return _res(**item, estado="Error", desc="Error al conectar o localizar robots.txt.")


# ---------------------------------------------------------------------------
# Evaluación de un endpoint de la lista maestra (fiel a la lógica por `tipo`)
# ---------------------------------------------------------------------------
def _check_endpoint(ep, base_https, baseline):
    baseline_status, baseline_len = baseline
    url = f"{base_https}{ep['path']}"
    base = dict(nombre=ep["nombre"], gravedad=ep["gravedad"], puntos=ep["puntos"],
                url=url, imp=ep["imp"])
    try:
        evitar_redir = ep["tipo"] in ("admin", "author")
        r = requests.get(url, headers=_UA, timeout=4, verify=False,
                         allow_redirects=not evitar_redir, stream=True)

        vulnerable, detalle = False, ""
        content_length = int(r.headers.get("Content-Length", 0) or 0)
        texto, gigante, leidos = "", False, b""

        if r.status_code == 200:
            if content_length > _GIGANTE:
                gigante = True
            else:
                for chunk in r.iter_content(chunk_size=4096):
                    leidos += chunk
                    if len(leidos) > _MAX_READ:
                        gigante = True
                        break
                texto = leidos.decode("utf-8", errors="ignore")

        tipo = ep["tipo"]
        if tipo == "admin":
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302) and ("wp-login" in loc or "wp-admin" in loc):
                vulnerable, detalle = True, f"La ruta redirige exponiendo el login en: {loc}"
            elif r.status_code == 200 and ("user_login" in texto or "wp-submit" in texto):
                vulnerable, detalle = True, "La URL carga directamente el formulario de login."

        elif tipo == "author":
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302) and "author/" in loc:
                vulnerable, detalle = True, f"El parámetro desvela el nombre de usuario en: {loc}"

        elif tipo == "xmlrpc":
            if r.status_code in (200, 405) and "xml-rpc" in texto.lower():
                vulnerable, detalle = True, "XML-RPC operativo: 'accepts POST requests only'."

        elif tipo == "json_users":
            if r.status_code == 200 and not gigante and "slug" in texto:
                try:
                    js = r.json()
                    if (isinstance(js, list) and js) or (isinstance(js, dict) and "slug" in js):
                        vulnerable, detalle = True, "La API REST devuelve los nombres de usuario en texto plano."
                except ValueError:
                    pass

        elif tipo == "cron":
            if r.status_code == 200:
                vulnerable, detalle = True, "El archivo está expuesto públicamente (200 OK)."

        else:  # "status" y "texto"
            if r.status_code == 200:
                vulnerable, detalle = True, ep["desc"]
                if gigante:
                    detalle = f"{ep['desc']} (Fichero masivo detectado)."
                else:
                    longitud = content_length if content_length > 0 else len(leidos)
                    if baseline_status == 200 and abs(longitud - baseline_len) < 150:
                        vulnerable = False  # soft-404: el server responde 200 a todo
                    if vulnerable and tipo == "texto" and ep.get("match", "") not in texto:
                        vulnerable = False
        r.close()

        if vulnerable:
            return _res(**base, estado="Error", desc=detalle or ep["desc"])
        return _res(**base, estado="Correcto",
                    desc="Ruta protegida, inaccesible o camuflada por el servidor.")
    except Exception:
        return _res(**base, estado="Correcto",
                    desc="No accesible o tiempo de respuesta excedido.")


def _enumerar_plugins(base_https):
    """Extrae slugs de plugins desde los namespaces de la REST API y comprueba
    directorios abiertos. Solo en modo completo."""
    resultados = []
    slugs = set()
    try:
        r = requests.get(f"{base_https}/wp-json", headers=_UA, timeout=5,
                         verify=False, allow_redirects=True)
        if r.status_code == 200:
            for ns in r.json().get("namespaces", []):
                if ns in ("wp/v2", "oembed/1.0", "wp-site-health/v1", "akismet/v1"):
                    continue
                if "/" in ns:
                    slug = ns.split("/")[0]
                    if slug and not slug.startswith("wp"):
                        slugs.add(slug)
    except Exception:
        return resultados

    def _dir(slug):
        url = f"{base_https}/wp-content/plugins/{slug}/"
        item = dict(nombre=f"Listado de directorio abierto en plugin: {slug}",
                    gravedad="Alta", puntos=7, url=url,
                    imp="Riesgo de ingeniería inversa y descubrimiento de archivos sensibles.")
        try:
            rp = requests.get(url, headers=_UA, timeout=5, verify=False, allow_redirects=False)
            if rp.status_code == 200 and "index of" in rp.text.lower():
                return _res(**item, estado="Error", desc=f"El directorio del plugin '{slug}' es navegable.")
            return _res(**item, estado="Correcto", desc="El directorio del plugin no es navegable.")
        except Exception:
            return _res(**item, estado="Correcto", desc="No accesible.")

    if slugs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            resultados = list(pool.map(_dir, slugs))
    return resultados


# ---------------------------------------------------------------------------
# Scoring (fiel al original)
# ---------------------------------------------------------------------------
def _clasificar_y_puntuar(resultados):
    por_categoria = {c: [] for c in MAPEO_CATEGORIAS}
    for item in resultados:
        nombre = item["nombre"]
        destino = CATEGORIA_POR_DEFECTO
        if "Listado de directorio abierto en plugin:" in nombre:
            destino = "6. EXPOSICIÓN DE REPOSITORIOS, REGISTROS DE ERROR Y DIRECTORIOS"
        else:
            for cat, vulns in MAPEO_CATEGORIAS.items():
                if nombre in vulns:
                    destino = cat
                    break
        por_categoria.setdefault(destino, []).append(item)

    total_max = sum(i["puntos"] for i in resultados)
    total_pen = sum(i["puntos"] for i in resultados if i["estado"] == "Error")
    nota = round(10.0 * (1.0 - (total_pen / total_max)), 1) if total_max > 0 else 10.0

    critico = any(i["estado"] == "Error" and i["gravedad"] == "Crítica" for i in resultados)
    if critico:
        nota = min(nota, 2.0)

    if nota >= 8.5:
        nivel = "Excelente (Riesgo Bajo)"
    elif nota >= 6.0:
        nivel = "Aceptable (Riesgo Medio)"
    elif nota >= 3.5:
        nivel = "Inseguro (Riesgo Alto)"
    else:
        nivel = "Crítico (Peligro de Secuestro)"

    puntuacion_seccion = {}
    for cat, items in por_categoria.items():
        mx = sum(i["puntos"] for i in items)
        pen = sum(i["puntos"] for i in items if i["estado"] == "Error")
        puntuacion_seccion[cat] = round(10.0 * (1.0 - pen / mx), 1) if mx > 0 else 10.0

    return {
        "nota_final": nota,
        "nivel_seguridad": nivel,
        "nota_capada_por_critico": critico,
        "puntuacion_por_seccion": puntuacion_seccion,
        "hallazgos": resultados,
        "errores": [i for i in resultados if i["estado"] == "Error"],
    }


# ---------------------------------------------------------------------------
# Orquestador principal
# ---------------------------------------------------------------------------
def run_audit(dominio_input: str, modo: str = "rapido") -> dict:
    dominio = limpiar_dominio(dominio_input)
    if not dominio or "." not in dominio:
        return {"error": "Dominio no válido", "dominio": dominio_input}

    base_https = f"https://{dominio}"
    base_http = f"http://{dominio}"

    # 1) Peticiones base (calibración + raíz) — secuenciales, son la referencia.
    baseline = _calibrar_soft404(base_https)
    try:
        root_resp = requests.get(base_https, headers=_UA, timeout=6, verify=False,
                                 allow_redirects=True)
    except Exception:
        root_resp = None

    # 2) Selección de endpoints según modo.
    if modo == "rapido":
        endpoints = [e for e in ENDPOINTS_MAESTROS if e.get("rapido")]
    else:
        endpoints = ENDPOINTS_MAESTROS

    resultados = []
    resultados += _checks_desde_raiz(root_resp, rapido=(modo == "rapido"))
    resultados.append(_check_ssl(base_http))
    resultados.append(_check_robots(base_https))

    # 3) Endpoints en paralelo (el grueso del trabajo).
    with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futuros = [pool.submit(_check_endpoint, ep, base_https, baseline) for ep in endpoints]
        for f in concurrent.futures.as_completed(futuros):
            resultados.append(f.result())

    # 4) Enumeración de plugins (solo completo).
    if modo != "rapido":
        resultados += _enumerar_plugins(base_https)

    salida = _clasificar_y_puntuar(resultados)
    salida.update({"dominio": dominio, "modo": modo})
    return salida


if __name__ == "__main__":
    import json
    import sys
    dom = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    md = sys.argv[2] if len(sys.argv) > 2 else "rapido"
    print(json.dumps(run_audit(dom, md), indent=2, ensure_ascii=False))
