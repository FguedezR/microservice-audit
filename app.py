"""
app.py — Microservicio FastAPI que expone `auditor_wp.run_audit` por HTTP.

Pensado para Render free (1 worker uvicorn, 512 MB RAM, CPU compartida). Decisiones
de arquitectura clave:

  1. Autenticación por token compartido (cabecera `X-Auditor-Token`) con comparación
     en tiempo constante (`secrets.compare_digest`) para no filtrar información por
     timing. Sin token válido -> 401. Si el token no está configurado, se rechaza todo
     por defecto (fail-closed).

  2. Semáforo de concurrencia. Cada auditoría abre ~8 hilos internos (ThreadPool del
     motor). Sin límite, varias peticiones simultáneas multiplicarían los hilos y
     agotarían la RAM del contenedor free. Cap configurable (MAX_CONCURRENT_AUDITS).
     Si está saturado devolvemos 429 + Retry-After en vez de encolar y consumir memoria.

  3. Sin CORS. Solo lo invoca WordPress server-to-server (PHP -> Render). El navegador
     nunca llama a este servicio, así que no hay preflight ni cabeceras CORS que exponer.
     Añadir CORS permisivo aquí solo abriría la puerta a que cualquier web dispare auditorías.

  4. Errores de dominio -> códigos HTTP correctos:
       ObjetivoInvalido (SSRF / no resuelve) -> 400
       AuditoriaError   (host caído)         -> 502
       saturación                            -> 429
       inesperado                            -> 500 (con traza en logs, sin filtrarla al cliente)

  5. Endpoint sync (`def`): Starlette lo ejecuta en su threadpool, de modo que el trabajo
     bloqueante de red no congela el event loop. El semáforo se gestiona sobre esos hilos.

Arranque local:
    uvicorn app:app --reload --port 8000
"""

from __future__ import annotations

import logging
import os
import secrets
import threading

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from main import AuditoriaError, MAX_WORKERS_DEFECTO, ObjetivoInvalido, run_audit

# ---------------------------------------------------------------------------
# Configuración por variables de entorno (definidas en Render, ver render.yaml)
# ---------------------------------------------------------------------------
AUDITOR_TOKEN = os.environ.get("AUDITOR_TOKEN", "")
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", MAX_WORKERS_DEFECTO))
MAX_CONCURRENT_AUDITS = int(os.environ.get("MAX_CONCURRENT_AUDITS", "2"))
VERIFY_SSL = os.environ.get("VERIFY_SSL", "false").lower() == "true"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("app")

if not AUDITOR_TOKEN:
    # fail-closed: mejor rechazar todo que quedar abierto por un despiste de config.
    logger.warning("AUDITOR_TOKEN no definido: /audit rechazará TODAS las peticiones.")

app = FastAPI(
    title="Hadock WP Auditor",
    version="1.0.0",
    docs_url=None,   # sin Swagger/Redoc públicos: no queremos exponer el esquema
    redoc_url=None,
    openapi_url=None,
)

# Semáforo global. BoundedSemaphore evita liberar de más por error de programación.
_audit_slots = threading.BoundedSemaphore(MAX_CONCURRENT_AUDITS)


class AuditRequest(BaseModel):
    """Cuerpo de la petición. Aceptamos dominio o URL; el motor lo normaliza."""
    url: str = Field(..., min_length=3, max_length=253,
                     description="Dominio o URL a auditar (ej. 'cliente.com').")


def _token_valido(recibido: str) -> bool:
    """Comparación en tiempo constante; fail-closed si el token del servidor está vacío."""
    if not AUDITOR_TOKEN:
        return False
    return secrets.compare_digest(recibido, AUDITOR_TOKEN)


@app.get("/health")
def health() -> dict[str, str]:
    """
    Health-check ligero para Render (no ejecuta auditoría).
    OJO: si usas un cron externo para mantener el servicio 'caliente' y evitar el
    cold start de 30-60s, ten en cuenta que hacerlo 24/7 consume ~720 h/mes, casi
    todo el cupo gratuito de 750 h. Para un flujo async por email, deja que duerma.
    """
    return {"status": "ok"}


@app.post("/audit")
def audit(body: AuditRequest, x_auditor_token: str = Header(default="")) -> dict:
    """
    Ejecuta la auditoría completa (bloqueante, ~12-15 s paralelizado) y devuelve el JSON.
    Se mantiene la conexión abierta hasta terminar: en Render free NO se puede confiar en
    hilos de fondo (la instancia puede dormirse tras responder y matarlos).
    """
    if not _token_valido(x_auditor_token):
        raise HTTPException(status_code=401, detail="Token inválido o ausente.")

    # No bloqueamos esperando turno: si está saturado, 429 inmediato y que reintente Make.
    if not _audit_slots.acquire(blocking=False):
        raise HTTPException(
            status_code=429,
            detail="Servicio ocupado. Reintenta en unos segundos.",
            headers={"Retry-After": "20"},
        )
    try:
        return run_audit(body.url, max_workers=MAX_WORKERS, verificar_ssl=VERIFY_SSL)
    except ObjetivoInvalido as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except AuditoriaError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception:  # noqa: BLE001 - queremos capturar cualquier fallo del motor
        logger.exception("Error inesperado auditando %s", body.url)
        raise HTTPException(status_code=500, detail="Error interno durante la auditoría.")
    finally:
        _audit_slots.release()