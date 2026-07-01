# -*- coding: utf-8 -*-
"""
main.py
-------
Microservicio FastAPI que expone la auditoría de seguridad WordPress.
Lo llaman, server-to-server:
    * WordPress (modo="rapido")   -> nota inmediata en pantalla
    * Make.com  (modo="completo") -> datos para el PDF y el email

Seguridad y rendimiento:
    * Cabecera X-Api-Key obligatoria (secreto compartido con WP y Make).
    * Rate-limit por IP en memoria.
    * Caché por (dominio, modo) con TTL para no repetir escaneos.
    * /health para monitorización y para "despertar" el servicio en Render.

Variables de entorno:
    API_SECRET       (obligatoria)  secreto compartido
    RATE_LIMIT_MAX   (opcional, def 20)   peticiones por ventana
    RATE_LIMIT_WINDOW(opcional, def 3600) ventana en segundos
    CACHE_TTL        (opcional, def 3600) validez de la caché en segundos
"""

import os
import time
import threading

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from auditor_core import run_audit, limpiar_dominio

API_SECRET = os.environ.get("API_SECRET", "")
RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", "20"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "3600"))
CACHE_TTL = int(os.environ.get("CACHE_TTL", "3600"))

app = FastAPI(title="Auditor WP - Hadock", version="1.0.0")

_lock = threading.Lock()
_rate: dict[str, list[float]] = {}     # ip -> [timestamps]
_cache: dict[str, tuple[float, dict]] = {}  # "dominio|modo" -> (expira_en, resultado)


class AuditRequest(BaseModel):
    dominio: str = Field(..., min_length=3, max_length=253)
    modo: str = Field("rapido", pattern="^(rapido|completo)$")


def _client_ip(request: Request) -> str:
    # Render/proxies ponen la IP real en X-Forwarded-For.
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def _check_rate_limit(ip: str):
    ahora = time.time()
    with _lock:
        marcas = [t for t in _rate.get(ip, []) if ahora - t < RATE_LIMIT_WINDOW]
        if len(marcas) >= RATE_LIMIT_MAX:
            raise HTTPException(status_code=429, detail="Demasiadas solicitudes. Espera un rato.")
        marcas.append(ahora)
        _rate[ip] = marcas


def _cache_get(clave: str):
    ahora = time.time()
    with _lock:
        entrada = _cache.get(clave)
        if entrada and entrada[0] > ahora:
            return entrada[1]
        if entrada:
            _cache.pop(clave, None)
    return None


def _cache_set(clave: str, valor: dict):
    with _lock:
        _cache[clave] = (time.time() + CACHE_TTL, valor)


@app.get("/health")
def health():
    """Ping ligero: monitorización y despertar del servicio (evita cold start en la petición real)."""
    return {"status": "ok", "service": "auditor-wp-hadock"}


@app.post("/audit")
def audit(
    payload: AuditRequest,
    request: Request,
    x_api_key: str | None = Header(default=None),
):
    # 1) Autenticación por secreto compartido.
    if not API_SECRET or x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail="No autorizado")

    # 2) Rate-limit por IP.
    _check_rate_limit(_client_ip(request))

    # 3) Normalización + caché.
    dominio = limpiar_dominio(payload.dominio)
    if not dominio or "." not in dominio:
        raise HTTPException(status_code=400, detail="Dominio no válido")

    clave = f"{dominio}|{payload.modo}"
    cacheado = _cache_get(clave)
    if cacheado is not None:
        return {**cacheado, "cache": True}

    # 4) Auditoría (concurrente dentro de run_audit).
    resultado = run_audit(dominio, modo=payload.modo)
    _cache_set(clave, resultado)
    return {**resultado, "cache": False}
