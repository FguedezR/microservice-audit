# Auditor WP — Microservicio (Hadock)

Microservicio de auditoría de seguridad WordPress. Recibe un dominio y devuelve
una nota de seguridad + hallazgos en JSON. Diseñado para:

- **WordPress** lo llama en `modo="rapido"` → nota inmediata en pantalla.
- **Make.com** lo llama en `modo="completo"` → datos para generar el PDF y el email.

## Estructura

```
main.py          API FastAPI (/audit protegido, /health)
auditor_core.py  Motor de auditoría concurrente (sin I/O de disco)
checks_data.py   Definición de checks y categorías (edita aquí para añadir más)
requirements.txt Dependencias
render.yaml      Configuración de despliegue en Render
```

## Ejecutar en local

```bash
pip install -r requirements.txt
export API_SECRET="pon-aqui-un-secreto-largo"
uvicorn main:app --reload
# Prueba:
curl -X POST http://localhost:8000/audit \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: pon-aqui-un-secreto-largo" \
  -d '{"dominio":"previas.hadock.es","modo":"rapido"}'
```

## Roadmap de despliegue

1. Subir este repo a GitHub.
2. Render → New Web Service → conectar repo. Definir `API_SECRET` en Environment.
3. Copiar la URL pública (`https://xxx.onrender.com`).
4. Make.com → escenario Webhook → HTTP → tu URL (`modo="completo"`) → PDF → Email.
5. WordPress → añadir la llamada al microservicio en el endpoint REST existente.
6. Probar en `https://previas.hadock.es/test/`.

## Añadir más comprobaciones

Pega las entradas de tu `endpoints_maestros` original en `checks_data.py`
(`ENDPOINTS_MAESTROS`). El formato de dict es idéntico. Marca `"rapido": True`
solo en las 2-3 más críticas que quieras mostrar en pantalla.
