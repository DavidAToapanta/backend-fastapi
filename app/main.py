from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.auditoria import rutas_auditoria
from app.api.campanas import rutas_campanas
from app.api.exportaciones import rutas_exportaciones
from app.api.llm import rutas_llm
from app.api.misp import rutas_misp
from app.api.panel import rutas_panel
from app.api.piloto import rutas_piloto
from app.api.rutas import rutas

app = FastAPI(title="Mi API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Analyst-Id"],
    expose_headers=["Content-Disposition", "X-Audit-Id", "X-Report-SHA256"],
)
app.include_router(rutas)
app.include_router(rutas_panel)
app.include_router(rutas_campanas)
app.include_router(rutas_exportaciones)
app.include_router(rutas_auditoria)
app.include_router(rutas_llm)
app.include_router(rutas_misp)
app.include_router(rutas_piloto)
