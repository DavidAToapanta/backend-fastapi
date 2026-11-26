from fastapi import FastAPI

from app.api.campanas import rutas_campanas
from app.api.panel import rutas_panel
from app.api.rutas import rutas

app = FastAPI(title="Mi API", version="0.1.0")
app.include_router(rutas)
app.include_router(rutas_panel)
app.include_router(rutas_campanas)
