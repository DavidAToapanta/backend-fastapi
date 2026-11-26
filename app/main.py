from fastapi import FastAPI

from app.api.rutas import rutas

app = FastAPI(title="Mi API", version="0.1.0")
app.include_router(rutas)
