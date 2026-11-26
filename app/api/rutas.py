from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.servicios.estado import consultar_estado_servicios

rutas = APIRouter()


class RespuestaEstado(BaseModel):
    postgres_disponible: bool = Field(serialization_alias="postgresReady")
    ollama_disponible: bool = Field(serialization_alias="ollamaReady")
    sin_egreso: bool = Field(serialization_alias="zeroEgress")


@rutas.get("/")
def read_root():
    return {"status": "ok", "message": "Backend funcionando"}


@rutas.get("/health")
def health_check():
    return {"status": "healthy"}


@rutas.get("/api/v1/health", summary="Consultar el estado de los servicios")
def consultar_estado() -> RespuestaEstado:
    estado = consultar_estado_servicios()
    return RespuestaEstado(
        postgres_disponible=estado.postgres_disponible,
        ollama_disponible=estado.ollama_disponible,
        sin_egreso=estado.sin_egreso,
    )
