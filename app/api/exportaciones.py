from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.servicios.exportaciones import (
    NOMBRE_PAQUETE_STIX,
    ExportacionNoDisponible,
    leer_paquete_stix,
    leer_reglas_sigma,
)

rutas_exportaciones = APIRouter(prefix="/api/v1/exports")
TIPO_STIX = "application/stix+json"


class ArchivoSigma(BaseModel):
    archivo: str = Field(serialization_alias="filename")
    titulo: str = Field(serialization_alias="title")
    contenido_yaml: str = Field(serialization_alias="yaml")


class RespuestaSigma(BaseModel):
    ioa: list[ArchivoSigma]
    ioc: list[ArchivoSigma]


@rutas_exportaciones.get(
    "/sigma",
    summary="Consultar las reglas Sigma agrupadas en IoA e IoC",
    responses={503: {"description": "Reglas Sigma no disponibles"}},
)
def obtener_reglas_sigma() -> RespuestaSigma:
    try:
        return RespuestaSigma.model_validate(leer_reglas_sigma())
    except ExportacionNoDisponible as error:
        raise HTTPException(status_code=503, detail="Las reglas Sigma no están disponibles.") from error


@rutas_exportaciones.get(
    "/stix",
    summary="Descargar el paquete STIX 2.1 de datos sintéticos",
    response_class=Response,
    responses={
        200: {"content": {TIPO_STIX: {"schema": {"type": "object"}}}},
        503: {"description": "Paquete STIX no disponible"},
    },
)
def descargar_paquete_stix() -> Response:
    try:
        contenido = leer_paquete_stix()
    except ExportacionNoDisponible as error:
        raise HTTPException(status_code=503, detail="El paquete STIX no está disponible.") from error

    return Response(
        content=contenido,
        media_type=f"{TIPO_STIX}; version=2.1",
        headers={
            "Content-Disposition": f'attachment; filename="{NOMBRE_PAQUETE_STIX}"',
            "Cache-Control": "no-store",
        },
    )
