from typing import Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field, model_validator

from app.cti_exports.pdf_compiler import Audiencia
from app.servicios.auditoria import AuditoriaNoDisponible
from app.servicios.campanas import CampanasNoDisponibles
from app.servicios.conclusiones import DatosF11NoDisponibles
from app.servicios.estado import consultar_estado_servicios
from app.servicios.exportaciones import ExportacionNoDisponible
from app.servicios.panel import PanelNoDisponible
from app.servicios.reporte_f11 import generar_reporte_auditado

rutas = APIRouter()


class SolicitudReporte(BaseModel):
    audience: Audiencia = "technical"
    format: Literal["F-11", "EJECUTIVO_MEDICO"] | None = None
    summary: str | None = Field(default=None, description="Nota opcional que se imprime solo en el F-11.")

    @model_validator(mode="after")
    def validar_formato(self):
        esperado = "F-11" if self.audience == "technical" else "EJECUTIVO_MEDICO"
        if self.format is not None and self.format != esperado:
            raise ValueError(f"El formato para {self.audience} debe ser {esperado}.")
        return self


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


@rutas.post(
    "/api/v1/reports/generate-pdf",
    summary="Descargar el reporte técnico o médico auditado",
    response_class=Response,
    responses={
        200: {"content": {"application/pdf": {"schema": {"type": "string", "format": "binary"}}}},
        503: {"description": "Evidencias, caché, auditoría o motor PDF no disponibles"},
    },
)
def descargar_reporte_f11(solicitud: SolicitudReporte | None = None) -> Response:
    opciones = solicitud or SolicitudReporte()
    try:
        contenido, nombre, audit_id, sha256 = generar_reporte_auditado(opciones.audience, opciones.summary)
    except (DatosF11NoDisponibles, PanelNoDisponible, CampanasNoDisponibles, ExportacionNoDisponible,
            AuditoriaNoDisponible, ImportError, OSError, KeyError, ValueError) as error:
        raise HTTPException(
            status_code=503, detail="No se pudo generar y auditar el reporte solicitado.",
        ) from error

    return Response(
        content=contenido,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{nombre}"',
            "Cache-Control": "no-store",
            "X-Audit-Id": str(audit_id),
            "X-Report-SHA256": sha256,
        },
    )
