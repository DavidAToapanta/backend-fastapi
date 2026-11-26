from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.cti_exports.pdf_compiler import preparar_datos_de_ejemplo, renderizar_pdf
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


@rutas.post(
    "/api/v1/reports/generate-pdf",
    summary="Descargar el borrador del reporte F-11",
    response_class=Response,
    responses={
        200: {"content": {"application/pdf": {"schema": {"type": "string", "format": "binary"}}}},
        503: {"description": "Motor PDF no disponible"},
    },
)
def descargar_borrador_f11() -> Response:
    try:
        contenido = renderizar_pdf(preparar_datos_de_ejemplo())
    except (ImportError, OSError) as error:
        raise HTTPException(status_code=503, detail="El motor de PDF no está disponible.") from error

    return Response(
        content=contenido,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="Reporte_CTI_F11_AegisHealth_borrador.pdf"',
            "Cache-Control": "no-store",
        },
    )
