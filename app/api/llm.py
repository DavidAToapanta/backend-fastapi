from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from app.llm.conclusiones import OllamaNoDisponible, generar_conclusiones
from app.servicios.conclusiones import DatosF11NoDisponibles, hechos_para_conclusiones
from app.servicios.panel import PanelNoDisponible

rutas_llm = APIRouter(prefix="/api/v1/llm")


class SolicitudConclusion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    section: Literal["conclusions"]


class RespuestaConclusion(SolicitudConclusion):
    text: str


@rutas_llm.post(
    "/regenerate-section",
    summary="Regenerar las conclusiones en Ollama local",
    responses={503: {"description": "Ollama local o agregados no disponibles"}},
)
def regenerar_seccion(solicitud: SolicitudConclusion) -> RespuestaConclusion:
    try:
        hechos = hechos_para_conclusiones()
        texto = generar_conclusiones(hechos)
    except (PanelNoDisponible, DatosF11NoDisponibles, OllamaNoDisponible) as error:
        raise HTTPException(
            status_code=503,
            detail="No se pudieron regenerar las conclusiones con los servicios locales.",
        ) from error
    return RespuestaConclusion(section=solicitud.section, text=texto)
