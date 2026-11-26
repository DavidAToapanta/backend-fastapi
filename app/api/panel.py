from datetime import date
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.servicios.panel import (
    MetricasML,
    PanelNoDisponible,
    consultar_mapa_horario,
    consultar_resumen_panel,
)

rutas_panel = APIRouter(prefix="/api/v1")


class ConteoFuente(BaseModel):
    fuente: Literal["FIREWALL", "MEDSYS"] = Field(serialization_alias="source")
    eventos: int = Field(serialization_alias="events")
    ips_sin_puntos: int = Field(serialization_alias="malformedIpEvents")


class ComparacionML(BaseModel):
    genericas: MetricasML | None = Field(serialization_alias="generic")
    dominio: MetricasML | None = Field(serialization_alias="domain")


class RespuestaResumenPanel(BaseModel):
    total_eventos: int = Field(serialization_alias="totalEvents")
    ips_sin_puntos: int = Field(serialization_alias="malformedIpEvents")
    horas: int = Field(serialization_alias="hoursCovered")
    por_fuente: list[ConteoFuente] = Field(serialization_alias="bySource")
    seudonimizacion_registrada: bool | None = Field(
        serialization_alias="pseudonymizationRecorded",
        description="Estado consignado en la auditoría de ingesta de ambas fuentes.",
    )
    ml: ComparacionML


class RespuestaMapaHorario(BaseModel):
    zona_horaria: Literal["UTC"] = Field(serialization_alias="timezone")
    dias: list[date] = Field(serialization_alias="days")
    horas: list[int] = Field(serialization_alias="hours")
    matriz: list[list[int]] = Field(
        serialization_alias="matrix",
        description="Cada fila corresponde a una hora y cada columna a un día.",
    )


@rutas_panel.get(
    "/dashboard/summary",
    summary="Consultar el resumen del panel",
    responses={503: {"description": "Agregados del panel no disponibles"}},
)
def obtener_resumen_panel() -> RespuestaResumenPanel:
    try:
        resumen = consultar_resumen_panel()
    except PanelNoDisponible as error:
        raise HTTPException(status_code=503, detail="Los datos del panel no están disponibles.") from error
    return RespuestaResumenPanel.model_validate(resumen)


@rutas_panel.get(
    "/analytics/hourly-heatmap",
    summary="Consultar el mapa de calor por hora y día",
    responses={503: {"description": "Agregados horarios no disponibles"}},
)
def obtener_mapa_horario() -> RespuestaMapaHorario:
    try:
        mapa = consultar_mapa_horario()
    except PanelNoDisponible as error:
        raise HTTPException(status_code=503, detail="Los datos del mapa horario no están disponibles.") from error
    return RespuestaMapaHorario.model_validate(mapa)
