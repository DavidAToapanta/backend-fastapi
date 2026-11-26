import re
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, IPvAnyAddress, ValidationError, ValidationInfo, field_validator

from app.servicios.campanas import (
    ESCENARIOS_IPE,
    CampanasNoDisponibles,
    consultar_campanas,
    consultar_linea_tiempo,
)

rutas_campanas = APIRouter(prefix="/api/v1/campaigns")


def normalizar_token_enmascarado(valor: object, prefijo: str) -> str | None:
    if isinstance(valor, str) and re.fullmatch(rf"{prefijo}-[A-Fa-f0-9]{{12}}", valor):
        return valor
    return None


class IndicadoresCompromiso(BaseModel):
    puertos: list[int] = Field(default_factory=list, alias="ports")
    ips_origen: list[IPvAnyAddress] = Field(
        default_factory=list, validation_alias="src_ips", serialization_alias="sourceIps"
    )
    ips_destino: list[IPvAnyAddress] = Field(
        default_factory=list, validation_alias="dst_ips", serialization_alias="destinationIps"
    )
    actores: list[str] = Field(
        default_factory=list, validation_alias="actor_tokens", serialization_alias="actorTokens"
    )
    cuentas: list[str] = Field(
        default_factory=list, validation_alias="account_tokens", serialization_alias="accountTokens"
    )

    @field_validator("actores", "cuentas", mode="before")
    @classmethod
    def conservar_tokens_enmascarados(cls, valores: object, info: ValidationInfo) -> list[str]:
        if not isinstance(valores, list):
            return []
        prefijo = "USR" if info.field_name == "actores" else "ACC"
        return [token for valor in valores if (token := normalizar_token_enmascarado(valor, prefijo)) is not None]


class Campana(BaseModel):
    codigo: str = Field(serialization_alias="campaignCode")
    titulo: str | None = Field(serialization_alias="title")
    tipo_adversario: str | None = Field(serialization_alias="adversaryType")
    severidad: str | None = Field(serialization_alias="severity")
    calificacion_admiralty: str | None = Field(serialization_alias="admiraltyRating")
    puntaje_anomalia: float | None = Field(
        serialization_alias="anomalyScore",
        description="Puntaje del artefacto de aprendizaje automático del Rol 2.",
    )
    eventos: int | None = Field(serialization_alias="eventCount")
    primera_observacion: datetime | None = Field(serialization_alias="firstSeen")
    ultima_observacion: datetime | None = Field(serialization_alias="lastSeen")
    tecnicas_mitre: list[str] = Field(serialization_alias="mitreTechniques")
    iocs: IndicadoresCompromiso
    ioas: list[str]


class EscenarioIPE(BaseModel):
    codigo: str = Field(serialization_alias="code")
    nombre: str = Field(serialization_alias="name")
    campanas: list[str] = Field(serialization_alias="campaignCodes")
    descripcion: str = Field(serialization_alias="description")
    hipotesis: str | None = Field(serialization_alias="hypothesis")


class RespuestaCampanas(BaseModel):
    campanas: list[Campana] = Field(serialization_alias="campaigns")
    escenarios_ipe: list[EscenarioIPE] = Field(serialization_alias="ipeScenarios")


class EventoLineaTiempo(BaseModel):
    id: int
    fecha: datetime = Field(serialization_alias="timestamp")
    fuente: Literal["FIREWALL", "MEDSYS"] = Field(serialization_alias="source")
    actor: str | None = Field(serialization_alias="actorToken")
    cuenta: str | None = Field(serialization_alias="accountToken")
    ip_origen: IPvAnyAddress | None = Field(serialization_alias="sourceIp")
    ip_destino: IPvAnyAddress | None = Field(serialization_alias="destinationIp")
    puerto_destino: int | None = Field(serialization_alias="destinationPort")
    resumen: str | None = Field(serialization_alias="summary")
    ajuste_de_reloj: bool = Field(serialization_alias="clockSkewAdjusted")

    @field_validator("actor", "cuenta", mode="before")
    @classmethod
    def conservar_token_enmascarado(cls, valor: object, info: ValidationInfo) -> str | None:
        return normalizar_token_enmascarado(valor, "USR" if info.field_name == "actor" else "ACC")


class RespuestaLineaTiempo(BaseModel):
    codigo: str = Field(serialization_alias="campaignCode")
    eventos: list[EventoLineaTiempo] = Field(serialization_alias="events")


@rutas_campanas.get(
    "",
    summary="Listar las campañas del ejercicio",
    responses={503: {"description": "Catálogo de campañas no disponible"}},
)
def obtener_campanas() -> RespuestaCampanas:
    try:
        return RespuestaCampanas.model_validate({
            "campanas": consultar_campanas(),
            "escenarios_ipe": ESCENARIOS_IPE,
        })
    except (CampanasNoDisponibles, ValidationError) as error:
        raise HTTPException(status_code=503, detail="Las campañas no están disponibles.") from error


@rutas_campanas.get(
    "/{code}/timeline",
    summary="Consultar la línea de tiempo de una campaña",
    responses={
        404: {"description": "Campaña desconocida"},
        503: {"description": "Línea de tiempo no disponible"},
    },
)
def obtener_linea_tiempo(code: str) -> RespuestaLineaTiempo:
    try:
        eventos = consultar_linea_tiempo(code)
        if eventos is None:
            raise HTTPException(status_code=404, detail="No se encontró la campaña.")
        return RespuestaLineaTiempo.model_validate({"codigo": code, "eventos": eventos})
    except (CampanasNoDisponibles, ValidationError) as error:
        raise HTTPException(status_code=503, detail="La línea de tiempo no está disponible.") from error
