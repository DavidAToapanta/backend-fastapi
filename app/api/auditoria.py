from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Response, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, StringConstraints

from app.servicios.auditoria import (
    AuditoriaNoDisponible,
    comprobar_cadena_auditoria,
    listar_eventos_auditoria,
)
from app.servicios.break_glass import (
    CredencialesInvestigacionInvalidas,
    CuentaTecnicaNoEncontrada,
    revelar_cuenta,
)

rutas_auditoria = APIRouter(prefix="/api/v1/audit")


class EventoAuditoria(BaseModel):
    identificador: int = Field(serialization_alias="auditId")
    fecha_ejecucion: datetime | None = Field(serialization_alias="executedAt")
    operacion: str = Field(serialization_alias="operation")
    nombre_dataset: str | None = Field(serialization_alias="datasetName")
    sha256_dataset: str | None = Field(serialization_alias="datasetSha256")
    filas_leidas: int | None = Field(serialization_alias="totalRowsRead")
    filas_guardadas: int | None = Field(serialization_alias="rowsPersisted")
    pii_depurada: bool | None = Field(serialization_alias="piiScrubbed")
    hash_registro: str = Field(serialization_alias="rowHash")


class RespuestaEventos(BaseModel):
    eventos: list[EventoAuditoria] = Field(serialization_alias="events")


class RespuestaVerificacion(BaseModel):
    cadena_integra: bool = Field(validation_alias="intact", serialization_alias="intact")
    filas_verificadas: int = Field(validation_alias="checked_rows", serialization_alias="checkedRows")


@rutas_auditoria.get(
    "/events",
    summary="Listar los registros de auditoría del más reciente al más antiguo",
    responses={503: {"description": "Bitácora no disponible"}},
)
def obtener_eventos_auditoria() -> RespuestaEventos:
    try:
        return RespuestaEventos.model_validate({"eventos": listar_eventos_auditoria()})
    except AuditoriaNoDisponible as error:
        raise HTTPException(status_code=503, detail="La bitácora de auditoría no está disponible.") from error


@rutas_auditoria.get(
    "/verify-chain",
    summary="Verificar la integridad de la cadena de auditoría",
    responses={503: {"description": "Bitácora no disponible"}},
)
def verificar_cadena() -> RespuestaVerificacion:
    try:
        return RespuestaVerificacion.model_validate(comprobar_cadena_auditoria())
    except AuditoriaNoDisponible as error:
        raise HTTPException(status_code=503, detail="La bitácora de auditoría no está disponible.") from error


class SolicitudRevelacion(BaseModel):
    analista: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)] = Field(alias="analystId")
    motivo: Annotated[str, StringConstraints(strip_whitespace=True, min_length=10)] = Field(alias="reason")
    token: str = Field(alias="accountToken", pattern=r"^ACC-[A-Fa-f0-9]{12}$")


class RespuestaRevelacion(BaseModel):
    token: str = Field(serialization_alias="accountToken")
    cuenta_tecnica: str = Field(serialization_alias="technicalAccount")
    identificador_auditoria: int = Field(serialization_alias="auditId")


clave_investigacion = HTTPBearer(auto_error=False, scheme_name="BreakGlassBearer")


@rutas_auditoria.post(
    "/reveal",
    summary="Revelar una cuenta técnica con autorización y auditoría",
    responses={
        401: {"description": "Credenciales inválidas"},
        404: {"description": "Cuenta técnica desconocida"},
        503: {"description": "Servicio de investigación no disponible"},
    },
)
def revelar_cuenta_tecnica(
    solicitud: SolicitudRevelacion,
    respuesta: Response,
    credenciales: Annotated[HTTPAuthorizationCredentials | None, Security(clave_investigacion)],
) -> RespuestaRevelacion:
    token = solicitud.token.upper()
    try:
        cuenta, audit_id = revelar_cuenta(
            solicitud.analista, credenciales.credentials if credenciales else None,
            solicitud.motivo, token,
        )
    except CredencialesInvestigacionInvalidas as error:
        raise HTTPException(
            status_code=401, detail="Credenciales de investigación inválidas.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error
    except CuentaTecnicaNoEncontrada as error:
        raise HTTPException(status_code=404, detail="No se encontró la cuenta técnica.") from error
    except AuditoriaNoDisponible as error:
        raise HTTPException(status_code=503, detail="El modo de investigación no está disponible.") from error

    respuesta.headers["Cache-Control"] = "no-store"
    return RespuestaRevelacion(token=token, cuenta_tecnica=cuenta, identificador_auditoria=audit_id)
