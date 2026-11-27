from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Response, Security
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, StringConstraints
from psycopg import Error as ErrorPostgres

from app.core.conexion_postgres import conectar_postgres
from app.servicios import piloto
from app.servicios.auditoria import AuditoriaNoDisponible
from app.servicios.break_glass import CredencialesInvestigacionInvalidas, autorizar_analista


class RutaPiloto(APIRoute):
    def get_route_handler(self):
        atender = super().get_route_handler()

        async def atender_piloto(request):
            try:
                return await atender(request)
            except RequestValidationError as error:
                # Pydantic incluye el valor recibido en el error por defecto.
                raise HTTPException(422, "Revisá los campos de la solicitud.") from error
            except (piloto.SesionInvalida, CredencialesInvestigacionInvalidas) as error:
                raise HTTPException(401, "Credencial de demo inválida.", headers={"WWW-Authenticate": "Bearer"}) from error
            except piloto.ReporteSinIndicadores as error:
                raise HTTPException(422, "El mensaje debe contener al menos un indicador.") from error
            except piloto.CasoNoEncontrado as error:
                raise HTTPException(404, "No se encontró el caso.") from error
            except piloto.CasoResuelto as error:
                raise HTTPException(409, "El caso ya tiene una decisión.") from error
            except (piloto.PilotoNoConfigurado, AuditoriaNoDisponible, ErrorPostgres) as error:
                raise HTTPException(503, "El piloto no está disponible.") from error

        return atender_piloto


rutas_piloto = APIRouter(prefix="/api/v1", tags=["Centinela y Guardián"], route_class=RutaPiloto)
sesion_bearer = HTTPBearer(auto_error=False, scheme_name="SesionPilotoBearer")
analista_bearer = HTTPBearer(auto_error=False, scheme_name="AnalistaPilotoBearer")
SesionBearer = Annotated[HTTPAuthorizationCredentials | None, Security(sesion_bearer)]


def autenticar_analista(
    credenciales: Annotated[HTTPAuthorizationCredentials | None, Security(analista_bearer)],
    analista: Annotated[str, Header(alias="X-Analyst-Id", max_length=100)] = "",
) -> str:
    analista = analista.strip()
    autorizar_analista(analista, credenciales.credentials if credenciales else None, variable="PILOTO_ANALISTAS_JSON")
    return analista


Analista = Annotated[str, Depends(autenticar_analista)]
Provincia = Literal[
    "Azuay", "Bolívar", "Cañar", "Carchi", "Chimborazo", "Cotopaxi", "El Oro", "Esmeraldas",
    "Galápagos", "Guayas", "Imbabura", "Loja", "Los Ríos", "Manabí", "Morona Santiago",
    "Napo", "Orellana", "Pastaza", "Pichincha", "Santa Elena", "Santo Domingo de los Tsáchilas",
    "Sucumbíos", "Tungurahua", "Zamora Chinchipe",
]


class SolicitudReporte(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]
    province: Provincia


class Reporte(BaseModel):
    reportId: UUID
    province: Provincia
    receivedAt: datetime
    indicators: dict[str, list[str]]
    summary: str


class CampanaCentinela(BaseModel):
    campaignId: str
    reportCount: int
    byProvince: dict[str, int]
    domains: list[str]
    status: Literal["EN_OBSERVACION", "AVISO_A_AFILIADOS"]


class SolicitudDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["CONFIRMAR", "DESCARTAR"]
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=10, max_length=300)]


class Paso(BaseModel):
    eventId: str
    timestamp: datetime
    event: str
    channel: str


class Evidencia(BaseModel):
    alertId: str
    rule: str
    affiliate: str | None
    employee: str | None
    affectedAffiliates: list[str]
    severity: str
    confidence: str
    action: str
    explanation: str
    timeline: list[Paso]
    durationMinutes: int | None
    verificationChannel: str | None
    phishingLink: str | None
    phishingReportId: UUID | None


class Alerta(Evidencia):
    caseId: UUID | None


class Caso(BaseModel):
    caseId: UUID
    status: Literal["EN_REVISION", "CONFIRMADO", "DESCARTADO"]
    operationStatus: Literal["EN_REVISION", "RETENIDA", "LIBERADA"]
    createdAt: datetime
    evidence: Evidencia
    auditId: int | None
    decidedBy: str | None
    decisionReason: str | None
    simulated: Literal[True]


class Evaluacion(BaseModel):
    alerts: list[Alerta]
    cases: list[Caso]
    evaluatedEvents: int
    ignoredEvents: int


@rutas_piloto.post("/centinela/reportes", status_code=201, responses={
    200: {"model": Reporte, "description": "Reporte duplicado"},
    401: {"description": "Sesión inválida"}, 503: {"description": "Piloto no disponible"},
})
def recibir_reporte(solicitud: SolicitudReporte, respuesta: Response, credenciales: SesionBearer) -> Reporte:
    nuevo, reporte = piloto.registrar_reporte(
        solicitud.text, solicitud.province, credenciales.credentials if credenciales else None,
    )
    if not nuevo:
        respuesta.status_code = 200
    return Reporte.model_validate(reporte)


@rutas_piloto.get("/centinela/campanas", responses={503: {"description": "Piloto no disponible"}})
def consultar_campanas() -> list[CampanaCentinela]:
    with conectar_postgres() as conn:
        campanas, _ = piloto.leer_campanas(conn)
    return campanas


@rutas_piloto.post("/guardian/evaluar")
def evaluar(analista: Analista) -> Evaluacion:
    return Evaluacion.model_validate(piloto.evaluar_piloto())


@rutas_piloto.get("/guardian/casos")
def listar_casos(analista: Analista) -> list[Caso]:
    return piloto.consultar_casos()


@rutas_piloto.get("/guardian/casos/{case_id}")
def obtener_caso(case_id: UUID, analista: Analista) -> Caso:
    return Caso.model_validate(piloto.consultar_casos(case_id))


@rutas_piloto.post("/guardian/casos/{case_id}/decision")
def resolver_caso(case_id: UUID, solicitud: SolicitudDecision, analista: Analista) -> Caso:
    return Caso.model_validate(piloto.decidir_caso(case_id, solicitud.decision, solicitud.reason, analista))
