import json
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.integraciones.misp_estado import estado_verificado
from app.servicios.exportaciones import carpeta_exportaciones

rutas_misp = APIRouter(prefix="/api/v1/misp")


class EstadoMISP(BaseModel):
    lastVerifiedAt: datetime
    eventCount: int
    distribution: str
    exports: list[str]


@rutas_misp.get("/estado", summary="Última carga local verificada en MISP",
                responses={503: {"description": "Resumen de verificación no disponible"}})
def estado_misp() -> EstadoMISP:
    ruta = carpeta_exportaciones() / "misp" / "misp_publicacion.json"
    try:
        if ruta.is_symlink() or ruta.parent.is_symlink():
            raise ValueError("El resumen debe ser local.")
        resumen = json.loads(ruta.read_text(encoding="utf-8"))
        return EstadoMISP(**estado_verificado(resumen))
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise HTTPException(503, "La última carga verificada de MISP no está disponible.") from error
