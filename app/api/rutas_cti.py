"""Rutas de inteligencia de amenazas (resultados del Rol 2). Respuestas en camelCase."""
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.servicios import inteligencia as cti

rutas_cti = APIRouter(prefix="/api/v1", tags=["Inteligencia de amenazas"])


def _seguro(funcion, *args):
    try:
        return funcion(*args)
    except cti.DatosNoDisponibles as error:
        raise HTTPException(status_code=503, detail=str(error)) from None


@rutas_cti.get("/dashboard/summary", summary="KPIs: calidad, detección, campañas y anticipación")
def resumen():
    return cti.a_camel(_seguro(cti.resumen))


@rutas_cti.get("/campaigns", summary="Campañas detectadas con MITRE ATT&CK y siguiente fase probable")
def campanas():
    return cti.a_camel({"campaigns": _seguro(cti.listar_campanas)})


@rutas_cti.get("/campaigns/{codigo}", summary="Detalle de una campaña con evidencia y pronóstico")
def campana(codigo: str):
    c = _seguro(cti.obtener_campana, codigo)
    if c is None:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")
    return cti.a_camel(c)


@rutas_cti.get("/campaigns/{codigo}/timeline", summary="Línea de tiempo de la campaña")
def linea_tiempo(codigo: str):
    t = _seguro(cti.linea_de_tiempo, codigo)
    if t is None:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")
    return cti.a_camel({"campaignCode": codigo, "eventos": t})


@rutas_cti.get("/ipe/escenarios", summary="Escenario más probable y más peligroso (IPE)")
def escenarios():
    return cti.a_camel(_seguro(cti.escenarios_ipe))


@rutas_cti.get("/anticipacion", summary="Riesgo previo por cuenta, alertas confirmadas y siguiente fase")
def anticipacion():
    return cti.a_camel(_seguro(cti.anticipacion))


@rutas_cti.get("/exports/sigma", summary="Lista de reglas Sigma")
def sigma():
    return {"reglas": _seguro(cti.listar_sigma)}


@rutas_cti.get("/exports/sigma/{nombre}", summary="Descargar una regla Sigma")
def sigma_archivo(nombre: str):
    ruta = _seguro(cti.ruta_sigma, nombre)
    if ruta is None:
        raise HTTPException(status_code=404, detail="Regla no encontrada")
    return FileResponse(ruta, media_type="application/x-yaml", filename=nombre)


@rutas_cti.get("/exports/stix", summary="Descargar bundle STIX 2.1 (importable en MISP)")
def stix():
    return FileResponse(_seguro(cti.ruta_stix), media_type="application/json",
                        filename="aegishealth_stix21_bundle.json")
