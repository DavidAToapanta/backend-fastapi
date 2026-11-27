"""Consecuencias de un compromiso: qué puede hacer el atacante, con caso real y fuente.

GET /api/v1/consequences            -> catálogo completo
GET /api/v1/consequences/{code}     -> por campaña (CAMP-2026-00X), regla (IOA-0X, GUARD-0X) o Centinela (CEN-XXX)
Solo lectura, sin base de datos y sin datos personales.
"""

from fastapi import APIRouter, HTTPException

from app.cti_exports.consecuencias import catalogo_completo, consecuencias_por_codigo

rutas_consecuencias = APIRouter(prefix="/api/v1/consequences", tags=["consecuencias"])

NOMBRES_CAMEL = {
    "activo_simple": "assetSimple",
    "control_simple": "controlSimple",
    "accion": "action",
    "accion_simple": "actionSimple",
    "caso": "caseId",
    "caso_nombre": "caseName",
    "caso_hecho": "caseFact",
    "caso_dato_simple": "caseFactSimple",
    "fuente": "source",
    "url": "sourceUrl",
    "activo": "asset",
    "campanas": "campaigns",
    "reglas": "rules",
    "evidencia": "evidence",
    "consecuencias": "consequences",
    "control": "control",
    "obligacion": "legalObligation",
    "id": "id",
}


def a_camel(valor):
    """Convierte las claves al formato camelCase que usa el resto de la API."""
    if isinstance(valor, dict):
        return {NOMBRES_CAMEL.get(clave, clave): a_camel(dato) for clave, dato in valor.items()}
    if isinstance(valor, list):
        return [a_camel(dato) for dato in valor]
    return valor


@rutas_consecuencias.get("")
def listar_consecuencias() -> dict:
    return {"items": a_camel(catalogo_completo())}


@rutas_consecuencias.get("/{code}")
def consecuencias_de(code: str) -> dict:
    codigo = code.strip().upper()
    try:
        items = consecuencias_por_codigo(codigo)
    except ValueError as error:
        raise HTTPException(422, "Código no reconocido. Use CAMP-2026-00X, IOA-0X, GUARD-0X o CEN-XXX.") from error
    if not items:
        raise HTTPException(404, "No hay consecuencias registradas para ese código.")
    return {"code": codigo, "items": a_camel(items)}
