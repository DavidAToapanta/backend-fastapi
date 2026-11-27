"""Contrato del resumen de carga verificada, compartido por CLI y API."""
from datetime import datetime

ARCHIVOS = ("iocs_bloqueo.csv", "reglas_suricata.rules", "misp_stix2.json")
CAMPANAS = tuple(f"CAMP-2026-{n:03}" for n in range(1, 6))
DISTRIBUCION = "Solo mi organización"


def estado_verificado(resumen: dict) -> dict:
    if not isinstance(resumen, dict) or resumen.get("verificado") is not True:
        raise ValueError("Falta la verificación.")
    fecha = datetime.fromisoformat(resumen["fecha"])
    eventos = resumen["eventos"]
    if (fecha.tzinfo is None or resumen["distribucion"] != DISTRIBUCION
            or resumen["publicado_a_comunidades"] is not False
            or resumen["extracciones"] != list(ARCHIVOS)
            or len(eventos) != len(CAMPANAS) + 1
            or {e["codigo"] for e in eventos} != {*CAMPANAS, "consolidado"}
            or any(not isinstance(e["id"], str) or not e["id"].isdecimal() for e in eventos)
            or len({e["id"] for e in eventos}) != len(eventos)):
        raise ValueError("Resumen de carga incompleto.")
    return {"lastVerifiedAt": fecha.isoformat(), "eventCount": len(eventos),
            "distribution": DISTRIBUCION, "exports": list(ARCHIVOS)}
