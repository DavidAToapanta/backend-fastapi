"""Pruebas del servicio de inteligencia (sin FastAPI). Ejecutar: python tests/test_inteligencia.py"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("CTI_EXPORTS_DIR", "data/exports_10m")
from app.servicios import inteligencia as cti  # noqa: E402

r = cti.resumen()
assert r["filas_analizadas"] > 10_000_000, r["filas_analizadas"]
assert r["deteccion"]["reglas_ioa"] == "5/5"
assert len(cti.listar_campanas()) == 5
assert cti.obtener_campana("CAMP-2026-001")["severity"] == "CRITICA"
assert cti.obtener_campana("NO-EXISTE") is None
assert len(cti.linea_de_tiempo("CAMP-2026-004")) >= 3
assert set(cti.escenarios_ipe()) >= {"ESCENARIO_MAS_PROBABLE", "ESCENARIO_MAS_PELIGROSO"}
assert len(cti.listar_sigma()) == 10
assert cti.ruta_sigma("../../.env") is None and cti.ruta_sigma("..%2Fsecreto.yml") is None   # path traversal bloqueado
assert "campaignCode" in cti.a_camel(cti.listar_campanas()[0])
ctx = cti.contexto_para_llm()
assert "XYZ" not in ctx and "MINAD" not in ctx and len(ctx) < 20_000
print("OK: todas las pruebas del servicio pasaron")
print(json.dumps(cti.a_camel(r), indent=2, ensure_ascii=False))
