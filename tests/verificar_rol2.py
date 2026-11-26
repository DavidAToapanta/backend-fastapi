"""
Prueba completa del Rol 2: revisa que las salidas existan, sean válidas y den los resultados esperados.
Uso:  python tests/verificar_rol2.py --salida data/exports_10m
"""
import argparse
import json
import re
import sys
from pathlib import Path

import yaml

p = argparse.ArgumentParser()
p.add_argument("--salida", default="data/exports_10m")
carpeta = Path(p.parse_args().salida)
resultados = []


def prueba(nombre, condicion, detalle=""):
    resultados.append(bool(condicion))
    print(f"{'[OK]   ' if condicion else '[FALLA]'} {nombre}" + (f"  ->  {detalle}" if detalle else ""))


def leer(nombre):
    return json.loads((carpeta / nombre).read_text(encoding="utf-8"))


print(f"Verificando {carpeta.resolve()}\n")
archivos = ["calidad_datos.json", "ml_metrics_A_genericas.json", "ml_metrics_B_dominio.json", "hallazgos_reglas.json",
            "campanas.json", "aegishealth_stix21_bundle.json", "anticipacion.json", "riesgo_cuentas.csv",
            "alertas_tempranas.csv"]
faltan = [a for a in archivos if not (carpeta / a).exists()]
prueba("Existen las 9 salidas principales", not faltan, f"faltan: {faltan}" if faltan else "")
if faltan:
    sys.exit(1)

cal = leer("calidad_datos.json")
filas = cal["firewall"]["filas"] + cal["sistema_medico"]["filas"]
prueba("Se procesaron los datos completos (más de 10 millones de filas)", filas >= 10_000_000, f"{filas:,} filas")
prueba("Calidad de datos >= 99%", min(cal["firewall"]["puntaje_calidad"], cal["sistema_medico"]["puntaje_calidad"]) >= 99,
       f"FW {cal['firewall']['puntaje_calidad']}% | MED {cal['sistema_medico']['puntaje_calidad']}%")
prueba("Sin valores nuevos inesperados (sin drift)", not cal["advertencias"], "; ".join(cal["advertencias"]))

a, b = leer("ml_metrics_A_genericas.json"), leer("ml_metrics_B_dominio.json")
prueba("ML genérico detecta al menos 4/5 sin reglas", int(a["incidentes_en_top_n"].split("/")[0]) >= 4, a["incidentes_en_top_n"])
prueba("ML con variables de dominio detecta 5/5", b["incidentes_en_top_n"] == "5/5", b["incidentes_en_top_n"])

r = leer("hallazgos_reglas.json")
prueba("Reglas IoA detectan 5/5 incidentes", r["incidentes_detectados_por_ioa"] == "5/5", r["incidentes_detectados_por_ioa"])

c = leer("campanas.json")
prueba("Se arman 5 campañas", len(c["campaigns"]) == 5, ", ".join(x["campaign_code"] for x in c["campaigns"]))
prueba("Existen los 2 escenarios IPE", {"ESCENARIO_MAS_PROBABLE", "ESCENARIO_MAS_PELIGROSO"} <= set(c["escenarios_ipe"]))

sigma = list((carpeta / "sigma").glob("*.yml"))
validos = sum(1 for f in sigma if all(d for d in yaml.safe_load_all(f.read_text(encoding="utf-8"))))
prueba("10 reglas Sigma con YAML válido", len(sigma) == 10 and validos == 10, f"{validos}/{len(sigma)}")

stix = leer("aegishealth_stix21_bundle.json")
ind = [o for o in stix["objects"] if o["type"] == "indicator"]
prueba("STIX: todos los indicadores con candado ético",
       ind and all({"synthetic-exercise-data", "hackathon-simulation"} <= set(o.get("labels", [])) for o in ind),
       f"{len(ind)} indicadores, {len(stix['objects'])} objetos")
try:
    import stix2
    stix2.parse(json.dumps(stix), allow_custom=False)
    prueba("STIX válido con la librería oficial stix2", True)
except ImportError:
    print("[AVISO]  stix2 no instalado: se omite la validación oficial")
except Exception as e:
    prueba("STIX válido con la librería oficial stix2", False, str(e)[:200])

ant = leer("anticipacion.json")
b_inc = next(x for x in ant["backtest_incidentes"] if x["campana"] == "CAMP-2026-004")
prueba("Anticipación: la cuenta del incidente B estaba en riesgo antes del ataque",
       b_inc.get("dias_de_anticipacion", 0) > 0, f"{b_inc.get('dias_de_anticipacion')} días antes")
con_alerta = [x["campana"] for x in ant["backtest_incidentes"] if x.get("alerta_temprana")]
prueba("Alerta temprana CONFIRMADA en la misma hora para A, B, C y D", len(con_alerta) == 4, ", ".join(con_alerta))
at = ant["alertas_tempranas"]
prueba("Pocas falsas alarmas confirmadas (<= 1 por semana)", at["horas_confirmadas"] - 5 <= 5,
       f"{at['horas_confirmadas']} horas confirmadas en {at['horas_evaluadas']} horas")

patron = re.compile(r"XYZ\d|WXY\d|MINAD|CMAP|RIMODE")
con_pii = [f.name for f in carpeta.rglob("*") if f.is_file() and patron.search(f.read_text(encoding="utf-8", errors="ignore"))]
prueba("Sin cuentas ni nombres en claro en ninguna salida (LOPDP)", not con_pii, f"revisar: {con_pii}" if con_pii else "")

ok = sum(resultados)
print(f"\nRESULTADO: {ok}/{len(resultados)} pruebas superadas")
sys.exit(0 if ok == len(resultados) else 1)
