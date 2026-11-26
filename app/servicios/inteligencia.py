"""
Servicio de inteligencia de amenazas: LEE los resultados que genera el Rol 2 (carpeta exports).

Decisión de diseño: la API NO ejecuta el análisis (pandas, scikit-learn, 10M de filas).
El análisis corre aparte (pipeline del Rol 2) y la API solo sirve los resultados ya
seudonimizados. Así la imagen Docker queda liviana, no contiene datos crudos y hay
menos superficie de ataque.

Solo usa la biblioteca estándar de Python.
"""
import csv
import json
import os
import re
from functools import lru_cache
from pathlib import Path

NOMBRE_SIGMA_VALIDO = re.compile(r"^(ioa|ioc)_\d{2}_[a-z0-9_]+\.yml$")


class DatosNoDisponibles(Exception):
    """Los resultados del Rol 2 no están en la carpeta configurada."""


def carpeta_exports() -> Path:
    return Path(os.getenv("CTI_EXPORTS_DIR", "data/exports_10m")).resolve()


@lru_cache(maxsize=32)
def _leer_json(nombre: str, _marca: float) -> dict:
    return json.loads((carpeta_exports() / nombre).read_text(encoding="utf-8"))


def leer_json(nombre: str) -> dict:
    ruta = carpeta_exports() / nombre
    if not ruta.is_file():
        raise DatosNoDisponibles(f"No existe {nombre} en {carpeta_exports()}")
    return _leer_json(nombre, ruta.stat().st_mtime)  # se recarga solo si el archivo cambia


def leer_csv(nombre: str) -> list[dict]:
    ruta = carpeta_exports() / nombre
    if not ruta.is_file():
        raise DatosNoDisponibles(f"No existe {nombre} en {carpeta_exports()}")
    with ruta.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def a_camel(dato):
    """snake_case -> camelCase en todas las claves (contrato del frontend)."""
    if isinstance(dato, dict):
        return {re.sub(r"_([a-z0-9])", lambda m: m.group(1).upper(), str(k)): a_camel(v) for k, v in dato.items()}
    if isinstance(dato, list):
        return [a_camel(x) for x in dato]
    return dato


# ---------------------------------------------------------------- consultas
def resumen() -> dict:
    cal, a, b = leer_json("calidad_datos.json"), leer_json("ml_metrics_A_genericas.json"), leer_json("ml_metrics_B_dominio.json")
    reglas, camp, ant = leer_json("hallazgos_reglas.json"), leer_json("campanas.json"), leer_json("anticipacion.json")
    b_inc = next((x for x in ant["backtest_incidentes"] if x["campana"] == "CAMP-2026-004"), {})
    return {
        "privacy_mode": camp.get("privacy_mode"),
        "filas_analizadas": cal["firewall"]["filas"] + cal["sistema_medico"]["filas"],
        "calidad": {"firewall": cal["firewall"]["puntaje_calidad"], "sistema_medico": cal["sistema_medico"]["puntaje_calidad"],
                    "advertencias": cal["advertencias"]},
        "deteccion": {"reglas_ioa": reglas["incidentes_detectados_por_ioa"],
                      "ml_generico": a["incidentes_en_top_n"], "ml_dominio": b["incidentes_en_top_n"],
                      "hallazgos_por_regla": reglas["resumen_por_regla"]},
        "campanas": {"total": len(camp["campaigns"]),
                     "por_severidad": {s: sum(c["severity"] == s for c in camp["campaigns"]) for s in ("CRITICA", "ALTA", "MEDIA")}},
        "anticipacion": {"cuentas_riesgo_alto_o_critico": ant["riesgo_actual"]["cuentas_alto_o_critico"],
                         "horas_alerta_confirmada": ant["alertas_tempranas"]["horas_confirmadas"],
                         "horas_evaluadas": ant["alertas_tempranas"]["horas_evaluadas"],
                         "dias_anticipacion_incidente_b": b_inc.get("dias_de_anticipacion"),
                         "siguiente_fase_backtest": ant["backtest_siguiente_fase"]["aciertos_top3"]},
    }


def listar_campanas() -> list[dict]:
    pron = {p["campaign_code"]: p for p in leer_json("anticipacion.json")["pronostico_siguiente_fase"]}
    salida = []
    for c in leer_json("campanas.json")["campaigns"]:
        ligera = {k: v for k, v in c.items() if k not in ("hallazgos", "evidence_refs")}
        ligera["siguiente_fase"] = pron.get(c["campaign_code"], {}).get("siguientes_fases_probables", [])
        salida.append(ligera)
    return salida


def obtener_campana(codigo: str) -> dict | None:
    pron = {p["campaign_code"]: p for p in leer_json("anticipacion.json")["pronostico_siguiente_fase"]}
    for c in leer_json("campanas.json")["campaigns"]:
        if c["campaign_code"] == codigo:
            return {**c, "pronostico": pron.get(codigo)}
    return None


def linea_de_tiempo(codigo: str) -> list[dict] | None:
    """Hallazgos de la campaña ordenados en el tiempo (incluye ajuste de reloj de +12h si aplica)."""
    if obtener_campana(codigo) is None:
        return None
    reglas = leer_json("hallazgos_reglas.json")
    camp = obtener_campana(codigo)
    entidades = set(camp["iocs"]["source_ips"] + camp["iocs"]["actor_tokens"] + camp["iocs"]["account_tokens"])
    eventos = []
    for h in reglas["hallazgos_ioa"]:
        valores = set()
        for v in h["entidades"].values():
            valores.update(v if isinstance(v, list) else [v])
        if valores & entidades:
            eventos.append({"inicio": h["inicio"], "fin": h["fin"], "regla": h["regla"], "nombre": h["nombre"],
                            "severidad": h["severidad"], "descripcion": h["descripcion"],
                            "dataset": h["evidencia"]["dataset"], "filas_evidencia": h["evidencia"]["total_filas"],
                            "ajuste_reloj_12h": h.get("ajuste_reloj_12h", False)})
    return sorted(eventos, key=lambda e: e["inicio"])


def escenarios_ipe() -> dict:
    return leer_json("campanas.json")["escenarios_ipe"]


def anticipacion() -> dict:
    ant = leer_json("anticipacion.json")
    alertas = [a for a in leer_csv("alertas_tempranas.csv") if a.get("nivel_alerta") == "CONFIRMADA"]
    return {
        "principio": ant["principio"],
        "riesgo_cuentas": leer_csv("riesgo_cuentas.csv"),
        "alertas_confirmadas": alertas,
        "backtest_incidentes": ant["backtest_incidentes"],
        "pronostico_siguiente_fase": ant["pronostico_siguiente_fase"],
        "backtest_siguiente_fase": ant["backtest_siguiente_fase"],
    }


def listar_sigma() -> list[str]:
    carpeta = carpeta_exports() / "sigma"
    if not carpeta.is_dir():
        raise DatosNoDisponibles(f"No existe la carpeta sigma en {carpeta_exports()}")
    return sorted(p.name for p in carpeta.glob("*.yml") if NOMBRE_SIGMA_VALIDO.match(p.name))


def ruta_sigma(nombre: str) -> Path | None:
    """Solo devuelve archivos de la lista blanca: evita leer archivos fuera de la carpeta (path traversal)."""
    if not NOMBRE_SIGMA_VALIDO.match(nombre) or nombre not in listar_sigma():
        return None
    return carpeta_exports() / "sigma" / nombre


def ruta_stix() -> Path:
    ruta = carpeta_exports() / "aegishealth_stix21_bundle.json"
    if not ruta.is_file():
        raise DatosNoDisponibles("No existe el bundle STIX")
    return ruta


def contexto_para_llm() -> str:
    """ÚNICO texto que se le pasa a Ollama: resumen agregado y seudonimizado (nunca filas crudas)."""
    campanas = [{k: c[k] for k in ("campaign_code", "adversary_type", "severity", "summary", "first_seen", "last_seen")}
                | {"tecnicas": [t["id"] + " " + t["name"] for t in c["mitre_techniques"]], "ioas": c["ioas"]}
                for c in leer_json("campanas.json")["campaigns"]]
    return json.dumps({"resumen": resumen(), "campanas": campanas, "escenarios_ipe": escenarios_ipe()},
                      ensure_ascii=False)
