"""
Mapeo a MITRE ATT&CK, armado de campañas y escenarios IPE (Rol 2).

Pasos:
  1. Agrupa los hallazgos de las reglas IoA en CAMPAÑAS: dos hallazgos van juntos si
     comparten una IP de origen, un usuario (actor_token) o una cuenta (account_token).
     Los grupos que solo tienen abuso de cuentas (IOA-06/07/08) se unen en una sola
     campaña porque muestran el mismo patrón.
  2. Asigna técnicas MITRE ATT&CK según las reglas que se activaron (y SOLO esas).
  3. Arma los 2 escenarios de la metodología IPE: el más probable y el más peligroso.

Uso:
  python -m backend.app.analytics.mitre_mapper --salida data/exports
  (lee data/exports/hallazgos_reglas.json y los rankings del ML)
"""
import argparse
import json
from pathlib import Path

import pandas as pd

# Catálogo de técnicas usadas (id -> nombre, táctica)
TECNICAS = {
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1078": ("Valid Accounts", "Defense Evasion, Persistence, Privilege Escalation, Initial Access"),
    "T1098": ("Account Manipulation", "Persistence, Privilege Escalation"),
    "T1531": ("Account Access Removal", "Impact"),
    "T1213": ("Data from Information Repositories", "Collection"),
    "T1074": ("Data Staged", "Collection"),
    "T1048.002": ("Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", "Exfiltration"),
}
PUERTOS_CREDENCIALES = {22, 23, 3389, 5985, 5986}
CLAVES_ENTIDAD = ("src_ip", "actor_token", "account_token")
REGLAS_ABUSO_CUENTAS = {"IOA-06", "IOA-07", "IOA-08"}
ORDEN_SEVERIDAD = {"MEDIA": 1, "ALTA": 2, "CRITICA": 3}


def tecnicas_de_hallazgo(h: dict) -> set[str]:
    """Técnicas que justifica UN hallazgo (solo lo que la evidencia respalda)."""
    r, e = h["regla"], h["entidades"]
    if r == "IOA-01":
        puerto = e.get("dst_port")
        t = {"T1110.001"} if puerto in PUERTOS_CREDENCIALES else {"T1046"}
        if puerto == 23:
            t.add("T1021")
        return t
    if r == "IOA-02":
        t = {"T1046"}
        if 3389 in e.get("puertos", []):
            t.add("T1021.001")
        if 445 in e.get("puertos", []):
            t.add("T1021.002")
        return t
    if r == "IOA-03":
        return {"T1110.001"}
    if r == "IOA-04":
        return {"T1213", "T1074"}
    if r == "IOA-05":
        t = {"T1048.002", "T1078"}
        if h.get("secuencia_exfiltracion"):
            t |= {"T1021.004", "T1213"}
        return t
    if r == "IOA-06":
        return {"T1078"}
    if r == "IOA-07":
        t = {"T1098"}
        if any("Inactivacion" in a for a in h.get("operaciones", {})):
            t.add("T1531")
        return t
    if r == "IOA-09":
        return {"T1021.004"}
    return set()  # IOA-08: sin técnica asignada (hipótesis de evasión, requiere análisis)


def _valores(h: dict) -> set[str]:
    vals = set()
    for k in CLAVES_ENTIDAD:
        v = h["entidades"].get(k)
        if v is None:
            continue
        vals.update(v if isinstance(v, list) else [v])
    return vals


def agrupar(hallazgos: list[dict]) -> list[list[dict]]:
    """Une hallazgos que comparten entidades (componentes conectados)."""
    padre = list(range(len(hallazgos)))

    def raiz(i):
        while padre[i] != i:
            padre[i] = padre[padre[i]]
            i = padre[i]
        return i

    vistos = {}
    for i, h in enumerate(hallazgos):
        for v in _valores(h):
            if v in vistos:
                padre[raiz(i)] = raiz(vistos[v])
            else:
                vistos[v] = i
    grupos = {}
    for i, h in enumerate(hallazgos):
        grupos.setdefault(raiz(i), []).append(h)

    # Grupos que SOLO tienen abuso de cuentas -> una sola campaña
    normales, abuso = [], []
    for g in grupos.values():
        (abuso if {h["regla"] for h in g} <= REGLAS_ABUSO_CUENTAS else normales).append(g)
    if abuso:
        normales.append([h for g in abuso for h in g])
    return normales


def _tipo_adversario(reglas: set[str]) -> str:
    if "IOA-05" in reglas:
        return "HYBRID"            # cuenta válida + salida de datos al exterior
    if reglas <= REGLAS_ABUSO_CUENTAS:
        return "INSIDER_THREAT"    # abuso desde adentro con cuentas legítimas
    return "ACTOR_CON_PRESENCIA_INTERNA"  # orígenes internos: equipo/cuenta comprometida o insider


def _codigo(grupo: list[dict], referencia: dict) -> str | None:
    """Usa la numeración del equipo (CAMP-2026-00X) si el grupo coincide con un incidente conocido."""
    vals = set().union(*(_valores(h) for h in grupo))
    for inc in referencia["incidentes"]:
        if any(v["entidad"] in vals for v in inc["ventanas"]):
            return inc["campana"]
    return None


def construir_campanas(hallazgos_ioa: list[dict], referencia: dict, puntajes_ml: dict) -> list[dict]:
    campanas, nuevas = [], 0
    for grupo in agrupar(hallazgos_ioa):
        reglas = {h["regla"] for h in grupo}
        tecnicas = set().union(*(tecnicas_de_hallazgo(h) for h in grupo))
        if {"IOA-03", "IOA-06"} <= reglas:
            tecnicas.add("T1110.003")  # muchos nombres distintos fallando en la misma cuenta
        codigo = _codigo(grupo, referencia)
        if codigo is None:
            nuevas += 1
            codigo = f"CAMP-2026-1{nuevas:02d}"

        def juntar(clave):
            out = set()
            for h in grupo:
                v = h["entidades"].get(clave)
                if v is not None:
                    out.update(v if isinstance(v, list) else [v])
            return sorted(out)

        entidades = set(juntar("actor_token") + juntar("account_token"))
        score = max((puntajes_ml.get(e, 0.0) for e in entidades), default=0.0)
        campanas.append({
            "campaign_code": codigo,
            "adversary_type": _tipo_adversario(reglas),
            "severity": max((h["severidad"] for h in grupo), key=ORDEN_SEVERIDAD.get),
            "anomaly_score": round(float(score), 4),
            "first_seen": min(h["inicio"] for h in grupo),
            "last_seen": max(h["fin"] for h in grupo),
            "summary": " | ".join(sorted({h["nombre"] for h in grupo})),
            "mitre_techniques": [
                {"id": t, "name": TECNICAS[t][0], "tactic": TECNICAS[t][1],
                 "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"}
                for t in sorted(tecnicas)
            ],
            "iocs": {
                "source_ips": juntar("src_ip"),
                "destination_ips": juntar("dst_ip"),
                "actor_tokens": juntar("actor_token")[:50],
                "account_tokens": juntar("account_token"),
            },
            "ioas": sorted(reglas),
            "hallazgos": [h["descripcion"] for h in grupo],
            "evidence_refs": [h["evidencia"] for h in grupo],
        })
    return sorted(campanas, key=lambda c: c["campaign_code"])


def escenarios_ipe(campanas: list[dict]) -> dict:
    """Los 2 cursos de acción del adversario que pide la metodología IPE."""
    codigos = {c["campaign_code"] for c in campanas}
    return {
        "metodologia": "IPE: 1) definir el entorno, 2) describir sus efectos, 3) evaluar la amenaza, "
                       "4) determinar los cursos de acción del adversario.",
        "ESCENARIO_MAS_PROBABLE": {
            "descripcion": "Abuso interno persistente de privilegios y manipulación de cuentas especiales "
                           "(cuentas usadas por cientos de identidades, activaciones y reactivaciones masivas), "
                           "acompañado de reconocimiento y fuerza bruta desde equipos internos.",
            "campanas": sorted(codigos & {"CAMP-2026-005", "CAMP-2026-003", "CAMP-2026-004"}),
            "por_que_es_probable": "Es la actividad con más volumen y dura todo el periodo; usa cuentas válidas, "
                                   "lo que la hace difícil de distinguir del trabajo normal.",
        },
        "ESCENARIO_MAS_PELIGROSO": {
            "descripcion": "Cadena multifase: el actor usa cuentas válidas y acceso SSH al servidor médico, extrae "
                           "información (transferencias masivas y descarga) y la envía a una IP externa por 8443, "
                           "lo que habilita extorsión o venta de datos de salud.",
            "campanas": sorted(codigos & {"CAMP-2026-005", "CAMP-2026-001", "CAMP-2026-002"}),
            "vinculo_005_a_001": "POSIBLE (no probable): solo 1 de las 811 conexiones al puerto 8443 sale a la IP "
                                 "externa (evidencias.json de Rol 1). Calificar con la escala Admiralty.",
        },
    }


def _puntajes_ml(carpeta: Path) -> dict:
    """Mejor puntaje de anomalía por entidad (de los rankings del ML, versión genérica)."""
    puntajes = {}
    for archivo in carpeta.glob("ranking_*_A_genericas.csv"):
        r = pd.read_csv(archivo, usecols=["entidad", "anomaly_score"])
        for e, s in r.groupby("entidad")["anomaly_score"].max().items():
            puntajes[e] = max(puntajes.get(e, 0.0), float(s))
    return puntajes


def ejecutar(carpeta_salida: str = "data/exports") -> dict:
    carpeta = Path(carpeta_salida)
    reglas = json.loads((carpeta / "hallazgos_reglas.json").read_text(encoding="utf-8"))
    referencia = json.loads((Path(__file__).parent / "incidentes_referencia.json").read_text(encoding="utf-8"))
    campanas = construir_campanas(reglas["hallazgos_ioa"], referencia, _puntajes_ml(carpeta))
    resultado = {
        "privacy_mode": "LOCAL_ONLY_HMAC_SHA256",
        "campaigns": campanas,
        "escenarios_ipe": escenarios_ipe(campanas),
    }
    (carpeta / "campanas.json").write_text(json.dumps(resultado, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Campañas: {len(campanas)}")
    for c in campanas:
        print(f"  {c['campaign_code']} [{c['severity']}] {c['adversary_type']} | "
              f"{', '.join(t['id'] for t in c['mitre_techniques'])} | {c['summary']}")
    print(f"Resultado en {(carpeta / 'campanas.json').resolve()}")
    return resultado


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Mapeo MITRE ATT&CK, campañas y escenarios IPE (Rol 2)")
    p.add_argument("--salida", default="data/exports")
    ejecutar(p.parse_args().salida)
