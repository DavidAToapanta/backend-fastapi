"""
Exportador STIX 2.1 (Rol 2).

STIX 2.1 es el formato internacional para compartir inteligencia de amenazas;
MISP lo importa directamente. El paquete (bundle) contiene:
  identity (nuestro equipo), marking-definition (TLP:AMBER), threat-actor, campaign,
  attack-pattern (técnicas MITRE), indicator (IoC) y relationship (cómo se conectan).

CANDADO ÉTICO: todo indicador lleva las etiquetas "synthetic-exercise-data" y
"hackathon-simulation", y su descripción dice que es un dato sintético.

Se construye a mano (sin librerías) para que funcione aunque falle internet.
Si tienes instalada la librería oficial stix2, el script además lo valida con ella.

Uso:
  python -m backend.app.cti_exports.stix_exporter --salida data/exports
"""
import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

ETIQUETAS = ["synthetic-exercise-data", "hackathon-simulation"]
AVISO = "DATO SINTÉTICO DE EJERCICIO - Hackatón IESS 2026. No usar como inteligencia real."
# Definición oficial de TLP:AMBER en STIX 2.1
TLP_AMBER = {
    "type": "marking-definition", "spec_version": "2.1",
    "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
    "name": "TLP:AMBER", "definition": {"tlp": "amber"},
}
TIPOS_ACTOR = {
    "INSIDER_THREAT": ["insider-disgruntled"],
    "HYBRID": ["insider-disgruntled", "criminal"],
    "ACTOR_CON_PRESENCIA_INTERNA": ["unknown"],
}
AHORA = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _id(tipo: str, clave: str) -> str:
    """Id estable: el mismo objeto siempre tiene el mismo id (reproducible)."""
    return f"{tipo}--{uuid.uuid5(uuid.NAMESPACE_URL, f'aegishealth-cti/{tipo}/{clave}')}"


def _ts(texto: str) -> str:
    return datetime.fromisoformat(str(texto)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _comun(tipo, clave, equipo_id):
    return {"type": tipo, "spec_version": "2.1", "id": _id(tipo, clave), "created": AHORA,
            "modified": AHORA, "created_by_ref": equipo_id, "object_marking_refs": [TLP_AMBER["id"]]}


def construir_bundle(campanas: list[dict], iocs: dict) -> dict:
    equipo = {"type": "identity", "spec_version": "2.1", "id": _id("identity", "equipo"),
              "created": AHORA, "modified": AHORA, "name": "Equipo AegisHealth-CTI (Hackatón IESS 2026)",
              "identity_class": "organization"}
    objetos, relaciones, patrones = [TLP_AMBER, equipo], [], {}

    def relacion(origen, tipo, destino):
        relaciones.append({**_comun("relationship", f"{origen}|{tipo}|{destino}", equipo["id"]),
                           "relationship_type": tipo, "source_ref": origen, "target_ref": destino})

    for c in campanas:
        camp = {**_comun("campaign", c["campaign_code"], equipo["id"]),
                "name": f"{c['campaign_code']} - {c['summary']}",
                "description": f"{AVISO} Severidad {c['severity']}. " + " ".join(c["hallazgos"][:5]),
                "first_seen": _ts(c["first_seen"]), "last_seen": _ts(c["last_seen"]), "labels": ETIQUETAS}
        actor = {**_comun("threat-actor", c["campaign_code"], equipo["id"]),
                 "name": f"Actor de {c['campaign_code']} ({c['adversary_type']})",
                 "threat_actor_types": TIPOS_ACTOR.get(c["adversary_type"], ["unknown"]),
                 "description": f"{AVISO} Perfil inferido de los hallazgos: {', '.join(c['ioas'])}.",
                 "labels": ETIQUETAS}
        objetos += [camp, actor]
        relacion(camp["id"], "attributed-to", actor["id"])

        for t in c["mitre_techniques"]:
            if t["id"] not in patrones:
                patrones[t["id"]] = {**_comun("attack-pattern", t["id"], equipo["id"]), "name": t["name"],
                                     "external_references": [{"source_name": "mitre-attack",
                                                              "external_id": t["id"], "url": t["url"]}]}
            relacion(camp["id"], "uses", patrones[t["id"]]["id"])

        # Indicadores de cuentas de la campaña (tokens seudonimizados)
        for cuenta in c["iocs"]["account_tokens"]:
            ind = {**_comun("indicator", f"{c['campaign_code']}|{cuenta}", equipo["id"]),
                   "name": f"Cuenta comprometida o abusada {cuenta}",
                   "description": f"{AVISO} Token seudonimizado (HMAC-SHA256); la identidad real no está en este archivo.",
                   "indicator_types": ["compromised"], "pattern_type": "stix",
                   "pattern": f"[user-account:user_id = '{cuenta}']",
                   "valid_from": _ts(c["first_seen"]), "labels": ETIQUETAS}
            objetos.append(ind)
            relacion(ind["id"], "indicates", camp["id"])

    # Indicadores de red del caso (IoC)
    camp_exfil = next((o for o in objetos if o["type"] == "campaign" and o["name"].startswith("CAMP-2026-001")), None)
    for ip in iocs["ips_destino_externas"]:
        for puerto in iocs["puertos_canal_sombra"]:
            ind = {**_comun("indicator", f"red|{ip}|{puerto}", equipo["id"]),
                   "name": f"Egreso hacia IP externa {ip}:{puerto} (sintético)",
                   "description": f"{AVISO} No consultar ni escanear esta IP.",
                   "indicator_types": ["malicious-activity"], "pattern_type": "stix",
                   "pattern": f"[network-traffic:dst_ref.value = '{ip}' AND network-traffic:dst_port = {puerto}]",
                   "valid_from": AHORA, "labels": ETIQUETAS}
            objetos.append(ind)
            if camp_exfil:
                relacion(ind["id"], "indicates", camp_exfil["id"])

    objetos += list(patrones.values()) + relaciones
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objetos}


def validar(bundle: dict) -> str:
    """Revisión propia + validación con la librería oficial stix2 si está instalada."""
    ids = {o["id"] for o in bundle["objects"]}
    for o in bundle["objects"]:
        for campo in ("source_ref", "target_ref", "created_by_ref"):
            if campo in o and o[campo] not in ids:
                raise ValueError(f"{o['id']} apunta a un objeto que no existe: {o[campo]}")
        if o["type"] == "indicator" and o.get("labels") != ETIQUETAS:
            raise ValueError(f"Indicador sin candado ético: {o['id']}")
    try:
        import stix2
    except ImportError:
        return "validación interna OK (stix2 no instalado)"
    try:
        stix2.parse(json.dumps(bundle), allow_custom=False)
        return "validado con la librería oficial stix2"
    except Exception as error:  # se informa, pero el archivo se guarda igual
        return f"ADVERTENCIA de stix2: {error}"


def exportar_bundle_stix(carpeta_salida: str = "data/exports", ruta_iocs: str | None = None) -> str:
    carpeta = Path(carpeta_salida)
    campanas = json.loads((carpeta / "campanas.json").read_text(encoding="utf-8"))["campaigns"]
    iocs_path = Path(ruta_iocs) if ruta_iocs else Path(__file__).parents[1] / "analytics" / "iocs_ejercicio.json"
    iocs = json.loads(iocs_path.read_text(encoding="utf-8"))
    bundle = construir_bundle(campanas, iocs)
    estado = validar(bundle)
    ruta = carpeta / "aegishealth_stix21_bundle.json"
    ruta.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
    tipos = {}
    for o in bundle["objects"]:
        tipos[o["type"]] = tipos.get(o["type"], 0) + 1
    print(f"Bundle STIX 2.1: {len(bundle['objects'])} objetos {tipos}")
    print(f"Validación: {estado}")
    print(f"Resultado en {ruta.resolve()}")
    return str(ruta)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Exportador STIX 2.1 compatible con MISP (Rol 2)")
    p.add_argument("--salida", default="data/exports")
    p.add_argument("--iocs", default=None)
    a = p.parse_args()
    exportar_bundle_stix(a.salida, a.iocs)
