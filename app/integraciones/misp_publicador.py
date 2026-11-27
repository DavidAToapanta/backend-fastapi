"""
Publicador MISP de AegisHealth-CTI (integración Rol 2 -> Rol 3).

Qué hace
  1. LEE los resultados ya seudonimizados del Rol 2 (carpeta exports_10m).
  2. ARMA un evento MISP por campaña + 1 evento consolidado, con:
       - atributos extraídos del ataque (IPs, puerto, cuentas ACC-, reglas Sigma),
       - etiquetas TLP:AMBER, "dato sintético" y técnicas MITRE ATT&CK (galaxia de MISP),
       - un informe (event report) en Markdown con hallazgos, evidencia, siguiente fase e IPE.
  3. PUBLICA en el MISP local por su API REST (solo 127.0.0.1).
  4. EXTRAE de vuelta desde MISP los indicadores para bloqueo (CSV, Suricata y STIX 2),
     es decir, cierra el ciclo: detección -> inteligencia compartible -> controles.

Privacidad (LOPDP): NUNCA envía filas crudas ni tokens de personas (USR-). Solo cuentas
técnicas seudonimizadas (ACC-), IPs, puertos y reglas. Distribución: "solo mi organización".

Sin dependencias externas (solo biblioteca estándar) para poder ejecutarse en cualquier
máquina. Modo --simular: arma todo y lo guarda en JSON SIN conectarse a MISP.

Uso:
  python -m app.integraciones.misp_publicador --exports data/exports_10m --simular
  python -m app.integraciones.misp_publicador --exports data/exports_10m
Variables de entorno (en .env, nunca en el código):
  MISP_URL=https://127.0.0.1:8443   MISP_API_KEY=<clave>   MISP_VERIFY_SSL=<ruta CA PEM>
"""
import argparse
import csv
import io
import json
import os
import re
import ssl
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5

from .misp_estado import ARCHIVOS, CAMPANAS, DISTRIBUCION, estado_verificado

ETIQUETA_PROYECTO = "aegishealth-cti"
ETIQUETAS_BASE = ["tlp:amber", ETIQUETA_PROYECTO, "synthetic-exercise-data", "hackathon-simulation"]
AVISO = "EJERCICIO CON DATOS SINTÉTICOS (Hackatón IESS 2026). No usar como inteligencia real."
NIVEL_AMENAZA = {"CRITICA": "1", "ALTA": "2", "MEDIA": "3"}   # MISP: 1 alto, 2 medio, 3 bajo
SOLO_MI_ORGANIZACION = "0"
# Regla IoA -> archivo Sigma que la implementa
SIGMA_POR_REGLA = {
    "IOA-01": "ioa_03_fuerza_bruta_telnet_umbral.yml", "IOA-02": "ioa_04_escaneo_multiservicio_4puertos.yml",
    "IOA-03": "ioa_03_fuerza_bruta_telnet_umbral.yml", "IOA-04": "ioa_02_rafaga_transferencias_ssh.yml",
    "IOA-05": "ioa_01_exfiltracion_egreso_no_rfc1918.yml", "IOA-06": "ioa_06_cuenta_compartida.yml",
    "IOA-07": "ioa_05_abuso_privilegios.yml", "IOA-08": "ioa_07_ip_malformada.yml",
    "IOA-09": "ioa_08_sesiones_ssh_masivas.yml",
}


# ------------------------------------------------------------------ lectura
def leer(carpeta: Path, nombre: str):
    return json.loads((carpeta / nombre).read_text(encoding="utf-8"))


def etiqueta_mitre(tecnica: dict) -> str:
    """Nombre de la galaxia MITRE de MISP: 'Password Guessing - T1110.001'."""
    nombre = tecnica["name"].split(": ")[-1]
    return f'misp-galaxy:mitre-attack-pattern="{nombre} - {tecnica["id"]}"'


def atributo(tipo, valor, comentario, para_ids=False):
    return {"type": tipo, "value": str(valor), "comment": comentario[:250],
            "to_ids": para_ids, "distribution": "5"}  # 5 = hereda la del evento


# ------------------------------------------------------------------ armado de eventos
def evento_de_campana(c: dict, iocs: dict, carpeta: Path, pronostico: dict | None, escenarios: dict) -> dict:
    attrs = []
    for ip in c["iocs"]["source_ips"]:
        attrs.append(atributo("ip-src", ip, "Equipo interno de origen del ataque (no bloquear sin revisión)"))
    for ip in c["iocs"]["destination_ips"]:
        externa = ip in iocs.get("ips_destino_externas", [])
        attrs.append(atributo("ip-dst", ip, ("IP externa de exfiltración. " + AVISO) if externa
                              else "Destino interno", para_ids=externa))
        if externa:
            for puerto in iocs.get("puertos_canal_sombra", []):
                attrs.append(atributo("ip-dst|port", f"{ip}|{puerto}", "Canal de salida observado. " + AVISO, True))
    # La evidencia del incidente D registra el salto SSH al servidor clínico
    # antes del egreso. En las otras campañas solo usamos sus destinos observados.
    if "IOA-05" in c["ioas"] and iocs["servidor_critico"] not in c["iocs"]["destination_ips"]:
        attrs.append(atributo("ip-dst", iocs["servidor_critico"], "Destino SSH previo al egreso (evidencia del incidente D)"))
    for cuenta in c["iocs"]["account_tokens"]:
        if not re.fullmatch(r"ACC-[A-F0-9]{12}", cuenta):
            raise ValueError("La campaña contiene una cuenta sin seudonimizar.")
        attrs.append(atributo("target-user", cuenta, "Cuenta técnica seudonimizada (HMAC-SHA256) usada o abusada"))
    for regla in sorted({SIGMA_POR_REGLA[r] for r in c["ioas"] if r in SIGMA_POR_REGLA}):
        ruta = carpeta / "sigma" / regla
        attrs.append(atributo("sigma", ruta.read_text(encoding="utf-8"), f"Regla de detección {regla}", True))

    etiquetas = ETIQUETAS_BASE + [etiqueta_mitre(t) for t in c["mitre_techniques"]]
    return {
        "Event": {
            "info": f"AegisHealth-CTI | {c['campaign_code']} | {c['summary'][:120]} (EJERCICIO)",
            "date": c["first_seen"][:10],
            "threat_level_id": NIVEL_AMENAZA.get(c["severity"], "4"),
            "analysis": "2",
            "distribution": SOLO_MI_ORGANIZACION,
            "published": False,
            "Attribute": attrs,
            "Tag": [{"name": t} for t in etiquetas],
        },
        "_informe": informe_campana(c, pronostico, escenarios),
    }


def informe_campana(c: dict, pronostico: dict | None, escenarios: dict) -> str:
    lineas = [f"# {c['campaign_code']} — {c['summary']}", "", f"> {AVISO}", "",
              f"- **Severidad:** {c['severity']}  ·  **Tipo de adversario:** {c['adversary_type']}",
              f"- **Periodo:** {c['first_seen']} → {c['last_seen']}",
              f"- **Reglas IoA activadas:** {', '.join(c['ioas'])}  ·  **Puntaje de anomalía (ML):** {c['anomaly_score']}",
              "", "## Técnicas MITRE ATT&CK", ""]
    lineas += [f"- [{t['id']}]({t['url']}) {t['name']} — {t['tactic']}" for t in c["mitre_techniques"]]
    lineas += ["", "## Hallazgos (extracción del ataque)", ""] + [f"- {h}" for h in c["hallazgos"]]
    lineas += ["", "## Evidencia (filas exactas en los datasets seudonimizados)", "",
               "| Dataset | Referencia | Filas | Primeras filas |", "|---|---|---|---|"]
    for e in c["evidence_refs"]:
        lineas.append(f"| {e['dataset']} | {e['referencia']} | {e['total_filas']} | {', '.join(map(str, e['primeras_filas'][:8]))} |")
    if pronostico and pronostico.get("siguientes_fases_probables"):
        lineas += ["", f"## Anticipación: fase actual **{pronostico['fase_actual']}**", "",
                   "| Siguiente fase probable | Probabilidad | Control recomendado |", "|---|---|---|"]
        lineas += [f"| {s['fase']} | {s['probabilidad']:.0%} | {s['control_recomendado']} |"
                   for s in pronostico["siguientes_fases_probables"]]
    for nombre, esc in escenarios.items():
        if isinstance(esc, dict) and c["campaign_code"] in esc.get("campanas", []):
            lineas += ["", f"## Escenario IPE: {nombre.replace('_', ' ').title()}", "", esc["descripcion"]]
    return "\n".join(lineas)


def evento_consolidado(resumen: dict, escenarios: dict, anticipacion: dict) -> dict:
    lineas = ["# AegisHealth-CTI — Informe consolidado", "", f"> {AVISO}", "", "## Resumen", "",
              "```json", json.dumps(resumen, indent=2, ensure_ascii=False), "```", "",
              "## Escenarios IPE", ""]
    for nombre, esc in escenarios.items():
        if isinstance(esc, dict):
            lineas += [f"### {nombre.replace('_', ' ').title()}", "", esc["descripcion"],
                       f"Campañas: {', '.join(esc.get('campanas', []))}", ""]
    lineas += ["## Anticipación (backtest sin mirar el futuro)", ""]
    for b in anticipacion["backtest_incidentes"]:
        lineas.append(f"- **{b['campana']}**: " + json.dumps({k: v for k, v in b.items() if k not in ('campana', 'incidente')},
                                                              ensure_ascii=False, default=str))
    return {"Event": {"info": "AegisHealth-CTI | Informe consolidado de inteligencia (EJERCICIO)",
                      "date": datetime.now().strftime("%Y-%m-%d"), "threat_level_id": "2", "analysis": "2",
                      "distribution": SOLO_MI_ORGANIZACION, "published": False, "Attribute": [],
                      "Tag": [{"name": t} for t in ETIQUETAS_BASE]},
            "_informe": "\n".join(lineas)}


def construir_eventos(carpeta: Path) -> list[dict]:
    camp = leer(carpeta, "campanas.json")
    codigos = [c["campaign_code"] for c in camp["campaigns"]]
    if sorted(codigos) != list(CAMPANAS):
        raise ValueError("Se requieren las cinco campañas distintas de la exportación del Rol 2.")
    ant = leer(carpeta, "anticipacion.json")
    # Indicadores del ejercicio: los mismos que usa el Rol 2 (backend/app/analytics/iocs_ejercicio.json)
    candidatos = [carpeta / "iocs_ejercicio.json", Path("backend/app/analytics/iocs_ejercicio.json")]
    ruta_iocs = next((r for r in candidatos if r.exists()), None)
    if ruta_iocs is None:
        raise SystemExit("No encuentro iocs_ejercicio.json (debe estar en backend/app/analytics/ del repo).")
    iocs = json.loads(ruta_iocs.read_text(encoding="utf-8"))
    pron = {p["campaign_code"]: p for p in ant["pronostico_siguiente_fase"]}
    eventos = [evento_de_campana(c, iocs, carpeta, pron.get(c["campaign_code"]), camp["escenarios_ipe"])
               for c in camp["campaigns"]]
    resumen = {"campanas": len(camp["campaigns"]), "riesgo_actual": ant["riesgo_actual"],
               "alertas_tempranas": {k: v for k, v in ant["alertas_tempranas"].items() if k != "por_senal"},
               "siguiente_fase_backtest": ant["backtest_siguiente_fase"]["aciertos_top3"]}
    eventos.append(evento_consolidado(resumen, camp["escenarios_ipe"], ant))
    for codigo, evento in zip([*codigos, "consolidado"], eventos, strict=True):
        evento["Event"]["uuid"] = str(uuid5(NAMESPACE_URL, f"urn:aegishealth:2026:{codigo}"))
    return eventos


def validar_privacidad(eventos: list[dict]) -> None:
    """Freno de seguridad: aborta si algo parece dato personal o cuenta en claro."""
    texto = json.dumps(eventos, ensure_ascii=False).upper()
    for prohibido in ("USR-", "XYZ", "WXY", "MINAD", "CMAP", "RIMODE"):
        if prohibido in texto:
            raise SystemExit(f"ABORTADO: aparece '{prohibido}' en los eventos. No se publica nada.")


# ------------------------------------------------------------------ cliente REST mínimo
class SinRedirecciones(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("MISP respondió con una redirección. Se canceló la solicitud.")


class ClienteMISP:
    def __init__(self, url: str, clave: str, verificar: str):
        partes = urlsplit(url)
        if (partes.scheme != "https" or partes.hostname not in {"127.0.0.1", "localhost", "::1"}
                or partes.username is not None or partes.password is not None
                or partes.path not in {"", "/"} or partes.query or partes.fragment or not clave):
            raise ValueError("MISP requiere una URL HTTPS local y una clave.")
        if verificar.lower() in {"false", "0", "no"}:
            raise ValueError("La verificación TLS es obligatoria.")
        cafile = None if verificar.lower() in {"true", "1", ""} else verificar
        contexto = ssl.create_default_context(cafile=cafile)
        self.url = url.rstrip("/")
        self.clave = clave
        self.abridor = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=contexto), SinRedirecciones()
        )

    def pedir(self, ruta, cuerpo=None, aceptar="application/json"):
        datos = None if cuerpo is None else json.dumps(cuerpo).encode("utf-8")
        req = urllib.request.Request(self.url + ruta, data=datos, headers={
            "Authorization": self.clave, "Accept": aceptar, "Content-Type": "application/json"})
        try:
            with self.abridor.open(req, timeout=60) as respuesta:
                contenido = respuesta.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            raise ValueError(f"MISP respondió HTTP {error.code} en {ruta}.") from None
        return json.loads(contenido) if aceptar == "application/json" else contenido


def verificar_evento(remoto, esperado):
    original = esperado["Event"]
    etiquetas = {t["name"] for t in remoto.get("Tag", [])}
    galaxias = {c["tag_name"] for g in remoto.get("Galaxy", []) for c in g.get("GalaxyCluster", [])}
    mitre = {t["name"] for t in original["Tag"] if t["name"].startswith("misp-galaxy:")}
    if (remoto["uuid"] != original["uuid"] or str(remoto["distribution"]) != "0"
            or remoto.get("published") not in (False, "0")
            or not set(ETIQUETAS_BASE).issubset(etiquetas)
            or not mitre.issubset(galaxias)):
        raise ValueError("Visibilidad, identidad o etiquetas distintas en MISP.")
    def firma(a):
        return a["type"], a["value"].strip(), a["to_ids"] in (True, "1")

    if {firma(a) for a in remoto["Attribute"]} != {firma(a) for a in original["Attribute"]}:
        raise ValueError("Los atributos almacenados en MISP difieren de la campaña.")


def verificar_exportaciones(contenidos, eventos):
    csv_texto, reglas, stix = contenidos
    validar_privacidad(contenidos)
    valores = {a["value"] for ev in eventos for a in ev["Event"]["Attribute"]
               if a["type"] == "ip-dst" and a["to_ids"]}
    filas = list(csv.DictReader(io.StringIO(csv_texto)))
    if not valores or not valores.issubset({f.get("value") for f in filas}):
        raise ValueError("El CSV no contiene los destinos IDS del ejercicio.")
    if not all(any(ip in linea and re.match(r"^(alert|drop|reject)\s", linea)
                   for linea in reglas.splitlines()) for ip in valores):
        raise ValueError("Las reglas Suricata no contienen los destinos exportados.")
    indicadores = [o.get("pattern", "") for o in stix["objects"] if o.get("type") == "indicator"]
    if stix.get("type") != "bundle" or not all(any(ip in p for p in indicadores) for ip in valores):
        raise ValueError("El bundle STIX no contiene los indicadores esperados.")


def cargar(misp, eventos, salida):
    existentes = misp.pedir("/events/restSearch", {"returnFormat": "json", "tags": [ETIQUETA_PROYECTO],
                                                    "metadata": True})["response"]
    if existentes:
        raise ValueError(f"Ya hay {len(existentes)} eventos del proyecto. Se conserva la carga anterior.")
    creados = []
    for ev in eventos:
        creado = misp.pedir("/events/add", {"Event": ev["Event"]})["Event"]
        ident = str(creado["id"])
        if not ident.isdecimal():
            raise ValueError("Identificador de evento MISP inválido.")
        print(f"Evento creado: {ident} | {ev['Event']['info']}", flush=True)
        informe = misp.pedir(f"/eventReports/add/{ident}", {"EventReport": {
            "name": "Informe AegisHealth-CTI", "content": ev["_informe"], "distribution": "5"}})["EventReport"]
        id_informe = str(informe["id"])
        if not id_informe.isdecimal():
            raise ValueError("Identificador de informe MISP inválido.")
        guardado = misp.pedir(f"/eventReports/view/{id_informe}")["EventReport"]
        if (guardado.get("content") != ev["_informe"] or str(guardado["event_id"]) != ident
                or str(guardado["distribution"]) not in {"0", "5"}):
            raise ValueError(f"Informe incompleto en evento {ident}.")
        creados.append(ident)

    detalles = []
    destinos = {ident: {a["value"] for a in ev["Event"]["Attribute"] if a["type"] == "ip-dst"}
                for ident, ev in zip(creados, eventos, strict=True)}
    correlacion = False
    for ident, ev in zip(creados, eventos, strict=True):
        almacenado = misp.pedir(f"/events/view/{ident}")["Event"]
        verificar_evento(almacenado, ev)
        for relacionado in almacenado.get("RelatedEvent", []):
            otro = str(relacionado["Event"]["id"])
            if otro != ident and destinos[ident].intersection(destinos.get(otro, set())):
                correlacion = True
        codigo = next((c for c in CAMPANAS if c in ev["Event"]["info"]), "consolidado")
        detalles.append({"codigo": codigo, "id": ident})
    if not correlacion:
        raise ValueError("MISP aún no muestra una correlación entre campañas con destino compartido.")
    filtros = {"tags": [ETIQUETA_PROYECTO], "eventid": creados, "to_ids": 1, "published": 0}
    contenidos = [misp.pedir("/attributes/restSearch", {**filtros, "returnFormat": formato}, mime)
                  for formato, mime in (("csv", "text/plain"), ("suricata", "text/plain"), ("stix2", "application/json"))]
    verificar_exportaciones(contenidos, eventos)
    resumen = {"verificado": True, "fecha": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "eventos": detalles, "distribucion": DISTRIBUCION, "publicado_a_comunidades": False,
               "extracciones": list(ARCHIVOS)}
    estado_verificado(resumen)
    # La API solo observa el resumen después de validar y guardar las tres extracciones.
    with tempfile.TemporaryDirectory(dir=salida) as temporal:
        tmp = Path(temporal)
        for nombre, contenido in zip(ARCHIVOS, contenidos, strict=True):
            (tmp / nombre).write_text(contenido if isinstance(contenido, str) else json.dumps(contenido),
                                      encoding="utf-8")
        nombre_resumen = "misp_publicacion.json"
        (tmp / nombre_resumen).write_text(json.dumps(resumen, ensure_ascii=False, indent=2), encoding="utf-8")
        for nombre in (*ARCHIVOS, nombre_resumen):
            (tmp / nombre).replace(salida / nombre)


def main():
    p = argparse.ArgumentParser(description="Cargar y verificar inteligencia de ejercicio en MISP local")
    p.add_argument("--exports", type=Path, default=Path("data/exports_10m"))
    p.add_argument("--salida", type=Path, help="Carpeta de resultados; por defecto <exports>/misp")
    p.add_argument("--simular", action="store_true", help="Generar únicamente el JSON local de ensayo")
    a = p.parse_args()
    salida = a.salida or a.exports / "misp"
    try:
        eventos = construir_eventos(a.exports)
        validar_privacidad(eventos)
        salida.mkdir(parents=True, exist_ok=True)
        print(f"Eventos: {len(eventos)} | atributos: {sum(len(e['Event']['Attribute']) for e in eventos)}")
        if a.simular:
            (salida / "eventos_simulados.json").write_text(json.dumps(eventos, ensure_ascii=False, indent=2),
                                                           encoding="utf-8")
            return
        misp = ClienteMISP(os.getenv("MISP_URL", "https://127.0.0.1:8443"), os.getenv("MISP_API_KEY", ""),
                           os.getenv("MISP_VERIFY_SSL", "true"))
        cargar(misp, eventos, salida)
        print("Carga verificada. Resumen disponible en", salida / "misp_publicacion.json")
    except (OSError, ValueError, KeyError, TypeError) as error:
        p.exit(1, f"Carga incompleta: {error}\n")


if __name__ == "__main__":
    main()
