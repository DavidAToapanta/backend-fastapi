import json
import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient

from app.integraciones import misp_publicador as misp
from app.integraciones.misp_estado import ARCHIVOS, CAMPANAS
from app.main import app


@pytest.mark.skipif(not os.getenv("MISP_EXPORTS_PRUEBA"), reason="requiere la exportación del Rol 2")
def test_exportacion_oficial():
    eventos = misp.construir_eventos(Path(os.environ["MISP_EXPORTS_PRUEBA"]))
    misp.validar_privacidad(eventos)
    assert len(eventos) == 6
    atributos = [e["Event"]["Attribute"] for e in eventos]
    assert sum(len(grupo) for grupo in atributos) == 35
    assert all(len({(a["type"], a["value"]) for a in grupo}) == len(grupo) for grupo in atributos)
    assert {a["type"] for grupo in atributos for a in grupo} == {"ip-src", "ip-dst", "ip-dst|port", "sigma", "target-user"}
    clinicas = {e["Event"]["info"].split(" | ")[1] for e in eventos
                if any(a["value"] == "10.10.100.30" for a in e["Event"]["Attribute"])}
    assert clinicas == {"CAMP-2026-001", "CAMP-2026-002"}
    assert any(a["type"] == "ip-dst|port" and a["value"] == "186.46.219.18|8443" and a["to_ids"]
               for grupo in atributos for a in grupo)


@pytest.fixture
def fuentes(tmp_path):
    def guardar(nombre, valor):
        (tmp_path / nombre).write_text(json.dumps(valor), encoding="utf-8")

    ip = "192.0.2.10"
    campanas = [{"campaign_code": codigo, "iocs": {"source_ips": [], "destination_ips": [ip],
                 "account_tokens": ["ACC-0123456789AB"]}, "ioas": [], "mitre_techniques": [],
                 "summary": "Ensayo", "first_seen": "2026-11-01", "last_seen": "2026-11-01",
                 "severity": "MEDIA", "adversary_type": "Ejercicio", "anomaly_score": 1,
                 "hallazgos": [], "evidence_refs": []} for codigo in CAMPANAS]
    guardar("campanas.json", {"campaigns": campanas, "escenarios_ipe": {}})
    guardar("anticipacion.json", {"pronostico_siguiente_fase": [], "riesgo_actual": {}, "alertas_tempranas": {},
                                "backtest_siguiente_fase": {"aciertos_top3": 0}, "backtest_incidentes": []})
    guardar("iocs_ejercicio.json", {"ips_destino_externas": [ip], "puertos_canal_sombra": [8443],
                                   "servidor_critico": "10.0.0.1"})
    return tmp_path


def test_simulacion_aislada(fuentes, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["publicador", "--simular", "--exports", str(fuentes)])
    with patch.object(misp, "ClienteMISP", side_effect=AssertionError("intentó conectarse")):
        misp.main()
    salida = fuentes / "misp"
    eventos = json.loads((salida / "eventos_simulados.json").read_bytes())
    assert len(eventos) == 6
    assert all(e["Event"]["published"] is False and e["Event"]["distribution"] == "0" for e in eventos)
    assert not (salida / "misp_publicacion.json").exists()


@pytest.mark.parametrize("campo", ["_informe", "Attribute"])
def test_privacidad_en_todo_el_evento(campo):
    with pytest.raises(SystemExit, match="ABORTADO"):
        misp.validar_privacidad([{campo: "identidad usr-001"}])


@pytest.mark.parametrize("url,tls", [("https://example.org", "true"), ("http://localhost", "true"),
                                     ("https://127.0.0.1", "false"), ("https://localhost@otro.test", "true")])
def test_destino_o_tls_invalidos(url, tls):
    with pytest.raises(ValueError):
        misp.ClienteMISP(url, "prueba", tls)


def test_no_sigue_redirecciones():
    with pytest.raises(ValueError, match="redirección"):
        misp.SinRedirecciones().redirect_request(None, None, 302, "", {}, "https://otro.test")


class ServidorSimulado:
    def __init__(self):
        self.eventos = []
        self.informes = []
        self.consultas = []

    def pedir(self, ruta, cuerpo=None, aceptar=None):
        if ruta == "/events/restSearch":
            return {"response": self.eventos}
        if ruta == "/events/add":
            self.eventos.append(cuerpo["Event"])
            return {"Event": {"id": len(self.eventos)}}
        if ruta.startswith("/eventReports/add/"):
            informe = {**cuerpo["EventReport"], "event_id": ruta.split("/")[-1], "id": len(self.informes) + 1}
            self.informes.append(informe)
            return {"EventReport": informe}
        if ruta.startswith("/eventReports/view/"):
            return {"EventReport": self.informes[int(ruta.split("/")[-1]) - 1]}
        if ruta.startswith("/events/view/"):
            evento = self.eventos[int(ruta.split("/")[-1]) - 1]
            return {"Event": {**evento, "RelatedEvent": [{"Event": {"id": "2"}}]}}
        assert ruta == "/attributes/restSearch"
        self.consultas.append(cuerpo)
        return {"csv": "value\n192.0.2.10\n", "suricata": "alert ip any any -> 192.0.2.10 any (sid:1;)",
                "stix2": {"type": "bundle", "objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '192.0.2.10']"}]}}[cuerpo["returnFormat"]]


def test_verificacion_y_consulta_sin_servidor(fuentes, monkeypatch):
    monkeypatch.setenv("METRICAS_ML_DIR", str(fuentes))
    salida = fuentes / "misp"
    salida.mkdir()
    servidor = ServidorSimulado()
    eventos = misp.construir_eventos(fuentes)
    misp.cargar(servidor, eventos, salida)
    assert len(servidor.informes) == 6
    assert all(c["published"] == 0 and len(c["eventid"]) == 6 for c in servidor.consultas)
    with pytest.raises(ValueError, match="Ya hay"):
        misp.cargar(servidor, eventos, salida)
    assert len(servidor.eventos) == 6
    with TestClient(app) as cliente:
        r = cliente.get("/api/v1/misp/estado")
        assert r.status_code == 200
        assert r.json()["eventCount"] == 6
        assert r.json()["exports"] == list(ARCHIVOS)


def test_interrupcion_conserva_resumen(fuentes):
    eventos = misp.construir_eventos(fuentes)
    ruta = fuentes / "misp_publicacion.json"
    ruta.write_bytes(b"resumen anterior")
    servidor = Mock()
    servidor.pedir.side_effect = [{"response": []}, {"Event": {"id": 1}}, OSError("interrumpido")]
    with pytest.raises(OSError):
        misp.cargar(servidor, eventos, fuentes)
    assert ruta.read_bytes() == b"resumen anterior"


def test_exportacion_vacia_conserva_ultima_carga(fuentes):
    eventos = misp.construir_eventos(fuentes)
    servidor = ServidorSimulado()
    pedir = servidor.pedir

    def exportacion_vacia(ruta, cuerpo=None, aceptar=None):
        if ruta == "/attributes/restSearch" and cuerpo["returnFormat"] == "suricata":
            return ""
        return pedir(ruta, cuerpo, aceptar)

    servidor.pedir = exportacion_vacia
    ruta = fuentes / "misp_publicacion.json"
    ruta.write_bytes(b"resumen anterior")
    with pytest.raises(ValueError, match="Suricata"):
        misp.cargar(servidor, eventos, fuentes)
    assert ruta.read_bytes() == b"resumen anterior"
    assert not any((fuentes / nombre).exists() for nombre in ARCHIVOS)


@pytest.mark.parametrize("contenido", [None, "{", "{}", '{"verificado": true}', "null"])
def test_estado_no_disponible(fuentes, monkeypatch, contenido):
    monkeypatch.setenv("METRICAS_ML_DIR", str(fuentes))
    salida = fuentes / "misp"
    salida.mkdir()
    if contenido is not None:
        (salida / "misp_publicacion.json").write_text(contenido, encoding="utf-8")
    with TestClient(app) as cliente:
        assert cliente.get("/api/v1/misp/estado").status_code == 503
        assert cliente.get("/health").status_code == 200
