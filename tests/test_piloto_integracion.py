import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from psycopg.conninfo import conninfo_to_dict

from app.core.conexion_postgres import conectar_postgres
from app.datos_demo.cargar_guardian import AFILIADO_CRITICO, CUENTA_SINTETICA, cargar, construir_eventos
from app.main import app
from app.servicios.centinela_privacidad import hash_valor
from app.servicios.guardian_cuenta import evaluar_eventos


def test_evidencia_bancaria_posterior_al_cambio_no_cuenta(monkeypatch):
    monkeypatch.setenv("AEGIS_HMAC_CLAVE", "solo-pruebas")
    inicio = datetime(2026, 10, 24, 22, tzinfo=timezone.utc)
    eventos = construir_eventos(inicio)
    evidencia = {"fecha_hora": (inicio + timedelta(minutes=30)).isoformat(),
                 "cuentas_hash": [hash_valor(CUENTA_SINTETICA, "solo-pruebas")], "campana_id": "CEN-PRUEBA"}
    criticas = [a for a in evaluar_eventos(eventos, [evidencia])["alertas"] if a["severidad"] == "CRITICA"]
    assert len(criticas) == 1
    assert criticas[0]["vinculo_phishing"] is None


@pytest.mark.skipif(not os.getenv("PILOTO_TEST_DSN"), reason="requiere PostgreSQL aislado con la migración")
def test_flujo_real_de_reporte_a_decision(monkeypatch):
    dsn = os.environ["PILOTO_TEST_DSN"]
    assert conninfo_to_dict(dsn)["dbname"] == "guardian_pruebas"
    monkeypatch.setenv("DATABASE_URL", dsn)
    monkeypatch.setenv("AEGIS_HMAC_CLAVE", "solo-pruebas")
    def huella(valor):
        return hashlib.sha256(valor.encode()).hexdigest()
    monkeypatch.setenv("PILOTO_SESIONES_JSON", json.dumps({
        "afiliado": {"keySha256": huella("sesion-a"), "affiliate": AFILIADO_CRITICO},
        "anonimo1": {"keySha256": huella("sesion-b"), "affiliate": None},
        "anonimo2": {"keySha256": huella("sesion-c"), "affiliate": None},
    }))
    monkeypatch.setenv("PILOTO_ANALISTAS_JSON", json.dumps({
        "analista": huella("prueba-analista"), "observador": huella("prueba-observador"),
    }))
    monkeypatch.setenv("NOTIFICACIONES_SMTP_HABILITADO", "false")
    analista = {"Authorization": "Bearer prueba-analista", "X-Analyst-Id": "analista"}
    observador = {"Authorization": "Bearer prueba-observador", "X-Analyst-Id": "observador"}
    reportes = "/api/v1/centinela/reportes"
    casos = "/api/v1/guardian/casos"
    evaluar = "/api/v1/guardian/evaluar"
    mensaje = {"text": f"Aviso de prueba https://alerta.example/privado?correo=persona@correo.test "
                       f"y cuenta {CUENTA_SINTETICA}", "province": "Pichincha"}
    with conectar_postgres() as conn:
        assert conn.execute("SELECT count(*) FROM cti_piloto.reportes").fetchone()[0] == 0

    with TestClient(app) as cliente:
        assert cliente.post(reportes, json=mensaje).status_code == 401
        invalido = cliente.post(reportes, json={**mensaje, "affiliate": "dato-privado"})
        assert invalido.status_code == 422
        assert "dato-privado" not in invalido.text
        assert cliente.post(evaluar).status_code == 401
        clave = {"Authorization": "Bearer sesion-a"}
        respuesta = cliente.post(reportes, headers=clave, json=mensaje)
        assert respuesta.status_code == 201, respuesta.text
        reporte = respuesta.json()
        assert "alerta[.]example" in reporte["indicators"]["domains"]
        for texto in ("privado", "persona@correo.test", CUENTA_SINTETICA):
            assert texto not in respuesta.text

        with conectar_postgres() as conn:
            contenido = conn.execute("SELECT row_to_json(r)::text FROM cti_piloto.reportes r").fetchone()[0]
            for dato in ("privado", "persona@correo.test", CUENTA_SINTETICA, "sesion-a"):
                assert dato not in contenido
        assert cargar(datetime.now(timezone.utc) + timedelta(seconds=1)) == 21
        assert cargar(datetime.now(timezone.utc) + timedelta(hours=1)) == 0

        reporte_umbral_id = None
        for token, provincia in [("sesion-b", "Azuay"), ("sesion-c", "Guayas")]:
            alta = cliente.post(reportes, headers={"Authorization": f"Bearer {token}"},
                               json={"text": "https://alerta.example", "province": provincia})
            assert alta.status_code == 201
            reporte_umbral_id = alta.json()["reportId"]

    with TestClient(app) as cliente:
        reenviado = cliente.post(reportes, headers=clave, json=mensaje)
        assert reenviado.status_code == 200
        assert reenviado.json()["reportId"] == reporte["reportId"]
        grupos = cliente.get("/api/v1/centinela/campanas").json()
        assert grupos[0]["reportCount"] == 3
        assert grupos[0]["byProvince"] == {"Azuay": 1, "Guayas": 1, "Pichincha": 1}
        assert grupos[0]["status"] == "AVISO_A_AFILIADOS"
        assert cliente.get(f"/api/v1/centinela/campanas/por-reporte/{reporte['reportId']}",
                           headers=analista).json() == grupos[0]
        avisos = cliente.get("/api/v1/notificaciones", headers=analista).json()
        assert len(avisos["items"]) == 1
        assert avisos["items"][0]["source"] == "CENTINELA"
        assert avisos["items"][0]["referenceId"] == reporte_umbral_id
        assert avisos["unreadCount"] == 1
        resultado = cliente.post(evaluar, headers=analista)
        assert resultado.status_code == 200, resultado.text
        resultado = resultado.json()
        assert len(resultado["alerts"]) == 6
        assert len(resultado["cases"]) == 2
        assert next(a for a in resultado["alerts"] if a["severity"] == "BAJA")["caseId"] is None
        critico = next(c for c in resultado["cases"] if c["evidence"]["rule"] == "GUARD-01")
        desembolso = next(c for c in resultado["cases"] if c["evidence"]["rule"] == "GUARD-03")
        assert critico["evidence"]["phishingReportId"] == reporte["reportId"]
        assert critico["status"] == "EN_REVISION"
        avisos = cliente.get("/api/v1/notificaciones", headers=analista).json()
        assert avisos["unreadCount"] == 2
        assert {aviso["source"] for aviso in avisos["items"]} == {"CENTINELA", "GUARDIAN"}
        aviso_guardian = next(aviso for aviso in avisos["items"] if aviso["source"] == "GUARDIAN")
        assert aviso_guardian["referenceId"] == critico["caseId"]
        assert cliente.post(evaluar, headers=analista).status_code == 200
        assert len(cliente.get("/api/v1/notificaciones", headers=analista).json()["items"]) == 2
        assert cliente.get("/api/v1/notificaciones", headers=observador).json()["unreadCount"] == 2
        lectura = cliente.post(f"/api/v1/notificaciones/{aviso_guardian['id']}/leer", headers=analista)
        assert lectura.status_code == 200
        assert cliente.post(f"/api/v1/notificaciones/{aviso_guardian['id']}/leer", headers=analista).json() == lectura.json()
        assert cliente.get("/api/v1/notificaciones", headers=analista).json()["unreadCount"] == 1
        assert cliente.get("/api/v1/notificaciones", headers=observador).json()["unreadCount"] == 2
        assert cliente.get(f"{casos}/{uuid4()}", headers=analista).status_code == 404
        assert cliente.get(f"{casos}/{critico['caseId']}", headers=analista).json() == critico

        decision = {"decision": "CONFIRMAR", "reason": "Se verificó la evidencia sintética."}
        ruta = f"{casos}/{critico['caseId']}/decision"
        with ThreadPoolExecutor(max_workers=2) as pool:
            respuestas = list(pool.map(lambda _: cliente.post(ruta, headers=analista, json=decision), range(2)))
        assert [r.status_code for r in respuestas] == [200, 200]
        resuelto = respuestas[0].json()
        assert resuelto["status"] == "CONFIRMADO"
        assert resuelto["auditId"] == respuestas[1].json()["auditId"]
        assert cliente.post(ruta, headers=analista, json={**decision, "decision": "DESCARTAR"}).status_code == 409

        respuesta = cliente.post(f"{casos}/{desembolso['caseId']}/decision", headers=analista,
                                 json={**decision, "decision": "DESCARTAR"})
        assert respuesta.status_code == 200
        assert respuesta.json()["operationStatus"] == "LIBERADA"
        actualizados = cliente.post(evaluar, headers=analista).json()["cases"]
        assert {c["status"] for c in actualizados} == {"CONFIRMADO", "DESCARTADO"}
        assert len(cliente.get(casos, headers=analista).json()) == 2
        cadena = cliente.get("/api/v1/audit/verify-chain").json()
        assert cadena == {"intact": True, "checkedRows": 2}
