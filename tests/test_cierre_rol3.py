import hashlib
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.cti_exports.cache_f11 import CacheF11, guardar_cache, leer_cache
from app.llm.conclusiones import OllamaNoDisponible, generar_conclusiones
from app.main import app
from app.servicios.conclusiones import DatosF11NoDisponibles
from app.servicios.reporte_f11 import generar_reporte_auditado

cliente = TestClient(app)


def test_regeneracion_acepta_una_seccion_y_rechaza_texto_del_cliente():
    with patch("app.api.llm.hechos_para_conclusiones", return_value={"total": 50}), \
         patch("app.api.llm.generar_conclusiones", return_value="Conclusión.") as generar:
        ruta = "/api/v1/llm/regenerate-section"
        respuesta = cliente.post(ruta, json={"section": "conclusions"})
        assert respuesta.status_code == 200
        assert respuesta.json() == {"section": "conclusions", "text": "Conclusión."}
        assert cliente.post(ruta, json={"section": "intro"}).status_code == 422
        assert cliente.post(ruta, json={"section": "conclusions", "text": "Datos crudos"}).status_code == 422
        generar.assert_called_once_with({"total": 50})


def test_ollama_envia_hechos_a_http_local_y_valida_la_salida(monkeypatch):
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
    with patch("app.llm.conclusiones.HTTPConnection") as conectar:
        conexion = conectar.return_value
        respuesta = conexion.getresponse.return_value.__enter__.return_value
        respuesta.status = 200
        respuesta.read.return_value = json.dumps({
            "done": True,
            "message": {"content": json.dumps({"lectura": "calidad_datos", "prioridad": "reloj"})},
        }).encode()
        texto = generar_conclusiones({"ips_sin_puntos": 1280})
        assert "1.280 IP sin puntos" in texto
        assert "sincronización de los relojes" in texto
        metodo, ruta = conexion.request.call_args.args
        solicitud = json.loads(conexion.request.call_args.kwargs["body"])
        assert (metodo, ruta) == ("POST", "/api/chat")
        assert solicitud["think"] is False
        assert '{"ips_sin_puntos": 1280}' in solicitud["messages"][1]["content"]

        respuesta.read.return_value = b'{"done":true,"done_reason":"length"}'
        with pytest.raises(OllamaNoDisponible):
            generar_conclusiones({"eventos": 50})
        assert conectar.call_count == 2
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://example.com")
        with pytest.raises(OllamaNoDisponible):
            generar_conclusiones({"eventos": 50})
        assert conectar.call_count == 2


def test_regeneracion_con_ollama_caido_devuelve_503():
    with patch("app.api.llm.hechos_para_conclusiones", return_value={"total": 50}), \
         patch("app.api.llm.generar_conclusiones", side_effect=OllamaNoDisponible):
        respuesta = cliente.post("/api/v1/llm/regenerate-section", json={"section": "conclusions"})
    assert respuesta.status_code == 503


def test_cache_ligada_a_los_insumos(monkeypatch, tmp_path):
    ruta = tmp_path / "llm_cache.json"
    monkeypatch.setenv("LLM_CACHE_PATH", str(ruta))
    with pytest.raises(DatosF11NoDisponibles):
        leer_cache("a" * 64)
    cache = CacheF11(sha256_insumos="a" * 64, text="Texto revisable.")
    guardar_cache(cache)
    assert leer_cache("a" * 64) == cache
    assert list(tmp_path.iterdir()) == [ruta]
    with pytest.raises(DatosF11NoDisponibles):
        leer_cache("b" * 64)


def test_pdf_registra_huella_antes_de_devolver_y_respeta_la_revision(monkeypatch, tmp_path):
    from app.servicios.reporte_f11 import huella_insumos

    monkeypatch.setenv("LLM_CACHE_PATH", str(tmp_path / "llm_cache.json"))
    insumos = ({"escenarios": []}, {}, {})
    huella = huella_insumos(*insumos)
    contenido = b"%PDF-1.7"
    with patch("app.servicios.reporte_f11.recopilar_insumos", return_value=insumos), \
         patch("app.servicios.reporte_f11.comprobar_cadena_auditoria",
               return_value={"intact": True, "checked_rows": 7}), \
         patch("app.servicios.reporte_f11.dibujar_graficos", return_value=("horario", "ipe")), \
         patch("app.servicios.reporte_f11.renderizar_pdf", return_value=contenido) as renderizar, \
         patch("app.servicios.reporte_f11.conectar_postgres") as conectar, \
         patch("app.servicios.reporte_f11.registrar_evento_auditoria", return_value=(8, "hash")) as registrar:
        guardar_cache(CacheF11(sha256_insumos=huella, text="Conclusión."))
        assert generar_reporte_auditado()[1] == "Reporte_CTI_Tecnico_F11_AegisHealth.pdf"
        assert "Pendiente" in renderizar.call_args.args[0]["estado"]
        guardar_cache(CacheF11(sha256_insumos=huella, text="Conclusión.", revisado=True))
        respuesta = cliente.post("/api/v1/reports/generate-pdf")
        sha256 = hashlib.sha256(contenido).hexdigest()
        assert respuesta.status_code == 200
        assert respuesta.headers["X-Report-SHA256"] == sha256
        assert respuesta.headers["X-Audit-Id"] == "8"
        assert 'filename="Reporte_CTI_Tecnico_F11_AegisHealth.pdf"' in respuesta.headers["Content-Disposition"]
        assert renderizar.call_args.args[1] == "technical"
        assert registrar.call_args.kwargs["operation"] == "EXPORT_TECHNICAL_F11_PDF"
        assert registrar.call_args.kwargs["metadata"]["reviewed"] is True
        assert registrar.call_args.kwargs["dataset_sha256"] == sha256

        respuesta = cliente.post("/api/v1/reports/generate-pdf", json={
            "audience": "technical", "format": "F-11", "summary": "Revisar durante el turno.",
        })
        assert respuesta.status_code == 200
        assert renderizar.call_args.args[0]["nota_solicitante"] == "Revisar durante el turno."

        import psycopg
        conectar.return_value.__exit__.side_effect = psycopg.OperationalError("commit")
        respuesta = cliente.post("/api/v1/reports/generate-pdf")
        assert respuesta.status_code == 503
        assert b"%PDF" not in respuesta.content


def test_pdf_medico_solo_renderiza_agregados_y_audita_el_archivo():
    contenido = b"%PDF-medico"
    with patch("app.servicios.reporte_f11.comprobar_cadena_auditoria", return_value={"intact": True}), \
         patch("app.servicios.reporte_f11.renderizar_pdf", return_value=contenido) as renderizar, \
         patch("app.servicios.reporte_f11.conectar_postgres"), \
         patch("app.servicios.reporte_f11.registrar_evento_auditoria", return_value=(9, "hash")) as registrar:
        respuesta = cliente.post("/api/v1/reports/generate-pdf", json={
            "audience": "medical", "format": "EJECUTIVO_MEDICO", "summary": "Texto privado del cliente",
        })
    assert respuesta.status_code == 200
    assert respuesta.content == contenido
    assert respuesta.headers["content-type"] == "application/pdf"
    nombre = "Reporte_Ejecutivo_Medico_AegisHealth.pdf"
    assert respuesta.headers["Content-Disposition"] == f'attachment; filename="{nombre}"'
    renderizar.assert_called_once_with({"cuentas": 16}, "medical")
    evento = registrar.call_args.kwargs
    assert evento["operation"] == "EXPORT_MEDICAL_PDF"
    assert evento["dataset_name"] == nombre
    assert evento["dataset_sha256"] == respuesta.headers["X-Report-SHA256"] == hashlib.sha256(contenido).hexdigest()
    assert respuesta.headers["X-Audit-Id"] == "9"
    assert "Texto privado" not in str(evento)


@pytest.mark.parametrize("solicitud", [
    {"audience": "otro"}, {"format": "docx"}, {"summary": {}},
    {"audience": "medical", "format": "F-11"}, {"audience": "technical", "format": "EJECUTIVO_MEDICO"},
])
def test_pdf_rechaza_solicitudes_invalidas_antes_de_exportar(solicitud):
    with patch("app.api.rutas.generar_reporte_auditado") as generar:
        assert cliente.post("/api/v1/reports/generate-pdf", json=solicitud).status_code == 422
        generar.assert_not_called()
