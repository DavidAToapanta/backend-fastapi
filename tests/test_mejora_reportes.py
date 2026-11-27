import base64
import json
import re
from datetime import date, datetime, timezone
from pathlib import Path
from unittest.mock import patch

from app.cti_exports.cache_f11 import CacheF11, guardar_cache
from app.cti_exports.contenido_f11 import HALLAZGOS
from app.cti_exports.graficos import dibujar_graficos
from app.cti_exports.pdf_compiler import (
    preparar_datos_de_ejemplo,
    preparar_datos_ejecutivo_ejemplo,
    renderizar_html,
)
from app.llm.conclusiones import EnfoqueConclusiones, redactar_conclusion
from app.servicios.panel import AnomaliasSinConfirmar, MetricasML
from app.servicios.reporte_f11 import (
    huella_insumos,
    preparar_ejecutivo_medico,
    preparar_f11,
)

PROHIBIDAS_EJECUTIVO = re.compile(r"\b(?:IoC|IoA|MITRE|SSH|IP|Sigma|STIX|HMAC)\b")
IP_SIN_DEFANG = re.compile(r"186\.46\.219\.18")


def _extraer_texto_svg(data_uri: str) -> str:
    prefijo = "data:image/svg+xml;base64,"
    assert data_uri.startswith(prefijo)
    return base64.b64decode(data_uri[len(prefijo):]).decode("utf-8")


def test_ejecutivo_medico_cumple_bluf_tres_semaforos_lopdp_y_sin_jerga():
    datos, _ = preparar_ejecutivo_medico()
    html = renderizar_html(datos, audiencia="medical")

    idx_urgente = html.index("LO MÁS IMPORTANTE")
    idx_autorizar = html.index("LO QUE NECESITAMOS QUE USTED AUTORICE HOY")
    assert idx_urgente < html.index("Estado del riesgo") < idx_autorizar < html.index("Plan de acción")

    assert "Posible salida de información de salud" in html
    assert "30 segundos después, hubo una conexión hacia un servidor externo" in html
    assert "11 de las" in html and "1.737" in html

    assert "Confidencialidad" in html
    assert "Integridad" in html
    assert "Disponibilidad" in html

    assert "LOPDP" in html and "artículo 43" in html
    assert "máximo 5 días" in html
    assert "16 días antes" in html

    assert "TLP:AMBER" in html
    assert "TLP:RED" not in html
    assert "Pendiente de revisión" not in html
    assert "Rol 1" not in html and "Rol 5" not in html
    assert "UTC" not in html and "+00:00" not in html
    assert not PROHIBIDAS_EJECUTIVO.search(html)


def test_ejecutivo_ejemplo_strict_undefined_completo():
    html = renderizar_html(preparar_datos_ejecutivo_ejemplo(), audiencia="medical")
    assert "LO MÁS IMPORTANTE" in html
    assert "TLP:AMBER" in html


def test_tecnico_f11_ejemplo_strict_undefined_cumple_estructura_y_verificacion():
    datos = preparar_datos_de_ejemplo()
    html = renderizar_html(datos, audiencia="technical")

    for marcador in (
        "0. Resumen de inteligencia",
        "1. Fuentes y metodología",
        "2. Evaluación de adversarios",
        "3. Inteligencia estratégica",
        "4. Inteligencia táctica",
        "5. Inteligencia operativa",
        "6. Inteligencia técnica",
        "7. Evaluación de escenarios (IPE) y anticipación",
        "8. Conclusiones, priorización de controles y brechas",
        "Anexo A. Integridad criptográfica y trazabilidad",
        "Anexo B. Calidad de datos y cumplimiento LOPDP",
    ):
        assert marcador in html

    posiciones = [
        html.index("0. Resumen de inteligencia"),
        html.index("1. Fuentes y metodología"),
        html.index("2. Evaluación de adversarios"),
        html.index("3. Inteligencia estratégica"),
        html.index("4. Inteligencia táctica"),
        html.index("5. Inteligencia operativa"),
        html.index("6. Inteligencia técnica"),
        html.index("7. Evaluación de escenarios (IPE) y anticipación"),
        html.index("8. Conclusiones, priorización de controles y brechas"),
        html.index("Anexo A. Integridad criptográfica y trazabilidad"),
        html.index("Anexo B. Calidad de datos y cumplimiento LOPDP"),
    ]
    assert posiciones == sorted(posiciones)


def test_tecnico_f11_con_insumos_auditados_cumple_checklist_completo(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_CACHE_PATH", str(tmp_path / "llm_cache.json"))

    resumen_mock = {
        "total_eventos": 10023532,
        "ips_sin_puntos": 1280,
        "horas": 744,
        "por_fuente": [
            {"fuente": "FIREWALL", "eventos": 5009031, "ips_sin_puntos": 493},
            {"fuente": "MEDSYS", "eventos": 5014501, "ips_sin_puntos": 787},
        ],
        "seudonimizacion_registrada": True,
        "ml": {
            "genericas": MetricasML(
                incidentes_en_top_n="4/5",
                top_n_evaluado=50,
                anomalias_no_confirmadas_en_top_n=AnomaliasSinConfirmar(
                    fw_hora=47, med_hora=47, med_periodo=47
                ),
            ),
            "dominio": MetricasML(
                incidentes_en_top_n="5/5",
                top_n_evaluado=50,
                anomalias_no_confirmadas_en_top_n=AnomaliasSinConfirmar(
                    fw_hora=46, med_hora=49, med_periodo=47
                ),
            ),
        },
    }

    dias = [date(2026, 10, d) for d in range(1, 32)]
    matriz = [[100] * 31 for _ in range(24)]
    mapa_mock = {"zona_horaria": "LOCAL", "dias": dias, "horas": list(range(24)), "matriz": matriz}

    campanas_mock = [
        {
            "codigo": codigo,
            "titulo": codigo,
            "tipo_adversario": "HYBRID",
            "severidad": "CRITICA" if codigo == "CAMP-2026-001" else "ALTA",
            "calificacion_admiralty": "B2",
            "eventos": 10,
            "primera_observacion": datetime(2026, 10, 1, tzinfo=timezone.utc),
            "ultima_observacion": datetime(2026, 10, 31, tzinfo=timezone.utc),
            "tecnicas_mitre": ["T1078", "T1048.002"] if codigo == "CAMP-2026-001" else ["T1078"],
            "iocs": {},
            "ioas": [],
        }
        for codigo in HALLAZGOS
    ]

    linea_mock = [
        {
            "id": 1,
            "fecha": datetime(2026, 10, 24, 22, 40, 0, tzinfo=timezone.utc),
            "fuente": "FIREWALL",
            "actor": "USR-1",
            "cuenta": "ACC-1",
            "ip_origen": "10.10.100.40",
            "ip_destino": "10.10.100.30",
            "puerto_destino": 22,
            "resumen": "SSH 10.10.100.40 -> 10.10.100.30 (permitido)",
            "ajuste_de_reloj": False,
        },
        {
            "id": 2,
            "fecha": datetime(2026, 10, 24, 22, 40, 15, tzinfo=timezone.utc),
            "fuente": "MEDSYS",
            "actor": "USR-1",
            "cuenta": "ACC-1",
            "ip_origen": "10.10.100.40",
            "ip_destino": "10.10.100.30",
            "puerto_destino": None,
            "resumen": "DESCARGA EXITOSA",
            "ajuste_de_reloj": True,
        },
        {
            "id": 3,
            "fecha": datetime(2026, 10, 24, 22, 40, 30, tzinfo=timezone.utc),
            "fuente": "FIREWALL",
            "actor": "USR-1",
            "cuenta": "ACC-1",
            "ip_origen": "10.10.100.40",
            "ip_destino": "186.46.219.18",
            "puerto_destino": 8443,
            "resumen": "Salida a 186.46.219.18:8443 (permitido)",
            "ajuste_de_reloj": False,
        },
    ]

    evidencia = json.loads(
        (Path(__file__).resolve().parents[1] / "docs" / "evidencias" / "evidencias.json").read_text(encoding="utf-8-sig")
    )["resumen_datasets"]
    eventos_auditoria = [
        {
            "operacion": "INGEST_FIREWALL_10M",
            "sha256_dataset": evidencia["firewall"]["sha256"],
            "filas_leidas": evidencia["firewall"]["total_filas"],
            "pii_depurada": True,
        },
        {
            "operacion": "INGEST_MEDSYS_10M",
            "sha256_dataset": evidencia["sistema_medico"]["sha256"],
            "filas_leidas": evidencia["sistema_medico"]["total_filas"],
            "pii_depurada": True,
        },
    ]
    stix_bytes = json.dumps(
        {
            "type": "bundle",
            "objects": [
                {"type": "indicator", "spec_version": "2.1", "labels": ["synthetic-exercise-data", "hackathon-simulation"]}
                for _ in range(82)
            ],
        }
    ).encode("utf-8")
    sigma_mock = {
        "ioa": [{"archivo": "ioa_01.yml", "titulo": "IoA ejemplo", "yaml": "title: IoA ejemplo"}],
        "ioc": [{"archivo": "ioc_01.yml", "titulo": "IoC ejemplo", "yaml": "title: IoC ejemplo"}],
    }

    with patch("app.servicios.reporte_f11.consultar_resumen_panel", return_value=resumen_mock), \
         patch("app.servicios.reporte_f11.listar_eventos_auditoria", return_value=eventos_auditoria), \
         patch("app.servicios.reporte_f11.consultar_mapa_horario", return_value=mapa_mock), \
         patch("app.servicios.reporte_f11.consultar_campanas", return_value=campanas_mock), \
         patch("app.servicios.reporte_f11.consultar_linea_tiempo", return_value=linea_mock), \
         patch("app.servicios.reporte_f11.leer_reglas_sigma", return_value=sigma_mock), \
         patch("app.servicios.reporte_f11.leer_paquete_stix", return_value=stix_bytes):
        from app.servicios.reporte_f11 import recopilar_insumos

        datos, mapa, hechos = recopilar_insumos()
        huella = huella_insumos(datos, mapa, hechos)
        conclusion = redactar_conclusion(
            EnfoqueConclusiones(lectura="cobertura_ml", prioridad="egreso"),
            hechos,
        )
        guardar_cache(CacheF11(sha256_insumos=huella, text=conclusion, revisado=True))
        datos_pdf, meta = preparar_f11({"intact": True, "checked_rows": 12}, summary=None)

    assert meta["reviewed"] is True
    html = renderizar_html(datos_pdf, audiencia="technical")

    # 1. Portada y Sección 0 BLUF primero + tabla ordenada 001 -> 005 -> 004 -> 002 -> 003
    assert html.index("0. Resumen de inteligencia") < html.index("1. Fuentes y metodología")
    idx_prio = html.index("Campañas ordenadas por prioridad operativa")
    tabla_prio = html[idx_prio:html.index("Cinco acciones prioritarias")]
    assert (
        tabla_prio.index("CAMP-2026-001")
        < tabla_prio.index("CAMP-2026-005")
        < tabla_prio.index("CAMP-2026-004")
        < tabla_prio.index("CAMP-2026-002")
        < tabla_prio.index("CAMP-2026-003")
    )
    assert "Cinco acciones prioritarias" in html

    # 2. TLP:AMBER y sin sellos ni menciones prohibidas
    assert "TLP:AMBER" in html
    assert "TLP:RED" not in html
    assert "Pendiente de revisión" not in html
    assert "Rol 1" not in html and "Rol 5" not in html

    # 3. Hora local sin +00:00 ni UTC (HTML + SVG horario)
    assert "hora local del registro" in html
    assert "+00:00" not in html
    assert "UTC" not in html
    assert "2026-10-24 10:40:15" in html
    assert "2026-10-24 22:40:15 (+12 h)" in html
    svg_horario = _extraer_texto_svg(datos_pdf["grafico_horario"])
    assert "UTC" not in svg_horario
    assert "hora local del registro" in svg_horario

    # 4. Anticipación, LOPDP art. 43, IP defangeada y Anexo A al final
    assert "16 días" in html
    assert "2 falsas alarmas en 744 h" in html
    assert "4/5 en su Top-3" in html
    assert "art. 43 de la LOPDP" in html and "máximo hasta en 5 días" in html
    assert "186.46.219[.]18" in html
    assert not IP_SIN_DEFANG.search(html)

    assert html.index("8. Conclusiones") < html.index("Anexo A. Integridad criptográfica")
    assert html.index("Anexo A. Integridad criptográfica") < html.index(evidencia["firewall"]["sha256"])
    assert html.index("Anexo A. Integridad criptográfica") < html.index(huella)


def test_graficos_sin_etiqueta_utc():
    dias = [date(2026, 10, d) for d in range(1, 32)]
    mapa = {"dias": dias, "matriz": [[1] * 31 for _ in range(24)]}
    escenarios = [("Más probable", "Alta", "Alto", "Desc"), ("Más peligroso", "Media", "Crítico", "Desc")]
    horario_uri, _ = dibujar_graficos(mapa, escenarios)
    svg = _extraer_texto_svg(horario_uri)
    assert "UTC" not in svg
    assert "hora local" in svg
