"""Pruebas del catálogo de consecuencias y de las correcciones de los reportes (Rol 2)."""
import re

import pytest

from app.cti_exports.consecuencias import (
    CASOS,
    CONSECUENCIAS,
    catalogo_completo,
    consecuencias_por_codigo,
    filas_ejecutivo,
    filas_tecnico,
    fuentes_usadas,
)
from app.cti_exports.pdf_compiler import (
    preparar_datos_de_ejemplo,
    preparar_datos_ejecutivo_ejemplo,
    renderizar_html,
)
from app.llm.conclusiones import CONTROLES, EnfoqueConclusiones, redactar_conclusion

PROHIBIDAS_EJECUTIVO = re.compile(r"\b(?:IoC|IoA|MITRE|SSH|IP|Sigma|STIX|HMAC)\b")


def test_cada_consecuencia_tiene_caso_real_con_fuente():
    for grupo in CONSECUENCIAS:
        assert grupo["consecuencias"], grupo["id"]
        for c in grupo["consecuencias"]:
            caso = CASOS[c["caso"]]
            assert caso["url"].startswith("https://")
            assert caso["fuente"] and caso["hecho"] and caso["dato_simple"]


def test_todas_las_campanas_y_reglas_guardian_tienen_consecuencias():
    for codigo in ["CAMP-2026-001", "CAMP-2026-002", "CAMP-2026-003", "CAMP-2026-004", "CAMP-2026-005",
                   "GUARD-01", "GUARD-02", "GUARD-03", "GUARD-04", "CEN-001", "IOA-05"]:
        assert consecuencias_por_codigo(codigo), codigo


def test_codigo_invalido_se_rechaza():
    for codigo in ["1710034065", "CAMP-2026-009", "<script>", ""]:
        with pytest.raises(ValueError):
            consecuencias_por_codigo(codigo)


def test_exfiltracion_incluye_extorsion_y_obligacion_legal():
    grupos = consecuencias_por_codigo("CAMP-2026-001")
    casos = {c["caso"] for g in grupos for c in g["consecuencias"]}
    assert {"vastaamo", "medibank"} <= casos
    assert any("art. 43" in (g["obligacion"] or "") for g in grupos)


def test_catalogo_sin_datos_personales():
    texto = str(catalogo_completo())
    assert not re.search(r"\b\d{10}\b", texto)           # sin cédulas
    assert "186.46.219.18" not in texto                  # IP siempre desactivada


def test_ejecutivo_muestra_consecuencias_sin_siglas_tecnicas():
    html = renderizar_html(preparar_datos_ejecutivo_ejemplo(), audiencia="medical")
    assert "Qué puede hacer un atacante con lo que se expuso" in html
    for g in filas_ejecutivo():
        assert g["activo_simple"] in html
    assert "Ya ocurrió" not in html and "Vastaamo" not in html   # el ejecutivo no muestra los casos
    assert "usuarios distintos" in html and "personas distintas" not in html
    assert not PROHIBIDAS_EJECUTIVO.search(html)


def test_tecnico_muestra_consecuencias_y_correcciones():
    datos = preparar_datos_de_ejemplo()
    html = renderizar_html(datos, audiencia="technical")
    assert "3.1 Consecuencias si se confirma el compromiso" in html
    for _, _, url in fuentes_usadas(filas_tecnico()):
        assert url in html
    assert html.index("3. Inteligencia estratégica") < html.index("3.1 Consecuencias") < html.index("4. Inteligencia táctica")
    # Correcciones de la revisión
    assert "IoA 5/5 · ML 4/5" in html and "5/5 · 5/5" not in html
    assert "Edición técnica de muestra" not in html and "Edición técnica generada" not in html
    assert "incidente B" not in html and "Incidentes A, B" not in html and "incidentes A, C" not in html
    assert "8470–8478" not in html and "8470–8476" in html
    assert "art. 37" not in html
    assert "break-before: page" not in html
    # Sección 7 sin el gráfico simple, con campañas y señales de inicio de cada escenario
    assert "Matriz cualitativa" not in html
    assert "Señal de que está empezando" in html and "IOA-05" in html[html.index("7. Evaluación"):]
    # Detalles repetidos retirados
    assert "Alcance de valoración" not in html
    assert "Edición técnica" not in html


def test_conclusion_nunca_pone_relojes_como_accion_prioritaria():
    hechos = {"campanas_detectadas_ml_genericas": 4, "campanas_detectadas_ml_dominio": 5,
              "campanas_evaluadas": 5, "ips_sin_puntos": 1280}
    for lectura in ("cobertura_ml", "calidad_datos"):
        for prioridad in CONTROLES:
            texto = redactar_conclusion(EnfoqueConclusiones(lectura=lectura, prioridad=prioridad), hechos)
            assert texto.startswith("Acción prioritaria: bloquear el egreso no autorizado")
            assert "priorizar la sincronización" not in texto
            assert len(texto) <= 900
