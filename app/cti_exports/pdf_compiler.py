"""Compila los reportes HTML/PDF (Técnico F-11 y Ejecutivo Médico) vía Jinja2 y WeasyPrint."""

import argparse
from pathlib import Path
from typing import Literal

from app.cti_exports.contenido_f11 import (
    ACCIONES_PRIORITARIAS,
    BRECHAS_LIMITACIONES,
    CAMPANAS_PRIORIDAD,
    CATALOGO_IOA,
    DETALLE_OPERATIVO_CAMPANAS,
    FUENTES_ADMIRALTY,
    IMPACTO_ESTRATEGICO,
    JUICIO_CLAVE,
    MARCO_LEGAL,
    MATRIZ_TACTICA,
    METADATA_F11,
    MODELO_DIAMANTE,
    TABLA_ANTICIPACION,
    TABLA_IOC,
    TECNICAS,
    TEXTO,
)

Audiencia = Literal["technical", "medical"]
PLANTILLAS = {
    "technical": "reporte_f11.html",
    "medical": "reporte_ejecutivo_medico.html",
}


def renderizar_html(datos: dict[str, object], audiencia: Audiencia = "technical") -> str:
    """Renderiza la plantilla HTML validando todas las variables requeridas."""
    from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

    entorno = Environment(
        loader=FileSystemLoader(Path(__file__).with_name("plantillas")),
        autoescape=select_autoescape(("html",)),
        undefined=StrictUndefined,
    )
    return entorno.get_template(PLANTILLAS[audiencia]).render(**datos)


def renderizar_pdf(datos: dict[str, object], audiencia: Audiencia = "technical") -> bytes:
    """Renderiza el reporte PDF para devolverlo por HTTP o guardarlo en disco."""
    from weasyprint import HTML

    documento = renderizar_html(datos, audiencia)
    return HTML(string=documento).write_pdf()


def generar_pdf(
    datos: dict[str, object],
    salida: Path,
    audiencia: Audiencia = "technical",
) -> Path:
    """Guarda el reporte generado en disco y devuelve su ruta."""
    pdf = renderizar_pdf(datos, audiencia)
    salida.parent.mkdir(parents=True, exist_ok=True)
    salida.write_bytes(pdf)
    return salida


def preparar_datos_de_ejemplo() -> dict[str, object]:
    """Proporciona un contexto completo compatible con todas las secciones del F-11."""
    return {
        **TEXTO,
        "metadata": dict(METADATA_F11),
        "estado": "Edición técnica de muestra · TLP:AMBER · Datos sintéticos",
        "juicio_clave": JUICIO_CLAVE,
        "indicadores": [
            ("1 crítica", "Exfiltración simulada (24-oct)"),
            ("5/5 · 5/5", "Campañas detectadas (ML / IoA)"),
            ("0 / 10.000", "Falsas alarmas en cuentas normales"),
            ("16 días", "Anticipación previa al ataque"),
        ],
        "campanas_prioridad": CAMPANAS_PRIORIDAD,
        "cifras_clave": [
            ("10.023.532", "Registros"),
            ("99,99% / 99,97%", "Calidad FW / Med"),
            ("5/5", "Reglas IoA"),
            ("4/5 (5/5 dom.)", "ML sin reglas"),
            ("0 / 10.000", "Normales marcadas"),
            ("16 días", "Anticipación"),
            ("2 en 744 h", "Falsas alarmas"),
        ],
        "acciones_prioritarias": ACCIONES_PRIORITARIAS,
        "fuentes_admiralty": FUENTES_ADMIRALTY,
        "modelo_diamante": MODELO_DIAMANTE,
        "impacto_estrategico": IMPACTO_ESTRATEGICO,
        "tecnicas": [(clave, desc) for clave, desc in TECNICAS.items()],
        "matriz_tactica": MATRIZ_TACTICA,
        "detalle_operativo": DETALLE_OPERATIVO_CAMPANAS,
        "nota_temporal": "Cronología en hora local del registro; muestra hora original y ajuste selectivo de +12 h.",
        "cronologia": [
            ("2026-10-24 22:40:00", "—", "Firewall", "SSH 10.10.100.40 → 10.10.100.30 (permitido)"),
            ("2026-10-24 10:40:00", "2026-10-24 22:40:00 (+12 h)", "Sistema médico", "INGRESO SIST_MED_IESS"),
            ("2026-10-24 10:40:15", "2026-10-24 22:40:15 (+12 h)", "Sistema médico", "DESCARGA EXITOSA"),
            ("2026-10-24 22:40:30", "—", "Firewall", "Salida a 186.46.219[.]18:8443 (permitido)"),
        ],
        "tabla_ioc": TABLA_IOC,
        "catalogo_ioa": CATALOGO_IOA,
        "metricas": (
            "IsolationForest sin reglas: 4/5 con variables genéricas y 5/5 con variables de dominio "
            "(16 cuentas especiales en los puestos 1 a 16 de 10.016 cuentas; 0 cuentas normales marcadas)."
        ),
        "exportaciones": "Sigma: 8 archivos IoA y 2 IoC (10 reglas). STIX 2.1: 82 objetos compatibles con MISP (TLP:AMBER).",
        "muestra_sigma": [
            ("IoA", "Salida de datos clínicos seguida de conexión externa"),
            ("IoC", "Bloqueo de IP externa sintética 186.46.219[.]18:8443"),
        ],
        "escenarios": [
            ("Más probable", "Alta", "Alto", "Abuso persistente de privilegios en cuentas compartidas con fuerza bruta y escaneo."),
            ("Más peligroso", "Media", "Crítico", "Cadena multifase con descarga clínica y salida hacia 186.46.219[.]18:8443 en 30 s."),
        ],
        "tabla_anticipacion": TABLA_ANTICIPACION,
        "conclusiones": (
            "Acción prioritaria: bloquear el egreso no autorizado, suspender las 16 cuentas compartidas y "
            "evaluar la notificación legal (LOPDP art. 43: máximo 5 días). Es probable el abuso interno persistente "
            "y posible su relación con la salida del 24-oct."
        ),
        "brechas": BRECHAS_LIMITACIONES,
        "estado_evidencias": (
            "Cadena SHA-256 íntegra verificada antes de emitir este documento. La huella de esta descarga queda auditada."
        ),
        "anexo_hashes": [
            ("FIREWALL", "5.009.031", "0" * 64),
            ("MEDSYS", "5.014.501", "1" * 64),
        ],
        "anexo_calidad": [
            ("Calidad estructural", "99,99% Firewall / 99,97% Sistema médico (BOM UTF-8 y errata TRANFERENCIA tratados)"),
            ("IP sin puntos normalizadas", "1.280 registros reparados (493 Firewall y 787 Sistema médico)"),
            ("Duplicados exactos detectados", "2.607 en Firewall y 5.220 en Sistema médico"),
            ("Privacidad y seudonimización", "0 PII expuesta; identidades y cuentas con HMAC-SHA256 truncado a 12 hex"),
            ("Normativa legal verificada", MARCO_LEGAL),
        ],
        "huella_insumos": "0" * 64,
        "nota_solicitante": None,
    }


def preparar_datos_ejecutivo_ejemplo() -> dict[str, object]:
    """Proporciona contexto completo de muestra para el Informe Ejecutivo Médico."""
    return {
        "cuentas": 16,
        "cuentas_compartidas": 11,
        "max_identidades_cuenta": "1.737",
        "millones_registros": "10 millones",
        "ataques_detectados": "5 de 5",
        "cuentas_normales_falsas": "0 de 10.000",
        "dias_anticipacion": 16,
        "fecha_evento": "24 de octubre",
        "hora_evento": "22:40 (hora local del registro)",
        "clasificacion": METADATA_F11["clasificacion"],
        "version": METADATA_F11["version"],
        "fecha_emision": METADATA_F11["fecha_emision"],
    }


def principal() -> None:
    argumentos = argparse.ArgumentParser(description="Generar un borrador HTML/PDF de los reportes")
    argumentos.add_argument("--salida", required=True, type=Path, help="Ruta del PDF de salida")
    argumentos.add_argument(
        "--audiencia",
        choices=("technical", "medical"),
        default="technical",
        help="Tipo de reporte a generar",
    )
    opciones = argumentos.parse_args()
    datos = (
        preparar_datos_ejecutivo_ejemplo()
        if opciones.audiencia == "medical"
        else preparar_datos_de_ejemplo()
    )
    salida = generar_pdf(datos, opciones.salida, audiencia=opciones.audiencia)
    print(f"PDF generado en {salida}")


if __name__ == "__main__":
    principal()
