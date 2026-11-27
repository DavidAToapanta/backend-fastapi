"""Genera el reporte F-11 y permite producir un borrador desde la terminal."""

import argparse
from pathlib import Path
from typing import Literal

Audiencia = Literal["technical", "medical"]
PLANTILLAS = {
    "technical": "reporte_f11.html",
    "medical": "reporte_ejecutivo_medico.html",
}


def renderizar_pdf(datos: dict[str, object], audiencia: Audiencia = "technical") -> bytes:
    """Renderiza el reporte para devolverlo por HTTP o guardarlo en disco."""
    from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
    from weasyprint import HTML

    entorno = Environment(
        loader=FileSystemLoader(Path(__file__).with_name("plantillas")),
        autoescape=select_autoescape(("html",)),
        undefined=StrictUndefined,
    )
    documento = entorno.get_template(PLANTILLAS[audiencia]).render(**datos)
    return HTML(string=documento).write_pdf()


def generar_pdf(datos: dict[str, object], salida: Path) -> Path:
    """Guarda el reporte y devuelve la ruta del PDF."""
    pdf = renderizar_pdf(datos)
    salida.parent.mkdir(parents=True, exist_ok=True)
    salida.write_bytes(pdf)
    return salida


def preparar_datos_de_ejemplo() -> dict[str, object]:
    """Proporciona contenido ficticio para revisar el formato de las ocho secciones."""
    return {
        "resumen": (
            "Ejemplo de informe para el equipo del hackatón. Resume hallazgos "
            "simulados y muestra cómo se presentarán la evidencia y los controles."
        ),
        "indicadores": [
            (120, "Eventos ficticios"),
            (2, "Campañas de ejemplo"),
            (2, "Escenarios IPE"),
        ],
        "metodologia": (
            "Ejemplo de ciclo CTI con selección de fuentes, agrupación por ventana horaria "
            "y correlación por identificador seudonimizado. El Modelo Diamante organiza "
            "la relación entre actor, capacidad, infraestructura y objetivo."
        ),
        "fuentes": [
            ("Registro de firewall simulado", 80, "Revisión de patrones de conexión"),
            ("Registro de acceso simulado", 40, "Correlación de actividad de cuentas"),
        ],
        "admiralty": "B2 de ejemplo aplicado a las fuentes simuladas.",
        "adversarios": (
            "El ejercicio ilustra a un actor que usa una cuenta comprometida para "
            "consultar un repositorio. El alias ACC-EJ-001 representa una cuenta ficticia "
            "y permite seguir la secuencia sin publicar datos personales."
        ),
        "impacto": (
            "La consulta indebida de un repositorio podría afectar la confidencialidad de "
            "los registros. Los controles de acceso y la trazabilidad reducen el riesgo "
            "y facilitan revisar la actividad sin interrumpir los servicios."
        ),
        "tecnicas": [
            ("T1078", "Uso de una cuenta válida en la simulación."),
            ("T1213", "Consulta a un repositorio de información ficticio."),
            ("T1098", "Cambio simulado de privilegios de una cuenta técnica."),
        ],
        "campanas": [
            ("CAMP-EJ-001", "08:00 a 09:00", "Se repiten fallos de autenticación."),
            ("CAMP-EJ-002", "09:00 a 10:00", "Se observa un cambio de nivel en ACC-EJ-001."),
        ],
        "nota_temporal": (
            "Las horas son ilustrativas. La revisión del desfase de 12 h se documentará "
            "junto con la evidencia de correlación del ejercicio."
        ),
        "comportamiento_observable": "Varios intentos de acceso fallidos en una misma ventana.",
        "indicador_compromiso": "El identificador ficticio ACC-EJ-001 vincula las filas del ejemplo.",
        "metricas": (
            "Ejemplo de presentación de IsolationForest sin reglas con tres detecciones "
            "de cinco casos simulados y dos alertas de ejemplo para revisión."
        ),
        "exportaciones": (
            "La evidencia técnica del ejercicio se documentará en colecciones Sigma "
            "para IoA e IoC y en un paquete STIX 2.1 con etiqueta de datos sintéticos."
        ),
        "alcance_ipe": "Las calificaciones ilustran dos cursos de acción del adversario ficticio.",
        "escenarios": [
            ("Más probable", "Alta", "Alto", "Abuso de privilegios y reconocimiento interno."),
            ("Más peligroso", "Media", "Crítico", "Encadenamiento de accesos y salida de datos simulada."),
        ],
        "conclusiones": (
            "El ejercicio prioriza controles sobre las cuentas técnicas y la verificación "
            "de las rutas de acceso a los repositorios."
        ),
        "controles": [
            ("Inmediato", "Revisar privilegios y alertas de autenticación."),
            ("Corto plazo", "Deshabilitar accesos en claro y planificar la migración a TLS."),
            ("Mediano plazo", "Verificar la sincronización NTP y la cadena de auditoría."),
        ],
        "estado_evidencias": (
            "Las cifras, huellas SHA-256 y el sello de auditoría se insertarán al validar "
            "la evidencia del ejercicio."
        ),
    }


def principal() -> None:
    argumentos = argparse.ArgumentParser(description="Generar un borrador del reporte F-11")
    argumentos.add_argument("--salida", required=True, type=Path, help="Ruta del PDF")
    opciones = argumentos.parse_args()
    salida = generar_pdf(preparar_datos_de_ejemplo(), opciones.salida)
    print(f"PDF generado en {salida}")


if __name__ == "__main__":
    principal()
