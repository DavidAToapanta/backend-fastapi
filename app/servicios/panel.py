import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import psycopg
from pydantic import BaseModel, Field

from app.core.conexion_postgres import conectar_postgres
from app.servicios.exportaciones import carpeta_exportaciones

FUENTES = ("FIREWALL", "MEDSYS")

CONSULTA_RESUMEN = """
WITH resumen AS (
    SELECT source_layer,
           COALESCE(SUM(event_count), 0)::bigint AS eventos,
           COALESCE(SUM(corrupt_ip_count), 0) AS ips_sin_puntos,
           COUNT(DISTINCT event_hour) AS horas
    FROM cti_core.baseline_hourly_metrics
    WHERE source_layer IN ('FIREWALL', 'MEDSYS')
    GROUP BY GROUPING SETS ((source_layer), ())
), ultima_ingesta AS (
    SELECT DISTINCT ON (operation) operation, total_rows_read, pii_scrubbed
    FROM cti_audit.audit_events
    WHERE operation IN ('INGEST_FIREWALL_10M', 'INGEST_MEDSYS_10M')
    ORDER BY operation, audit_id DESC
)
SELECT r.source_layer, r.eventos, r.ips_sin_puntos, r.horas,
       CASE WHEN r.eventos = i.total_rows_read THEN i.pii_scrubbed END
FROM resumen r
LEFT JOIN ultima_ingesta i ON i.operation = CASE r.source_layer
    WHEN 'FIREWALL' THEN 'INGEST_FIREWALL_10M'
    WHEN 'MEDSYS' THEN 'INGEST_MEDSYS_10M'
END
"""


CONSULTA_MAPA_HORARIO = """
SELECT (event_hour AT TIME ZONE 'UTC')::date AS dia,
       EXTRACT(HOUR FROM event_hour AT TIME ZONE 'UTC')::int AS hora,
       SUM(event_count)::bigint AS eventos
FROM cti_core.baseline_hourly_metrics
WHERE source_layer IN ('FIREWALL', 'MEDSYS')
GROUP BY 1, 2
ORDER BY 1, 2
"""


class PanelNoDisponible(Exception):
    """La API no pudo consultar los agregados del panel."""


class AnomaliasSinConfirmar(BaseModel):
    firewall_por_hora: int = Field(ge=0, validation_alias="fw_hora", serialization_alias="firewallHourly")
    medsys_por_hora: int = Field(ge=0, validation_alias="med_hora", serialization_alias="medsysHourly")
    medsys_por_periodo: int = Field(ge=0, validation_alias="med_periodo", serialization_alias="medsysByPeriod")


class MetricasML(BaseModel):
    incidentes_top_n: str = Field(
        pattern=r"^[0-9]+/[0-9]+$",
        validation_alias="incidentes_en_top_n",
        serialization_alias="incidentsInTopN",
    )
    top_n: int = Field(gt=0, validation_alias="top_n_evaluado", serialization_alias="topN")
    anomalias_sin_confirmar: AnomaliasSinConfirmar = Field(
        validation_alias="anomalias_no_confirmadas_en_top_n",
        serialization_alias="unconfirmedAnomalies",
    )


def leer_metricas(ruta: Path) -> MetricasML | None:
    try:
        return MetricasML.model_validate_json(ruta.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None


def consultar_agregados(consulta: str) -> list[tuple[Any, ...]]:
    try:
        with conectar_postgres() as conexion:
            return conexion.execute(consulta).fetchall()
    except (psycopg.Error, ValueError) as error:
        raise PanelNoDisponible from error


def consultar_resumen_panel() -> dict[str, object]:
    filas = consultar_agregados(CONSULTA_RESUMEN)
    conteos = {fuente: (eventos, ips, horas, evidencia) for fuente, eventos, ips, horas, evidencia in filas}
    eventos, ips, horas, _ = conteos[None]
    por_fuente = []
    evidencias = []
    for fuente in FUENTES:
        eventos_fuente, ips_fuente, _, evidencia = conteos.get(fuente, (0, 0, 0, None))
        por_fuente.append({"fuente": fuente, "eventos": eventos_fuente, "ips_sin_puntos": ips_fuente})
        evidencias.append(evidencia)

    seudonimizacion = None
    if False in evidencias:
        seudonimizacion = False
    elif all(evidencia is True for evidencia in evidencias):
        seudonimizacion = True

    carpeta_metricas = carpeta_exportaciones()
    return {
        "total_eventos": eventos,
        "ips_sin_puntos": ips,
        "horas": horas,
        "por_fuente": por_fuente,
        "seudonimizacion_registrada": seudonimizacion,
        "ml": {
            "genericas": leer_metricas(carpeta_metricas / "ml_metrics_A_genericas.json"),
            "dominio": leer_metricas(carpeta_metricas / "ml_metrics_B_dominio.json"),
        },
    }


def consultar_mapa_horario() -> dict[str, object]:
    filas = consultar_agregados(CONSULTA_MAPA_HORARIO)
    horas = list(range(24))
    dias: list[date] = []
    if filas:
        primero, ultimo = filas[0][0], filas[-1][0]
        dias = [primero + timedelta(days=indice) for indice in range((ultimo - primero).days + 1)]

    matriz = [[0] * len(dias) for _ in horas]
    for dia, hora, eventos in filas:
        matriz[hora][(dia - dias[0]).days] = eventos

    return {"zona_horaria": "UTC", "dias": dias, "horas": horas, "matriz": matriz}
