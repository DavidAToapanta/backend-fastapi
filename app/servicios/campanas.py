import json

import psycopg
from psycopg.rows import dict_row

from app.core.conexion_postgres import conectar_postgres
from app.servicios.exportaciones import carpeta_exportaciones

CONSULTA_CAMPANAS = """
SELECT campaign_code AS codigo,
       title AS titulo,
       adversary_type AS tipo_adversario,
       severity AS severidad,
       admiralty_rating AS calificacion_admiralty,
       event_count AS eventos,
       first_seen AS primera_observacion,
       last_seen AS ultima_observacion,
       COALESCE(mitre_techniques, '[]'::jsonb) AS tecnicas_mitre,
       COALESCE(iocs, '{}'::jsonb) AS iocs,
       COALESCE(ioas, '[]'::jsonb) AS ioas
FROM cti_core.threat_campaigns
ORDER BY campaign_code
"""

CONSULTA_LINEA_TIEMPO = """
SELECT e.timeline_id AS id,
       e.event_ts AS fecha,
       e.source_layer AS fuente,
       e.actor_token AS actor,
       e.account_token AS cuenta,
       host(e.src_or_conn_ip) AS ip_origen,
       host(e.dst_ip) AS ip_destino,
       e.dst_port AS puerto_destino,
       e.event_summary AS resumen,
       COALESCE(e.clock_skew_12h_fix, FALSE) AS ajuste_de_reloj
FROM cti_core.threat_campaigns c
LEFT JOIN cti_core.campaign_timeline_events e ON e.campaign_code = c.campaign_code
WHERE c.campaign_code = %s
ORDER BY e.event_ts, e.timeline_id
"""


ESCENARIOS_IPE = (
    {
        "codigo": "ESCENARIO_MAS_PROBABLE",
        "nombre": "Más probable",
        "campanas": ["CAMP-2026-003", "CAMP-2026-004", "CAMP-2026-005"],
        "descripcion": "Abuso de privilegios acompañado de reconocimiento y accesos fallidos.",
        "hipotesis": None,
    },
    {
        "codigo": "ESCENARIO_MAS_PELIGROSO",
        "nombre": "Más peligroso",
        "campanas": ["CAMP-2026-001", "CAMP-2026-002", "CAMP-2026-005"],
        "descripcion": "Operación multifase con cambios de privilegios y egreso de datos simulado.",
        "hipotesis": "El vínculo entre CAMP-2026-005 y CAMP-2026-001 sigue como hipótesis.",
    },
)


class CampanasNoDisponibles(Exception):
    """Falló la lectura de los datos de campañas."""


def leer_puntajes_ml() -> dict[str, float]:
    ruta = carpeta_exportaciones() / "campanas.json"
    try:
        datos = json.loads(ruta.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return {}

    campanas = datos.get("campaigns") if isinstance(datos, dict) else None
    if not isinstance(campanas, list):
        return {}

    puntajes = {}
    for entrada in campanas:
        if not isinstance(entrada, dict):
            continue
        codigo = entrada.get("campaign_code")
        puntaje = entrada.get("anomaly_score")
        if isinstance(codigo, str) and type(puntaje) in (int, float) and 0 <= puntaje <= 1:
            puntajes[codigo] = float(puntaje)
    return puntajes


def consultar_filas(consulta: str, parametros: tuple[str, ...] | None = None) -> list[dict]:
    try:
        with conectar_postgres() as conexion, conexion.cursor(row_factory=dict_row) as cursor:
            return cursor.execute(consulta, parametros).fetchall()
    except (psycopg.Error, ValueError) as error:
        raise CampanasNoDisponibles from error


def consultar_campanas() -> list[dict]:
    filas = consultar_filas(CONSULTA_CAMPANAS)
    puntajes = leer_puntajes_ml()
    return [{**fila, "puntaje_anomalia": puntajes.get(fila["codigo"])} for fila in filas]


def consultar_linea_tiempo(codigo: str) -> list[dict] | None:
    filas = consultar_filas(CONSULTA_LINEA_TIEMPO, (codigo,))
    if not filas:
        return None
    return [fila for fila in filas if fila["id"] is not None]
