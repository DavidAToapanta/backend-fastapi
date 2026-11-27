from pathlib import PureWindowsPath

import psycopg
from psycopg.rows import dict_row

from app.core.conexion_postgres import conectar_postgres
from backend.app.core.security import verificar_cadena_auditoria

CONSULTA_EVENTOS = """
SELECT audit_id AS identificador,
       executed_at AS fecha_ejecucion,
       operation AS operacion,
       dataset_name AS nombre_dataset,
       dataset_sha256 AS sha256_dataset,
       total_rows_read AS filas_leidas,
       rows_persisted AS filas_guardadas,
       pii_scrubbed AS pii_depurada,
       row_hash AS hash_registro
FROM cti_audit.audit_events
ORDER BY audit_id DESC
"""


class AuditoriaNoDisponible(Exception):
    """Falló la consulta de la bitácora."""


def listar_eventos_auditoria() -> list[dict]:
    try:
        with conectar_postgres() as conexion, conexion.cursor(row_factory=dict_row) as cursor:
            eventos = cursor.execute(CONSULTA_EVENTOS).fetchall()
    except (psycopg.Error, ValueError) as error:
        raise AuditoriaNoDisponible from error

    for evento in eventos:
        nombre = evento["nombre_dataset"]
        if nombre:
            evento["nombre_dataset"] = PureWindowsPath(nombre).name
    return eventos


def comprobar_cadena_auditoria() -> dict:
    try:
        with conectar_postgres() as conexion:
            return verificar_cadena_auditoria(conexion)
    except (psycopg.Error, ValueError) as error:
        raise AuditoriaNoDisponible from error
