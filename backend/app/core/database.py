"""
Utilidades de conexión segura hacia PostgreSQL 16 usando psycopg (v3)
y soporte para carga masiva mediante el protocolo COPY.
"""

from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg import sql

from backend.app.core.config import Settings, get_settings


@contextmanager
def obtener_conexion(
    usar_rol_app: bool = False,
    settings: Settings | None = None,
) -> Iterator[psycopg.Connection[Any]]:
    """Abre una conexión transaccional con psycopg v3 y garantiza su cierre."""
    cfg = settings or get_settings()
    dsn = cfg.dsn_app if usar_rol_app else cfg.dsn_admin
    with psycopg.connect(dsn) as conn:
        yield conn


def copiar_filas_tabla(
    conn: psycopg.Connection[Any],
    esquema: str,
    tabla: str,
    columnas: list[str],
    filas: Iterable[Sequence[Any]],
) -> int:
    """
    Inserta registros por flujo usando COPY FROM STDIN con identificadores SQL escapados.
    Retorna la cantidad exacta de filas transferidas en la operación.
    """
    if not columnas:
        raise ValueError("Se requiere al menos una columna para ejecutar COPY.")

    consulta = sql.SQL("COPY {}.{} ({}) FROM STDIN").format(
        sql.Identifier(esquema),
        sql.Identifier(tabla),
        sql.SQL(", ").join(sql.Identifier(col) for col in columnas),
    )

    total = 0
    with conn.cursor() as cur:
        with cur.copy(consulta) as copy_ctx:
            for fila in filas:
                copy_ctx.write_row(fila)
                total += 1
    return total
