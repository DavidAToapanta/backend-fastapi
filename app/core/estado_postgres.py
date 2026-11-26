import os

import psycopg


def comprobar_postgres() -> bool:
    """Comprueba que la cuenta configurada puede ejecutar una consulta sencilla."""
    url_base_de_datos = os.getenv("DATABASE_URL", "").strip()
    if not url_base_de_datos:
        return False

    try:
        with psycopg.connect(
            url_base_de_datos,
            connect_timeout=2,
            options="-c statement_timeout=1000",
            autocommit=True,
        ) as conexion:
            return conexion.execute("SELECT 1").fetchone() == (1,)
    except (psycopg.Error, ValueError):
        return False
