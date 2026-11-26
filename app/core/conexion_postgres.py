import os

import psycopg


def conectar_postgres() -> psycopg.Connection:
    """Abre la conexión con las credenciales configuradas para la API."""
    url = os.getenv("DATABASE_URL", "").strip()
    if not url and not os.getenv("PGHOST"):
        raise ValueError("Configura DATABASE_URL o PGHOST para conectar con PostgreSQL")

    return psycopg.connect(
        url,
        connect_timeout=2,
        options="-c statement_timeout=1000",
        autocommit=True,
    )
