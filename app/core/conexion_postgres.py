import os

import psycopg


def conectar_postgres() -> psycopg.Connection:
    """Abre la conexión con las credenciales configuradas para la API."""
    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        raise ValueError("DATABASE_URL no configurada")

    return psycopg.connect(
        url,
        connect_timeout=2,
        options="-c statement_timeout=1000",
        autocommit=True,
    )
