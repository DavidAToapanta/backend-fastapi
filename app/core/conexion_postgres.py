import os

import psycopg
from psycopg.conninfo import make_conninfo

from app.core.configuracion_servicios import valor_configurado


def conectar_postgres() -> psycopg.Connection:
    """Abre la conexión con las credenciales configuradas para la API."""
    # Con PGHOST explícito, libpq usa la configuración del proceso (p. ej. Docker).
    url = os.getenv("DATABASE_URL") if os.getenv("PGHOST") else valor_configurado("DATABASE_URL")
    url = (url or "").strip()
    if not url and not os.getenv("PGHOST"):
        usuario = valor_configurado("POSTGRES_APP_USER")
        base = valor_configurado("POSTGRES_DB")
        if not usuario or not base:
            raise ValueError("Configura la cuenta de aplicación y la base de PostgreSQL")
        url = make_conninfo(
            host=valor_configurado("POSTGRES_HOST", "127.0.0.1"),
            port=valor_configurado("POSTGRES_PORT", "5434"),
            dbname=base,
            user=usuario,
            password=valor_configurado("POSTGRES_APP_PASSWORD"),
        )

    return psycopg.connect(
        url,
        connect_timeout=2,
        options="-c statement_timeout=1000",
        autocommit=True,
    )
