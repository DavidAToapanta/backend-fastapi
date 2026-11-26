import psycopg

from app.core.conexion_postgres import conectar_postgres


def comprobar_postgres() -> bool:
    """Comprueba que la cuenta configurada puede ejecutar una consulta sencilla."""
    try:
        with conectar_postgres() as conexion:
            return conexion.execute("SELECT 1").fetchone() == (1,)
    except (psycopg.Error, ValueError):
        return False
