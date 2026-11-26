from dataclasses import dataclass
from socket import create_connection

from app.core.estado_postgres import comprobar_postgres
from app.llm.estado_ollama import comprobar_ollama


@dataclass(frozen=True)
class EstadoServicios:
    postgres_disponible: bool
    ollama_disponible: bool
    sin_egreso: bool


def comprobar_fallo_de_egreso() -> bool:
    """Prueba la conexión TCP sin enviar datos de la aplicación."""
    try:
        with create_connection(("1.1.1.1", 443), timeout=1.0):
            return False
    except OSError:
        return True


def consultar_estado_servicios() -> EstadoServicios:
    return EstadoServicios(
        postgres_disponible=comprobar_postgres(),
        ollama_disponible=comprobar_ollama(),
        sin_egreso=comprobar_fallo_de_egreso(),
    )
