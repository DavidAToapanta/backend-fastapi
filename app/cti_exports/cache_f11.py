import argparse
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from pydantic import ConfigDict, Field

from app.llm.conclusiones import OllamaNoDisponible, generar_conclusiones, TextoConclusiones
from app.servicios.auditoria import AuditoriaNoDisponible
from app.servicios.campanas import CampanasNoDisponibles
from app.servicios.conclusiones import DatosF11NoDisponibles
from app.servicios.exportaciones import ExportacionNoDisponible
from app.servicios.panel import PanelNoDisponible


class CacheF11(TextoConclusiones):
    model_config = ConfigDict(extra="forbid", strict=True)
    sha256_insumos: str = Field(pattern=r"^[a-f0-9]{64}$")
    revisado: bool = False


def ruta_cache() -> Path:
    return Path(os.getenv("LLM_CACHE_PATH", "data/exports/llm_cache.json"))


def leer_cache(huella: str) -> CacheF11:
    try:
        cache = CacheF11.model_validate_json(ruta_cache().read_bytes())
    except (OSError, ValueError) as error:
        raise DatosF11NoDisponibles("La caché F-11 no está disponible.") from error
    if cache.sha256_insumos != huella:
        raise DatosF11NoDisponibles("La caché F-11 corresponde a otros insumos. Vuelve a prepararla.")
    return cache


def guardar_cache(cache: CacheF11) -> None:
    destino = ruta_cache()
    destino.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(mode="w", encoding="utf-8", dir=destino.parent, delete=False) as archivo:
        temporal = Path(archivo.name)
        try:
            archivo.write(cache.model_dump_json(indent=2) + "\n")
            archivo.close()
            temporal.replace(destino)
        finally:
            temporal.unlink(missing_ok=True)


def principal() -> None:
    from app.servicios.reporte_f11 import huella_insumos, recopilar_insumos

    argumentos = argparse.ArgumentParser(description="Preparar la caché local del F-11.")
    argumentos.add_argument("--aprobar", action="store_true", help="Marcar la edición técnica del informe F-11 como validada.")
    opciones = argumentos.parse_args()
    try:
        datos, mapa, hechos = recopilar_insumos()
        huella = huella_insumos(datos, mapa, hechos)
        if opciones.aprobar:
            cache = leer_cache(huella).model_copy(update={"revisado": True})
        else:
            cache = CacheF11(sha256_insumos=huella, text=generar_conclusiones(hechos))
        guardar_cache(cache)
    except (DatosF11NoDisponibles, PanelNoDisponible, AuditoriaNoDisponible, CampanasNoDisponibles,
            ExportacionNoDisponible, OllamaNoDisponible, OSError, KeyError, ValueError):
        argumentos.exit(1, "Error al preparar la caché F-11. Revisa PostgreSQL, los insumos y Ollama.\n")
    print(f"Caché F-11 {'validada' if cache.revisado else 'generada'} en {ruta_cache()}")


if __name__ == "__main__":
    principal()
