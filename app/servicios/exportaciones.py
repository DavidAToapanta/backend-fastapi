import json
import os
from pathlib import Path

import yaml

NOMBRE_PAQUETE_STIX = "aegishealth_stix21_bundle.json"
ETIQUETAS_SINTETICAS = ("synthetic-exercise-data", "hackathon-simulation")


class ExportacionNoDisponible(Exception):
    """Falta el artefacto o su contenido no se puede servir."""


def carpeta_exportaciones() -> Path:
    return Path(os.getenv("METRICAS_ML_DIR", "data/exports"))


def leer_reglas_sigma() -> dict[str, list[dict[str, str]]]:
    grupos: dict[str, list[dict[str, str]]] = {"ioa": [], "ioc": []}
    try:
        for ruta in sorted((carpeta_exportaciones() / "sigma").iterdir()):
            grupo = ruta.stem.partition("_")[0]
            if grupo not in grupos or ruta.suffix not in {".yml", ".yaml"}:
                continue
            if ruta.is_symlink() or not ruta.is_file():
                continue

            contenido = ruta.read_text(encoding="utf-8-sig")
            documentos = list(yaml.safe_load_all(contenido))
            if not documentos or not all(
                isinstance(documento, dict) and isinstance(documento.get("title"), str)
                and documento["title"].strip()
                for documento in documentos
            ):
                raise ExportacionNoDisponible("Archivo Sigma sin títulos válidos.")

            # En los archivos de correlación, el último documento es la regla principal.
            grupos[grupo].append({
                "archivo": ruta.name,
                "titulo": documentos[-1]["title"],
                "contenido_yaml": contenido,
            })
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ExportacionNoDisponible from error

    if not all(grupos.values()):
        raise ExportacionNoDisponible("Falta un grupo de reglas Sigma.")
    return grupos


def leer_paquete_stix() -> bytes:
    ruta = carpeta_exportaciones() / NOMBRE_PAQUETE_STIX
    if ruta.is_symlink():
        raise ExportacionNoDisponible("El archivo STIX es un enlace.")

    try:
        contenido = ruta.read_bytes()
        paquete = json.loads(contenido)
    except (OSError, ValueError) as error:
        raise ExportacionNoDisponible from error

    if not isinstance(paquete, dict) or paquete.get("type") != "bundle":
        raise ExportacionNoDisponible("El documento no es un paquete STIX.")

    objetos = paquete.get("objects")
    if not isinstance(objetos, list) or not all(isinstance(objeto, dict) for objeto in objetos):
        raise ExportacionNoDisponible("El paquete STIX no contiene objetos válidos.")

    indicadores = [objeto for objeto in objetos if objeto.get("type") == "indicator"]
    if not indicadores or not all(
        indicador.get("spec_version") == "2.1"
        and isinstance(indicador.get("labels"), list)
        and all(etiqueta in indicador["labels"] for etiqueta in ETIQUETAS_SINTETICAS)
        for indicador in indicadores
    ):
        raise ExportacionNoDisponible("Los indicadores STIX requieren etiquetas de datos sintéticos.")

    return contenido
