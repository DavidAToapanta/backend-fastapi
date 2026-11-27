import os
from pathlib import Path

from dotenv import dotenv_values


_entorno_local = dotenv_values(Path(__file__).resolve().parents[2] / ".env")


def valor_configurado(nombre: str, predeterminado: str = "") -> str:
    return os.environ.get(nombre, _entorno_local.get(nombre) or predeterminado)


def url_ollama() -> str:
    return valor_configurado("OLLAMA_BASE_URL", "http://127.0.0.1:11434").strip()
