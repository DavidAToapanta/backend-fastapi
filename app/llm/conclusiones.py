import json
import os
from contextlib import closing
from http.client import HTTPConnection, HTTPException
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

MODELO_POR_DEFECTO = "qwen3:4b"
LIMITE_RESPUESTA = 64 * 1024
CONTROLES = {
    "privilegios": "Prioriza la revisión de privilegios y las alertas sobre cambios de cuentas.",
    "egreso": "Prioriza la restricción del egreso y la revisión de transferencias atípicas.",
    "reloj": "Prioriza la sincronización de los relojes y la revisión de las correlaciones temporales.",
}


class OllamaNoDisponible(Exception):
    """Ollama no pudo generar una conclusión válida."""


class TextoConclusiones(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    text: str = Field(min_length=1, max_length=900)


class EnfoqueConclusiones(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lectura: Literal["cobertura_ml", "calidad_datos"]
    prioridad: Literal["privilegios", "egreso", "reloj"]


def redactar_conclusion(enfoque: EnfoqueConclusiones, hechos: dict[str, int]) -> str:
    if enfoque.lectura == "cobertura_ml":
        genericas = hechos["campanas_detectadas_ml_genericas"]
        dominio = hechos["campanas_detectadas_ml_dominio"]
        total = hechos["campanas_evaluadas"]
        lectura = (
            f"Con las variables genéricas, el modelo detectó {genericas} de {total} campañas. "
            f"Con las variables de dominio, detectó {dominio} de {total}. "
            "Las anomalías adicionales todavía requieren revisión."
        )
    else:
        conteo = f"{hechos['ips_sin_puntos']:,}".replace(",", ".")
        lectura = f"Los registros contienen {conteo} IP sin puntos. Valida su normalización antes de correlacionar."
    return f"{lectura} {CONTROLES[enfoque.prioridad]}"


def generar_conclusiones(hechos: dict[str, int]) -> str:
    """Usa Ollama para orientar la conclusión y conserva las cifras verificadas."""
    if any(type(valor) is not int for valor in hechos.values()):
        raise ValueError("Los hechos enviados a Ollama deben ser enteros.")

    esquema = EnfoqueConclusiones.model_json_schema()
    solicitud = {
        "model": os.getenv("OLLAMA_MODEL", MODELO_POR_DEFECTO),
        "stream": False,
        "think": False,
        "format": esquema,
        "options": {"temperature": 0.1, "num_predict": 100},
        "messages": [
            {
                "role": "system",
                "content": (
                    "Para la conclusión del ejercicio CTI sintético, selecciona la lectura más "
                    "relevante según los agregados: cobertura_ml o calidad_datos. Prioriza un "
                    "control defensivo: privilegios, egreso o reloj. Devuelve solo ese JSON."
                ),
            },
            {
                "role": "user",
                "content": f"/no_think\nHechos: {json.dumps(hechos)}\nEsquema: {json.dumps(esquema)}",
            },
        ],
    }

    try:
        url = urlsplit(os.getenv("OLLAMA_BASE_URL", "").strip())
        if (
            url.scheme != "http"
            or url.hostname not in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}
            or url.username is not None
            or url.query
            or url.fragment
        ):
            raise ValueError("Configura la dirección HTTP local de Ollama.")
        with closing(HTTPConnection(url.hostname, url.port or 11434, timeout=90)) as conexion:
            conexion.request(
                "POST", f"{url.path.rstrip('/')}/api/chat",
                body=json.dumps(solicitud),
                headers={"Content-Type": "application/json"},
            )
            with conexion.getresponse() as respuesta:
                if respuesta.status != 200:
                    raise OllamaNoDisponible("Ollama respondió con un error.")
                cuerpo = respuesta.read(LIMITE_RESPUESTA + 1)
        if len(cuerpo) > LIMITE_RESPUESTA:
            raise OllamaNoDisponible("La respuesta de Ollama excedió el tamaño esperado.")
        datos = json.loads(cuerpo)
        if datos["done"] is not True or datos.get("done_reason") == "length":
            raise OllamaNoDisponible("Ollama entregó una respuesta incompleta.")
        enfoque = EnfoqueConclusiones.model_validate_json(datos["message"]["content"])
        return redactar_conclusion(enfoque, hechos)
    except (OSError, HTTPException, KeyError, TypeError, ValueError) as error:
        raise OllamaNoDisponible("Ollama local no está disponible o respondió en un formato inválido.") from error
