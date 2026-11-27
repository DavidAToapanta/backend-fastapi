import json
from contextlib import closing
from http.client import HTTPConnection, HTTPException
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from app.core.configuracion_servicios import url_ollama, valor_configurado

MODELO_POR_DEFECTO = "qwen3:4b"
LIMITE_RESPUESTA = 64 * 1024

CONTROLES = {
    "privilegios": "Acción prioritaria: suspender cuentas compartidas y priorizar la revisión de privilegios y alertas de cuentas.",
    "egreso": "Acción prioritaria: bloquear el egreso no autorizado y priorizar la revisión de transferencias externas atípicas.",
    "reloj": "Acción prioritaria: priorizar la sincronización de los relojes locales y validar las correlaciones temporales.",
}

PROMPT_SISTEMA_BLUF = (
    "Redacta usando EXCLUSIVAMENTE las cifras del JSON recibido. Empieza por la conclusión y las acciones "
    "(pirámide invertida). Distingue hecho observado de hipótesis ('probable', 'posible'). "
    "Si un dato no está en el JSON, escribe 'por confirmar'. No inventes cifras. "
    "Selecciona la lectura más relevante (cobertura_ml o calidad_datos) y prioriza un control defensivo "
    "(privilegios, egreso o reloj). Devuelve solo ese JSON."
)

PROMPT_EJECUTIVO_MEDICO = (
    "Redacta para Dirección Médica usando EXCLUSIVAMENTE las cifras del JSON. Empieza por la conclusión "
    "y las acciones con responsable y plazo. Prohibido usar siglas técnicas (IoC, IoA, MITRE, SSH, IP, "
    "Sigma, STIX, HMAC). Distingue hecho confirmado de punto por confirmar. No inventes cifras."
)


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
    """Compone una síntesis BLUF (acción y conclusión primero) usando solo cifras verificadas."""
    accion = CONTROLES[enfoque.prioridad]
    if enfoque.lectura == "cobertura_ml":
        genericas = hechos["campanas_detectadas_ml_genericas"]
        dominio = hechos["campanas_detectadas_ml_dominio"]
        total = hechos["campanas_evaluadas"]
        respaldo = (
            f"Conclusión operativa: es probable que el abuso de privilegios requiera contención prioritaria "
            f"(detección ML sin reglas de {genericas} de {total} campañas en versión genérica y {dominio} de {total} "
            "con dominio); la relación entre campañas previas y la posible salida externa sigue como hipótesis y "
            "el resto de anomalías queda por confirmar."
        )
    else:
        conteo = f"{hechos['ips_sin_puntos']:,}".replace(",", ".")
        respaldo = (
            f"Conclusión de calidad y trazabilidad: se confirmaron {conteo} IP sin puntos en registros horarios "
            "locales; su normalización es obligatoria antes de correlacionar eventos. El volumen exfiltrado sigue por confirmar."
        )
    return f"{accion} {respaldo}"


def generar_conclusiones(hechos: dict[str, int]) -> str:
    """Usa Ollama local para elegir prioridad BLUF y conserva cifras verificadas."""
    if any(type(valor) is not int for valor in hechos.values()):
        raise ValueError("Los hechos enviados a Ollama deben ser enteros.")

    esquema = EnfoqueConclusiones.model_json_schema()
    solicitud = {
        "model": valor_configurado("OLLAMA_MODEL", MODELO_POR_DEFECTO),
        "stream": False,
        "think": False,
        "format": esquema,
        "options": {"temperature": 0.1, "num_predict": 100},
        "messages": [
            {"role": "system", "content": PROMPT_SISTEMA_BLUF},
            {
                "role": "user",
                "content": f"/no_think\nHechos: {json.dumps(hechos)}\nEsquema: {json.dumps(esquema)}",
            },
        ],
    }

    try:
        url = urlsplit(url_ollama())
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
                "POST",
                f"{url.path.rstrip('/')}/api/chat",
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
