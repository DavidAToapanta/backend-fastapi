import json
from contextlib import closing
from http.client import HTTPConnection, HTTPException
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from app.core.configuracion_servicios import url_ollama, valor_configurado

MODELO_POR_DEFECTO = "qwen3:4b"
LIMITE_RESPUESTA = 64 * 1024

# La acción prioritaria es FIJA: hay una posible salida de datos de salud (CAMP-2026-001),
# así que ninguna respuesta del modelo puede cambiarla por un control secundario.
ACCION_PRIORITARIA = (
    "Acción prioritaria: bloquear el egreso no autorizado, suspender las 16 cuentas especiales compartidas "
    "y evaluar la notificación a la Superintendencia de Protección de Datos Personales (LOPDP art. 43: máximo 5 días)."
)
CONCLUSION_BASE = (
    "Conclusión: es probable un abuso interno persistente de cuentas privilegiadas (CAMP-2026-005) y es posible "
    "su relación con la salida de datos del 24-oct (CAMP-2026-001), con confianza baja-media."
)
# Ollama solo elige cuál control complementario destacar.
CONTROLES = {
    "privilegios": "Control complementario: revisar los privilegios y las alertas de las cuentas especiales.",
    "egreso": "Control complementario: revisar las transferencias externas atípicas desde la red clínica.",
    "reloj": "Control complementario: sincronización de los relojes del firewall y del sistema médico para confirmar correlaciones.",
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
    """Compone la síntesis BLUF: acción prioritaria fija, conclusión, respaldo con cifras y control complementario."""
    if enfoque.lectura == "cobertura_ml":
        genericas = hechos["campanas_detectadas_ml_genericas"]
        dominio = hechos["campanas_detectadas_ml_dominio"]
        total = hechos["campanas_evaluadas"]
        respaldo = (
            f"Respaldo: el modelo sin reglas detectó {genericas} de {total} campañas con variables genéricas "
            f"y {dominio} de {total} con variables de dominio."
        )
    else:
        conteo = f"{hechos['ips_sin_puntos']:,}".replace(",", ".")
        respaldo = (
            f"Respaldo: se normalizaron {conteo} IP sin puntos antes de correlacionar eventos; "
            "el volumen de datos que salió sigue por confirmar."
        )
    return f"{ACCION_PRIORITARIA} {CONCLUSION_BASE} {respaldo} {CONTROLES[enfoque.prioridad]}"


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
