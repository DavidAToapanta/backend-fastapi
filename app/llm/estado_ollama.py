import json
from contextlib import closing
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from urllib.parse import urlsplit

from app.core.configuracion_servicios import url_ollama


def comprobar_ollama() -> bool:
    """Comprueba que el servidor local responde con su catálogo de modelos."""
    url_base = url_ollama()
    if not url_base:
        return False

    try:
        url = urlsplit(url_base)
        tipo_conexion = {"http": HTTPConnection, "https": HTTPSConnection}.get(url.scheme)
        if tipo_conexion is None or not url.hostname or url.query or url.fragment:
            return False

        ruta_catalogo = f"{url.path.rstrip('/')}/api/tags"
        with closing(tipo_conexion(url.hostname, url.port, timeout=1.0)) as conexion:
            conexion.request("GET", ruta_catalogo)
            with conexion.getresponse() as respuesta:
                if respuesta.status != 200:
                    return False
                catalogo = json.load(respuesta)
    except (OSError, HTTPException, ValueError):
        return False

    return isinstance(catalogo, dict) and isinstance(catalogo.get("models"), list)
