"""Carga el escenario sintético con una fecha de inicio reproducible."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from psycopg.types.json import Jsonb

from app.core.conexion_postgres import conectar_postgres
from app.servicios.centinela_privacidad import hash_valor, obtener_clave
from app.servicios.guardian_cuenta import ZONA_ECUADOR, leer_fecha

AFILIADO_CRITICO = "AFI-00000000A001"
CUENTA_SINTETICA = "2200123456"


def construir_eventos(inicio: datetime) -> list[dict]:
    if inicio.tzinfo is None:
        raise ValueError("La fecha de inicio requiere zona horaria.")
    datos = json.loads(Path(__file__).with_name("escenarios_guardian.json").read_text(encoding="utf-8"))
    eventos = datos["eventos"]
    original = min(leer_fecha(e["fecha_hora"]) for e in eventos if e["afiliado"] == AFILIADO_CRITICO)
    clave = obtener_clave()
    for evento in eventos:
        critico = evento["afiliado"] == AFILIADO_CRITICO
        if critico:
            diferencia = leer_fecha(evento["fecha_hora"]) - original
            evento["fecha_hora"] = (inicio.astimezone(ZONA_ECUADOR) + diferencia).isoformat()
        if evento.pop("valor_hash", None) and critico:
            evento["valor_hash"] = hash_valor(CUENTA_SINTETICA, clave)
    return eventos


def cargar(inicio: datetime) -> int:
    eventos = construir_eventos(inicio)
    with conectar_postgres() as conn, conn.transaction(), conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO cti_piloto.eventos VALUES (%s, %s) ON CONFLICT (id) DO NOTHING",
            [(evento["id_evento"], Jsonb(evento)) for evento in eventos],
        )
        return cur.rowcount


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inicio", type=datetime.fromisoformat, help="Inicio del caso crítico, con zona ISO 8601.")
    opciones = parser.parse_args()
    print(f"Eventos sintéticos nuevos: {cargar(opciones.inicio or datetime.now(timezone.utc))}")
