"""
Carga de los datos seudonimizados que entrega el Rol 1.

Acepta archivos Parquet (formato oficial) o CSV (solo para pruebas).
Solo lee las columnas que el Rol 2 necesita: así se usa menos memoria
y se cumple el principio de minimización de datos (LOPDP).
"""
from pathlib import Path

import numpy as np
import pandas as pd

# Columnas mínimas que necesita el Rol 2 de cada dataset
COLUMNAS_FW = [
    "event_ts", "src_ip", "dst_ip", "dst_port", "protocol", "application",
    "action", "actor_token", "is_external_ip", "was_dotless_ip",
]
COLUMNAS_MED = [
    "event_ts", "account_token", "actor_token", "action_desc", "conn_ip",
    "was_dotless_ip", "is_special_account",
]

# Columna opcional: número de fila original (para citar evidencia exacta)
COLUMNA_EVIDENCIA = "event_id"


def _leer(ruta: str, columnas: list[str]) -> pd.DataFrame:
    """Lee un Parquet o CSV con solo las columnas pedidas."""
    ruta = Path(ruta)
    if not ruta.exists():
        raise FileNotFoundError(f"No existe el archivo: {ruta}")

    if ruta.suffix.lower() == ".parquet":
        try:
            # Si Rol 1 ya agregó event_id, también lo leemos
            df = pd.read_parquet(ruta, columns=columnas + [COLUMNA_EVIDENCIA])
        except Exception:
            df = pd.read_parquet(ruta, columns=columnas)
    else:
        encabezado = pd.read_csv(ruta, nrows=0).columns
        usar = columnas + ([COLUMNA_EVIDENCIA] if COLUMNA_EVIDENCIA in encabezado else [])
        df = pd.read_csv(ruta, usecols=usar, keep_default_na=False, na_values=[""])

    faltan = set(columnas) - set(df.columns)
    if faltan:
        raise ValueError(f"Faltan columnas en {ruta.name}: {sorted(faltan)}")

    df["event_ts"] = pd.to_datetime(df["event_ts"])
    # Posición de cada fila dentro del archivo: sirve para citar evidencia exacta
    # mientras Rol 1 no agregue la columna event_id.
    df["fila_origen"] = np.arange(len(df), dtype="int64")
    df.attrs["archivo"] = ruta.name
    return df


def cargar_firewall(ruta: str) -> pd.DataFrame:
    """Dataset 1: conexiones del firewall (ya seudonimizado por Rol 1)."""
    df = _leer(ruta, COLUMNAS_FW)
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").fillna(-1).astype("int32")
    return df


def cargar_sistema_medico(ruta: str) -> pd.DataFrame:
    """Dataset 2: eventos del sistema médico (ya seudonimizado por Rol 1)."""
    return _leer(ruta, COLUMNAS_MED)
