"""
Control de calidad y contrato de datos a la ENTRADA del Rol 2.

Cuando lleguen datos reales distintos a los del hackatón, este paso avisa antes de analizar:
  - si faltan columnas o hay vacíos,
  - si hay duplicados o IPs mal escritas,
  - si aparecen VALORES NUEVOS (por ejemplo una acción que no conocíamos), lo que indica que
    las reglas podrían necesitar ajuste (cambio en los datos o "drift").
"""
import ipaddress

import pandas as pd

ESPERADOS = {
    "firewall": {"action": {"permitido", "negado"}, "protocol": {"tcp", "udp", "SSH"}},
    "sistema_medico": {"action_desc": {
        "ACCESO FALLIDO", "Inactivacion de usuarios", "Reactivacion de usuarios", "TRANFERENCIA INTERRUMPIDA",
        "DESCARGA EXITOSA", "USUARIOS - Activar usuario", "TRANFERENCIA EXITOSA",
        "USUARIOS - Actualizar nivel de Usuario", "INGRESO SIST_MED_IESS"}},
}


def _ip_valida(ip) -> bool:
    try:
        ipaddress.ip_address(str(ip))
        return True
    except ValueError:
        return False


def evaluar(df: pd.DataFrame, nombre: str, columna_ip: str) -> dict:
    columnas = [c for c in df.columns if c != "fila_origen"]
    total = len(df)
    nulos = df[columnas].isna().sum()
    duplicados = int(df[columnas].duplicated().sum())
    unicas = pd.Series(df[columna_ip].unique())
    invalidas_unicas = set(unicas[~unicas.map(_ip_valida)])
    ips_invalidas = int(df[columna_ip].isin(invalidas_unicas).sum())
    nuevos = {}
    for col, esperados in ESPERADOS[nombre].items():
        vistos = set(df[col].dropna().unique())
        if vistos - esperados:
            nuevos[col] = sorted(vistos - esperados)[:20]

    completitud = 1 - nulos.sum() / (total * len(columnas))
    unicidad = 1 - duplicados / total
    validez = 1 - ips_invalidas / total
    consistencia = 1.0 if not nuevos else 0.9
    return {
        "filas": total,
        "rango_fechas": [str(df["event_ts"].min()), str(df["event_ts"].max())],
        "vacios_por_columna": {k: int(v) for k, v in nulos.items() if v},
        "duplicados_exactos": duplicados,
        "ips_invalidas_tras_reparacion": ips_invalidas,
        "ips_reparadas_por_rol1": int(df["was_dotless_ip"].sum()),
        "valores_nuevos_no_esperados": nuevos,
        "puntajes": {"completitud": round(completitud * 100, 2), "unicidad": round(unicidad * 100, 2),
                     "validez": round(validez * 100, 2), "consistencia": round(consistencia * 100, 2)},
        "puntaje_calidad": round((completitud + unicidad + validez + consistencia) / 4 * 100, 2),
    }


def reporte(fw: pd.DataFrame, med: pd.DataFrame) -> dict:
    r = {"firewall": evaluar(fw, "firewall", "dst_ip"),
         "sistema_medico": evaluar(med, "sistema_medico", "conn_ip")}
    r["advertencias"] = [
        f"{n}: aparecieron valores nuevos {v} -> revisar reglas y umbrales"
        for n in ("firewall", "sistema_medico") for v in [r[n]["valores_nuevos_no_esperados"]] if v
    ]
    return r
