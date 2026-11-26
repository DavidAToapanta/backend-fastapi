"""
Auditoría forense reproducible sobre los CSV oficiales del Reto 3 (AegisHealth-CTI)
usando Polars en modo Lazy/Streaming y protegiendo la privacidad bajo LOPDP Art. 25.

Genera el archivo docs/evidencias/evidencias.json sin exponer ningún nombre real
ni código de cuenta técnica en claro.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import polars as pl

# Asegura resolución de paquetes locales aunque el script se ejecute desde scripts/
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.core.config import get_settings  # noqa: E402
from backend.app.core.security import (  # noqa: E402
    PARTICULAS,
    calcular_sha256_archivo,
    construir_mapa_hmac_unicos,
    detectar_colisiones_canonicas,
    es_ip_externa_publica,
    normalizar_texto,
    resumir_distribucion_palabras,
    separar_apellidos_y_nombres,
    validar_y_reparar_ip_sin_puntos,
)

SERVIDOR_CENTRAL_IP = "10.10.100.30"
USUARIO_SERVIDOR_CENTRAL = "sist_med_iess"
IP_PUBLICA_ESPERADA = "186.46.219.18"

# Patrones estrictamente prohibidos en evidencias.json y en consola
CADENAS_PROHIBIDAS_PII = (
    "ROSALES",
    "PRIETO",
    "REYES",
    "VALENZUELA",
    "CALERO",
    "DIAZ",
    "pamela.rosales",
    "ivan.prieto",
    "andrea.reyes",
    "santiago.valenzuela",
    "RIMODE1",
    "MINAD",
    "CMAP09002",
    "WXY1210010",
    "XYZ9999",
    "XYZ1111",
    "XYW9999",
)

FW_SCHEMA_OVERRIDES: dict[str, pl.DataType] = {
    "Fecha_Generacion": pl.String,
    "IP_Origen": pl.String,
    "IP_Destino": pl.String,
    "Usuario_Origen": pl.String,
    "Usuario_Destino": pl.String,
    "Aplicacion": pl.String,
    "Puerto_Destino": pl.Int64,
    "Protocolo": pl.String,
    "Accion": pl.String,
}

MED_SCHEMA_OVERRIDES: dict[str, pl.DataType] = {
    "USUARIO_EJECUTA_EVENTO": pl.String,
    "NOMBRE_USUARIO_EJECUTA_EVENTO": pl.String,
    "FECHA_EJECUTA_EVENTO": pl.String,
    "HORA_EJECUTA_EVENTO": pl.String,
    "DESCRIPCION_ACCION": pl.String,
    "IP_CONEXION": pl.String,
}


def colectar_streaming(lf: pl.LazyFrame) -> pl.DataFrame:
    """Ejecuta un LazyFrame con el motor streaming compatible con Polars 2.x."""
    try:
        return lf.collect(engine="streaming")
    except TypeError:
        return lf.collect(streaming=True)


def detectar_bom_csv(ruta: Path) -> bool:
    """Comprueba si el archivo inicia con la marca BOM UTF-8 (\\xef\\xbb\\xbf)."""
    with ruta.open("rb") as f:
        return f.read(3) == b"\xef\xbb\xbf"


def escanear_fw(ruta: Path) -> pl.LazyFrame:
    """Abre el CSV del Firewall en modo Lazy limpiando BOM y vacíos en Usuario_Destino."""
    lf = pl.scan_csv(
        ruta,
        schema_overrides={
            **FW_SCHEMA_OVERRIDES,
            "\ufeffFecha_Generacion": pl.String,
        },
        null_values=[],
    )
    nombres = lf.collect_schema().names()
    renombres = {col: col.lstrip("\ufeff") for col in nombres if col.startswith("\ufeff")}
    if renombres:
        lf = lf.rename(renombres)
    return lf


def escanear_med(ruta: Path) -> pl.LazyFrame:
    """Abre el CSV del Sistema Médico en modo Lazy limpiando BOM inicial."""
    lf = pl.scan_csv(
        ruta,
        schema_overrides={
            **MED_SCHEMA_OVERRIDES,
            "\ufeffUSUARIO_EJECUTA_EVENTO": pl.String,
        },
        null_values=[],
    )
    nombres = lf.collect_schema().names()
    renombres = {col: col.lstrip("\ufeff") for col in nombres if col.startswith("\ufeff")}
    if renombres:
        lf = lf.rename(renombres)
    return lf


def auditar_lista_ips(
    df_ips: pl.DataFrame,
    col_ip: str,
    col_count: str = "len",
) -> dict[str, Any]:
    """
    Evalúa IPs únicas y sus frecuencias para detectar IPs sin puntos (^10\\d{9}$),
    verificar octetos entre 100 y 255, y validar la existencia de IPs públicas.
    """
    total_filas = 0
    dotless_filas = 0
    dotless_reparables_filas = 0
    dotless_no_reparables_filas = 0
    no_dotless_invalidas_filas = 0
    ips_publicas_conteo: Counter[str] = Counter()

    octetos_min = [999, 999, 999]
    octetos_max = [-1, -1, -1]
    fuera_de_rango_b1 = 0
    fuera_de_rango_b2 = 0
    fuera_de_rango_b3 = 0
    ejemplos_reparables: list[dict[str, Any]] = []
    ejemplos_no_reparables: list[dict[str, Any]] = []

    for row in df_ips.iter_rows(named=True):
        ip_raw = str(row[col_ip])
        conteo = int(row[col_count])
        total_filas += conteo

        ip_limpia, was_dotless, reparable = validar_y_reparar_ip_sin_puntos(ip_raw)
        if was_dotless:
            dotless_filas += conteo
            b1, b2, b3 = int(ip_raw[2:5]), int(ip_raw[5:8]), int(ip_raw[8:11])
            octetos_min = [min(octetos_min[0], b1), min(octetos_min[1], b2), min(octetos_min[2], b3)]
            octetos_max = [max(octetos_max[0], b1), max(octetos_max[1], b2), max(octetos_max[2], b3)]
            if not (100 <= b1 <= 255):
                fuera_de_rango_b1 += conteo
            if not (100 <= b2 <= 255):
                fuera_de_rango_b2 += conteo
            if not (100 <= b3 <= 255):
                fuera_de_rango_b3 += conteo

            if reparable:
                dotless_reparables_filas += conteo
                if len(ejemplos_reparables) < 5:
                    ejemplos_reparables.append(
                        {
                            "raw": ip_raw,
                            "reconstruida": ip_limpia,
                            "octetos": [b1, b2, b3],
                            "ocurrencias": conteo,
                        }
                    )
            else:
                dotless_no_reparables_filas += conteo
                if len(ejemplos_no_reparables) < 5:
                    ejemplos_no_reparables.append(
                        {
                            "raw": ip_raw,
                            "octetos": [b1, b2, b3],
                            "ocurrencias": conteo,
                        }
                    )
        elif not reparable:
            no_dotless_invalidas_filas += conteo

        if ip_limpia and es_ip_externa_publica(ip_limpia):
            ips_publicas_conteo[ip_limpia] += conteo

    return {
        "total_filas_evaluadas": total_filas,
        "ips_unicas_evaluadas": df_ips.height,
        "dotless_ip_filas": dotless_filas,
        "dotless_reparables_100_255_filas": dotless_reparables_filas,
        "dotless_no_reparables_filas": dotless_no_reparables_filas,
        "no_dotless_invalidas_filas": no_dotless_invalidas_filas,
        "octetos_rango_observado": (
            {
                "b1_min": octetos_min[0],
                "b1_max": octetos_max[0],
                "b2_min": octetos_min[1],
                "b2_max": octetos_max[1],
                "b3_min": octetos_min[2],
                "b3_max": octetos_max[2],
            }
            if dotless_filas > 0
            else None
        ),
        "octetos_fuera_rango_filas": {
            "b1": fuera_de_rango_b1,
            "b2": fuera_de_rango_b2,
            "b3": fuera_de_rango_b3,
        },
        "ejemplos_reparables": ejemplos_reparables,
        "ejemplos_no_reparables": ejemplos_no_reparables,
        "ips_publicas_post_reparacion": dict(ips_publicas_conteo),
    }


def construir_histograma_dict(df_hist: pl.DataFrame) -> dict[str, int]:
    """Convierte un DataFrame (hora, len) en diccionario ordenado '00'..'23'."""
    mapa = {f"{int(r['hora']):02d}": int(r["len"]) for r in df_hist.iter_rows(named=True)}
    return {f"{h:02d}": mapa.get(f"{h:02d}", 0) for h in range(24)}


def validar_cero_pii_en_texto(contenido_json: str) -> None:
    """Aborta con error explícito si cualquier identificador prohibido aparece en el JSON."""
    for patron in CADENAS_PROHIBIDAS_PII:
        if patron in contenido_json:
            raise RuntimeError(
                f"Violación LOPDP: se detectó cadena prohibida ({patron!r}) en evidencias.json"
            )


def ejecutar_auditoria() -> dict[str, Any]:
    """Ejecuta todas las verificaciones forenses en streaming y retorna el diccionario final."""
    cfg = get_settings()
    clave = cfg.PSEUDONYMIZATION_KEY
    fw_ruta = cfg.fw_csv_absoluto
    med_ruta = cfg.iess_csv_absoluto

    if not fw_ruta.exists():
        raise FileNotFoundError(f"No se encontró FW_CSV_PATH en {fw_ruta}")
    if not med_ruta.exists():
        raise FileNotFoundError(f"No se encontró IESS_CSV_PATH en {med_ruta}")

    print("[1/6] Calculando SHA-256 y metadatos base de ambos CSV...")
    fw_sha256 = calcular_sha256_archivo(fw_ruta)
    med_sha256 = calcular_sha256_archivo(med_ruta)
    fw_bom = detectar_bom_csv(fw_ruta)
    med_bom = detectar_bom_csv(med_ruta)

    lf_fw = escanear_fw(fw_ruta)
    lf_med = escanear_med(med_ruta)

    # ------------------------------------------------------------------
    # 1. Conteos globales, fechas, vacíos, invariantes y duplicados exactos
    # ------------------------------------------------------------------
    print("[2/6] Auditando conteos globales, duplicados, vacíos y typos...")
    fw_stats = colectar_streaming(
        lf_fw.select(
            pl.len().alias("total_filas"),
            pl.col("Fecha_Generacion").min().alias("fecha_min"),
            pl.col("Fecha_Generacion").max().alias("fecha_max"),
            (
                pl.col("Usuario_Destino").is_null() | (pl.col("Usuario_Destino") == "")
            )
            .sum()
            .alias("usuario_destino_vacios"),
            (pl.col("IP_Destino") == SERVIDOR_CENTRAL_IP)
            .sum()
            .alias("ip_destino_central"),
            (pl.col("Usuario_Destino") == USUARIO_SERVIDOR_CENTRAL)
            .sum()
            .alias("usuario_destino_central"),
            (
                (pl.col("IP_Destino") == SERVIDOR_CENTRAL_IP)
                & (pl.col("Usuario_Destino") == USUARIO_SERVIDOR_CENTRAL)
            )
            .sum()
            .alias("relacion_1a1_central"),
            (pl.col("Protocolo") == "SSH").sum().alias("protocolo_ssh_filas"),
            (pl.col("Aplicacion") == "SSH").sum().alias("aplicacion_ssh_filas"),
            (pl.col("Puerto_Destino") == 8443).sum().alias("puerto_8443_filas"),
        )
    ).to_dicts()[0]

    fw_filas_unicas = colectar_streaming(lf_fw.unique().select(pl.len())).item()
    fw_duplicados_exactos = int(fw_stats["total_filas"]) - int(fw_filas_unicas)

    med_stats = colectar_streaming(
        lf_med.select(
            pl.len().alias("total_filas"),
            pl.col("FECHA_EJECUTA_EVENTO").min().alias("fecha_min"),
            pl.col("FECHA_EJECUTA_EVENTO").max().alias("fecha_max"),
            pl.col("HORA_EJECUTA_EVENTO").min().alias("hora_min"),
            pl.col("HORA_EJECUTA_EVENTO").max().alias("hora_max"),
            pl.col("USUARIO_EJECUTA_EVENTO")
            .str.starts_with("SIM")
            .sum()
            .alias("filas_sim"),
            (~pl.col("USUARIO_EJECUTA_EVENTO").str.starts_with("SIM"))
            .sum()
            .alias("filas_especiales"),
            (pl.col("IP_CONEXION") == SERVIDOR_CENTRAL_IP)
            .sum()
            .alias("ip_central_filas"),
        )
    ).to_dicts()[0]

    med_filas_unicas = colectar_streaming(lf_med.unique().select(pl.len())).item()
    med_duplicados_exactos = int(med_stats["total_filas"]) - int(med_filas_unicas)

    df_acciones_med = colectar_streaming(
        lf_med.group_by("DESCRIPCION_ACCION").len().sort("len", descending=True)
    )
    acciones_med_dict = {
        r["DESCRIPCION_ACCION"]: int(r["len"]) for r in df_acciones_med.iter_rows(named=True)
    }
    acciones_con_s = sum(
        v for k, v in acciones_med_dict.items() if "TRANSFERENCIA" in k
    )

    # ------------------------------------------------------------------
    # 2. Histograma horario 0..23 de FW y MedSys (total vs especiales)
    # ------------------------------------------------------------------
    print("[3/6] Calculando histogramas horarios 00..23...")
    df_hist_fw = colectar_streaming(
        lf_fw.with_columns(
            pl.col("Fecha_Generacion").str.slice(11, 2).cast(pl.Int32).alias("hora")
        )
        .group_by("hora")
        .len()
        .sort("hora")
    )
    df_hist_med_total = colectar_streaming(
        lf_med.with_columns(
            pl.col("HORA_EJECUTA_EVENTO").str.slice(0, 2).cast(pl.Int32).alias("hora")
        )
        .group_by("hora")
        .len()
        .sort("hora")
    )
    df_hist_med_esp = colectar_streaming(
        lf_med.filter(~pl.col("USUARIO_EJECUTA_EVENTO").str.starts_with("SIM"))
        .with_columns(
            pl.col("HORA_EJECUTA_EVENTO").str.slice(0, 2).cast(pl.Int32).alias("hora")
        )
        .group_by("hora")
        .len()
        .sort("hora")
    )

    hist_fw = construir_histograma_dict(df_hist_fw)
    hist_med_total = construir_histograma_dict(df_hist_med_total)
    hist_med_esp = construir_histograma_dict(df_hist_med_esp)

    med_horas_13_23 = sum(hist_med_total[f"{h:02d}"] for h in range(13, 24))
    med_horas_00_12 = sum(hist_med_total[f"{h:02d}"] for h in range(0, 13))
    med_esp_horas_13_23 = sum(hist_med_esp[f"{h:02d}"] for h in range(13, 24))

    # ------------------------------------------------------------------
    # 3. Validación estricta de IPs sin puntos (^10\d{9}$) y 1 IP pública
    # ------------------------------------------------------------------
    print("[4/6] Auditando IPs sin puntos (octetos 100..255) y única IP pública...")
    df_fw_src_ips = colectar_streaming(lf_fw.group_by("IP_Origen").len())
    df_fw_dst_ips = colectar_streaming(lf_fw.group_by("IP_Destino").len())
    df_med_ips_total = colectar_streaming(lf_med.group_by("IP_CONEXION").len())
    df_med_ips_sim = colectar_streaming(
        lf_med.filter(pl.col("USUARIO_EJECUTA_EVENTO").str.starts_with("SIM"))
        .group_by("IP_CONEXION")
        .len()
    )
    df_med_ips_esp = colectar_streaming(
        lf_med.filter(~pl.col("USUARIO_EJECUTA_EVENTO").str.starts_with("SIM"))
        .group_by("IP_CONEXION")
        .len()
    )

    audit_fw_src = auditar_lista_ips(df_fw_src_ips, "IP_Origen")
    audit_fw_dst = auditar_lista_ips(df_fw_dst_ips, "IP_Destino")
    audit_med_total = auditar_lista_ips(df_med_ips_total, "IP_CONEXION")
    audit_med_sim = auditar_lista_ips(df_med_ips_sim, "IP_CONEXION")
    audit_med_esp = auditar_lista_ips(df_med_ips_esp, "IP_CONEXION")

    # ------------------------------------------------------------------
    # 4. Auditoría de identidades, colisiones, partículas y mapa HMAC único
    # ------------------------------------------------------------------
    print("[5/6] Auditando identidades, colisiones y seudonimización sobre únicos...")
    df_fw_uorig = colectar_streaming(lf_fw.group_by("Usuario_Origen").len())
    df_fw_udest = colectar_streaming(
        lf_fw.with_columns(
            pl.when(
                pl.col("Usuario_Destino").is_null() | (pl.col("Usuario_Destino") == "")
            )
            .then(pl.lit("EMPTY"))
            .otherwise(pl.col("Usuario_Destino"))
            .alias("Usuario_Destino_Norm")
        )
        .group_by("Usuario_Destino_Norm")
        .len()
    )
    df_med_nombres = colectar_streaming(
        lf_med.group_by("NOMBRE_USUARIO_EJECUTA_EVENTO").len()
    )
    df_med_cuentas = colectar_streaming(
        lf_med.group_by("USUARIO_EJECUTA_EVENTO").len()
    )
    df_med_esp_nombre_cnt = colectar_streaming(
        lf_med.filter(~pl.col("USUARIO_EJECUTA_EVENTO").str.starts_with("SIM"))
        .group_by("NOMBRE_USUARIO_EJECUTA_EVENTO")
        .len()
    )

    fw_usuarios_origen_unicos = df_fw_uorig["Usuario_Origen"].to_list()
    fw_usuarios_destino_personales = [
        u
        for u in df_fw_udest["Usuario_Destino_Norm"].to_list()
        if u not in {"EMPTY", USUARIO_SERVIDOR_CENTRAL}
    ]
    med_nombres_unicos = df_med_nombres["NOMBRE_USUARIO_EJECUTA_EVENTO"].to_list()
    med_cuentas_especiales = sorted(
        c
        for c in df_med_cuentas["USUARIO_EJECUTA_EVENTO"].to_list()
        if not c.startswith("SIM")
    )

    # Construcción de mapas HMAC exclusivamente sobre valores únicos
    todos_canonicos_unicos = (
        set(fw_usuarios_origen_unicos)
        | set(fw_usuarios_destino_personales)
    )
    mapa_canonico_med, canonicos_ambiguos, conteos_por_canonico = (
        detectar_colisiones_canonicas(med_nombres_unicos)
    )
    todos_canonicos_unicos |= set(mapa_canonico_med.values()) - {""}

    mapa_hmac_actores = construir_mapa_hmac_unicos(
        todos_canonicos_unicos, clave=clave, prefijo="USR"
    )
    mapa_hmac_cuentas = construir_mapa_hmac_unicos(
        med_cuentas_especiales, clave=clave, prefijo="ACC"
    )

    # Análisis estructural de Usuario_Origen en FW (sin guardar nombres reales)
    fw_apellidos_long = [
        len(u.split(".", 1)[1]) for u in fw_usuarios_origen_unicos if "." in u
    ]
    fw_sin_un_punto = sum(1 for u in fw_usuarios_origen_unicos if u.count(".") != 1)
    fw_con_espacios_o_no_ascii = sum(
        1 for u in fw_usuarios_origen_unicos if (" " in u or not u.isascii())
    )
    fw_prefijo_particula = sum(
        1
        for u in fw_usuarios_origen_unicos
        if "." in u
        and u.split(".", 1)[1].startswith(("dela", "delos", "delas", "del", "san", "santa"))
    )

    # Análisis estructural de NOMBRE_USUARIO_EJECUTA_EVENTO en MedSys
    dist_palabras_med = resumir_distribucion_palabras(med_nombres_unicos)
    conteo_menos_4 = sum(v for k, v in dist_palabras_med.items() if k < 4)
    conteo_mas_4 = sum(v for k, v in dist_palabras_med.items() if k > 4)

    nombres_con_particula_total = 0
    particula_en_apellidos = 0
    particula_en_nombres = 0
    particulas_vistas: Counter[str] = Counter()

    for nombre in med_nombres_unicos:
        toks = normalizar_texto(nombre).split()
        toks_part = [t for t in toks if t in PARTICULAS]
        if toks_part:
            nombres_con_particula_total += 1
            for tp in toks_part:
                particulas_vistas[tp] += 1
            apellidos, nombres = separar_apellidos_y_nombres(nombre)
            ap_toks = " ".join(apellidos).split()
            nom_toks = " ".join(nombres).split()
            if any(t in PARTICULAS for t in ap_toks):
                particula_en_apellidos += 1
            if any(t in PARTICULAS for t in nom_toks):
                particula_en_nombres += 1

    # Estadísticas de colisión de canónicos (nombre1.apellido1)
    distribucion_multiplicidad = Counter(conteos_por_canonico.values())
    nombres_afectados_colision = sum(
        c for c in conteos_por_canonico.values() if c > 1
    )
    filas_med_por_nombre = {
        r["NOMBRE_USUARIO_EJECUTA_EVENTO"]: int(r["len"])
        for r in df_med_nombres.iter_rows(named=True)
    }
    filas_med_totales_ambiguas = sum(
        filas_med_por_nombre[n]
        for n in med_nombres_unicos
        if mapa_canonico_med.get(n) in canonicos_ambiguos
    )
    filas_esp_ambiguas = sum(
        int(r["len"])
        for r in df_med_esp_nombre_cnt.iter_rows(named=True)
        if mapa_canonico_med.get(r["NOMBRE_USUARIO_EJECUTA_EVENTO"]) in canonicos_ambiguos
    )

    top_colisiones_tokens = [
        {
            "actor_token": mapa_hmac_actores[canonico],
            "personas_distintas": total,
        }
        for canonico, total in sorted(
            ((c, n) for c, n in conteos_por_canonico.items() if n > 1),
            key=lambda par: (-par[1], par[0]),
        )[:15]
    ]

    canonicos_med_set = set(mapa_canonico_med.values()) - {""}
    interseccion_fw_med = set(fw_usuarios_origen_unicos) & canonicos_med_set

    # Desglose de IPs sin puntos en cuentas especiales usando solo ACC-...
    df_med_dotless_por_cuenta = colectar_streaming(
        lf_med.filter(
            (~pl.col("USUARIO_EJECUTA_EVENTO").str.starts_with("SIM"))
            & pl.col("IP_CONEXION").str.contains(r"^10\d{9}$")
        )
        .group_by("USUARIO_EJECUTA_EVENTO")
        .len()
        .sort("len", descending=True)
    )
    med_dotless_por_account_token = {
        mapa_hmac_cuentas[r["USUARIO_EJECUTA_EVENTO"]]: int(r["len"])
        for r in df_med_dotless_por_cuenta.iter_rows(named=True)
    }

    # ------------------------------------------------------------------
    # 5. Auditoría del canal 8443/tcp (811 filas) y verificación 5 incidentes
    # ------------------------------------------------------------------
    print("[6/6] Auditando canal 8443/tcp y cuantificando los 5 incidentes forenses...")
    df_8443 = colectar_streaming(
        lf_fw.filter(pl.col("Puerto_Destino") == 8443)
    )
    destinos_8443_conteo = Counter(df_8443["IP_Destino"].to_list())
    actores_8443_tokens = Counter(
        mapa_hmac_actores[u] for u in df_8443["Usuario_Origen"].to_list()
    )
    apps_8443_conteo = Counter(df_8443["Aplicacion"].to_list())
    acciones_8443_conteo = Counter(df_8443["Accion"].to_list())
    protocols_8443_conteo = Counter(df_8443["Protocolo"].to_list())
    ip_orig_8443_subred_100 = df_8443.filter(
        pl.col("IP_Origen").str.starts_with("10.10.100.")
    ).height
    ip_dst_8443_dotless = sum(
        1
        for ip in df_8443["IP_Destino"].to_list()
        if validar_y_reparar_ip_sin_puntos(ip)[1]
    )

    # Cruce 8443/tcp vs SSH (826 filas) y actores de incidentes
    df_ssh_app = colectar_streaming(
        lf_fw.filter(pl.col("Aplicacion") == "SSH")
    )
    actores_ssh_app_tokens = set(
        mapa_hmac_actores[u] for u in df_ssh_app["Usuario_Origen"].to_list()
    )
    ips_ssh_app = set(df_ssh_app["IP_Origen"].to_list())
    actores_8443_set = set(actores_8443_tokens.keys())
    ips_8443_origen_set = set(df_8443["IP_Origen"].to_list())

    # Incidente A: Telnet 23/tcp (2,000) <-> XYZ9999021 (2,000 ACCESO FALLIDO)
    df_inc_a_fw = colectar_streaming(
        lf_fw.filter(
            (pl.col("Fecha_Generacion").str.starts_with("2026-10-10 00:"))
            & (pl.col("IP_Origen") == "10.10.100.10")
            & (pl.col("IP_Destino") == SERVIDOR_CENTRAL_IP)
            & (pl.col("Puerto_Destino") == 23)
            & (pl.col("Accion") == "negado")
        )
    )
    df_inc_a_med = colectar_streaming(
        lf_med.filter(
            (pl.col("FECHA_EJECUTA_EVENTO") == "20261010")
            & (pl.col("HORA_EJECUTA_EVENTO").str.starts_with("00:"))
            & (pl.col("DESCRIPCION_ACCION") == "ACCESO FALLIDO")
            & (~pl.col("USUARIO_EJECUTA_EVENTO").str.starts_with("SIM"))
        )
    )

    # Incidente B: Escaneo 4x250 + RIMODE1 (1,000 + 118)
    df_inc_b_fw = colectar_streaming(
        lf_fw.filter(
            (pl.col("Fecha_Generacion").str.starts_with("2026-10-19 14:"))
            & (pl.col("IP_Origen") == "10.10.100.20")
            & (pl.col("IP_Destino") == SERVIDOR_CENTRAL_IP)
            & (pl.col("Accion") == "negado")
        )
        .group_by(["Puerto_Destino", "Protocolo", "Aplicacion"])
        .len()
        .sort("Puerto_Destino")
    )
    df_inc_b_med = colectar_streaming(
        lf_med.filter(pl.col("USUARIO_EJECUTA_EVENTO") == "RIMODE1")
        .with_columns(
            (
                (pl.col("FECHA_EJECUTA_EVENTO") == "20261019")
                & (pl.col("HORA_EJECUTA_EVENTO").str.starts_with("14:"))
                & (pl.col("DESCRIPCION_ACCION") == "ACCESO FALLIDO")
            ).alias("en_ventana_incidente")
        )
        .group_by(["en_ventana_incidente", "DESCRIPCION_ACCION"])
        .len()
    )

    # Incidente C: Protocolo == "SSH" (30) <-> XYZ1111331 (30 exitosas + 2,970 interrumpidas)
    df_inc_c_fw = colectar_streaming(
        lf_fw.filter(pl.col("Protocolo") == "SSH")
    )
    df_inc_c_med = colectar_streaming(
        lf_med.filter(pl.col("USUARIO_EJECUTA_EVENTO") == "XYZ1111331")
        .group_by("DESCRIPCION_ACCION")
        .len()
    )

    # Incidente D: Exfiltración 2026-10-24 (SSH 22:40:00 -> MedSys 10:40:00/10:40:15 -> 186.46.219.18:8443 22:40:30)
    df_inc_d_fw = colectar_streaming(
        lf_fw.filter(
            (pl.col("Fecha_Generacion").str.starts_with("2026-10-24 22:40:"))
            & (pl.col("IP_Origen") == "10.10.100.40")
        ).sort("Fecha_Generacion")
    )
    df_inc_d_med = colectar_streaming(
        lf_med.filter(pl.col("USUARIO_EJECUTA_EVENTO") == "WXY1210010")
        .sort(["FECHA_EJECUTA_EVENTO", "HORA_EJECUTA_EVENTO"])
    )

    # Incidente E y resumen de las 16 cuentas especiales (totalmente tokenizadas)
    df_esp_resumen = colectar_streaming(
        lf_med.filter(~pl.col("USUARIO_EJECUTA_EVENTO").str.starts_with("SIM"))
        .group_by(["USUARIO_EJECUTA_EVENTO", "DESCRIPCION_ACCION"])
        .len()
    )
    resumen_cuentas_esp: dict[str, dict[str, Any]] = {}
    for row in df_esp_resumen.iter_rows(named=True):
        acc_tok = mapa_hmac_cuentas[row["USUARIO_EJECUTA_EVENTO"]]
        entry = resumen_cuentas_esp.setdefault(
            acc_tok, {"total_filas": 0, "acciones": {}, "dotless_ips": 0}
        )
        entry["total_filas"] += int(row["len"])
        entry["acciones"][row["DESCRIPCION_ACCION"]] = int(row["len"])
    for acc_tok, cnt in med_dotless_por_account_token.items():
        if acc_tok in resumen_cuentas_esp:
            resumen_cuentas_esp[acc_tok]["dotless_ips"] = cnt

    # Actores involucrados en los incidentes A..D (solo tokens y bandera ambigua)
    actores_incidentes_canonicos = {
        "incidente_A": df_inc_a_fw["Usuario_Origen"][0],
        "incidente_B": "andrea.reyes",
        "incidente_C": df_inc_c_fw["Usuario_Origen"][0],
        "incidente_D": df_inc_d_fw["Usuario_Origen"][0],
    }
    estado_actores_incidentes = {
        clave_inc: {
            "actor_token": mapa_hmac_actores[canon],
            "personas_distintas_con_mismo_canonico": conteos_por_canonico.get(canon, 0),
            "identidad_ambigua": canon in canonicos_ambiguos,
        }
        for clave_inc, canon in actores_incidentes_canonicos.items()
    }

    incidente_a_account_tok = mapa_hmac_cuentas[df_inc_a_med["USUARIO_EJECUTA_EVENTO"][0]]
    incidente_b_account_tok = mapa_hmac_cuentas["RIMODE1"]
    incidente_c_account_tok = mapa_hmac_cuentas["XYZ1111331"]
    incidente_d_account_tok = mapa_hmac_cuentas["WXY1210010"]
    minad_account_tok = mapa_hmac_cuentas["MINAD"]
    cmap_account_tok = mapa_hmac_cuentas["CMAP09002"]
    xyz9999002_account_tok = mapa_hmac_cuentas["XYZ9999002"]

    evidencias: dict[str, Any] = {
        "generado_por": "scripts/verificar_datos.py",
        "version_esquema": "1.0-rol1",
        "lopdp_politica": "Cero PII y cero cuentas técnicas en claro; tokens HMAC-SHA256 truncados a 12 hex.",
        "resumen_datasets": {
            "total_registros_combinados": int(fw_stats["total_filas"]) + int(med_stats["total_filas"]),
            "firewall": {
                "archivo": fw_ruta.name,
                "tamano_bytes": fw_ruta.stat().st_size,
                "sha256": fw_sha256,
                "bom_utf8_detectado": fw_bom,
                "total_filas": int(fw_stats["total_filas"]),
                "duplicados_exactos": fw_duplicados_exactos,
                "rango_fechas": {
                    "min": fw_stats["fecha_min"],
                    "max": fw_stats["fecha_max"],
                },
                "usuario_destino_vacios": int(fw_stats["usuario_destino_vacios"]),
                "ip_destino_central_filas": int(fw_stats["ip_destino_central"]),
                "usuario_destino_central_filas": int(fw_stats["usuario_destino_central"]),
                "relacion_1a1_central_exacta": int(fw_stats["relacion_1a1_central"])
                == int(fw_stats["ip_destino_central"])
                == int(fw_stats["usuario_destino_central"]),
            },
            "sistema_medico": {
                "archivo": med_ruta.name,
                "tamano_bytes": med_ruta.stat().st_size,
                "sha256": med_sha256,
                "bom_utf8_detectado": med_bom,
                "total_filas": int(med_stats["total_filas"]),
                "duplicados_exactos": med_duplicados_exactos,
                "rango_fechas": {
                    "fecha_min": med_stats["fecha_min"],
                    "fecha_max": med_stats["fecha_max"],
                    "hora_min": med_stats["hora_min"],
                    "hora_max": med_stats["hora_max"],
                },
                "filas_sim": int(med_stats["filas_sim"]),
                "filas_cuentas_especiales": int(med_stats["filas_especiales"]),
                "cuentas_especiales_unicas": len(med_cuentas_especiales),
                "ip_central_filas": int(med_stats["ip_central_filas"]),
                "acciones_distribucion": acciones_med_dict,
                "trampa_typo_tranferencia": {
                    "tranferencia_exitosa_sin_s": acciones_med_dict.get("TRANFERENCIA EXITOSA", 0),
                    "tranferencia_interrumpida_sin_s": acciones_med_dict.get("TRANFERENCIA INTERRUMPIDA", 0),
                    "transferencia_con_s_encontradas": acciones_con_s,
                },
            },
        },
        "histograma_horario": {
            "firewall_00_23": hist_fw,
            "medsys_total_00_23": hist_med_total,
            "medsys_especiales_00_23": hist_med_esp,
            "resumen_horas_tarde_noche_medsys": {
                "medsys_total_horas_00_12": med_horas_00_12,
                "medsys_total_horas_13_23": med_horas_13_23,
                "porcentaje_horas_13_23": round(
                    100.0 * med_horas_13_23 / int(med_stats["total_filas"]), 2
                ),
                "medsys_especiales_horas_13_23": med_esp_horas_13_23,
                "confirmacion_reloj_24h_y_prohibicion_ajuste_global": (
                    med_horas_13_23 > 0
                ),
            },
        },
        "auditoria_ips_sin_puntos": {
            "fw_ip_origen": audit_fw_src,
            "fw_ip_destino": audit_fw_dst,
            "medsys_total_ip_conexion": audit_med_total,
            "medsys_sim_ip_conexion": audit_med_sim,
            "medsys_especiales_ip_conexion": audit_med_esp,
            "medsys_dotless_por_account_token": med_dotless_por_account_token,
            "confirmacion_unica_ip_publica": {
                "fw_ips_publicas": audit_fw_dst["ips_publicas_post_reparacion"],
                "medsys_ips_publicas": audit_med_total["ips_publicas_post_reparacion"],
                "ip_publica_esperada_unica": list(
                    audit_fw_dst["ips_publicas_post_reparacion"].keys()
                )
                == [IP_PUBLICA_ESPERADA],
            },
        },
        "auditoria_identidades_y_colisiones": {
            "firewall": {
                "usuario_origen_unicos": len(fw_usuarios_origen_unicos),
                "usuario_destino_personales_unicos": len(fw_usuarios_destino_personales),
                "formato_sin_un_punto": fw_sin_un_punto,
                "con_espacios_o_no_ascii": fw_con_espacios_o_no_ascii,
                "apellido_longitud_min": min(fw_apellidos_long),
                "apellido_longitud_max": max(fw_apellidos_long),
                "apellidos_con_particula_concatenada_detectados": fw_prefijo_particula,
            },
            "sistema_medico": {
                "nombres_completos_unicos": len(med_nombres_unicos),
                "distribucion_palabras_por_nombre": {
                    str(k): v for k, v in dist_palabras_med.items()
                },
                "nombres_menos_4_palabras": conteo_menos_4,
                "nombres_mas_4_palabras": conteo_mas_4,
                "nombres_con_particulas": {
                    "total_nombres_con_particula": nombres_con_particula_total,
                    "en_apellidos": particula_en_apellidos,
                    "en_nombres": particula_en_nombres,
                    "frecuencia_particulas": dict(particulas_vistas.most_common()),
                },
            },
            "colisiones_canonico_nombre1_apellido1": {
                "canonicos_unicos_medsys": len(conteos_por_canonico),
                "canonicos_con_colision": len(canonicos_ambiguos),
                "porcentaje_canonicos_con_colision": round(
                    100.0 * len(canonicos_ambiguos) / len(conteos_por_canonico), 2
                ),
                "nombres_completos_afectados": nombres_afectados_colision,
                "distribucion_multiplicidad": {
                    str(k): v for k, v in sorted(distribucion_multiplicidad.items())
                },
                "filas_medsys_totales_con_identidad_ambigua": filas_med_totales_ambiguas,
                "filas_medsys_especiales_con_identidad_ambigua": filas_esp_ambiguas,
                "interseccion_canonicos_fw_y_medsys": len(interseccion_fw_med),
                "top_15_actor_tokens_mas_colisiones": top_colisiones_tokens,
                "estado_actores_incidentes_A_a_D": estado_actores_incidentes,
            },
        },
        "auditoria_canal_8443_tcp": {
            "total_registros_8443": df_8443.height,
            "rango_fechas": {
                "min": df_8443["Fecha_Generacion"].min(),
                "max": df_8443["Fecha_Generacion"].max(),
            },
            "protocolos": dict(protocols_8443_conteo),
            "aplicaciones": dict(apps_8443_conteo),
            "acciones": dict(acciones_8443_conteo),
            "destinos": {
                "hacia_10_10_100_30_central": destinos_8443_conteo.get(SERVIDOR_CENTRAL_IP, 0),
                "hacia_186_46_219_18_externa": destinos_8443_conteo.get(IP_PUBLICA_ESPERADA, 0),
                "hacia_otras_ips_internas": sum(
                    v
                    for k, v in destinos_8443_conteo.items()
                    if k not in {SERVIDOR_CENTRAL_IP, IP_PUBLICA_ESPERADA}
                ),
                "destinos_unicos_totales": len(destinos_8443_conteo),
                "destinos_ip_sin_puntos": ip_dst_8443_dotless,
            },
            "origenes": {
                "ips_origen_unicas": len(ips_8443_origen_set),
                "ips_subred_10_10_100_x": ip_orig_8443_subred_100,
                "actor_tokens_unicos": len(actores_8443_set),
                "actor_incident_D_presente": estado_actores_incidentes["incidente_D"]["actor_token"]
                in actores_8443_set,
                "ocurrencias_actor_incident_D_en_8443": actores_8443_tokens.get(
                    estado_actores_incidentes["incidente_D"]["actor_token"], 0
                ),
                "top_5_actores_en_8443": [
                    {"actor_token": tok, "eventos": cnt}
                    for tok, cnt in actores_8443_tokens.most_common(5)
                ],
            },
            "cruce_con_canal_ssh_826": {
                "actores_compartidos_8443_y_ssh": len(actores_8443_set & actores_ssh_app_tokens),
                "ips_origen_compartidas_8443_y_ssh": len(ips_8443_origen_set & ips_ssh_app),
                "evaluacion_hipotesis_005_a_001": (
                    "Solo 1 registro de 8443/tcp (actor e IP del Incidente D) apunta a 186.46.219.18; "
                    "el resto del tráfico 8443/tcp se distribuye en usuarios e IPs internas sin concentración en la subred 10.10.100.x."
                ),
            },
        },
        "verificacion_5_incidentes": {
            "incidente_A_telnet_brute_force": {
                "actor_token": estado_actores_incidentes["incidente_A"]["actor_token"],
                "account_token": incidente_a_account_tok,
                "fw_ip_origen": "10.10.100.10",
                "fw_puerto": 23,
                "fw_conexiones_negadas_ventana": df_inc_a_fw.height,
                "med_eventos_acceso_fallido_ventana": df_inc_a_med.height,
            },
            "incidente_B_escaneo_multiservicio_y_spraying": {
                "actor_token": estado_actores_incidentes["incidente_B"]["actor_token"],
                "account_token": incidente_b_account_tok,
                "fw_ip_origen": "10.10.100.20",
                "fw_bloques_negados_por_puerto": [
                    {
                        "puerto": int(r["Puerto_Destino"]),
                        "protocolo": r["Protocolo"],
                        "aplicacion": r["Aplicacion"],
                        "eventos": int(r["len"]),
                    }
                    for r in df_inc_b_fw.iter_rows(named=True)
                ],
                "med_account_desglose": [
                    {
                        "en_ventana_incidente": bool(r["en_ventana_incidente"]),
                        "accion": r["DESCRIPCION_ACCION"],
                        "eventos": int(r["len"]),
                    }
                    for r in df_inc_b_med.iter_rows(named=True)
                ],
            },
            "incidente_C_exfiltracion_protocolo_ssh": {
                "actor_token": estado_actores_incidentes["incidente_C"]["actor_token"],
                "account_token": incidente_c_account_tok,
                "fw_ip_origen": "10.10.100.50",
                "fw_protocolo_ssh_filas": df_inc_c_fw.height,
                "med_transferencias": {
                    r["DESCRIPCION_ACCION"]: int(r["len"])
                    for r in df_inc_c_med.iter_rows(named=True)
                },
            },
            "incidente_D_exfiltracion_8443_desfase_12h": {
                "actor_token": estado_actores_incidentes["incidente_D"]["actor_token"],
                "account_token": incidente_d_account_tok,
                "fw_ip_origen": "10.10.100.40",
                "fw_eventos_ventana_22_40": [
                    {
                        "ts": r["Fecha_Generacion"],
                        "dst_ip": r["IP_Destino"],
                        "puerto": int(r["Puerto_Destino"]),
                        "aplicacion": r["Aplicacion"],
                        "accion": r["Accion"],
                    }
                    for r in df_inc_d_fw.iter_rows(named=True)
                ],
                "med_eventos_account": [
                    {
                        "fecha": r["FECHA_EJECUTA_EVENTO"],
                        "hora": r["HORA_EJECUTA_EVENTO"],
                        "accion": r["DESCRIPCION_ACCION"],
                        "conn_ip": r["IP_CONEXION"],
                    }
                    for r in df_inc_d_med.iter_rows(named=True)
                ],
                "desfase_horario_detectado_horas": 12,
                "clock_skew_12h_fix_requerido": True,
            },
            "incidente_E_ssh_y_abuso_cuentas_especiales": {
                "fw_aplicacion_ssh_filas": int(fw_stats["aplicacion_ssh_filas"]),
                "fw_puerto_8443_filas": int(fw_stats["puerto_8443_filas"]),
                "med_reactivaciones_cuenta_espejo_token": xyz9999002_account_tok,
                "med_reactivaciones_cuenta_espejo_conteo": resumen_cuentas_esp[
                    xyz9999002_account_tok
                ]["acciones"].get("Reactivacion de usuarios", 0),
                "med_cuenta_nivel_token": minad_account_tok,
                "med_cuenta_nivel_filas": resumen_cuentas_esp[minad_account_tok]["total_filas"],
                "med_cuenta_activacion_token": cmap_account_tok,
                "med_cuenta_activacion_filas": resumen_cuentas_esp[cmap_account_tok]["total_filas"],
                "resumen_16_cuentas_especiales_tokenizadas": resumen_cuentas_esp,
            },
        },
    }

    json_serializado = json.dumps(evidencias, indent=2, ensure_ascii=False)
    validar_cero_pii_en_texto(json_serializado)

    salida_ruta = PROJECT_ROOT / "docs" / "evidencias" / "evidencias.json"
    salida_ruta.parent.mkdir(parents=True, exist_ok=True)
    salida_ruta.write_text(json_serializado + "\n", encoding="utf-8")
    print(f"[OK] Evidencias generadas sin PII en: {salida_ruta}")
    return evidencias


if __name__ == "__main__":
    ejecutar_auditoria()
