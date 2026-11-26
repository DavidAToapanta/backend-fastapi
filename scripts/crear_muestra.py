"""
Generador de muestra rápida Parquet (~200,000 filas por capa) para la Fase 1
del Rol 1. Desbloquea de inmediato el desarrollo de ML (Rol 2) y API/PDF (Rol 3)
garantizando la inclusión completa de las ventanas ±10 min de los 5 incidentes y
la seudonimización estricta bajo LOPDP Art. 25.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import polars as pl

# Asegura resolución de paquetes locales aunque el script se ejecute desde scripts/
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.core.config import get_settings  # noqa: E402
from backend.app.core.security import (  # noqa: E402
    construir_mapa_hmac_unicos,
    detectar_colisiones_canonicas,
    es_ip_externa_publica,
    validar_y_reparar_ip_sin_puntos,
)
from scripts.verificar_datos import (  # noqa: E402
    CADENAS_PROHIBIDAS_PII,
    IP_PUBLICA_ESPERADA,
    SERVIDOR_CENTRAL_IP,
    USUARIO_SERVIDOR_CENTRAL,
    colectar_streaming,
    escanear_fw,
    escanear_med,
)

MUESTRA_BASE_OBJETIVO = 180_000
SEMILLA_MUESTRA = 42


def _construir_diccionario_ips(valores_unicos: list[str]) -> dict[str, tuple[str | None, bool, bool, bool]]:
    """Precalcula reparación y clasificación pública exclusivamente sobre IPs únicas."""
    resultado: dict[str, tuple[str | None, bool, bool, bool]] = {}
    for ip_raw in valores_unicos:
        ip_limpia, was_dotless, reparable = validar_y_reparar_ip_sin_puntos(ip_raw)
        externa = es_ip_externa_publica(ip_limpia)
        resultado[ip_raw] = (ip_limpia, was_dotless, reparable, externa)
    return resultado


def _filtro_ventanas_incidentes_fw() -> pl.Expr:
    """Expresión booleana que captura ±10 minutos de incidentes A-D y alta señal de E."""
    ts = pl.col("Fecha_Generacion")
    ventanas_tiempo = (
        # Incidente C (2026-10-07 13:00:xx -> 12:50:00..13:15:59)
        ((ts >= "2026-10-07 12:50:00") & (ts <= "2026-10-07 13:15:59"))
        # Incidente A (2026-10-10 00:00..00:59 -> 2026-10-09 23:50:00..2026-10-10 01:10:00)
        | ((ts >= "2026-10-09 23:50:00") & (ts <= "2026-10-10 01:10:00"))
        # Incidente B (2026-10-19 14:00..14:59 -> 13:50:00..15:10:00)
        | ((ts >= "2026-10-19 13:50:00") & (ts <= "2026-10-19 15:10:00"))
        # Incidente D ventana MedSys (10:30..10:50) y ventana FW (22:30..22:50)
        | ((ts >= "2026-10-24 10:30:00") & (ts <= "2026-10-24 10:50:59"))
        | ((ts >= "2026-10-24 22:30:00") & (ts <= "2026-10-24 22:50:59"))
    )
    alta_senal_e = (
        (pl.col("Aplicacion") == "SSH")
        | (pl.col("Protocolo") == "SSH")
        | (pl.col("Puerto_Destino") == 8443)
        | pl.col("IP_Destino").str.contains(r"^10\d{9}$")
        | (pl.col("IP_Destino") == IP_PUBLICA_ESPERADA)
    )
    return ventanas_tiempo | alta_senal_e


def _filtro_ventanas_incidentes_med() -> pl.Expr:
    """Expresión booleana que captura todas las 14,501 cuentas especiales y ventanas ±10 min."""
    ts = pl.col("FECHA_EJECUTA_EVENTO") + " " + pl.col("HORA_EJECUTA_EVENTO")
    ventanas_tiempo = (
        ((ts >= "20261007 12:50:00") & (ts <= "20261007 13:15:59"))
        | ((ts >= "20261009 23:50:00") & (ts <= "20261010 01:10:00"))
        | ((ts >= "20261019 13:50:00") & (ts <= "20261019 15:10:00"))
        | ((ts >= "20261024 10:30:00") & (ts <= "20261024 10:50:59"))
        | ((ts >= "20261024 22:30:00") & (ts <= "20261024 22:50:59"))
    )
    cuentas_especiales = ~pl.col("USUARIO_EJECUTA_EVENTO").str.starts_with("SIM")
    return ventanas_tiempo | cuentas_especiales


def _validar_parquet_sin_pii(ruta_parquet: Path) -> int:
    """Lee el Parquet resultante y verifica que no contenga ningún texto PII prohibido."""
    df = pl.read_parquet(ruta_parquet)
    columnas_texto = [c for c, dt in df.schema.items() if dt == pl.String]
    for col in columnas_texto:
        for patron in CADENAS_PROHIBIDAS_PII:
            if df.filter(pl.col(col).str.contains(patron, literal=True)).height > 0:
                raise RuntimeError(
                    f"Fuga LOPDP en {ruta_parquet.name} columna {col}: patrón {patron!r}"
                )
    return df.height


def generar_muestras() -> dict[str, Any]:
    """Construye sample_fw_200k.parquet y sample_med_200k.parquet seudonimizados."""
    cfg = get_settings()
    clave = cfg.PSEUDONYMIZATION_KEY
    fw_ruta = cfg.fw_csv_absoluto
    med_ruta = cfg.iess_csv_absoluto

    salida_dir = PROJECT_ROOT / "data" / "processed"
    salida_dir.mkdir(parents=True, exist_ok=True)
    out_fw = salida_dir / "sample_fw_200k.parquet"
    out_med = salida_dir / "sample_med_200k.parquet"

    lf_fw = escanear_fw(fw_ruta)
    lf_med = escanear_med(med_ruta)

    # 1. Precalcular mapas de colisiones y HMAC exclusivamente sobre únicos globales
    print("[1/4] Calculando mapas únicos HMAC-SHA256 y detección de colisiones...")
    u_orig_fw = colectar_streaming(lf_fw.select("Usuario_Origen").unique())["Usuario_Origen"].to_list()
    u_dest_fw_raw = colectar_streaming(
        lf_fw.with_columns(
            pl.when(pl.col("Usuario_Destino").is_null() | (pl.col("Usuario_Destino") == ""))
            .then(pl.lit("EMPTY"))
            .otherwise(pl.col("Usuario_Destino"))
            .alias("ud")
        )
        .select("ud")
        .unique()
    )["ud"].to_list()
    u_dest_fw_personales = [
        u for u in u_dest_fw_raw if u not in {"EMPTY", USUARIO_SERVIDOR_CENTRAL}
    ]
    med_nombres_unicos = colectar_streaming(
        lf_med.select("NOMBRE_USUARIO_EJECUTA_EVENTO").unique()
    )["NOMBRE_USUARIO_EJECUTA_EVENTO"].to_list()
    med_cuentas_unicas = colectar_streaming(
        lf_med.select("USUARIO_EJECUTA_EVENTO").unique()
    )["USUARIO_EJECUTA_EVENTO"].to_list()

    mapa_canonico_med, canonicos_ambiguos, _ = detectar_colisiones_canonicas(
        med_nombres_unicos
    )
    todos_canonicos = (
        set(u_orig_fw)
        | set(u_dest_fw_personales)
        | (set(mapa_canonico_med.values()) - {""})
    )
    mapa_hmac_actores = construir_mapa_hmac_unicos(todos_canonicos, clave=clave, prefijo="USR")
    mapa_hmac_cuentas = construir_mapa_hmac_unicos(med_cuentas_unicas, clave=clave, prefijo="ACC")

    mapa_nombre_a_token = {
        nombre: mapa_hmac_actores.get(canon, "USR-DESCONOCIDO")
        for nombre, canon in mapa_canonico_med.items()
    }
    mapa_nombre_a_ambigua = {
        nombre: (canon in canonicos_ambiguos)
        for nombre, canon in mapa_canonico_med.items()
    }
    mapa_fw_orig_ambigua = {u: (u in canonicos_ambiguos) for u in u_orig_fw}
    mapa_dst_scope = {"EMPTY": "EMPTY", USUARIO_SERVIDOR_CENTRAL: USUARIO_SERVIDOR_CENTRAL}
    for u in u_dest_fw_personales:
        mapa_dst_scope[u] = mapa_hmac_actores[u]

    # 2. Muestra Firewall (~200k): incidentes + alta señal + 180k tráfico base
    print("[2/4] Extrayendo muestra Firewall (ventanas ±10 min + alta señal + 180k base)...")
    cond_fw = _filtro_ventanas_incidentes_fw()
    df_fw_critico = colectar_streaming(lf_fw.filter(cond_fw))
    df_fw_base_pool = colectar_streaming(lf_fw.filter(~cond_fw))
    n_fw_base = min(MUESTRA_BASE_OBJETIVO, df_fw_base_pool.height)
    df_fw_muestra = pl.concat(
        [df_fw_critico, df_fw_base_pool.sample(n=n_fw_base, seed=SEMILLA_MUESTRA)],
        how="vertical",
    )

    fw_ips_unicas = df_fw_muestra["IP_Destino"].unique().to_list()
    fw_ip_info = _construir_diccionario_ips(fw_ips_unicas)
    fw_dst_ip_map = {k: v[0] for k, v in fw_ip_info.items()}
    fw_was_dotless_map = {k: v[1] for k, v in fw_ip_info.items()}
    fw_reparable_map = {k: v[2] for k, v in fw_ip_info.items()}
    fw_externa_map = {k: v[3] for k, v in fw_ip_info.items()}

    df_fw_out = (
        df_fw_muestra.with_columns(
            pl.col("Fecha_Generacion")
            .str.strptime(pl.Datetime("us"), "%Y-%m-%d %H:%M:%S")
            .alias("event_ts"),
            pl.col("IP_Origen").alias("src_ip"),
            pl.col("IP_Destino").alias("dst_ip_raw"),
            pl.col("IP_Destino").replace_strict(fw_dst_ip_map, return_dtype=pl.String).alias("dst_ip"),
            pl.col("IP_Destino").replace_strict(fw_was_dotless_map, return_dtype=pl.Boolean).alias("was_dotless_ip"),
            pl.col("IP_Destino").replace_strict(fw_reparable_map, return_dtype=pl.Boolean).alias("ip_reparable"),
            pl.col("IP_Destino").replace_strict(fw_externa_map, return_dtype=pl.Boolean).alias("is_external_ip"),
            pl.col("Usuario_Origen").replace_strict(mapa_hmac_actores, return_dtype=pl.String).alias("actor_token"),
            pl.col("Usuario_Origen").replace_strict(mapa_fw_orig_ambigua, return_dtype=pl.Boolean).alias("identidad_ambigua"),
            pl.when(pl.col("Usuario_Destino").is_null() | (pl.col("Usuario_Destino") == ""))
            .then(pl.lit("EMPTY"))
            .otherwise(pl.col("Usuario_Destino"))
            .replace_strict(mapa_dst_scope, return_dtype=pl.String)
            .alias("dst_user_scope"),
            pl.col("Aplicacion").alias("application"),
            pl.col("Puerto_Destino").cast(pl.Int32).alias("dst_port"),
            pl.col("Protocolo").alias("protocol"),
            pl.col("Accion").alias("action"),
        )
        .select(
            [
                "event_ts",
                "src_ip",
                "dst_ip_raw",
                "dst_ip",
                "was_dotless_ip",
                "ip_reparable",
                "is_external_ip",
                "actor_token",
                "identidad_ambigua",
                "dst_user_scope",
                "application",
                "dst_port",
                "protocol",
                "action",
            ]
        )
        .sort("event_ts")
    )
    df_fw_out.write_parquet(out_fw, compression="zstd")

    # 3. Muestra MedSys (~200k): 14,501 especiales + ventanas ±10 min + 180k base
    print("[3/4] Extrayendo muestra Sistema Médico (14,501 especiales + ventanas + 180k base)...")
    cond_med = _filtro_ventanas_incidentes_med()
    df_med_critico = colectar_streaming(lf_med.filter(cond_med))
    df_med_base_pool = colectar_streaming(lf_med.filter(~cond_med))
    n_med_base = min(MUESTRA_BASE_OBJETIVO, df_med_base_pool.height)
    df_med_muestra = pl.concat(
        [df_med_critico, df_med_base_pool.sample(n=n_med_base, seed=SEMILLA_MUESTRA)],
        how="vertical",
    )

    med_ips_unicas = df_med_muestra["IP_CONEXION"].unique().to_list()
    med_ip_info = _construir_diccionario_ips(med_ips_unicas)
    med_conn_ip_map = {k: v[0] for k, v in med_ip_info.items()}
    med_was_dotless_map = {k: v[1] for k, v in med_ip_info.items()}
    med_reparable_map = {k: v[2] for k, v in med_ip_info.items()}

    df_med_out = (
        df_med_muestra.with_columns(
            (pl.col("FECHA_EJECUTA_EVENTO") + " " + pl.col("HORA_EJECUTA_EVENTO"))
            .str.strptime(pl.Datetime("us"), "%Y%m%d %H:%M:%S")
            .alias("event_ts"),
            (~pl.col("USUARIO_EJECUTA_EVENTO").str.starts_with("SIM")).alias("is_special_account"),
            pl.col("USUARIO_EJECUTA_EVENTO")
            .replace_strict(mapa_hmac_cuentas, return_dtype=pl.String)
            .alias("account_token"),
            pl.col("NOMBRE_USUARIO_EJECUTA_EVENTO")
            .replace_strict(mapa_nombre_a_token, return_dtype=pl.String)
            .alias("actor_token"),
            pl.col("NOMBRE_USUARIO_EJECUTA_EVENTO")
            .replace_strict(mapa_nombre_a_ambigua, return_dtype=pl.Boolean)
            .alias("identidad_ambigua"),
            pl.col("DESCRIPCION_ACCION").alias("action_desc"),
            pl.col("IP_CONEXION").alias("conn_ip_raw"),
            pl.col("IP_CONEXION")
            .replace_strict(med_conn_ip_map, return_dtype=pl.String)
            .alias("conn_ip"),
            pl.col("IP_CONEXION")
            .replace_strict(med_was_dotless_map, return_dtype=pl.Boolean)
            .alias("was_dotless_ip"),
            pl.col("IP_CONEXION")
            .replace_strict(med_reparable_map, return_dtype=pl.Boolean)
            .alias("ip_reparable"),
            (pl.col("IP_CONEXION") == SERVIDOR_CENTRAL_IP).alias("is_central_server"),
        )
        .select(
            [
                "event_ts",
                "is_special_account",
                "account_token",
                "actor_token",
                "identidad_ambigua",
                "action_desc",
                "conn_ip_raw",
                "conn_ip",
                "was_dotless_ip",
                "ip_reparable",
                "is_central_server",
            ]
        )
        .sort("event_ts")
    )
    df_med_out.write_parquet(out_med, compression="zstd")

    # 4. Validación post-escritura cero PII
    print("[4/4] Verificando integridad y ausencia total de PII en ambos Parquet...")
    filas_fw = _validar_parquet_sin_pii(out_fw)
    filas_med = _validar_parquet_sin_pii(out_med)

    resumen = {
        "sample_fw_200k": {
            "ruta": str(out_fw),
            "filas": filas_fw,
            "tamano_bytes": out_fw.stat().st_size,
        },
        "sample_med_200k": {
            "ruta": str(out_med),
            "filas": filas_med,
            "tamano_bytes": out_med.stat().st_size,
        },
    }
    print(f"[OK] Muestra FW:  {filas_fw:,} filas -> {out_fw}")
    print(f"[OK] Muestra Med: {filas_med:,} filas -> {out_med}")
    return resumen


if __name__ == "__main__":
    generar_muestras()
