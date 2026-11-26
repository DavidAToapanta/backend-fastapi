"""
Ingestor ETL completo en modo streaming (Polars -> Parquet -> PostgreSQL 16)
para procesar los 10,023,532 registros oficiales bajo cumplimiento estricto
de la LOPDP (Art. 25), validando octetos IP 100..255 y registrando hash-chain.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import timezone
from pathlib import Path
from typing import Any

import polars as pl

# Asegura resolución de paquetes locales si se ejecuta directamente como script
PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.core.config import Settings, get_settings  # noqa: E402
from backend.app.core.database import copiar_filas_tabla, obtener_conexion  # noqa: E402
from backend.app.core.security import (  # noqa: E402
    calcular_sha256_archivo,
    construir_mapa_hmac_unicos,
    detectar_colisiones_canonicas,
    registrar_evento_auditoria,
)
from scripts.verificar_datos import (  # noqa: E402
    IP_PUBLICA_ESPERADA,
    SERVIDOR_CENTRAL_IP,
    USUARIO_SERVIDOR_CENTRAL,
    colectar_streaming,
    escanear_fw,
    escanear_med,
)

# Subred de IPs de origen identificadas en incidentes forenses para tabla de alta señal
IPS_ORIGEN_ALTA_SENAL = [
    "10.10.100.10",
    "10.10.100.20",
    "10.10.100.40",
    "10.10.100.50",
]

_PATRON_IPV4_ESTANDAR = (
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)
_PATRON_RFC1918_O_LOCAL = (
    r"^(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
)


def _obtener_rss_mb() -> float:
    """Retorna la memoria física residente (RSS) actual del proceso en MiB."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        psapi = ctypes.WinDLL("psapi")
        kernel32 = ctypes.WinDLL("kernel32")
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
            wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        handle = kernel32.GetCurrentProcess()
        if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return round(counters.PeakWorkingSetSize / (1024 * 1024), 2)
    return 0.0


def _expresiones_ip_vectorizadas(col_nombre: str, prefijo_salida: str) -> list[pl.Expr]:
    """
    Construye expresiones vectorizadas nativas en Polars equivalentes exactamente
    a validar_y_reparar_ip_sin_puntos (^10\\d{9}$ con octetos 100..255).
    """
    col = pl.col(col_nombre).str.strip_chars()
    es_sin_puntos = col.str.contains(r"^10\d{9}$")
    b1 = col.str.slice(2, 3).cast(pl.Int32, strict=False)
    b2 = col.str.slice(5, 3).cast(pl.Int32, strict=False)
    b3 = col.str.slice(8, 3).cast(pl.Int32, strict=False)

    octetos_validos = (
        b1.is_between(100, 255)
        & b2.is_between(100, 255)
        & b3.is_between(100, 255)
    )
    es_ipv4_normal = col.str.contains(_PATRON_IPV4_ESTANDAR)

    ip_limpia_expr = (
        pl.when(es_sin_puntos & octetos_validos)
        .then(
            pl.concat_str(
                [
                    pl.lit("10."),
                    b1.cast(pl.String),
                    pl.lit("."),
                    b2.cast(pl.String),
                    pl.lit("."),
                    b3.cast(pl.String),
                ]
            )
        )
        .when((~es_sin_puntos) & es_ipv4_normal)
        .then(col)
        .otherwise(pl.lit(None, dtype=pl.String))
        .alias(prefijo_salida)
    )

    reparable_expr = (
        pl.when(es_sin_puntos)
        .then(octetos_validos.fill_null(False))
        .otherwise(es_ipv4_normal)
        .alias("ip_reparable")
    )

    return [
        es_sin_puntos.alias("was_dotless_ip"),
        reparable_expr,
        ip_limpia_expr,
    ]


def _escribir_parquet_streaming(lf: pl.LazyFrame, destino: Path) -> None:
    """Materializa un LazyFrame hacia Parquet usando sink_parquet en modo streaming."""
    destino.parent.mkdir(parents=True, exist_ok=True)
    try:
        lf.sink_parquet(destino, compression="zstd", engine="streaming")
    except TypeError:
        try:
            lf.sink_parquet(destino, compression="zstd")
        except Exception:
            colectar_streaming(lf).write_parquet(destino, compression="zstd")


def _asegurar_utc(dt: Any) -> Any:
    """Etiqueta un datetime naive de Polars como UTC para inserción consistente en TIMESTAMPTZ."""
    if dt is not None and getattr(dt, "tzinfo", None) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def ejecutar_ingesta_completa(settings: Settings | None = None) -> dict[str, Any]:
    """
    Ejecuta el pipeline completo de Fase 2:
    1) Precalcula diccionarios HMAC únicos (USR-... y ACC-...).
    2) Genera fw_seudonimizado.parquet y med_seudonimizado.parquet en streaming.
    3) Carga PostgreSQL 16 vía COPY (agregados horarios, alta señal, especiales y bóveda).
    4) Registra los dos eventos encadenados en cti_audit.audit_events con rol aegis_app.
    """
    inicio_total = time.perf_counter()
    cfg = settings or get_settings()
    clave = cfg.PSEUDONYMIZATION_KEY
    fw_ruta = cfg.fw_csv_absoluto
    med_ruta = cfg.iess_csv_absoluto

    if not fw_ruta.exists():
        raise FileNotFoundError(f"No se encontró FW_CSV_PATH en {fw_ruta}")
    if not med_ruta.exists():
        raise FileNotFoundError(f"No se encontró IESS_CSV_PATH en {med_ruta}")

    salida_dir = PROJECT_ROOT / "data" / "processed"
    fw_parquet = salida_dir / "fw_seudonimizado.parquet"
    med_parquet = salida_dir / "med_seudonimizado.parquet"

    print("[1/5] Calculando SHA-256 de los CSV originales y diccionarios únicos HMAC...")
    fw_sha256 = calcular_sha256_archivo(fw_ruta)
    med_sha256 = calcular_sha256_archivo(med_ruta)

    lf_fw = escanear_fw(fw_ruta)
    lf_med = escanear_med(med_ruta)

    u_orig_fw = colectar_streaming(lf_fw.select("Usuario_Origen").unique())[
        "Usuario_Origen"
    ].to_list()
    u_dest_fw_raw = colectar_streaming(
        lf_fw.with_columns(
            pl.when(
                pl.col("Usuario_Destino").is_null() | (pl.col("Usuario_Destino") == "")
            )
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
    mapa_hmac_actores = construir_mapa_hmac_unicos(
        todos_canonicos, clave=clave, prefijo="USR"
    )
    mapa_hmac_cuentas = construir_mapa_hmac_unicos(
        med_cuentas_unicas, clave=clave, prefijo="ACC"
    )

    mapa_nombre_a_token = {
        nombre: mapa_hmac_actores.get(canon, "USR-DESCONOCIDO")
        for nombre, canon in mapa_canonico_med.items()
    }
    mapa_nombre_a_ambigua = {
        nombre: (canon in canonicos_ambiguos)
        for nombre, canon in mapa_canonico_med.items()
    }
    mapa_fw_orig_ambigua = {u: (u in canonicos_ambiguos) for u in u_orig_fw}
    mapa_dst_scope = {
        "EMPTY": "EMPTY",
        USUARIO_SERVIDOR_CENTRAL: USUARIO_SERVIDOR_CENTRAL,
    }
    for u in u_dest_fw_personales:
        mapa_dst_scope[u] = mapa_hmac_actores[u]

    # ------------------------------------------------------------------
    # 2. Escritura streaming de fw_seudonimizado.parquet (5,009,031 filas)
    # ------------------------------------------------------------------
    print("[2/5] Procesando Firewall (5,009,031 filas) en streaming hacia Parquet...")
    t_fw = time.perf_counter()
    lf_fw_out = (
        lf_fw.with_columns(_expresiones_ip_vectorizadas("IP_Destino", "dst_ip"))
        .with_columns(
            pl.col("Fecha_Generacion")
            .str.strptime(pl.Datetime("us"), "%Y-%m-%d %H:%M:%S")
            .alias("event_ts"),
            pl.col("IP_Origen").alias("src_ip"),
            pl.col("IP_Destino").alias("dst_ip_raw"),
            (
                pl.col("dst_ip").is_not_null()
                & (~pl.col("dst_ip").str.contains(_PATRON_RFC1918_O_LOCAL))
            ).alias("is_external_ip"),
            pl.col("Usuario_Origen")
            .replace_strict(mapa_hmac_actores, return_dtype=pl.String)
            .alias("actor_token"),
            pl.col("Usuario_Origen")
            .replace_strict(mapa_fw_orig_ambigua, return_dtype=pl.Boolean)
            .alias("identidad_ambigua"),
            pl.when(
                pl.col("Usuario_Destino").is_null() | (pl.col("Usuario_Destino") == "")
            )
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
    )
    _escribir_parquet_streaming(lf_fw_out, fw_parquet)
    dur_fw = round(time.perf_counter() - t_fw, 2)

    # ------------------------------------------------------------------
    # 3. Escritura streaming de med_seudonimizado.parquet (5,014,501 filas)
    # ------------------------------------------------------------------
    print("[3/5] Procesando Sistema Médico (5,014,501 filas) en streaming hacia Parquet...")
    t_med = time.perf_counter()
    lf_med_out = (
        lf_med.with_columns(_expresiones_ip_vectorizadas("IP_CONEXION", "conn_ip"))
        .with_columns(
            (pl.col("FECHA_EJECUTA_EVENTO") + " " + pl.col("HORA_EJECUTA_EVENTO"))
            .str.strptime(pl.Datetime("us"), "%Y%m%d %H:%M:%S")
            .alias("event_ts"),
            (~pl.col("USUARIO_EJECUTA_EVENTO").str.starts_with("SIM")).alias(
                "is_special_account"
            ),
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
            (pl.col("conn_ip") == SERVIDOR_CENTRAL_IP).alias("is_central_server"),
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
    )
    _escribir_parquet_streaming(lf_med_out, med_parquet)
    dur_med = round(time.perf_counter() - t_med, 2)

    # ------------------------------------------------------------------
    # 4. Agregaciones horarias y extracción de subconjuntos para PostgreSQL
    # ------------------------------------------------------------------
    print("[4/5] Agregando métricas horarias y cargando PostgreSQL 16 vía COPY...")
    lf_fw_pq = pl.scan_parquet(fw_parquet)
    lf_med_pq = pl.scan_parquet(med_parquet)

    fw_total_filas = colectar_streaming(lf_fw_pq.select(pl.len())).item()
    med_total_filas = colectar_streaming(lf_med_pq.select(pl.len())).item()

    df_base_fw = colectar_streaming(
        lf_fw_pq.with_columns(pl.col("event_ts").dt.truncate("1h").alias("event_hour"))
        .group_by(["event_hour", "application", "action"])
        .agg(
            pl.len().alias("event_count"),
            pl.col("was_dotless_ip").cast(pl.Int64).sum().alias("corrupt_ip_count"),
        )
        .select(
            pl.lit("FIREWALL").alias("source_layer"),
            pl.col("event_hour"),
            pl.col("application").alias("category"),
            pl.col("action").alias("action_status"),
            pl.col("event_count"),
            pl.col("corrupt_ip_count"),
        )
        .sort(["event_hour", "category", "action_status"])
    )

    df_base_med = colectar_streaming(
        lf_med_pq.with_columns(
            pl.col("event_ts").dt.truncate("1h").alias("event_hour"),
            pl.when(pl.col("is_special_account"))
            .then(pl.lit("SPECIAL_ACCOUNT"))
            .otherwise(pl.lit("SIM_BASELINE"))
            .alias("action_status"),
        )
        .group_by(["event_hour", "action_desc", "action_status"])
        .agg(
            pl.len().alias("event_count"),
            pl.col("was_dotless_ip").cast(pl.Int64).sum().alias("corrupt_ip_count"),
        )
        .select(
            pl.lit("MEDSYS").alias("source_layer"),
            pl.col("event_hour"),
            pl.col("action_desc").alias("category"),
            pl.col("action_status"),
            pl.col("event_count"),
            pl.col("corrupt_ip_count"),
        )
        .sort(["event_hour", "category", "action_status"])
    )

    df_fw_high = colectar_streaming(
        lf_fw_pq.filter(
            pl.col("is_external_ip")
            | pl.col("was_dotless_ip")
            | (pl.col("protocol") == "SSH")
            | (pl.col("application") == "SSH")
            | (pl.col("dst_port") == 8443)
            | (pl.col("dst_port") == 3389)
            | pl.col("src_ip").is_in(IPS_ORIGEN_ALTA_SENAL)
        ).sort("event_ts")
    )

    df_med_special = colectar_streaming(
        lf_med_pq.filter(pl.col("is_special_account")).sort("event_ts")
    )

    # Bóveda aislada: únicamente cuentas técnicas especiales (jamás nombres humanos)
    cuentas_especiales = sorted(c for c in med_cuentas_unicas if not c.startswith("SIM"))
    filas_vault = [(mapa_hmac_cuentas[c], c) for c in cuentas_especiales]

    with obtener_conexion(usar_rol_app=False, settings=cfg) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                TRUNCATE TABLE
                    cti_core.baseline_hourly_metrics,
                    cti_core.fw_high_signal_events,
                    cti_core.med_special_events,
                    cti_core.account_vault
                RESTART IDENTITY CASCADE
                """
            )

        filas_base_fw = (
            (
                r["source_layer"],
                _asegurar_utc(r["event_hour"]),
                r["category"],
                r["action_status"],
                int(r["event_count"]),
                int(r["corrupt_ip_count"]),
            )
            for r in df_base_fw.iter_rows(named=True)
        )
        n_base_fw = copiar_filas_tabla(
            conn,
            "cti_core",
            "baseline_hourly_metrics",
            [
                "source_layer",
                "event_hour",
                "category",
                "action_status",
                "event_count",
                "corrupt_ip_count",
            ],
            filas_base_fw,
        )

        filas_base_med = (
            (
                r["source_layer"],
                _asegurar_utc(r["event_hour"]),
                r["category"],
                r["action_status"],
                int(r["event_count"]),
                int(r["corrupt_ip_count"]),
            )
            for r in df_base_med.iter_rows(named=True)
        )
        n_base_med = copiar_filas_tabla(
            conn,
            "cti_core",
            "baseline_hourly_metrics",
            [
                "source_layer",
                "event_hour",
                "category",
                "action_status",
                "event_count",
                "corrupt_ip_count",
            ],
            filas_base_med,
        )

        filas_fw_high = (
            (
                _asegurar_utc(r["event_ts"]),
                r["src_ip"],
                r["dst_ip_raw"],
                r["dst_ip"],
                bool(r["was_dotless_ip"]),
                bool(r["ip_reparable"]),
                bool(r["is_external_ip"]),
                r["actor_token"],
                r["dst_user_scope"],
                r["application"],
                int(r["dst_port"]),
                r["protocol"],
                r["action"],
            )
            for r in df_fw_high.iter_rows(named=True)
        )
        n_fw_high = copiar_filas_tabla(
            conn,
            "cti_core",
            "fw_high_signal_events",
            [
                "event_ts",
                "src_ip",
                "dst_ip_raw",
                "dst_ip",
                "was_dotless_ip",
                "ip_reparable",
                "is_external_ip",
                "actor_token",
                "dst_user_scope",
                "application",
                "dst_port",
                "protocol",
                "action",
            ],
            filas_fw_high,
        )

        filas_med_esp = (
            (
                _asegurar_utc(r["event_ts"]),
                r["account_token"],
                r["actor_token"],
                bool(r["identidad_ambigua"]),
                r["action_desc"],
                r["conn_ip_raw"],
                r["conn_ip"],
                bool(r["was_dotless_ip"]),
                bool(r["ip_reparable"]),
                bool(r["is_central_server"]),
            )
            for r in df_med_special.iter_rows(named=True)
        )
        n_med_esp = copiar_filas_tabla(
            conn,
            "cti_core",
            "med_special_events",
            [
                "event_ts",
                "account_token",
                "actor_token",
                "identidad_ambigua",
                "action_desc",
                "conn_ip_raw",
                "conn_ip",
                "was_dotless_ip",
                "ip_reparable",
                "is_central_server",
            ],
            filas_med_esp,
        )

        n_vault = copiar_filas_tabla(
            conn,
            "cti_core",
            "account_vault",
            ["account_token", "system_account_id"],
            filas_vault,
        )
        conn.commit()

    # ------------------------------------------------------------------
    # 5. Registro de auditoría inmutable con rol aegis_app (hash-chain)
    # ------------------------------------------------------------------
    print("[5/5] Registrando auditoría encadenada en cti_audit.audit_events...")
    with obtener_conexion(usar_rol_app=True, settings=cfg) as conn_app:
        audit_fw_id, hash_fw = registrar_evento_auditoria(
            conn_app,
            operation="INGEST_FIREWALL_10M",
            dataset_name=fw_ruta.name,
            dataset_sha256=fw_sha256,
            total_rows_read=int(fw_total_filas),
            rows_persisted=int(n_base_fw + n_fw_high),
            pii_scrubbed=True,
            metadata={
                "parquet_path": str(fw_parquet.relative_to(PROJECT_ROOT)),
                "baseline_rows": int(n_base_fw),
                "high_signal_rows": int(n_fw_high),
                "duration_seconds": dur_fw,
            },
        )
        audit_med_id, hash_med = registrar_evento_auditoria(
            conn_app,
            operation="INGEST_MEDSYS_10M",
            dataset_name=med_ruta.name,
            dataset_sha256=med_sha256,
            total_rows_read=int(med_total_filas),
            rows_persisted=int(n_base_med + n_med_esp + n_vault),
            pii_scrubbed=True,
            metadata={
                "parquet_path": str(med_parquet.relative_to(PROJECT_ROOT)),
                "baseline_rows": int(n_base_med),
                "special_events_rows": int(n_med_esp),
                "account_vault_rows": int(n_vault),
                "duration_seconds": dur_med,
            },
        )
        conn_app.commit()

    dur_total = round(time.perf_counter() - inicio_total, 2)
    rss_pico_mb = _obtener_rss_mb()

    resumen = {
        "fw_parquet": str(fw_parquet),
        "fw_parquet_bytes": fw_parquet.stat().st_size,
        "fw_rows": int(fw_total_filas),
        "med_parquet": str(med_parquet),
        "med_parquet_bytes": med_parquet.stat().st_size,
        "med_rows": int(med_total_filas),
        "baseline_hourly_metrics_rows": int(n_base_fw + n_base_med),
        "fw_high_signal_events_rows": int(n_fw_high),
        "med_special_events_rows": int(n_med_esp),
        "account_vault_rows": int(n_vault),
        "audit_ids": [audit_fw_id, audit_med_id],
        "audit_hashes": [hash_fw, hash_med],
        "duration_seconds": dur_total,
        "peak_rss_mb": rss_pico_mb,
    }
    print(
        f"[OK] Ingesta completa en {dur_total}s (pico RAM: {rss_pico_mb} MiB) | "
        f"FW={fw_total_filas:,} | MedSys={med_total_filas:,} | "
        f"HighSignal={n_fw_high:,} | MedSpecial={n_med_esp:,} | Vault={n_vault}"
    )
    return resumen


if __name__ == "__main__":
    ejecutar_ingesta_completa()
