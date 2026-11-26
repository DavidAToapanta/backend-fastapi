"""
Compuerta determinística de QA, exactitud forense y privacidad LOPDP (Fase 3)
para el Rol 1 de AegisHealth-CTI.

Valida:
1. Pruebas unitarias de security.py y correlator.py (+12h selectivo).
2. Inmutabilidad real y hash-chain de cti_audit.audit_events (positiva y negativa).
3. Cero fugas PII o cuentas técnicas en claro en JSON, Parquet y tablas públicas.
4. Conteos exactos sobre los 10,023,532 registros y las 5 campañas correlacionadas.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import polars as pl
import psycopg
import pytest
from psycopg import errors

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.core.config import get_settings  # noqa: E402
from backend.app.core.database import obtener_conexion  # noqa: E402
from backend.app.core.security import (  # noqa: E402
    calcular_hash_encadenado,
    derivar_canonico_fw,
    detectar_colisiones_canonicas,
    generar_token_hmac,
    normalizar_texto,
    separar_apellidos_y_nombres,
    validar_y_reparar_ip_sin_puntos,
    verificar_cadena_auditoria,
)
from backend.app.etl.correlator import evaluar_ventana_correlacion  # noqa: E402

CADENAS_PROHIBIDAS_PUBLICAS = (
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
    "XYZ9999021",
    "XYZ1111331",
)

NOMBRES_PROHIBIDOS_VAULT = (
    "ROSALES",
    "PRIETO",
    "REYES",
    "VALENZUELA",
    "CALERO",
    "DIAZ",
    "PAMELA",
    "IVAN",
    "ANDREA",
    "SANTIAGO",
)


# ---------------------------------------------------------------------------
# 1. Pruebas unitarias de privacidad, normalización e IPs sin puntos
# ---------------------------------------------------------------------------


def test_normalizar_texto_nfkd_tildes_y_ene() -> None:
    """Normaliza tildes, diéresis, letra Ñ y espacios múltiples."""
    assert normalizar_texto("  PEÑA   NUÑEZ  JOSÉ  ÁNGEL ") == "pena nunez jose angel"


def test_apellidos_compuestos_de_la_torre() -> None:
    """Agrupa partículas en apellidos compuestos para derivar 'nombre1.apellido1'."""
    apellidos, nombres = separar_apellidos_y_nombres("DE LA TORRE GOMEZ JUAN CARLOS")
    assert apellidos == ["de la torre", "gomez"]
    assert nombres == ["juan", "carlos"]
    assert derivar_canonico_fw("DE LA TORRE GOMEZ JUAN CARLOS") == "juan.delatorre"


def test_fallback_dos_tokens() -> None:
    """Aplica respaldo obligatorio ante entradas cortas de solo dos palabras."""
    apellidos, nombres = separar_apellidos_y_nombres("GOMEZ JUAN")
    assert apellidos == ["gomez"]
    assert nombres == ["juan"]
    assert derivar_canonico_fw("GOMEZ JUAN") == "juan.gomez"


def test_deteccion_colisiones_canonicas() -> None:
    """Detecta colisión cuando dos personas distintas generan el mismo canónico."""
    nombres = [
        "REYES TOBAR ANDREA DEL ROCIO",
        "REYES PEREZ ANDREA CAROLINA",
        "ROSALES BRITO PAMELA LOLITA",
    ]
    mapa_canonico, ambiguos, conteos = detectar_colisiones_canonicas(nombres)
    assert mapa_canonico["REYES TOBAR ANDREA DEL ROCIO"] == "andrea.reyes"
    assert mapa_canonico["REYES PEREZ ANDREA CAROLINA"] == "andrea.reyes"
    assert "andrea.reyes" in ambiguos
    assert "pamela.rosales" not in ambiguos
    assert conteos["andrea.reyes"] == 2
    assert conteos["pamela.rosales"] == 1


def test_validacion_estricta_octetos_ip_sin_puntos() -> None:
    """Repara IPs 10XXXXXXXXX con octetos 100..255 y rechaza octetos fuera de rango."""
    assert validar_y_reparar_ip_sin_puntos("10201194105") == (
        "10.201.194.105",
        True,
        True,
    )
    assert validar_y_reparar_ip_sin_puntos("10999111222") == (None, True, False)
    assert validar_y_reparar_ip_sin_puntos("10099111222") == (None, True, False)
    assert validar_y_reparar_ip_sin_puntos("186.46.219.18") == (
        "186.46.219.18",
        False,
        True,
    )


def test_determinismo_hmac_y_regla_12h_selectiva() -> None:
    """Verifica determinismo HMAC y aplicación estrictamente selectiva de +12h."""
    t1 = generar_token_hmac("pamela.rosales", "clave_secreta_prueba", "USR")
    t2 = generar_token_hmac("pamela.rosales", "clave_secreta_prueba", "USR")
    t3 = generar_token_hmac("WXY1210010", "clave_secreta_prueba", "ACC")
    assert t1 == t2
    assert t1.startswith("USR-") and len(t1) == 16
    assert t3.startswith("ACC-") and len(t3) == 16

    fw_ts = datetime(2026, 10, 24, 22, 40, 0, tzinfo=timezone.utc)
    med_ts = datetime(2026, 10, 24, 10, 40, 15, tzinfo=timezone.utc)

    coincide, fix_12h, ts_corr = evaluar_ventana_correlacion(
        fw_ts, med_ts, mismo_actor_o_ip=True
    )
    assert coincide is True
    assert fix_12h is True
    assert ts_corr == med_ts + timedelta(hours=12)

    # Prohibido aplicar +12h si no coincide el mismo actor/cuenta/IP
    coincide_distinto, fix_distinto, _ = evaluar_ventana_correlacion(
        fw_ts, med_ts, mismo_actor_o_ip=False
    )
    assert coincide_distinto is False
    assert fix_distinto is False


def test_hash_chain_unitario_e_inmutabilidad_postgresql() -> None:
    """
    Valida la cadena criptográfica en cti_audit.audit_events:
    - El estado persistido debe estar íntegro.
    - El rol aegis_app no tiene permiso UPDATE ni DELETE en auditoría.
    - Alterar un solo byte en memoria/transacción (con rollback) invalida la cadena.
    """
    h1 = calcular_hash_encadenado("GENESIS", {"evento": 1})
    h2 = calcular_hash_encadenado("GENESIS", {"evento": 2})
    assert h1 != h2 and len(h1) == 64

    cfg = get_settings()
    with obtener_conexion(usar_rol_app=True, settings=cfg) as conn_app:
        estado = verificar_cadena_auditoria(conn_app)
        assert estado["intact"] is True
        assert estado["checked_rows"] >= 3
        assert estado["errores"] == []

        with pytest.raises(errors.InsufficientPrivilege):
            conn_app.execute(
                "UPDATE cti_audit.audit_events SET operation = 'TAMPERED' WHERE audit_id = 1"
            )
        conn_app.rollback()

        with pytest.raises(errors.InsufficientPrivilege):
            conn_app.execute("DELETE FROM cti_audit.audit_events WHERE audit_id = 1")
        conn_app.rollback()

    # Prueba negativa reversible: altera 1 byte dentro de una transacción con ROLLBACK
    with obtener_conexion(usar_rol_app=False, settings=cfg) as conn_admin:
        try:
            with conn_admin.cursor() as cur:
                cur.execute(
                    "UPDATE cti_audit.audit_events SET dataset_name = dataset_name || 'X' "
                    "WHERE audit_id = (SELECT MIN(audit_id) FROM cti_audit.audit_events)"
                )
            estado_corrupto = verificar_cadena_auditoria(conn_admin)
            assert estado_corrupto["intact"] is False
            assert len(estado_corrupto["errores"]) >= 1
        finally:
            conn_admin.rollback()

        estado_restaurado = verificar_cadena_auditoria(conn_admin)
        assert estado_restaurado["intact"] is True


# ---------------------------------------------------------------------------
# 2. Gate de Privacidad LOPDP (0 PII en evidencias.json, Parquet y PostgreSQL)
# ---------------------------------------------------------------------------


def test_gate_privacidad_evidencias_json() -> None:
    """Confirma cero PII ni códigos técnicos en claro en docs/evidencias/evidencias.json."""
    ruta = PROJECT_ROOT / "docs" / "evidencias" / "evidencias.json"
    assert ruta.exists()
    contenido = ruta.read_text(encoding="utf-8")
    for cadena in CADENAS_PROHIBIDAS_PUBLICAS:
        assert cadena not in contenido, f"Se filtró cadena prohibida en JSON: {cadena}"


@pytest.mark.parametrize(
    "nombre_parquet",
    [
        "sample_fw_200k.parquet",
        "sample_med_200k.parquet",
        "fw_seudonimizado.parquet",
        "med_seudonimizado.parquet",
    ],
)
def test_gate_privacidad_parquets(nombre_parquet: str) -> None:
    """Confirma que los cuatro Parquet generados carecen por completo de PII y cuentas en claro."""
    ruta = PROJECT_ROOT / "data" / "processed" / nombre_parquet
    assert ruta.exists(), f"Falta archivo Parquet esperado: {ruta}"

    lf = pl.scan_parquet(ruta)
    cols_texto = [c for c, dt in lf.collect_schema().items() if dt == pl.String]
    expresiones = [
        pl.col(col).str.contains(patron, literal=True).fill_null(False).sum().alias(f"{col}__{patron}")
        for col in cols_texto
        for patron in CADENAS_PROHIBIDAS_PUBLICAS
    ]
    resultado = lf.select(expresiones).collect(engine="streaming").to_dicts()[0]
    hallazgos = {k: v for k, v in resultado.items() if v > 0}
    assert hallazgos == {}, f"Fuga PII detectada en {nombre_parquet}: {hallazgos}"


def test_gate_privacidad_postgresql_tablas_publicas_y_vault() -> None:
    """Valida que ninguna tabla de presentación ni auditoría exponga PII o cuentas técnicas."""
    cfg = get_settings()
    consultas_texto = [
        ("baseline_hourly_metrics", "SELECT category || ' ' || action_status FROM cti_core.baseline_hourly_metrics"),
        ("fw_high_signal_events", "SELECT actor_token || ' ' || dst_user_scope || ' ' || application FROM cti_core.fw_high_signal_events"),
        ("med_special_events", "SELECT account_token || ' ' || actor_token || ' ' || action_desc FROM cti_core.med_special_events"),
        ("threat_campaigns", "SELECT title || ' ' || iocs::text || ' ' || ioas::text FROM cti_core.threat_campaigns"),
        ("campaign_timeline_events", "SELECT COALESCE(actor_token,'') || ' ' || COALESCE(account_token,'') || ' ' || COALESCE(event_summary,'') FROM cti_core.campaign_timeline_events"),
        ("audit_events", "SELECT operation || ' ' || dataset_name || ' ' || metadata::text FROM cti_audit.audit_events"),
    ]

    with obtener_conexion(usar_rol_app=True, settings=cfg) as conn:
        with conn.cursor() as cur:
            for tabla, sql_txt in consultas_texto:
                cur.execute(sql_txt)
                bloque = "\n".join(str(r[0]) for r in cur.fetchall())
                for cadena in CADENAS_PROHIBIDAS_PUBLICAS:
                    assert cadena not in bloque, (
                        f"Fuga LOPDP en tabla {tabla}: apareció {cadena!r}"
                    )

            cur.execute("SELECT account_token, system_account_id FROM cti_core.account_vault")
            vault_filas = cur.fetchall()
            assert len(vault_filas) == 16
            vault_texto = " ".join(f"{a} {s}" for a, s in vault_filas).upper()
            for nombre_humano in NOMBRES_PROHIBIDOS_VAULT:
                assert nombre_humano not in vault_texto


# ---------------------------------------------------------------------------
# 3. Gate de Exactitud Forense sobre los 10,023,532 registros
# ---------------------------------------------------------------------------


def test_gate_exactitud_10m_y_correlacion_5_campanas() -> None:
    """Verifica todos los conteos obligatorios de Rol 1 en Parquet y PostgreSQL 16."""
    fw_pq = PROJECT_ROOT / "data" / "processed" / "fw_seudonimizado.parquet"
    med_pq = PROJECT_ROOT / "data" / "processed" / "med_seudonimizado.parquet"

    fw_stats = (
        pl.scan_parquet(fw_pq)
        .select(
            pl.len().alias("total"),
            pl.col("was_dotless_ip").sum().alias("dotless"),
            pl.col("ip_reparable").all().alias("todas_reparables"),
            pl.col("is_external_ip").sum().alias("externas"),
        )
        .collect(engine="streaming")
        .to_dicts()[0]
    )
    assert fw_stats["total"] == 5_009_031
    assert fw_stats["dotless"] == 493
    assert fw_stats["todas_reparables"] is True
    assert fw_stats["externas"] == 1

    fw_ips_externas = (
        pl.scan_parquet(fw_pq)
        .filter(pl.col("is_external_ip"))
        .select("dst_ip")
        .collect(engine="streaming")["dst_ip"]
        .to_list()
    )
    assert fw_ips_externas == ["186.46.219.18"]

    med_stats = (
        pl.scan_parquet(med_pq)
        .select(
            pl.len().alias("total"),
            pl.col("is_special_account").sum().alias("especiales"),
            pl.col("was_dotless_ip").sum().alias("dotless"),
            pl.col("ip_reparable").all().alias("todas_reparables"),
        )
        .collect(engine="streaming")
        .to_dicts()[0]
    )
    assert med_stats["total"] == 5_014_501
    assert med_stats["especiales"] == 14_501
    assert med_stats["dotless"] == 787
    assert med_stats["todas_reparables"] is True

    cfg = get_settings()
    with obtener_conexion(usar_rol_app=True, settings=cfg) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT source_layer, SUM(event_count), SUM(corrupt_ip_count)
                FROM cti_core.baseline_hourly_metrics
                GROUP BY source_layer
                """
            )
            resumen_base = {r[0]: (int(r[1]), int(r[2])) for r in cur.fetchall()}
            assert resumen_base["FIREWALL"] == (5_009_031, 493)
            assert resumen_base["MEDSYS"] == (5_014_501, 787)

            cur.execute("SELECT COUNT(*), SUM(CASE WHEN was_dotless_ip THEN 1 ELSE 0 END) FROM cti_core.med_special_events")
            med_esp_cnt, med_esp_dotless = cur.fetchone()
            assert int(med_esp_cnt) == 14_501
            assert int(med_esp_dotless) == 787

            cur.execute("SELECT DISTINCT host(dst_ip) FROM cti_core.fw_high_signal_events WHERE is_external_ip = TRUE")
            assert [r[0] for r in cur.fetchall()] == ["186.46.219.18"]

            cur.execute("SELECT campaign_code FROM cti_core.threat_campaigns ORDER BY campaign_code")
            assert [r[0] for r in cur.fetchall()] == [
                "CAMP-2026-001",
                "CAMP-2026-002",
                "CAMP-2026-003",
                "CAMP-2026-004",
                "CAMP-2026-005",
            ]

            cur.execute(
                """
                SELECT campaign_code, COUNT(*)
                FROM cti_core.campaign_timeline_events
                WHERE clock_skew_12h_fix = TRUE
                GROUP BY campaign_code
                """
            )
            fixes = cur.fetchall()
            assert fixes == [("CAMP-2026-001", 2)]
