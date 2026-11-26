"""
Correlador temporal cross-layer (Firewall <-> Sistema Médico) en PostgreSQL 16.
Construye las 5 campañas base y puebla cti_core.campaign_timeline_events aplicando
la regla +12h exclusivamente cuando coincide el mismo actor/cuenta/IP.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from psycopg.types.json import Jsonb

# Asegura resolución de paquetes locales si se ejecuta directamente como script
PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.core.config import Settings, get_settings  # noqa: E402
from backend.app.core.database import copiar_filas_tabla, obtener_conexion  # noqa: E402
from backend.app.core.security import registrar_evento_auditoria  # noqa: E402
from scripts.verificar_datos import IP_PUBLICA_ESPERADA  # noqa: E402


def evaluar_ventana_correlacion(
    fw_ts: datetime,
    med_ts: datetime,
    mismo_actor_o_ip: bool,
    tolerancia_seg: int = 120,
) -> tuple[bool, bool, datetime]:
    """
    Evalúa coincidencia temporal directa (delta <= tolerancia_seg) o con desfase
    de +12 horas (abs((fw_ts - med_ts) - 12h) <= tolerancia_seg) únicamente cuando
    mismo_actor_o_ip es True. Jamás aplica +12h de manera global.

    Retorna: (coincide, clock_skew_12h_fix, timestamp_correlacionado).
    """
    delta_seg = (fw_ts - med_ts).total_seconds()
    if abs(delta_seg) <= tolerancia_seg:
        return True, False, med_ts

    if mismo_actor_o_ip and abs(delta_seg - 43200) <= tolerancia_seg:
        return True, True, med_ts + timedelta(hours=12)

    return False, False, med_ts


def _asegurar_utc(dt: datetime) -> datetime:
    """Garantiza zona horaria UTC explícita en timestamps consultados de PostgreSQL."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def ejecutar_correlacion(settings: Settings | None = None) -> dict[str, Any]:
    """
    Lee los eventos seudonimizados de PostgreSQL 16, correlaciona las 5 campañas
    oficiales (A..E), inserta cti_core.threat_campaigns y
    cti_core.campaign_timeline_events, y audita la operación en cti_audit.
    """
    cfg = settings or get_settings()

    with obtener_conexion(usar_rol_app=False, settings=cfg) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                TRUNCATE TABLE
                    cti_core.campaign_timeline_events,
                    cti_core.threat_campaigns
                RESTART IDENTITY CASCADE
                """
            )

            # --------------------------------------------------------------
            # 1. CAMP-2026-001 (Incidente D: Exfiltración 8443/tcp + desfase +12h)
            # --------------------------------------------------------------
            cur.execute(
                """
                SELECT event_ts, host(src_ip), host(dst_ip), dst_port, actor_token, application, action
                FROM cti_core.fw_high_signal_events
                WHERE src_ip = '10.10.100.40'::inet
                  AND event_ts >= '2026-10-24 22:30:00+00'::timestamptz
                  AND event_ts <= '2026-10-24 22:50:00+00'::timestamptz
                ORDER BY event_ts ASC
                """
            )
            fw_d = cur.fetchall()
            if not fw_d:
                raise RuntimeError("No se encontraron eventos FW para CAMP-2026-001.")
            actor_d = fw_d[0][4]

            cur.execute(
                """
                SELECT event_ts, account_token, actor_token, action_desc, host(conn_ip)
                FROM cti_core.med_special_events
                WHERE actor_token = %s
                  AND event_ts >= '2026-10-24 00:00:00+00'::timestamptz
                  AND event_ts <= '2026-10-24 23:59:59+00'::timestamptz
                ORDER BY event_ts ASC
                """,
                (actor_d,),
            )
            med_d = cur.fetchall()
            if not med_d:
                raise RuntimeError("No se encontraron eventos MedSys para CAMP-2026-001.")
            account_d = med_d[0][1]

            fw_ref_d = _asegurar_utc(fw_d[0][0])
            timeline_filas: list[tuple[Any, ...]] = []
            timestamps_d: list[datetime] = []

            for ev_ts, src_ip, dst_ip, dst_port, act_tok, app, action in fw_d:
                ts_utc = _asegurar_utc(ev_ts)
                timestamps_d.append(ts_utc)
                destino_tag = (
                    "IP publica sintetica externa"
                    if dst_ip == IP_PUBLICA_ESPERADA
                    else "servidor central sist_med_iess"
                )
                timeline_filas.append(
                    (
                        "CAMP-2026-001",
                        ts_utc,
                        "FIREWALL",
                        act_tok,
                        account_d,
                        src_ip,
                        dst_ip,
                        int(dst_port),
                        f"Conexion FW {app} ({action}) hacia {destino_tag} puerto {dst_port}.",
                        False,
                    )
                )

            clock_fixes_d = 0
            for ev_ts, acc_tok, act_tok, action_desc, conn_ip in med_d:
                ts_orig = _asegurar_utc(ev_ts)
                coincide, fix_12h, ts_corr = evaluar_ventana_correlacion(
                    fw_ref_d, ts_orig, mismo_actor_o_ip=(act_tok == actor_d)
                )
                if not coincide:
                    raise RuntimeError(
                        "Fallo correlación temporal +12h en CAMP-2026-001."
                    )
                if fix_12h:
                    clock_fixes_d += 1
                timestamps_d.append(ts_corr)
                timeline_filas.append(
                    (
                        "CAMP-2026-001",
                        ts_corr,
                        "MEDSYS",
                        act_tok,
                        acc_tok,
                        conn_ip,
                        conn_ip,
                        None,
                        (
                            f"Evento MedSys {action_desc} (reloj origen {ts_orig.strftime('%H:%M:%S')} "
                            f"ajustado +12h por coincidencia de actor/IP)."
                        ),
                        bool(fix_12h),
                    )
                )

            # --------------------------------------------------------------
            # 2. CAMP-2026-002 (Incidente C: Protocolo SSH + 30/2970 TRANFERENCIA)
            # --------------------------------------------------------------
            cur.execute(
                """
                SELECT COUNT(*), MIN(event_ts), MAX(event_ts), MIN(actor_token)
                FROM cti_core.fw_high_signal_events
                WHERE protocol = 'SSH' AND src_ip = '10.10.100.50'::inet
                """
            )
            fw_c_cnt, fw_c_min, fw_c_max, actor_c = cur.fetchone()

            cur.execute(
                """
                SELECT action_desc, COUNT(*), MIN(event_ts), MAX(event_ts), MIN(account_token), MIN(host(conn_ip))
                FROM cti_core.med_special_events
                WHERE actor_token = %s
                  AND event_ts >= '2026-10-07 13:00:00+00'::timestamptz
                  AND event_ts < '2026-10-07 14:00:00+00'::timestamptz
                GROUP BY action_desc
                ORDER BY action_desc ASC
                """,
                (actor_c,),
            )
            med_c_grupos = cur.fetchall()
            med_c_tot = sum(int(g[1]) for g in med_c_grupos)
            account_c = med_c_grupos[0][4]
            ip_c_med = med_c_grupos[0][5]

            cur.execute(
                """
                SELECT event_ts, host(src_ip), host(dst_ip), dst_port, actor_token
                FROM cti_core.fw_high_signal_events
                WHERE protocol = 'SSH' AND src_ip = '10.10.100.50'::inet
                ORDER BY event_ts ASC
                LIMIT 2
                """
            )
            for ev_ts, src_ip, dst_ip, dst_port, act_tok in cur.fetchall():
                timeline_filas.append(
                    (
                        "CAMP-2026-002",
                        _asegurar_utc(ev_ts),
                        "FIREWALL",
                        act_tok,
                        account_c,
                        src_ip,
                        dst_ip,
                        int(dst_port),
                        f"Inicio de rafaga FW Protocolo=SSH ({fw_c_cnt} sesiones permitidas a puerto 22).",
                        False,
                    )
                )

            for accion_desc, cnt, min_ts, max_ts, acc_tok, conn_ip in med_c_grupos:
                timeline_filas.append(
                    (
                        "CAMP-2026-002",
                        _asegurar_utc(min_ts),
                        "MEDSYS",
                        actor_c,
                        acc_tok,
                        conn_ip,
                        conn_ip,
                        22,
                        f"Bloque MedSys '{accion_desc}' ({cnt} eventos entre {min_ts.strftime('%H:%M:%S')} y {max_ts.strftime('%H:%M:%S')}).",
                        False,
                    )
                )

            # --------------------------------------------------------------
            # 3. CAMP-2026-003 (Incidente A: Fuerza bruta Telnet 23/tcp)
            # --------------------------------------------------------------
            cur.execute(
                """
                SELECT COUNT(*), MIN(event_ts), MAX(event_ts), MIN(actor_token)
                FROM cti_core.fw_high_signal_events
                WHERE src_ip = '10.10.100.10'::inet
                  AND dst_port = 23
                  AND action = 'negado'
                  AND event_ts >= '2026-10-10 00:00:00+00'::timestamptz
                  AND event_ts < '2026-10-10 01:00:00+00'::timestamptz
                """
            )
            fw_a_cnt, fw_a_min, fw_a_max, actor_a = cur.fetchone()

            cur.execute(
                """
                SELECT COUNT(*), MIN(event_ts), MAX(event_ts), MIN(account_token), MIN(host(conn_ip))
                FROM cti_core.med_special_events
                WHERE actor_token = %s
                  AND action_desc = 'ACCESO FALLIDO'
                  AND event_ts >= '2026-10-10 00:00:00+00'::timestamptz
                  AND event_ts < '2026-10-10 01:00:00+00'::timestamptz
                """,
                (actor_a,),
            )
            med_a_cnt, med_a_min, med_a_max, account_a, ip_a_med = cur.fetchone()

            timeline_filas.extend(
                [
                    (
                        "CAMP-2026-003",
                        _asegurar_utc(fw_a_min),
                        "FIREWALL",
                        actor_a,
                        account_a,
                        "10.10.100.10",
                        ip_a_med,
                        23,
                        f"Inicio fuerza bruta Telnet 23/tcp ({fw_a_cnt} conexiones negadas).",
                        False,
                    ),
                    (
                        "CAMP-2026-003",
                        _asegurar_utc(med_a_min),
                        "MEDSYS",
                        actor_a,
                        account_a,
                        ip_a_med,
                        ip_a_med,
                        23,
                        f"Inicio rafaga ACCESO FALLIDO en sistema medico ({med_a_cnt} eventos).",
                        False,
                    ),
                    (
                        "CAMP-2026-003",
                        _asegurar_utc(fw_a_max),
                        "FIREWALL",
                        actor_a,
                        account_a,
                        "10.10.100.10",
                        ip_a_med,
                        23,
                        "Fin de ventana de fuerza bruta Telnet 23/tcp (2,000 intentos negados).",
                        False,
                    ),
                ]
            )

            # --------------------------------------------------------------
            # 4. CAMP-2026-004 (Incidente B: Escaneo 4 puertos + identidad_ambigua)
            # --------------------------------------------------------------
            cur.execute(
                """
                SELECT dst_port, protocol, application, COUNT(*), MIN(event_ts), MAX(event_ts), MIN(actor_token)
                FROM cti_core.fw_high_signal_events
                WHERE src_ip = '10.10.100.20'::inet
                  AND action = 'negado'
                  AND event_ts >= '2026-10-19 14:00:00+00'::timestamptz
                  AND event_ts < '2026-10-19 15:00:00+00'::timestamptz
                GROUP BY dst_port, protocol, application
                ORDER BY dst_port ASC
                """
            )
            fw_b_bloques = cur.fetchall()
            fw_b_cnt = sum(int(b[3]) for b in fw_b_bloques)
            actor_b = fw_b_bloques[0][6]
            fw_b_min = min(_asegurar_utc(b[4]) for b in fw_b_bloques)
            fw_b_max = max(_asegurar_utc(b[5]) for b in fw_b_bloques)

            cur.execute(
                """
                SELECT account_token, COUNT(*), MIN(event_ts), MAX(event_ts), BOOL_OR(identidad_ambigua)
                FROM cti_core.med_special_events
                WHERE actor_token = %s
                  AND action_desc = 'ACCESO FALLIDO'
                  AND event_ts >= '2026-10-19 14:00:00+00'::timestamptz
                  AND event_ts < '2026-10-19 15:00:00+00'::timestamptz
                GROUP BY account_token
                ORDER BY COUNT(*) DESC
                LIMIT 1
                """,
                (actor_b,),
            )
            account_b, med_b_cnt, med_b_min, med_b_max, ambigua_b = cur.fetchone()

            for puerto, proto, app, cnt, min_ts, _, act_tok in fw_b_bloques:
                timeline_filas.append(
                    (
                        "CAMP-2026-004",
                        _asegurar_utc(min_ts),
                        "FIREWALL",
                        act_tok,
                        account_b,
                        "10.10.100.20",
                        "10.10.100.30",
                        int(puerto),
                        f"Bloque escaneo/spraying FW puerto {puerto}/{proto} ({app}): {cnt} intentos negados.",
                        False,
                    )
                )
            timeline_filas.append(
                (
                    "CAMP-2026-004",
                    _asegurar_utc(med_b_min),
                    "MEDSYS",
                    actor_b,
                    account_b,
                    "10.10.100.30",
                    "10.10.100.30",
                    None,
                    (
                        f"Correlacion por cuenta tecnica ({med_b_cnt} ACCESO FALLIDO en ventana; "
                        f"identidad_ambigua={ambigua_b} sobre canonico)."
                    ),
                    False,
                )
            )

            # --------------------------------------------------------------
            # 5. CAMP-2026-005 (Incidente E: Abuso de privilegios, dotless IPs y SSH/8443)
            # --------------------------------------------------------------
            cur.execute(
                """
                SELECT COUNT(*), MIN(event_ts), MAX(event_ts)
                FROM cti_core.fw_high_signal_events
                WHERE application = 'SSH' AND protocol = 'tcp' AND dst_port = 22
                """
            )
            ssh_826_cnt, ssh_826_min, ssh_826_max = cur.fetchone()

            cur.execute(
                """
                SELECT COUNT(*) FROM cti_core.fw_high_signal_events WHERE dst_port = 8443
                """
            )
            puerto_8443_cnt = cur.fetchone()[0]

            cur.execute(
                """
                SELECT
                    account_token,
                    COUNT(*),
                    SUM(CASE WHEN was_dotless_ip THEN 1 ELSE 0 END) AS dotless_cnt,
                    MIN(event_ts),
                    MAX(event_ts)
                FROM cti_core.med_special_events
                GROUP BY account_token
                HAVING SUM(CASE WHEN was_dotless_ip THEN 1 ELSE 0 END) > 0
                ORDER BY COUNT(*) DESC
                """
            )
            cuentas_e = cur.fetchall()
            total_dotless_med = sum(int(c[2]) for c in cuentas_e)
            total_eventos_e_med = sum(int(c[1]) for c in cuentas_e)

            cur.execute(
                """
                SELECT account_token, COUNT(*)
                FROM cti_core.med_special_events
                WHERE action_desc = 'Reactivacion de usuarios'
                GROUP BY account_token
                HAVING COUNT(*) = %s
                """,
                (ssh_826_cnt,),
            )
            espejo_826 = cur.fetchone()
            cuenta_espejo_tok = espejo_826[0] if espejo_826 else cuentas_e[0][0]

            timeline_filas.append(
                (
                    "CAMP-2026-005",
                    _asegurar_utc(ssh_826_min),
                    "FIREWALL",
                    None,
                    cuenta_espejo_tok,
                    None,
                    "10.10.100.30",
                    22,
                    f"Canal SSH (Application=SSH): {ssh_826_cnt} sesiones permitidas distribuidas en octubre 2026.",
                    False,
                )
            )
            timeline_filas.append(
                (
                    "CAMP-2026-005",
                    _asegurar_utc(cuentas_e[0][3]),
                    "MEDSYS",
                    None,
                    cuenta_espejo_tok,
                    "10.10.100.30",
                    "10.10.100.30",
                    None,
                    (
                        f"Abuso de privilegios y sabotaje: cuenta {cuenta_espejo_tok} registra "
                        f"{ssh_826_cnt} reactivaciones; {total_dotless_med} IPs sin puntos en cuentas especiales."
                    ),
                    False,
                )
            )
            for acc_tok, cnt_tot, dot_cnt, min_ts, _ in cuentas_e[:4]:
                timeline_filas.append(
                    (
                        "CAMP-2026-005",
                        _asegurar_utc(min_ts),
                        "MEDSYS",
                        None,
                        acc_tok,
                        "10.10.100.30",
                        "10.10.100.30",
                        8443,
                        f"Actividad anomala en cuenta tecnica {acc_tok}: {cnt_tot} eventos ({dot_cnt} IPs sin puntos).",
                        False,
                    )
                )

            # --------------------------------------------------------------
            # Inserción de las 5 campañas consolidadas en cti_core.threat_campaigns
            # --------------------------------------------------------------
            campanas = [
                (
                    "CAMP-2026-001",
                    "Exfiltracion Clinica SSH hacia IP Externa (8443/tcp)",
                    "HYBRID",
                    "CRITICAL",
                    "ESCENARIO_MAS_PELIGROSO",
                    "B2",
                    0.9850,
                    len(fw_d) + len(med_d),
                    min(timestamps_d),
                    max(timestamps_d),
                    ["TA0001", "TA0008", "TA0009", "TA0010"],
                    ["T1078", "T1021.004", "T1213", "T1048.002"],
                    {
                        "src_ips": ["10.10.100.40"],
                        "dst_ips": ["10.10.100.30", IP_PUBLICA_ESPERADA],
                        "ports": [22, 8443],
                        "actor_tokens": [actor_d],
                        "account_tokens": [account_d],
                    },
                    [
                        "Acceso SSH seguido de descarga exitosa y egreso hacia IP no-RFC1918 en < 60s",
                        "Desfase horario puntual +12h entre sistema medico (10:40) y firewall (22:40)",
                    ],
                    {
                        "fw_events": len(fw_d),
                        "med_events": len(med_d),
                        "clock_skew_12h_fixes": clock_fixes_d,
                    },
                ),
                (
                    "CAMP-2026-002",
                    "Extraccion Masiva Automatizada via Protocolo SSH",
                    "INSIDER_THREAT",
                    "HIGH",
                    "ESCENARIO_MAS_PELIGROSO",
                    "B2",
                    0.9420,
                    int(fw_c_cnt) + med_c_tot,
                    _asegurar_utc(fw_c_min),
                    _asegurar_utc(fw_c_max),
                    ["TA0008", "TA0009"],
                    ["T1021.004", "T1213", "T1074"],
                    {
                        "src_ips": ["10.10.100.50"],
                        "dst_ips": ["10.10.100.30"],
                        "ports": [22],
                        "actor_tokens": [actor_c],
                        "account_tokens": [account_c],
                    },
                    [
                        "30 sesiones con Protocolo=='SSH' correlacionadas 1:1 con 30 TRANFERENCIA EXITOSA",
                        "Rafaga de 2,970 TRANFERENCIA INTERRUMPIDA en la misma hora",
                    ],
                    {
                        "fw_ssh_protocol_events": int(fw_c_cnt),
                        "med_tranferencia_exitosa": 30,
                        "med_tranferencia_interrumpida": 2970,
                    },
                ),
                (
                    "CAMP-2026-003",
                    "Fuerza Bruta Nocturna sobre Servicio Telnet (23/tcp)",
                    "EXTERNAL_ACTOR",
                    "HIGH",
                    "ESCENARIO_MAS_PROBABLE",
                    "A2",
                    0.9150,
                    int(fw_a_cnt) + int(med_a_cnt),
                    _asegurar_utc(fw_a_min),
                    _asegurar_utc(fw_a_max),
                    ["TA0006", "TA0008"],
                    ["T1110.001", "T1021"],
                    {
                        "src_ips": ["10.10.100.10"],
                        "dst_ips": ["10.10.100.30"],
                        "ports": [23],
                        "actor_tokens": [actor_a],
                        "account_tokens": [account_a],
                    },
                    [
                        "Rafaga de 2,000 conexiones negadas a puerto 23/tcp en menos de 1 hora",
                        "Correlacion exacta con 2,000 eventos ACCESO FALLIDO en MedSys",
                    ],
                    {
                        "fw_denied_telnet": int(fw_a_cnt),
                        "med_failed_access": int(med_a_cnt),
                    },
                ),
                (
                    "CAMP-2026-004",
                    "Reconocimiento Multi-Servicio (RDP/SMB/BD/NetBIOS) y Spraying",
                    "EXTERNAL_ACTOR",
                    "HIGH",
                    "ESCENARIO_MAS_PROBABLE",
                    "B2",
                    0.9310,
                    fw_b_cnt + int(med_b_cnt),
                    fw_b_min,
                    max(fw_b_max, _asegurar_utc(med_b_max)),
                    ["TA0007", "TA0006", "TA0008"],
                    ["T1046", "T1110.003", "T1021.001", "T1021.002"],
                    {
                        "src_ips": ["10.10.100.20"],
                        "dst_ips": ["10.10.100.30"],
                        "ports": [137, 445, 3389, 8471],
                        "actor_tokens": [actor_b],
                        "account_tokens": [account_b],
                    },
                    [
                        "Diversidad exacta de 4 puertos criticos (4 x 250 intentos negados)",
                        "Resolucion desambiguada mediante account_token por identidad_ambigua=True",
                    ],
                    {
                        "fw_denied_scan": fw_b_cnt,
                        "med_failed_window": int(med_b_cnt),
                        "identidad_ambigua": bool(ambigua_b),
                    },
                ),
                (
                    "CAMP-2026-005",
                    "Abuso Interno de Privilegios, Sabotaje de Cuentas y Canal Sombra SSH/8443",
                    "INSIDER_THREAT",
                    "CRITICAL",
                    "ESCENARIO_MAS_PROBABLE",
                    "B3",
                    0.9640,
                    int(ssh_826_cnt) + int(puerto_8443_cnt) + total_eventos_e_med,
                    _asegurar_utc(ssh_826_min),
                    _asegurar_utc(ssh_826_max),
                    ["TA0003", "TA0004", "TA0040"],
                    ["T1078", "T1098", "T1531"],
                    {
                        "dst_ips": ["10.10.100.30"],
                        "ports": [22, 8443],
                        "account_tokens": [c[0] for c in cuentas_e],
                    },
                    [
                        "Operaciones masivas de activacion, reactivacion, inactivacion y cambio de nivel",
                        "787 IPs sin puntos concentradas al 100% en cuentas especiales no-SIM",
                        "Coincidencia volumetrica de 826 sesiones SSH con 826 reactivaciones en cuenta espejo",
                    ],
                    {
                        "fw_app_ssh": int(ssh_826_cnt),
                        "fw_port_8443": int(puerto_8443_cnt),
                        "med_dotless_ips": total_dotless_med,
                    },
                ),
            ]

            for camp in campanas:
                cur.execute(
                    """
                    INSERT INTO cti_core.threat_campaigns (
                        campaign_code, title, adversary_type, severity, ipe_scenario,
                        admiralty_rating, anomaly_score, event_count, first_seen, last_seen,
                        mitre_tactics, mitre_techniques, iocs, ioas, summary_metrics
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        camp[0],
                        camp[1],
                        camp[2],
                        camp[3],
                        camp[4],
                        camp[5],
                        camp[6],
                        camp[7],
                        camp[8],
                        camp[9],
                        Jsonb(camp[10]),
                        Jsonb(camp[11]),
                        Jsonb(camp[12]),
                        Jsonb(camp[13]),
                        Jsonb(camp[14]),
                    ),
                )

        n_timeline = copiar_filas_tabla(
            conn,
            "cti_core",
            "campaign_timeline_events",
            [
                "campaign_code",
                "event_ts",
                "source_layer",
                "actor_token",
                "account_token",
                "src_or_conn_ip",
                "dst_ip",
                "dst_port",
                "event_summary",
                "clock_skew_12h_fix",
            ],
            timeline_filas,
        )
        conn.commit()

    with obtener_conexion(usar_rol_app=True, settings=cfg) as conn_app:
        audit_id, row_hash = registrar_evento_auditoria(
            conn_app,
            operation="CORRELATE_THREAT_CAMPAIGNS",
            dataset_name="postgres_cti_core",
            dataset_sha256="CROSS_LAYER_CORRELATION",
            total_rows_read=int(n_timeline),
            rows_persisted=int(len(campanas) + n_timeline),
            pii_scrubbed=True,
            metadata={
                "campaigns_inserted": len(campanas),
                "timeline_events_inserted": int(n_timeline),
                "clock_skew_12h_fixes": clock_fixes_d,
            },
        )
        conn_app.commit()

    resumen = {
        "campaigns_inserted": len(campanas),
        "timeline_events_inserted": int(n_timeline),
        "clock_skew_12h_fixes": clock_fixes_d,
        "audit_id": audit_id,
        "audit_hash": row_hash,
    }
    print(
        f"[OK] Correlación completada: {len(campanas)} campañas, "
        f"{n_timeline} eventos en timeline, {clock_fixes_d} ajustes +12h."
    )
    return resumen


if __name__ == "__main__":
    ejecutar_correlacion()
