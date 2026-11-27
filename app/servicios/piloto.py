import hashlib
import hmac
import json
import os
import re
from uuid import NAMESPACE_URL, uuid4, uuid5

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app.core.conexion_postgres import conectar_postgres
from app.servicios.centinela_privacidad import (
    extraer_indicadores, grupos_por_indicadores, obtener_clave, seudonimo_reportante,
)
from app.servicios.guardian_cuenta import PATRON_AFILIADO, PRESTAMO, evaluar_eventos
from app.servicios.notificaciones import crear_aviso
from backend.app.core.security import registrar_evento_auditoria


class PilotoNoConfigurado(Exception):
    pass


class SesionInvalida(Exception):
    pass


class ReporteSinIndicadores(Exception):
    pass


class CasoNoEncontrado(Exception):
    pass


class CasoResuelto(Exception):
    pass


def autenticar_reportante(token):
    if not token:
        raise SesionInvalida
    try:
        sesiones = json.loads(os.getenv("PILOTO_SESIONES_JSON", "{}"))
        if not isinstance(sesiones, dict) or not sesiones:
            raise ValueError
        for sesion in sesiones.values():
            afiliado = sesion["affiliate"]
            if (not re.fullmatch(r"[0-9a-f]{64}", sesion["keySha256"])
                    or (afiliado is not None and not PATRON_AFILIADO.fullmatch(afiliado))):
                raise ValueError
        if len({s["keySha256"] for s in sesiones.values()}) != len(sesiones):
            raise ValueError
        clave = obtener_clave()
    except (ValueError, KeyError, TypeError, RuntimeError) as error:
        raise PilotoNoConfigurado from error

    huella = hashlib.sha256(token.encode()).hexdigest()
    for nombre, sesion in sesiones.items():
        if hmac.compare_digest(sesion["keySha256"], huella):
            afiliado = sesion["affiliate"]
            return seudonimo_reportante(afiliado or "sesion:" + nombre, clave), afiliado, clave
    raise SesionInvalida


def registrar_reporte(texto, provincia, token):
    reportante, afiliado, clave = autenticar_reportante(token)
    indicadores = extraer_indicadores(texto, clave)
    claves = [
        sorted(set(indicadores["dominios"])),
        sorted({t["hash"] for t in indicadores["telefonos"]}),
        sorted({c["hash"] for c in indicadores["cuentas"]}),
    ]
    if not any(claves):
        raise ReporteSinIndicadores
    huella = hashlib.sha256(json.dumps(claves).encode()).hexdigest()
    with conectar_postgres() as conn, conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT pg_advisory_xact_lock('cti_piloto.reportes'::regclass::oid::bigint)")
        reporte_id = uuid4()
        cur.execute(
            """INSERT INTO cti_piloto.reportes (id, reportante, afiliado, provincia, huella, indicadores)
               VALUES (%s, %s, %s, %s, %s, %s)
               ON CONFLICT (reportante, huella) DO NOTHING RETURNING *""",
            (reporte_id, reportante, afiliado, provincia, huella, Jsonb(indicadores)),
        )
        fila = cur.fetchone()
        nuevo = fila is not None
        if not nuevo:
            cur.execute("SELECT * FROM cti_piloto.reportes WHERE reportante = %s AND huella = %s",
                        (reportante, huella))
            fila = cur.fetchone()
        else:
            notificar_umbral(conn, reporte_id)
    ind = fila["indicadores"]
    dominios = [d.replace(".", "[.]") for d in ind["dominios"]]
    return nuevo, {
        "reportId": str(fila["id"]), "province": fila["provincia"], "receivedAt": fila["recibido_en"],
        "indicators": {"domains": dominios, "phones": sorted({t["mascara"] for t in ind["telefonos"]}),
                       "accounts": sorted({c["mascara"] for c in ind["cuentas"]})},
        "summary": f"{len(dominios)} dominio(s), {len({t['hash'] for t in ind['telefonos']})} teléfono(s), "
                   f"{len({c['hash'] for c in ind['cuentas']})} cuenta(s)",
    }


def leer_campanas(conn, excluir_reporte=None):
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT * FROM cti_piloto.reportes WHERE id IS DISTINCT FROM %s ORDER BY recibido_en, id",
            (excluir_reporte,),
        )
        grupos = grupos_por_indicadores(cur.fetchall())
    campanas, vinculos = [], []
    for miembros in grupos:
        primero = miembros[0]["id"]
        campana_id = "CEN-" + primero.hex
        provincias = {}
        reportantes = set()
        for reporte in miembros:
            provincia = reporte["provincia"]
            if reporte["reportante"] not in reportantes:
                provincias[provincia] = provincias.get(provincia, 0) + 1
                reportantes.add(reporte["reportante"])
            vinculos.append({
                "campana_id": campana_id, "reporte_id": str(reporte["id"]), "afiliado": reporte["afiliado"],
                "fecha_hora": reporte["recibido_en"].isoformat(),
                "cuentas_hash": [c["hash"] for c in reporte["indicadores"]["cuentas"]],
            })
        campanas.append({
            "campaignId": campana_id, "reportCount": len(reportantes),
            "byProvince": provincias,
            "domains": sorted({d.replace(".", "[.]") for m in miembros for d in m["indicadores"]["dominios"]}),
            "status": "AVISO_A_AFILIADOS" if len(reportantes) >= 3 else "EN_OBSERVACION",
        })
    return sorted(campanas, key=lambda c: (-c["reportCount"], c["campaignId"])), vinculos


def campana_por_reporte(campanas, vinculos, reporte_id):
    enlace = next((v for v in vinculos if v["reporte_id"] == str(reporte_id)), None)
    if enlace:
        return next(c for c in campanas if c["campaignId"] == enlace["campana_id"])
    return None


def notificar_umbral(conn, reporte_id):
    campanas, vinculos = leer_campanas(conn)
    actual = campana_por_reporte(campanas, vinculos, reporte_id)
    if actual["status"] != "AVISO_A_AFILIADOS":
        return

    miembros = {v["reporte_id"] for v in vinculos if v["campana_id"] == actual["campaignId"]}
    previas, vinculos_previos = leer_campanas(conn, excluir_reporte=reporte_id)
    sobre_umbral = {c["campaignId"] for c in previas if c["status"] == "AVISO_A_AFILIADOS"}
    if not any(v["campana_id"] in sobre_umbral and v["reporte_id"] in miembros for v in vinculos_previos):
        crear_aviso(conn, "CENTINELA", reporte_id)


def vista_alerta(alerta):
    return {
        "alertId": alerta["id_alerta"], "rule": alerta["regla"], "affiliate": alerta["afiliado"],
        "employee": alerta.get("funcionario"), "affectedAffiliates": alerta.get("afiliados_afectados", []),
        "severity": alerta["severidad"], "confidence": alerta["confianza"],
        "action": alerta["accion"], "explanation": alerta["explicacion"],
        "timeline": [{"eventId": e["id_evento"], "timestamp": e["hora"] + "-05:00",
                      "event": e["evento"], "channel": e["canal"]} for e in alerta["linea_tiempo"]],
        "durationMinutes": alerta.get("minutos_totales"), "verificationChannel": alerta.get("canal_verificacion"),
        "phishingLink": alerta.get("vinculo_phishing"), "phishingReportId": alerta.get("reporte_phishing_id"),
    }


def vista_caso(fila):
    return {
        "caseId": str(fila["id"]), "status": fila["estado"],
        "operationStatus": {"EN_REVISION": "EN_REVISION", "CONFIRMADO": "RETENIDA",
                            "DESCARTADO": "LIBERADA"}[fila["estado"]],
        "createdAt": fila["creado_en"], "evidence": fila["evidencia"],
        "auditId": fila["audit_id"], "decidedBy": fila["decision_analista"],
        "decisionReason": fila["decision_motivo"], "simulated": True,
    }


def evaluar_piloto():
    with conectar_postgres() as conn, conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
        # Serializa evaluaciones del piloto. La decisión toma únicamente el bloqueo de su fila.
        cur.execute("SELECT pg_advisory_xact_lock('cti_piloto.casos'::regclass::oid::bigint)")
        cur.execute("SELECT datos FROM cti_piloto.eventos ORDER BY id")
        eventos = [e["datos"] for e in cur.fetchall()]
        prestamos = {e["id_evento"] for e in eventos if e["tipo"] == PRESTAMO}
        _, vinculos = leer_campanas(conn)
        resultado = evaluar_eventos(eventos, vinculos)
        alertas, casos = [], []
        for alerta in resultado["alertas"]:
            vista = vista_alerta(alerta)
            caso_id = None
            if alerta["accion"] in {"RETENER_PRESTAMO_Y_VERIFICAR", "RETENER_DESEMBOLSO"}:
                prestamo = next(id_evento for id_evento in alerta["eventos"] if id_evento in prestamos)
                caso_id = uuid5(NAMESPACE_URL, f"aegishealth/guardian/{alerta['regla']}/{prestamo}")
                critico_nuevo = (alerta["regla"] == "GUARD-01" and alerta["severidad"] == "CRITICA"
                                 and cur.execute("SELECT 1 FROM cti_piloto.casos WHERE id = %s",
                                                 (caso_id,)).fetchone() is None)
                cur.execute(
                    """INSERT INTO cti_piloto.casos (id, evidencia) VALUES (%s, %s)
                       ON CONFLICT (id) DO UPDATE SET evidencia = EXCLUDED.evidencia
                       WHERE cti_piloto.casos.estado = 'EN_REVISION' RETURNING *""",
                    (caso_id, Jsonb(vista)),
                )
                fila = cur.fetchone()
                if fila is None:
                    cur.execute("SELECT * FROM cti_piloto.casos WHERE id = %s", (caso_id,))
                    fila = cur.fetchone()
                casos.append(vista_caso(fila))
                if critico_nuevo:
                    crear_aviso(conn, "GUARDIAN", caso_id)
            alertas.append({**vista, "caseId": str(caso_id) if caso_id else None})
    return {"alerts": alertas, "cases": casos, "evaluatedEvents": resultado["eventos_evaluados"],
            "ignoredEvents": resultado["eventos_ignorados"]}


def consultar_casos(caso_id=None):
    with conectar_postgres() as conn, conn.cursor(row_factory=dict_row) as cur:
        if caso_id is None:
            cur.execute("SELECT * FROM cti_piloto.casos ORDER BY creado_en DESC, id")
            return [vista_caso(f) for f in cur.fetchall()]
        cur.execute("SELECT * FROM cti_piloto.casos WHERE id = %s", (caso_id,))
        fila = cur.fetchone()
        if fila is None:
            raise CasoNoEncontrado
        return vista_caso(fila)


def decidir_caso(caso_id, decision, motivo, analista):
    estado = "CONFIRMADO" if decision == "CONFIRMAR" else "DESCARTADO"
    with conectar_postgres() as conn, conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM cti_piloto.casos WHERE id = %s FOR UPDATE", (caso_id,))
        fila = cur.fetchone()
        if fila is None:
            raise CasoNoEncontrado
        if fila["estado"] != "EN_REVISION":
            if (fila["estado"], fila["decision_motivo"], fila["decision_analista"]) != (estado, motivo, analista):
                raise CasoResuelto
            return vista_caso(fila)
        audit_id, _ = registrar_evento_auditoria(
            conn, operation="GUARDIAN_CASE_DECISION", dataset_name="cti_piloto.casos",
            dataset_sha256="", total_rows_read=1, rows_persisted=1,
            metadata={"caseId": str(caso_id), "analystId": analista, "decision": decision, "reason": motivo},
        )
        cur.execute(
            """UPDATE cti_piloto.casos
               SET estado = %s, decision_analista = %s, decision_motivo = %s, audit_id = %s
               WHERE id = %s RETURNING *""", (estado, analista, motivo, audit_id, caso_id),
        )
        return vista_caso(cur.fetchone())
