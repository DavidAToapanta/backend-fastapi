import os
from uuid import uuid4

from psycopg.rows import dict_row

from app.core.conexion_postgres import conectar_postgres

TITULOS = {
    "DEMO": "[DEMO] Centinela: tercer reporte de prueba",
    "GUARDIAN": "Alerta crítica · Préstamo en revisión",
    "CENTINELA": "Centinela · Campaña de phishing alcanzó el umbral",
}


def correo_habilitado():
    return os.getenv("NOTIFICACIONES_SMTP_HABILITADO", "").strip().lower() == "true"


def crear_aviso(conn, origen, referencia):
    fila = conn.execute(
        """INSERT INTO cti_piloto.notificaciones (id, origen, referencia)
           VALUES (%s, %s, %s)
           ON CONFLICT (origen, referencia) DO NOTHING RETURNING id""",
        (uuid4(), origen, referencia),
    ).fetchone()
    if fila and correo_habilitado():
        conn.execute("INSERT INTO cti_piloto.cola_correo (notificacion_id) VALUES (%s)", (fila[0],))


def listar_avisos(analista):
    with conectar_postgres() as conn, conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        cur.execute(
            """SELECT n.id, n.origen, n.referencia, n.creado_en, l.leido_en
               FROM cti_piloto.notificaciones n
               LEFT JOIN cti_piloto.notificaciones_leidas l
               ON l.notificacion_id = n.id AND l.analista = %s
               WHERE n.origen <> 'DEMO'
               ORDER BY n.creado_en DESC, n.id DESC LIMIT 50""", (analista,),
        )
        items = [{
            "id": f["id"], "source": f["origen"], "referenceId": f["referencia"],
            "createdAt": f["creado_en"], "readAt": f["leido_en"], "title": TITULOS[f["origen"]],
        } for f in cur.fetchall()]
        cur.execute(
            """SELECT count(*) AS total FROM cti_piloto.notificaciones n
               WHERE n.origen <> 'DEMO' AND NOT EXISTS (SELECT 1 FROM cti_piloto.notificaciones_leidas l
                                 WHERE l.notificacion_id = n.id AND l.analista = %s)""", (analista,),
        )
        return {"items": items, "unreadCount": cur.fetchone()["total"]}


def marcar_leido(aviso_id, analista):
    with conectar_postgres() as conn, conn.transaction():
        fila = conn.execute(
            """INSERT INTO cti_piloto.notificaciones_leidas (notificacion_id, analista)
               SELECT id, %s FROM cti_piloto.notificaciones WHERE id = %s AND origen <> 'DEMO'
               ON CONFLICT DO NOTHING RETURNING leido_en""", (analista, aviso_id),
        ).fetchone()
        if fila is None:
            fila = conn.execute(
                """SELECT leido_en FROM cti_piloto.notificaciones_leidas
                   WHERE notificacion_id = %s AND analista = %s""", (aviso_id, analista),
            ).fetchone()
        return fila[0] if fila else None
