"""Proceso SMTP de AegisHealth. Ejecutar como servicio independiente."""
import os
import smtplib
import ssl
import time
from dataclasses import dataclass
from email.message import EmailMessage
from uuid import uuid4

from psycopg import Error as ErrorPostgres
from psycopg.rows import dict_row

from app.core.conexion_postgres import conectar_postgres
from app.servicios.notificaciones import TITULOS

MAX_INTENTOS = 3


@dataclass(frozen=True)
class Smtp:
    host: str
    port: int
    modo: str
    remitente: str
    destinatario: str
    usuario: str
    clave: str

    @classmethod
    def desde_entorno(cls):
        modo = os.getenv("NOTIFICACIONES_SMTP_MODO", "starttls").strip().lower()
        if modo not in {"starttls", "ssl"}:
            raise ValueError("Elegí starttls o ssl para el envío.")
        campos = [os.getenv("NOTIFICACIONES_SMTP_" + nombre, "").strip()
                  for nombre in ("HOST", "REMITENTE", "DESTINATARIO", "USUARIO", "CLAVE")]
        if not all(campos) or any(c in campos[2] or c in campos[1] for c in "\r\n,;"):
            raise ValueError("Completá la configuración SMTP con un remitente y un destinatario de prueba.")
        puerto = int(os.getenv("NOTIFICACIONES_SMTP_PUERTO") or (465 if modo == "ssl" else 587))
        if not 1 <= puerto <= 65535:
            raise ValueError("Puerto SMTP inválido.")
        return cls(campos[0], puerto, modo, *campos[1:])


def reclamar():
    reclamo = uuid4()
    with conectar_postgres() as conn, conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """UPDATE cti_piloto.cola_correo SET estado = 'FALLIDO', reclamo = NULL,
                      vence_reclamo = NULL, ultimo_error = 'Proceso de correo interrumpido'
               WHERE estado = 'PROCESANDO' AND vence_reclamo <= now() AND intentos >= %s""",
            (MAX_INTENTOS,),
        )
        cur.execute(
            """WITH siguiente AS (
                   SELECT notificacion_id FROM cti_piloto.cola_correo
                   WHERE intentos < %s AND (
                       (estado = 'PENDIENTE' AND siguiente_intento <= now())
                       OR (estado = 'PROCESANDO' AND vence_reclamo <= now())
                   )
                   ORDER BY siguiente_intento, notificacion_id
                   LIMIT 1 FOR UPDATE SKIP LOCKED
               )
               UPDATE cti_piloto.cola_correo c
               SET estado = 'PROCESANDO', intentos = c.intentos + 1,
                   reclamo = %s, vence_reclamo = now() + interval '2 minutes'
               FROM siguiente s JOIN cti_piloto.notificaciones n ON n.id = s.notificacion_id
               WHERE c.notificacion_id = s.notificacion_id
               RETURNING n.id, n.origen, n.creado_en, c.intentos, c.reclamo""",
            (MAX_INTENTOS, reclamo),
        )
        return cur.fetchone()


def enviar(config, aviso):
    mensaje = EmailMessage()
    mensaje["From"] = config.remitente
    mensaje["To"] = config.destinatario
    mensaje["Subject"] = TITULOS[aviso["origen"]]
    mensaje["Message-ID"] = f"<{aviso['id']}@notificaciones.aegishealth.local>"
    mensaje.set_content(
        f"Origen: {aviso['origen']}\nFecha: {aviso['creado_en'].isoformat()}\n"
        f"Identificador del aviso: {aviso['id']}\n\nAbrí la campana del SOC en AegisHealth."
    )
    contexto = ssl.create_default_context()
    if config.modo == "ssl":
        cliente = smtplib.SMTP_SSL(config.host, config.port, timeout=10, context=contexto)
    else:
        cliente = smtplib.SMTP(config.host, config.port, timeout=10)
    try:
        if config.modo == "starttls":
            cliente.starttls(context=contexto)
        cliente.login(config.usuario, config.clave)
        cliente.send_message(mensaje, from_addr=config.remitente, to_addrs=[config.destinatario])
    finally:
        cliente.close()


def resultado_error(error):
    if isinstance(error, smtplib.SMTPRecipientsRefused):
        codigo = next(iter(error.recipients.values()))[0]
    elif isinstance(error, smtplib.SMTPResponseException):
        codigo = error.smtp_code
    else:
        permanente = isinstance(error, (ssl.SSLCertVerificationError, smtplib.SMTPNotSupportedError, ValueError))
        return type(error).__name__, permanente
    return f"SMTP {codigo}", not 400 <= codigo < 500


def procesar_un_aviso(config):
    aviso = reclamar()
    if aviso is None:
        return False

    error = None
    estado = "ENVIADO"
    try:
        enviar(config, aviso)
    except (OSError, smtplib.SMTPException, ValueError) as fallo:
        error, permanente = resultado_error(fallo)
        estado = "FALLIDO" if permanente or aviso["intentos"] >= MAX_INTENTOS else "PENDIENTE"

    with conectar_postgres() as conn:
        conn.execute(
            """UPDATE cti_piloto.cola_correo SET estado = %s, ultimo_error = %s,
                      enviado_en = CASE WHEN %s = 'ENVIADO' THEN now() END,
                      siguiente_intento = now() + (%s * interval '1 minute'),
                      reclamo = NULL, vence_reclamo = NULL
               WHERE notificacion_id = %s AND reclamo = %s""",
            (estado, error, estado, aviso["intentos"], aviso["id"], aviso["reclamo"]),
        )
    return True


def main():
    if os.getenv("NOTIFICACIONES_SMTP_HABILITADO", "").strip().lower() != "true":
        raise SystemExit("El correo de notificaciones está desactivado.")
    try:
        config = Smtp.desde_entorno()
    except ValueError:
        raise SystemExit("Configuración SMTP incompleta o inválida.") from None

    while True:
        try:
            if procesar_un_aviso(config):
                continue
        except ErrorPostgres:
            print("Cola de correo temporalmente indisponible.", flush=True)
        time.sleep(5)


if __name__ == "__main__":
    main()
