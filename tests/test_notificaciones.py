from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.servicios import correo_notificaciones, notificaciones


class ConexionFalsa:
    def __init__(self, filas):
        self.filas = list(filas)
        self.consultas = []

    def execute(self, sql, parametros):
        self.consultas.append((sql, parametros))
        return SimpleNamespace(fetchone=lambda: self.filas.pop(0))


def test_crear_aviso_idempotente_y_encola_correo_en_la_misma_transaccion(monkeypatch):
    aviso_id = "00000000-0000-0000-0000-000000000001"
    conn = ConexionFalsa([(aviso_id,)])
    monkeypatch.setenv("NOTIFICACIONES_SMTP_HABILITADO", "true")

    notificaciones.crear_aviso(conn, "GUARDIAN", aviso_id)

    assert len(conn.consultas) == 2
    assert "ON CONFLICT (origen, referencia) DO NOTHING" in conn.consultas[0][0]
    assert "cola_correo" in conn.consultas[1][0]
    assert conn.consultas[1][1] == (aviso_id,)


def test_aviso_duplicado_no_duplica_mensaje_en_cola(monkeypatch):
    conn = ConexionFalsa([None])
    monkeypatch.setenv("NOTIFICACIONES_SMTP_HABILITADO", "true")

    notificaciones.crear_aviso(conn, "CENTINELA", "reporte-id")

    assert len(conn.consultas) == 1


def test_correo_usa_tls_destinatario_y_message_id_determinista():
    config = correo_notificaciones.Smtp(
        host="smtp.test", port=587, modo="starttls", remitente="soc@test.invalid",
        destinatario="pruebas@test.invalid", usuario="usuario", clave="secreto",
    )
    cliente = Mock()
    aviso = {"id": "00000000-0000-0000-0000-000000000002", "origen": "GUARDIAN",
             "creado_en": datetime(2026, 11, 27, tzinfo=timezone.utc)}

    with patch.object(correo_notificaciones.smtplib, "SMTP", return_value=cliente), \
         patch.object(correo_notificaciones.ssl, "create_default_context", return_value=object()):
        correo_notificaciones.enviar(config, aviso)

    cliente.starttls.assert_called_once()
    cliente.login.assert_called_once_with("usuario", "secreto")
    args, kwargs = cliente.send_message.call_args
    assert args[0]["To"] == "pruebas@test.invalid"
    assert args[0]["Message-ID"] == f"<{aviso['id']}@notificaciones.aegishealth.local>"
    assert "correo.test" not in args[0].get_content()
    assert kwargs["to_addrs"] == ["pruebas@test.invalid"]
    cliente.close.assert_called_once()


def test_smtp_reintenta_errores_temporales_y_detiene_errores_permanentes():
    error_temporal = correo_notificaciones.smtplib.SMTPResponseException(451, b"intentar luego")
    error_permanente = correo_notificaciones.smtplib.SMTPResponseException(550, b"rechazado")

    assert correo_notificaciones.resultado_error(error_temporal)[1] is False
    assert correo_notificaciones.resultado_error(error_permanente)[1] is True

