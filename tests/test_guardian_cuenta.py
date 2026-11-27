"""Pruebas de la regla Guardián de Cuenta (Rol 2).
Ejecutar desde la raíz del repositorio:  python -m unittest tests.test_guardian_cuenta -v
"""
import unittest

from app.servicios.guardian_cuenta import evaluar_eventos

A1 = "AFI-000000000001"
A2 = "AFI-000000000002"


def ev(i, afiliado, tipo, hora, canal="WEB", origen="AFILIADO", **extra):
    e = {"id_evento": f"E{i}", "afiliado": afiliado, "tipo": tipo,
         "fecha_hora": hora, "canal": canal, "origen": origen}
    e.update(extra)
    return e


def reglas(resultado):
    return sorted(a["regla"] for a in resultado["alertas"])


def una(resultado, regla):
    return next(a for a in resultado["alertas"] if a["regla"] == regla)


class PruebasGuardian(unittest.TestCase):

    def test_ataque_clasico_se_retiene(self):
        r = evaluar_eventos([
            ev(1, A1, "CAMBIO_CELULAR", "2026-10-24T22:00:00"),
            ev(2, A1, "CAMBIO_CORREO", "2026-10-24T22:10:00"),
            ev(3, A1, "CAMBIO_CUENTA_BANCARIA", "2026-10-24T22:20:00"),
            ev(4, A1, "SOLICITUD_PRESTAMO", "2026-10-24T22:40:00"),
        ])
        g1 = una(r, "GUARD-01")
        self.assertEqual(g1["severidad"], "CRITICA")
        self.assertEqual(g1["accion"], "RETENER_PRESTAMO_Y_VERIFICAR")
        self.assertEqual(g1["minutos_totales"], 40)
        self.assertEqual(g1["confianza"], "ALTA")          # menos de 6 horas
        self.assertIn("ANTERIORES", g1["canal_verificacion"])
        self.assertIn("GUARD-02", reglas(r))               # el aviso temprano también salió
        self.assertEqual(r["alertas"][0]["regla"], "GUARD-01")  # lo crítico va primero

    def test_limite_exacto_de_24_horas_si_alerta(self):
        r = evaluar_eventos([
            ev(1, A1, "CAMBIO_CELULAR", "2026-10-01T08:00:00"),
            ev(2, A1, "CAMBIO_CUENTA_BANCARIA", "2026-10-01T09:00:00"),
            ev(3, A1, "SOLICITUD_PRESTAMO", "2026-10-02T08:00:00"),
        ])
        self.assertEqual(una(r, "GUARD-01")["confianza"], "MEDIA")  # más de 6 h

    def test_un_minuto_fuera_de_la_ventana_no_alerta(self):
        r = evaluar_eventos([
            ev(1, A1, "CAMBIO_CELULAR", "2026-10-01T08:00:00"),
            ev(2, A1, "CAMBIO_CUENTA_BANCARIA", "2026-10-01T09:00:00"),
            ev(3, A1, "SOLICITUD_PRESTAMO", "2026-10-02T08:01:00"),
        ])
        self.assertNotIn("GUARD-01", reglas(r))

    def test_ataque_lento_no_lo_detecta_limitacion_conocida(self):
        r = evaluar_eventos([
            ev(1, A1, "CAMBIO_CELULAR", "2026-10-01T08:00:00"),
            ev(2, A1, "CAMBIO_CUENTA_BANCARIA", "2026-10-03T08:00:00"),
            ev(3, A1, "SOLICITUD_PRESTAMO", "2026-10-05T08:00:00"),
        ])
        self.assertEqual(r["alertas"], [])

    def test_sin_cambio_de_banco_no_alerta(self):
        r = evaluar_eventos([
            ev(1, A1, "CAMBIO_CELULAR", "2026-10-01T08:00:00"),
            ev(2, A1, "SOLICITUD_PRESTAMO", "2026-10-01T09:00:00"),
        ])
        self.assertEqual(r["alertas"], [])

    def test_banco_cambiado_despues_del_prestamo(self):
        r = evaluar_eventos([
            ev(1, A1, "SOLICITUD_PRESTAMO", "2026-10-01T10:00:00"),
            ev(2, A1, "CAMBIO_CUENTA_BANCARIA", "2026-10-01T15:00:00"),
        ])
        self.assertEqual(una(r, "GUARD-03")["accion"], "RETENER_DESEMBOLSO")

    def test_cambios_en_agencia_con_biometria_solo_se_registran(self):
        r = evaluar_eventos([
            ev(1, A1, "CAMBIO_CELULAR", "2026-10-01T09:00:00", canal="AGENCIA_BIOMETRICO", origen="FUNCIONARIO"),
            ev(2, A1, "CAMBIO_CUENTA_BANCARIA", "2026-10-01T09:05:00", canal="AGENCIA_BIOMETRICO", origen="FUNCIONARIO"),
            ev(3, A1, "SOLICITUD_PRESTAMO", "2026-10-01T12:00:00"),
        ])
        g1 = una(r, "GUARD-01")
        self.assertEqual((g1["severidad"], g1["accion"]), ("BAJA", "REGISTRAR"))
        self.assertNotIn("GUARD-02", reglas(r))

    def test_proceso_masivo_del_banco_se_ignora(self):
        r = evaluar_eventos([
            ev(1, A1, "CAMBIO_CELULAR", "2026-10-01T08:00:00"),
            ev(2, A1, "CAMBIO_CUENTA_BANCARIA", "2026-10-01T09:00:00", canal="SISTEMA", origen="PROCESO_MASIVO"),
            ev(3, A1, "SOLICITUD_PRESTAMO", "2026-10-01T10:00:00"),
        ])
        self.assertEqual(r["alertas"], [])
        self.assertEqual(r["eventos_ignorados"], 1)

    def test_vinculo_con_phishing_por_cuenta_bancaria(self):
        r = evaluar_eventos(
            [ev(1, A1, "CAMBIO_CORREO", "2026-10-01T08:00:00"),
             ev(2, A1, "CAMBIO_CUENTA_BANCARIA", "2026-10-01T09:00:00", valor_hash="abc123"),
             ev(3, A1, "SOLICITUD_PRESTAMO", "2026-10-02T07:00:00")],
            reportes_phishing=[{"campana_id": "CEN-001", "fecha_hora": "2026-09-30T10:00:00",
                                "cuentas_hash": ["abc123"]}])
        g1 = una(r, "GUARD-01")
        self.assertIn("CEN-001", g1["vinculo_phishing"])
        self.assertEqual(g1["confianza"], "ALTA")   # 23 h, pero hay vínculo verificable

    def test_vinculo_por_reporte_del_mismo_afiliado(self):
        r = evaluar_eventos(
            [ev(1, A1, "CAMBIO_CELULAR", "2026-10-10T08:00:00"),
             ev(2, A1, "CAMBIO_CUENTA_BANCARIA", "2026-10-10T09:00:00"),
             ev(3, A1, "SOLICITUD_PRESTAMO", "2026-10-11T07:00:00")],
            reportes_phishing=[{"afiliado": A1, "campana_id": "CEN-002", "fecha_hora": "2026-10-07T10:00:00"},
                               {"afiliado": A2, "campana_id": "CEN-009", "fecha_hora": "2026-10-09T10:00:00"}])
        self.assertIn("CEN-002", una(r, "GUARD-01")["vinculo_phishing"])

    def test_no_mezcla_afiliados(self):
        r = evaluar_eventos([
            ev(1, A1, "CAMBIO_CELULAR", "2026-10-01T08:00:00"),
            ev(2, A2, "CAMBIO_CUENTA_BANCARIA", "2026-10-01T08:10:00"),
            ev(3, A2, "SOLICITUD_PRESTAMO", "2026-10-01T08:20:00"),
        ])
        self.assertEqual(r["alertas"], [])

    def test_rechaza_cedula_en_lugar_de_seudonimo(self):
        with self.assertRaises(ValueError):
            evaluar_eventos([ev(1, "1710034065", "CAMBIO_CELULAR", "2026-10-01T08:00:00")])

    def test_funcionario_fuera_de_horario(self):
        nocturnos = [ev(i, f"AFI-0000000000{i:02d}", "CAMBIO_CUENTA_BANCARIA", f"2026-10-05T23:{i:02d}:00",
                        canal="AGENCIA", origen="FUNCIONARIO", funcionario="FUN-7") for i in range(10, 15)]
        self.assertIn("GUARD-04", reglas(evaluar_eventos(nocturnos)))
        diurnos = [dict(e, fecha_hora=e["fecha_hora"].replace("T23", "T10")) for e in nocturnos]
        self.assertNotIn("GUARD-04", reglas(evaluar_eventos(diurnos)))

    def test_tipo_desconocido_y_hora_con_zona(self):
        r = evaluar_eventos([
            ev(1, A1, "CAMBIO_CELULAR", "2026-10-25T03:00:00+00:00"),   # = 24-oct 22:00 en Ecuador
            ev(2, A1, "CAMBIO_CUENTA_BANCARIA", "2026-10-24T22:10:00"),
            ev(3, A1, "SOLICITUD_PRESTAMO", "2026-10-24T22:20:00"),
            ev(4, A1, "CONSULTA_SALDO", "2026-10-24T22:30:00"),
        ])
        self.assertEqual(una(r, "GUARD-01")["minutos_totales"], 20)
        self.assertEqual(r["eventos_ignorados"], 1)

    def test_ventana_configurable(self):
        eventos = [ev(1, A1, "CAMBIO_CELULAR", "2026-10-01T08:00:00"),
                   ev(2, A1, "CAMBIO_CUENTA_BANCARIA", "2026-10-02T08:00:00"),
                   ev(3, A1, "SOLICITUD_PRESTAMO", "2026-10-03T07:00:00")]
        self.assertNotIn("GUARD-01", reglas(evaluar_eventos(eventos)))
        self.assertIn("GUARD-01", reglas(evaluar_eventos(eventos, config={"ventana_horas": 48})))


if __name__ == "__main__":
    unittest.main()
