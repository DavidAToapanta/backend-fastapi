import hashlib
import json
import os
import unittest
from unittest.mock import patch

import psycopg
from fastapi.testclient import TestClient

from app.main import app

CLAVE = "clave-de-pruebas-unitarias"
RUTA = "/api/v1/audit/reveal"
DATOS = {
    "analystId": "analista-prueba",
    "reason": "  Validar el caso simulado  ",
    "accountToken": "ACC-0123456789AB",
}


class PruebasBreakGlass(unittest.TestCase):
    def setUp(self):
        self.cliente = self.enterContext(TestClient(app))
        self.enterContext(patch.dict(os.environ, {
            "BREAK_GLASS_ANALYST_KEYS_JSON": json.dumps({
                "analista-prueba": hashlib.sha256(CLAVE.encode()).hexdigest(),
            }),
            "BREAK_GLASS_DATABASE_URL": "postgresql://aegis_break_glass@postgres:5432/aegis_cti",
        }))
        self.conectar_boveda = self.enterContext(patch("app.servicios.break_glass.psycopg.connect"))
        self.consulta = self.conectar_boveda.return_value.__enter__.return_value.execute
        self.consulta.return_value.fetchone.return_value = ("CUENTA-FICTICIA",)
        self.conectar_bitacora = self.enterContext(patch("app.servicios.break_glass.conectar_postgres"))
        self.bitacora = self.conectar_bitacora.return_value.__enter__.return_value
        self.registrar = self.enterContext(patch("app.servicios.break_glass.registrar_evento_auditoria"))
        self.registrar.return_value = (7, "a" * 64)

    def solicitar(self, datos=DATOS, clave=CLAVE):
        encabezado = {"Authorization": f"Bearer {clave}"} if clave else {}
        return self.cliente.post(RUTA, json=datos, headers=encabezado)

    def test_revela_una_cuenta_despues_de_registrar_y_confirmar(self):
        respuesta = self.solicitar()

        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(respuesta.headers["cache-control"], "no-store")
        self.assertEqual(respuesta.json(), {
            "accountToken": "ACC-0123456789AB",
            "technicalAccount": "CUENTA-FICTICIA",
            "auditId": 7,
        })
        self.assertEqual(self.consulta.call_args.args[1], ("ACC-0123456789AB",))
        self.assertEqual(self.registrar.call_args.kwargs["metadata"], {
            "analystId": "analista-prueba",
            "reason": "Validar el caso simulado",
            "accountToken": "ACC-0123456789AB",
        })
        self.assertNotIn("CUENTA-FICTICIA", repr(self.registrar.call_args))
        self.bitacora.transaction.return_value.__exit__.assert_called_once_with(None, None, None)

    def test_rechaza_credenciales_antes_de_consultar_la_boveda(self):
        for datos, clave in ((DATOS, ""), (DATOS, "incorrecta"), ({**DATOS, "analystId": "otro"}, CLAVE)):
            with self.subTest(datos=datos, clave=clave):
                self.assertEqual(self.solicitar(datos, clave).status_code, 401)
        self.conectar_boveda.assert_not_called()
        self.registrar.assert_not_called()

    def test_rechaza_motivo_corto_o_token_invalido(self):
        for datos in ({**DATOS, "reason": "  corto  "}, {**DATOS, "accountToken": "invalido"}):
            self.assertEqual(self.solicitar(datos).status_code, 422)
        self.conectar_boveda.assert_not_called()

    def test_cuenta_desconocida_devuelve_404_sin_registrar_revelacion(self):
        self.consulta.return_value.fetchone.return_value = None

        self.assertEqual(self.solicitar().status_code, 404)
        self.registrar.assert_not_called()

    def test_fallo_al_guardar_o_confirmar_impide_revelar(self):
        self.registrar.side_effect = psycopg.OperationalError("fallo interno")
        fallo_registro = self.solicitar()
        self.registrar.side_effect = None
        self.bitacora.transaction.return_value.__exit__.side_effect = psycopg.OperationalError("fallo de confirmación")
        fallo_confirmacion = self.solicitar()

        for respuesta in (fallo_registro, fallo_confirmacion):
            self.assertEqual(respuesta.status_code, 503)
            self.assertNotIn("CUENTA-FICTICIA", respuesta.text)

    def test_configuracion_ausente_o_con_rol_incorrecto_devuelve_503(self):
        for configuracion in (
            {"BREAK_GLASS_ANALYST_KEYS_JSON": ""},
            {"BREAK_GLASS_DATABASE_URL": "postgresql://aegis_app@postgres/aegis_cti"},
        ):
            with patch.dict(os.environ, configuracion):
                self.assertEqual(self.solicitar().status_code, 503)
        self.conectar_boveda.assert_not_called()
