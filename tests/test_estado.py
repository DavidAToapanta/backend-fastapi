import os
import unittest
from unittest.mock import patch

import psycopg
from fastapi.testclient import TestClient

from app.main import app


class PruebasEstado(unittest.TestCase):
    def setUp(self):
        self.cliente = self.enterContext(TestClient(app))

    def test_conserva_rutas_existentes_y_documentacion(self):
        respuesta_raiz = self.cliente.get("/")
        self.assertEqual(respuesta_raiz.status_code, 200)
        self.assertEqual(
            respuesta_raiz.json(), {"status": "ok", "message": "Backend funcionando"}
        )

        respuesta_salud = self.cliente.get("/health")
        self.assertEqual(respuesta_salud.status_code, 200)
        self.assertEqual(respuesta_salud.json(), {"status": "healthy"})

        documentacion = self.cliente.get("/docs")
        self.assertEqual(documentacion.status_code, 200)
        self.assertIn("Swagger UI", documentacion.text)

        esquema = self.cliente.get("/openapi.json")
        self.assertEqual(esquema.status_code, 200)
        rutas = esquema.json()["paths"]
        self.assertEqual(rutas["/"]["get"]["operationId"], "read_root__get")
        self.assertEqual(rutas["/health"]["get"]["operationId"], "health_check_health_get")
        nuevo_contrato = esquema.json()["components"]["schemas"]["RespuestaEstado"]
        self.assertEqual(
            {nombre: campo["type"] for nombre, campo in nuevo_contrato["properties"].items()},
            {"postgresReady": "boolean", "ollamaReady": "boolean", "zeroEgress": "boolean"},
        )
        self.assertIn("/api/v1/health", rutas)

    def test_reporta_los_servicios_y_el_egreso_por_separado(self):
        casos = (
            (True, True, False),
            (True, False, True),
            (False, True, False),
            (False, False, True),
        )
        entorno = {
            "DATABASE_URL": "postgresql://aegis_app@postgres:5432/aegishealth",
            "OLLAMA_BASE_URL": "http://ollama:11434",
        }

        for postgres, ollama, sin_egreso in casos:
            with (
                self.subTest(postgres=postgres, ollama=ollama, sin_egreso=sin_egreso),
                patch.dict(os.environ, entorno),
                patch("app.core.estado_postgres.psycopg.connect") as conectar_postgres,
                patch("app.llm.estado_ollama.HTTPConnection") as conectar_ollama,
                patch("app.servicios.estado.create_connection") as conectar_tcp,
            ):
                conexion_postgres = conectar_postgres.return_value.__enter__.return_value
                conexion_postgres.execute.return_value.fetchone.return_value = (1,)
                if not postgres:
                    conectar_postgres.side_effect = psycopg.OperationalError("Servicio caído")

                conexion_ollama = conectar_ollama.return_value
                catalogo = conexion_ollama.getresponse.return_value.__enter__.return_value
                catalogo.status = 200
                catalogo.read.return_value = b'{"models": []}'
                if not ollama:
                    conexion_ollama.request.side_effect = ConnectionRefusedError()

                if sin_egreso:
                    conectar_tcp.side_effect = TimeoutError()

                respuesta = self.cliente.get("/api/v1/health")

                self.assertEqual(respuesta.status_code, 200)
                self.assertEqual(
                    respuesta.json(),
                    {"postgresReady": postgres, "ollamaReady": ollama, "zeroEgress": sin_egreso},
                )
                if postgres:
                    conexion_postgres.execute.assert_called_once_with("SELECT 1")
                conexion_ollama.request.assert_called_once_with("GET", "/api/tags")
                conectar_tcp.assert_called_once_with(("1.1.1.1", 443), timeout=1.0)

    def test_sin_configuracion_omite_las_conexiones_a_servicios(self):
        with (
            patch.dict(os.environ, {"DATABASE_URL": "", "OLLAMA_BASE_URL": ""}),
            patch("app.core.estado_postgres.psycopg.connect") as conectar_postgres,
            patch("app.llm.estado_ollama.HTTPConnection") as conectar_ollama,
            patch("app.servicios.estado.create_connection", side_effect=ConnectionRefusedError),
        ):
            respuesta = self.cliente.get("/api/v1/health")

        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(
            respuesta.json(), {"postgresReady": False, "ollamaReady": False, "zeroEgress": True}
        )
        conectar_postgres.assert_not_called()
        conectar_ollama.assert_not_called()
