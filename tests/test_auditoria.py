import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import psycopg
from fastapi.testclient import TestClient

from app.main import app
from backend.app.core.security import calcular_hash_encadenado


class PruebasAuditoria(unittest.TestCase):
    def setUp(self):
        self.cliente = self.enterContext(TestClient(app))
        self.conectar = self.enterContext(patch("app.servicios.auditoria.conectar_postgres"))
        conexion = self.conectar.return_value.__enter__.return_value
        self.cursor = conexion.cursor.return_value.__enter__.return_value

    def test_lista_los_campos_publicos_de_mas_reciente_a_mas_antiguo(self):
        fecha = datetime(2026, 10, 24, 22, 40, tzinfo=timezone.utc)
        fila = {
            "identificador": 2,
            "fecha_ejecucion": fecha,
            "operacion": "INGEST_FIREWALL_10M",
            "nombre_dataset": r"C:\trabajo\firewall.csv",
            "sha256_dataset": "a" * 64,
            "filas_leidas": 20,
            "filas_guardadas": 8,
            "pii_depurada": True,
            "hash_registro": "b" * 64,
            "metadata": {"motivo": "interno"},
            "prev_hash": "interno",
        }
        self.cursor.execute.return_value.fetchall.return_value = [fila, {**fila, "identificador": 1}]

        respuesta = self.cliente.get("/api/v1/audit/events")

        self.assertEqual(respuesta.status_code, 200)
        eventos = respuesta.json()["events"]
        self.assertEqual([evento["auditId"] for evento in eventos], [2, 1])
        self.assertEqual(eventos[0], {
            "auditId": 2,
            "executedAt": "2026-10-24T22:40:00Z",
            "operation": "INGEST_FIREWALL_10M",
            "datasetName": "firewall.csv",
            "datasetSha256": "a" * 64,
            "totalRowsRead": 20,
            "rowsPersisted": 8,
            "piiScrubbed": True,
            "rowHash": "b" * 64,
        })
        consulta = self.cursor.execute.call_args.args[0]
        self.assertIn("ORDER BY audit_id DESC", consulta)
        self.assertNotIn("metadata", consulta)

    def test_verifica_la_cadena_y_detecta_un_cambio_simulado(self):
        carga = {
            "operation": "INGEST_FIREWALL_10M",
            "dataset_name": "firewall.csv",
            "dataset_sha256": "a" * 64,
            "total_rows_read": 20,
            "rows_persisted": 8,
            "pii_scrubbed": True,
            "metadata": {"baseline_rows": 8},
        }
        hash_registro = calcular_hash_encadenado("GENESIS", carga)
        fila = (1, *carga.values(), "GENESIS", hash_registro)
        fila_alterada = (1, fila[1], "archivo-alterado.csv", *fila[3:])
        self.cursor.fetchall.side_effect = [[fila], [fila_alterada]]

        integra = self.cliente.get("/api/v1/audit/verify-chain")
        alterada = self.cliente.get("/api/v1/audit/verify-chain")

        self.assertEqual(integra.status_code, 200)
        self.assertEqual(integra.json(), {"intact": True, "checkedRows": 1})
        self.assertEqual(alterada.status_code, 200)
        self.assertEqual(alterada.json(), {"intact": False, "checkedRows": 1})

    def test_postgres_caido_devuelve_503_en_ambas_rutas(self):
        self.conectar.side_effect = psycopg.OperationalError("detalle interno")
        for ruta in ("/api/v1/audit/events", "/api/v1/audit/verify-chain"):
            with self.subTest(ruta=ruta):
                respuesta = self.cliente.get(ruta)
                self.assertEqual(respuesta.status_code, 503)
                self.assertEqual(respuesta.json(), {"detail": "La bitácora de auditoría no está disponible."})
