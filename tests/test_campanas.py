import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import psycopg
from fastapi.testclient import TestClient

from app.main import app


class PruebasCampanas(unittest.TestCase):
    def setUp(self):
        self.cliente = self.enterContext(TestClient(app))
        self.carpeta = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.dict(os.environ, {"METRICAS_ML_DIR": str(self.carpeta)}))
        self.conectar = self.enterContext(patch("app.servicios.campanas.conectar_postgres"))
        conexion = self.conectar.return_value.__enter__.return_value
        self.consulta = conexion.cursor.return_value.__enter__.return_value.execute
        self.consulta.return_value.fetchall.return_value = [{
            "codigo": "CAMP-2026-001",
            "titulo": "Campaña del ejercicio",
            "tipo_adversario": "HYBRID",
            "severidad": "CRITICAL",
            "calificacion_admiralty": "B2",
            "eventos": 4,
            "primera_observacion": datetime(2026, 10, 1, tzinfo=timezone.utc),
            "ultima_observacion": None,
            "tecnicas_mitre": ["T1213"],
            "iocs": {
                "ports": [443],
                "dst_ips": ["192.0.2.1"],
                "actor_tokens": ["USR-0123456789AB", "Nombre sin enmascarar"],
                "account_tokens": ["ACC-A1B2C3D4E5F6", "cuenta-interna-ejemplo"],
                "cuenta_original": "se-omite",
            },
            "ioas": ["Accesos repetidos en la simulación"],
        }]

    def test_lista_campanas_con_puntaje_ml_y_tokens_enmascarados(self):
        contenido = {"campaigns": [{"campaign_code": "CAMP-2026-001", "anomaly_score": 0.75}]}
        (self.carpeta / "campanas.json").write_text(json.dumps(contenido), encoding="utf-8")

        respuesta = self.cliente.get("/api/v1/campaigns")

        self.assertEqual(respuesta.status_code, 200)
        datos = respuesta.json()
        campana = datos["campaigns"][0]
        self.assertEqual(campana["campaignCode"], "CAMP-2026-001")
        self.assertEqual(campana["admiraltyRating"], "B2")
        self.assertEqual(campana["anomalyScore"], 0.75)
        self.assertEqual(campana["mitreTechniques"], ["T1213"])
        self.assertEqual(campana["iocs"], {
            "ports": [443],
            "sourceIps": [],
            "destinationIps": ["192.0.2.1"],
            "actorTokens": ["USR-0123456789AB"],
            "accountTokens": ["ACC-A1B2C3D4E5F6"],
        })
        self.assertEqual(campana["ioas"], ["Accesos repetidos en la simulación"])
        self.assertEqual(len(datos["ipeScenarios"]), 2)
        self.assertTrue(all("CAMP-2026-005" in escenario["campaignCodes"] for escenario in datos["ipeScenarios"]))

    def test_sin_archivo_ml_el_puntaje_queda_nulo(self):
        respuesta = self.cliente.get("/api/v1/campaigns")

        self.assertEqual(respuesta.status_code, 200)
        self.assertIsNone(respuesta.json()["campaigns"][0]["anomalyScore"])

    def test_base_caida_devuelve_503_sin_detalles_internos(self):
        self.conectar.side_effect = psycopg.OperationalError("Detalle interno")

        respuesta = self.cliente.get("/api/v1/campaigns")

        self.assertEqual(respuesta.status_code, 503)
        self.assertEqual(respuesta.json(), {"detail": "Las campañas no están disponibles."})

    def test_linea_tiempo_consulta_por_codigo_y_mantiene_tokens_enmascarados(self):
        self.consulta.return_value.fetchall.return_value = [{
            "id": 10,
            "fecha": datetime(2026, 10, 24, 22, 40, tzinfo=timezone.utc),
            "fuente": "MEDSYS",
            "actor": "actor-sin-enmascarar",
            "cuenta": "ACC-0123456789AB",
            "ip_origen": "192.0.2.1",
            "ip_destino": None,
            "puerto_destino": None,
            "resumen": "Evento del ejercicio",
            "ajuste_de_reloj": True,
        }]

        respuesta = self.cliente.get("/api/v1/campaigns/CAMP-2026-001/timeline")

        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(self.consulta.call_args.args[1], ("CAMP-2026-001",))
        self.assertEqual(respuesta.json(), {"campaignCode": "CAMP-2026-001", "events": [{
            "id": 10,
            "timestamp": "2026-10-24T22:40:00Z",
            "source": "MEDSYS",
            "actorToken": None,
            "accountToken": "ACC-0123456789AB",
            "sourceIp": "192.0.2.1",
            "destinationIp": None,
            "destinationPort": None,
            "summary": "Evento del ejercicio",
            "clockSkewAdjusted": True,
        }]})

    def test_linea_tiempo_distingue_campana_desconocida_de_campana_sin_eventos(self):
        self.consulta.return_value.fetchall.side_effect = [[], [{"id": None}]]

        desconocida = self.cliente.get("/api/v1/campaigns/CAMP-2026-999/timeline")
        sin_eventos = self.cliente.get("/api/v1/campaigns/CAMP-2026-001/timeline")

        self.assertEqual(desconocida.status_code, 404)
        self.assertEqual(sin_eventos.status_code, 200)
        self.assertEqual(sin_eventos.json(), {"campaignCode": "CAMP-2026-001", "events": []})

    def test_linea_tiempo_devuelve_503_si_la_base_esta_caida(self):
        self.conectar.side_effect = psycopg.OperationalError("Detalle interno")

        respuesta = self.cliente.get("/api/v1/campaigns/CAMP-2026-001/timeline")

        self.assertEqual(respuesta.status_code, 503)
        self.assertEqual(respuesta.json(), {"detail": "La línea de tiempo no está disponible."})
