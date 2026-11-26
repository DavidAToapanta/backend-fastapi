import json
import os
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

import psycopg
from fastapi.testclient import TestClient

from app.main import app


class PruebasResumenPanel(unittest.TestCase):
    def setUp(self):
        self.cliente = self.enterContext(TestClient(app))
        self.carpeta = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.dict(os.environ, {"METRICAS_ML_DIR": str(self.carpeta)}))
        self.conectar = self.enterContext(patch("app.servicios.panel.conectar_postgres"))
        self.consulta = self.conectar.return_value.__enter__.return_value.execute

    def test_expone_los_agregados_y_las_metricas_permitidas(self):
        self.consulta.return_value.fetchall.return_value = [
            (None, 16, 5, 3, None),
            ("FIREWALL", 9, 2, 2, True),
            ("MEDSYS", 7, 3, 2, True),
        ]
        metricas = {
            "incidentes_en_top_n": "4/5",
            "top_n_evaluado": 50,
            "anomalias_no_confirmadas_en_top_n": {"fw_hora": 1, "med_hora": 2, "med_periodo": 3},
            "detalle_interno": "Este campo se omite",
        }
        (self.carpeta / "ml_metrics_A_genericas.json").write_text(json.dumps(metricas), encoding="utf-8")
        (self.carpeta / "ml_metrics_B_dominio.json").write_text("archivo dañado", encoding="utf-8")

        respuesta = self.cliente.get("/api/v1/dashboard/summary")

        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(respuesta.json(), {
            "totalEvents": 16,
            "malformedIpEvents": 5,
            "hoursCovered": 3,
            "bySource": [
                {"source": "FIREWALL", "events": 9, "malformedIpEvents": 2},
                {"source": "MEDSYS", "events": 7, "malformedIpEvents": 3},
            ],
            "pseudonymizationRecorded": True,
            "ml": {
                "generic": {
                    "incidentsInTopN": "4/5",
                    "topN": 50,
                    "unconfirmedAnomalies": {"firewallHourly": 1, "medsysHourly": 2, "medsysByPeriod": 3},
                },
                "domain": None,
            },
        })

    def test_fuente_ausente_no_afirma_seudonimizacion(self):
        self.consulta.return_value.fetchall.return_value = [
            (None, 9, 2, 2, None),
            ("FIREWALL", 9, 2, 2, True),
        ]

        respuesta = self.cliente.get("/api/v1/dashboard/summary")

        self.assertEqual(respuesta.status_code, 200)
        datos = respuesta.json()
        self.assertIsNone(datos["pseudonymizationRecorded"])
        self.assertEqual(datos["bySource"][1], {"source": "MEDSYS", "events": 0, "malformedIpEvents": 0})
        self.assertEqual(datos["ml"], {"generic": None, "domain": None})

    def test_base_caida_devuelve_503_sin_detalles_de_conexion(self):
        self.conectar.side_effect = psycopg.OperationalError("Detalle interno")

        respuesta = self.cliente.get("/api/v1/dashboard/summary")

        self.assertEqual(respuesta.status_code, 503)
        self.assertEqual(respuesta.json(), {"detail": "Los datos del panel no están disponibles."})

    def test_mapa_horario_ordena_dias_y_completa_horas_sin_eventos(self):
        self.consulta.return_value.fetchall.return_value = [
            (date(2026, 10, 1), 1, 7),
            (date(2026, 10, 1), 23, 2),
            (date(2026, 10, 3), 0, 5),
        ]

        respuesta = self.cliente.get("/api/v1/analytics/hourly-heatmap")

        self.assertEqual(respuesta.status_code, 200)
        mapa = respuesta.json()
        self.assertEqual(mapa["timezone"], "UTC")
        self.assertEqual(mapa["days"], ["2026-10-01", "2026-10-02", "2026-10-03"])
        self.assertEqual(mapa["hours"], list(range(24)))
        self.assertEqual(len(mapa["matrix"]), 24)
        self.assertEqual(mapa["matrix"][0], [0, 0, 5])
        self.assertEqual(mapa["matrix"][1], [7, 0, 0])
        self.assertEqual(mapa["matrix"][23], [2, 0, 0])
        self.assertEqual(sum(map(sum, mapa["matrix"])), 14)

    def test_mapa_horario_sin_datos_devuelve_ejes_vacios_por_dia(self):
        self.consulta.return_value.fetchall.return_value = []

        respuesta = self.cliente.get("/api/v1/analytics/hourly-heatmap")

        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(respuesta.json(), {
            "timezone": "UTC", "days": [], "hours": list(range(24)), "matrix": [[] for _ in range(24)],
        })

    def test_mapa_horario_devuelve_503_si_falla_la_consulta(self):
        self.consulta.side_effect = psycopg.OperationalError("Detalle interno")

        respuesta = self.cliente.get("/api/v1/analytics/hourly-heatmap")

        self.assertEqual(respuesta.status_code, 503)
        self.assertEqual(respuesta.json(), {"detail": "Los datos del mapa horario no están disponibles."})
