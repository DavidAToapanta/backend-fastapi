import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.servicios.exportaciones import carpeta_exportaciones


def test_resuelve_montaje_host_y_prioriza_directorio_runtime():
    raiz = Path(__file__).resolve().parents[1]
    with (
        patch.dict(os.environ, {}, clear=True),
        patch("app.core.configuracion_servicios._entorno_local", {"METRICAS_ML_DIR_HOST": "../datos-rol2"}),
    ):
        assert carpeta_exportaciones().resolve() == raiz / "datos-rol2"
        with patch.dict(os.environ, {"METRICAS_ML_DIR": "data/pruebas"}):
            assert carpeta_exportaciones() == raiz / "data" / "pruebas"


class PruebasExportaciones(unittest.TestCase):
    def setUp(self):
        self.cliente = self.enterContext(TestClient(app))
        self.carpeta = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.dict(os.environ, {"METRICAS_ML_DIR": str(self.carpeta)}))
        self.sigma = self.carpeta / "sigma"
        self.sigma.mkdir()
        self.archivo_stix = self.carpeta / "aegishealth_stix21_bundle.json"

    def test_sigma_sirve_archivos_completos_en_sus_grupos(self):
        ioa = "title: Señal base\n---\ntitle: Correlación de ejemplo\n"
        ioc = "title: Indicador ficticio\n"
        (self.sigma / "ioa_01.yml").write_text(ioa, encoding="utf-8", newline="\n")
        (self.sigma / "ioc_01.yaml").write_text(ioc, encoding="utf-8", newline="\n")
        (self.sigma / "otro.yml").write_text("fuera de los grupos", encoding="utf-8")

        respuesta = self.cliente.get("/api/v1/exports/sigma")

        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(respuesta.json(), {
            "ioa": [{"filename": "ioa_01.yml", "title": "Correlación de ejemplo", "yaml": ioa}],
            "ioc": [{"filename": "ioc_01.yaml", "title": "Indicador ficticio", "yaml": ioc}],
        })

    def test_sigma_devuelve_503_si_hay_yaml_invalido_o_falta_un_grupo(self):
        ioa = self.sigma / "ioa_01.yml"
        ioa.write_text("title: Señal base", encoding="utf-8")

        faltante = self.cliente.get("/api/v1/exports/sigma")
        (self.sigma / "ioc_01.yml").write_text("title: [", encoding="utf-8")
        invalido = self.cliente.get("/api/v1/exports/sigma")

        self.assertEqual(faltante.status_code, 503)
        self.assertEqual(invalido.status_code, 503)

    def test_stix_descarga_los_bytes_del_paquete_etiquetado(self):
        datos = {
            "type": "bundle",
            "objects": [{
                "type": "indicator",
                "spec_version": "2.1",
                "labels": ["synthetic-exercise-data", "hackathon-simulation"],
            }],
        }
        contenido = json.dumps(datos, indent=2).encode("utf-8")
        self.archivo_stix.write_bytes(contenido)

        respuesta = self.cliente.get("/api/v1/exports/stix")

        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(respuesta.headers["content-type"], "application/stix+json; version=2.1")
        self.assertEqual(
            respuesta.headers["content-disposition"],
            'attachment; filename="aegishealth_stix21_bundle.json"',
        )
        self.assertEqual(respuesta.content, contenido)

    def test_stix_devuelve_503_si_falta_el_archivo_o_las_etiquetas(self):
        faltante = self.cliente.get("/api/v1/exports/stix")
        self.archivo_stix.write_text(
            '{"type":"bundle","objects":[{"type":"indicator","spec_version":"2.1","labels":[]}]}',
            encoding="utf-8",
        )
        sin_etiquetas = self.cliente.get("/api/v1/exports/stix")

        self.assertEqual(faltante.status_code, 503)
        self.assertEqual(sin_etiquetas.status_code, 503)
