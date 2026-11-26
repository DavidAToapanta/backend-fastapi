"""
Corre TODO el trabajo del Rol 2 con un solo comando:
  1. Detector ML (Isolation Forest)      -> ml_metrics_*.json, ranking_*.csv
  2. Motor de reglas IoA / IoC           -> hallazgos_reglas.json
  3. Campañas, MITRE ATT&CK y escenarios -> campanas.json
  4. Reglas Sigma                        -> sigma/*.yml
  5. Paquete STIX 2.1 para MISP          -> aegishealth_stix21_bundle.json

Uso (desde la carpeta raíz del proyecto):
  python -m backend.app.analytics.pipeline_rol2 --fw data/processed/sample_fw_200k.parquet \
      --med data/processed/sample_med_200k.parquet --salida data/exports
"""
import argparse
from pathlib import Path

from . import mitre_mapper, ml_detector, rules_engine
from ..cti_exports import sigma_generator, stix_exporter


def main():
    p = argparse.ArgumentParser(description="Pipeline completo del Rol 2")
    p.add_argument("--fw", required=True)
    p.add_argument("--med", required=True)
    p.add_argument("--salida", default="data/exports")
    a = p.parse_args()

    print("=" * 60, "\nPASO 1/5 · Detector ML sin reglas\n" + "=" * 60)
    ml_detector.ejecutar(a.fw, a.med, a.salida)
    print("=" * 60, "\nPASO 2/5 · Motor de reglas IoA / IoC\n" + "=" * 60)
    rules_engine.ejecutar(a.fw, a.med, a.salida)
    print("=" * 60, "\nPASO 3/5 · Campañas, MITRE ATT&CK y escenarios IPE\n" + "=" * 60)
    mitre_mapper.ejecutar(a.salida)
    print("=" * 60, "\nPASO 4/5 · Reglas Sigma\n" + "=" * 60)
    archivos = sigma_generator.generar_reglas_sigma(str(Path(a.salida) / "sigma"))
    print(f"{len(archivos)} reglas Sigma generadas y validadas")
    print("=" * 60, "\nPASO 5/5 · Paquete STIX 2.1\n" + "=" * 60)
    stix_exporter.exportar_bundle_stix(a.salida)
    print("\nLISTO. Todo quedó en", Path(a.salida).resolve())


if __name__ == "__main__":
    main()
