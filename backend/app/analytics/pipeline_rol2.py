"""
Corre TODO el trabajo del Rol 2 con un solo comando:
  0. Calidad y contrato de datos            -> calidad_datos.json
  1. Detector ML (Isolation Forest)         -> ml_metrics_*.json, ranking_*.csv
  2. Motor de reglas IoA / IoC              -> hallazgos_reglas.json
  3. Campañas, MITRE ATT&CK y escenarios    -> campanas.json
  4. Reglas Sigma                           -> sigma/*.yml
  5. Paquete STIX 2.1 para MISP             -> aegishealth_stix21_bundle.json
  6. Anticipación (riesgo previo, alerta
     temprana y siguiente fase)             -> anticipacion.json, riesgo_cuentas.csv, alertas_tempranas.csv

Uso (desde la carpeta raíz del proyecto):
  python -m backend.app.analytics.pipeline_rol2 --fw data/processed/fw_seudonimizado.parquet \
      --med data/processed/med_seudonimizado.parquet --salida data/exports_10m [--config config_rol2.json]
"""
import argparse
import json
import time
from pathlib import Path

from . import anticipacion, calidad_datos, mitre_mapper, ml_detector, rules_engine
from .carga import cargar_firewall, cargar_sistema_medico
from ..cti_exports import sigma_generator, stix_exporter


def titulo(texto):
    print("=" * 64 + f"\n{texto}\n" + "=" * 64)


def main():
    p = argparse.ArgumentParser(description="Pipeline completo del Rol 2")
    p.add_argument("--fw", required=True)
    p.add_argument("--med", required=True)
    p.add_argument("--salida", default="data/exports")
    p.add_argument("--config", default=None, help="JSON opcional para ajustar umbrales sin tocar el código")
    a = p.parse_args()
    inicio = time.time()
    salida = Path(a.salida)
    salida.mkdir(parents=True, exist_ok=True)

    if a.config:  # ajustes para datos reales distintos
        cfg = json.loads(Path(a.config).read_text(encoding="utf-8"))
        rules_engine.UMBRALES.update(cfg.get("umbrales_reglas", {}))
        anticipacion.PARAMS.update(cfg.get("anticipacion", {}))
        print(f"Configuración aplicada desde {a.config}")

    titulo("PASO 0/6 · Calidad y contrato de datos")
    fw, med = cargar_firewall(a.fw), cargar_sistema_medico(a.med)
    calidad = calidad_datos.reporte(fw, med)
    (salida / "calidad_datos.json").write_text(json.dumps(calidad, indent=2, ensure_ascii=False), encoding="utf-8")
    for n in ("firewall", "sistema_medico"):
        c = calidad[n]
        print(f"{n}: {c['filas']:,} filas | calidad {c['puntaje_calidad']}% | duplicados {c['duplicados_exactos']:,} "
              f"| IPs inválidas {c['ips_invalidas_tras_reparacion']} | valores nuevos {c['valores_nuevos_no_esperados'] or 'ninguno'}")
    for adv in calidad["advertencias"]:
        print("ADVERTENCIA:", adv)
    del fw, med

    titulo("PASO 1/6 · Detector ML sin reglas")
    ml_detector.ejecutar(a.fw, a.med, a.salida)
    titulo("PASO 2/6 · Motor de reglas IoA / IoC")
    rules_engine.ejecutar(a.fw, a.med, a.salida)
    titulo("PASO 3/6 · Campañas, MITRE ATT&CK y escenarios IPE")
    mitre_mapper.ejecutar(a.salida)
    titulo("PASO 4/6 · Reglas Sigma")
    archivos = sigma_generator.generar_reglas_sigma(str(salida / "sigma"))
    print(f"{len(archivos)} reglas Sigma generadas y validadas")
    titulo("PASO 5/6 · Paquete STIX 2.1")
    stix_exporter.exportar_bundle_stix(a.salida)
    titulo("PASO 6/6 · Anticipación de amenazas")
    anticipacion.ejecutar(cargar_firewall(a.fw), cargar_sistema_medico(a.med), a.salida)

    print(f"\nLISTO en {time.time() - inicio:.0f} s. Todo quedó en {salida.resolve()}")


if __name__ == "__main__":
    main()
