"""
Generador de reglas Sigma (Rol 2).

Sigma es un formato abierto de reglas de detección: el SIEM del IESS puede convertirlas
a su propio lenguaje (Splunk, Elastic, QRadar...). Generamos dos grupos:
  - IoA (comportamiento, sirven para cualquier atacante)
  - IoC (indicadores concretos de este caso, para contención inmediata)

Las reglas con umbral ("100 eventos en 1 hora") usan el formato de CORRELACIÓN de
Sigma: un archivo con 2 documentos YAML (regla base + regla de correlación).

Uso:
  python -m backend.app.cti_exports.sigma_generator --salida data/exports/sigma
"""
import argparse
import json
import uuid
from datetime import date
from pathlib import Path

import yaml

from ..analytics.rules_engine import PUERTOS_CRITICOS, UMBRALES

AUTOR = "Equipo AegisHealth-CTI (Hackatón IESS 2026)"
HOY = date.today().strftime("%Y-%m-%d")
FW = {"product": "aegishealth", "category": "firewall"}
MED = {"product": "aegishealth", "service": "sistema_medico"}
REDES_PRIVADAS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
ACCIONES_ADMIN = ["USUARIOS - Activar usuario", "Reactivacion de usuarios",
                  "Inactivacion de usuarios", "USUARIOS - Actualizar nivel de Usuario"]
ETIQUETA_SINTETICA = "Dato sintético de ejercicio (Hackatón IESS 2026). No usar como inteligencia real."


def _id(nombre: str) -> str:
    """Identificador estable: la misma regla siempre tiene el mismo id."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"aegishealth-cti/sigma/{nombre}"))


def _base(nombre, titulo, descripcion, logsource, deteccion, nivel, tags, falsos_positivos):
    return {
        "title": titulo, "id": _id(nombre), "name": nombre, "status": "experimental",
        "description": descripcion, "author": AUTOR, "date": HOY, "tags": tags,
        "logsource": logsource, "detection": deteccion,
        "falsepositives": falsos_positivos, "level": nivel,
    }


def _correlacion(nombre, titulo, descripcion, base, tipo, agrupar, ventana, condicion, nivel, tags):
    return {
        "title": titulo, "id": _id(nombre), "name": nombre, "status": "experimental",
        "description": descripcion, "author": AUTOR, "date": HOY, "tags": tags,
        "correlation": {"type": tipo, "rules": [base], "group-by": agrupar,
                        "timespan": ventana, "condition": condicion},
        "level": nivel,
    }


def definir_reglas(iocs: dict) -> dict[str, list[dict]]:
    u = UMBRALES
    r = {}

    r["ioa_01_exfiltracion_egreso_no_rfc1918.yml"] = [_base(
        "aegis_ioa01_egreso_externo", "Conexión permitida hacia IP pública desde la red interna",
        "Salida de tráfico permitida hacia una IP fuera de las redes privadas RFC1918. Un servidor "
        "clínico no debería comunicarse directo con internet.",
        FW, {"seleccion": {"action": "permitido"}, "filtro_privadas": {"dst_ip|cidr": REDES_PRIVADAS},
             "condition": "seleccion and not filtro_privadas"},
        "high", ["attack.exfiltration", "attack.t1048.002"],
        ["Actualizaciones de software o servicios en la nube autorizados (revisar lista blanca)"])]

    r["ioa_02_rafaga_transferencias_ssh.yml"] = [
        _base("aegis_ioa02_transferencia_cortada", "Transferencia interrumpida en el sistema médico (base)",
              "Evento base: transferencia interrumpida. El texto original viene sin la S (TRANFERENCIA).",
              MED, {"seleccion": {"action_desc": "TRANFERENCIA INTERRUMPIDA"}, "condition": "seleccion"},
              "low", ["attack.collection", "attack.t1213"], ["Cortes de red"]),
        _correlacion("aegis_ioa02_rafaga_transferencias", "Ráfaga de transferencias interrumpidas por cuenta",
                     f"{u['interrumpidas_cuenta_hora']} o más transferencias interrumpidas de una misma cuenta "
                     "en 1 hora: posible extracción automatizada.",
                     "aegis_ioa02_transferencia_cortada", "event_count", ["account_token"], "1h",
                     {"gte": u["interrumpidas_cuenta_hora"]}, "high",
                     ["attack.collection", "attack.t1213", "attack.t1074"]),
    ]

    r["ioa_03_fuerza_bruta_telnet_umbral.yml"] = [
        _base("aegis_ioa03_conexion_negada", "Conexión negada en el firewall (base)",
              "Evento base: conexión negada por el firewall.", FW,
              {"seleccion": {"action": "negado"}, "condition": "seleccion"}, "low",
              ["attack.credential-access"], ["Equipos mal configurados"]),
        _correlacion("aegis_ioa03_rafaga_negadas", "Ráfaga de conexiones negadas al mismo puerto",
                     f"{u['negados_mismo_puerto_hora']} o más conexiones negadas desde la misma IP al mismo "
                     "puerto en 1 hora (ejemplo observado: Telnet 23/tcp).",
                     "aegis_ioa03_conexion_negada", "event_count", ["src_ip", "dst_port"], "1h",
                     {"gte": u["negados_mismo_puerto_hora"]}, "high",
                     ["attack.credential-access", "attack.t1110.001"]),
    ]

    r["ioa_04_escaneo_multiservicio_4puertos.yml"] = [
        _base("aegis_ioa04_negada_puerto_critico", "Conexión negada a servicio crítico (base)",
              "Evento base: conexión negada a un puerto de administración remota o base de datos.", FW,
              {"seleccion": {"action": "negado", "dst_port": PUERTOS_CRITICOS}, "condition": "seleccion"},
              "low", ["attack.discovery"], ["Inventarios de red autorizados"]),
        _correlacion("aegis_ioa04_escaneo_multiservicio", "Escaneo de varios servicios críticos",
                     f"Una misma IP intenta {u['puertos_criticos_distintos_hora']} o más servicios críticos "
                     "distintos en 1 hora.",
                     "aegis_ioa04_negada_puerto_critico", "value_count", ["src_ip"], "1h",
                     {"field": "dst_port", "gte": u["puertos_criticos_distintos_hora"]}, "high",
                     ["attack.discovery", "attack.t1046"]),
    ]

    r["ioa_05_abuso_privilegios.yml"] = [
        _base("aegis_ioa05_operacion_admin", "Operación de administración de usuarios (base)",
              "Evento base: activar, reactivar, inactivar o cambiar el nivel de un usuario.", MED,
              {"seleccion": {"action_desc": ACCIONES_ADMIN}, "condition": "seleccion"}, "low",
              ["attack.persistence"], ["Mesa de ayuda en jornadas de alta de personal"]),
        _correlacion("aegis_ioa05_abuso_privilegios", "Volumen anómalo de administración de usuarios por cuenta",
                     f"{u['minimo_operaciones_admin']} o más operaciones de administración de usuarios de una "
                     "misma cuenta en 1 día.",
                     "aegis_ioa05_operacion_admin", "event_count", ["account_token"], "1d",
                     {"gte": u["minimo_operaciones_admin"]}, "high",
                     ["attack.persistence", "attack.t1098", "attack.impact", "attack.t1531"]),
    ]

    r["ioa_06_cuenta_compartida.yml"] = [
        _base("aegis_ioa06_actividad_cuenta", "Actividad de una cuenta del sistema médico (base)",
              "Evento base: cualquier acción registrada por una cuenta.", MED,
              {"seleccion": {"account_token|exists": True}, "condition": "seleccion"}, "low",
              ["attack.defense-evasion"], ["Ninguno"]),
        _correlacion("aegis_ioa06_cuenta_compartida", "Cuenta usada por varias identidades",
                     f"Una misma cuenta usada por {u['identidades_por_cuenta']} o más identidades distintas "
                     "(lo normal es 1 persona por cuenta).",
                     "aegis_ioa06_actividad_cuenta", "value_count", ["account_token"], "30d",
                     {"field": "actor_token", "gte": u["identidades_por_cuenta"]}, "high",
                     ["attack.defense-evasion", "attack.t1078"]),
    ]

    r["ioa_07_ip_malformada.yml"] = [_base(
        "aegis_ioa07_ip_malformada", "Registro con IP escrita sin puntos",
        "IP de conexión con formato anómalo (11 dígitos sin puntos). Posible manipulación de registros o "
        "evasión de herramientas que validan IPs. Requiere análisis.", MED,
        {"seleccion": {"conn_ip_raw|re": r"^10\d{9}$"}, "condition": "seleccion"},
        "medium", ["attack.defense-evasion"], ["Errores de integración entre sistemas"])]

    r["ioa_08_sesiones_ssh_masivas.yml"] = [
        _base("aegis_ioa08_ssh", "Conexión SSH (base)", "Evento base: conexión SSH.", FW,
              {"seleccion_puerto": {"dst_port": 22}, "seleccion_protocolo": {"protocol": "SSH"},
               "condition": "seleccion_puerto or seleccion_protocolo"}, "low",
              ["attack.lateral-movement"], ["Administradores de servidores"]),
        _correlacion("aegis_ioa08_ssh_masivo", "Sesiones SSH masivas desde una misma máquina",
                     f"{u['ssh_misma_ip_hora']} o más conexiones SSH desde la misma IP en 1 hora.",
                     "aegis_ioa08_ssh", "event_count", ["src_ip"], "1h",
                     {"gte": u["ssh_misma_ip_hora"]}, "high",
                     ["attack.lateral-movement", "attack.t1021.004"]),
    ]

    # ---- IoC: contención inmediata (datos sintéticos)
    r["ioc_01_bloqueo_destino_sintetico_8443.yml"] = [_base(
        "aegis_ioc01_destino_externo", "Conexión a IP externa del caso (IoC sintético)",
        f"{ETIQUETA_SINTETICA} Conexión hacia la IP externa observada en la exfiltración.", FW,
        {"seleccion": {"dst_ip": iocs["ips_destino_externas"], "dst_port": iocs["puertos_canal_sombra"]},
         "condition": "seleccion"},
        "critical", ["attack.exfiltration", "attack.t1048.002"], ["Ninguno conocido"])]

    r["ioc_02_monitoreo_origenes_subred_critica.yml"] = [_base(
        "aegis_ioc02_origenes_vigilados", "Actividad de equipos vigilados hacia el servidor médico (IoC sintético)",
        f"{ETIQUETA_SINTETICA} Equipos internos que originaron los incidentes.", FW,
        {"seleccion": {"src_ip": iocs["ips_origen_vigiladas"], "dst_ip": iocs["servidor_critico"]},
         "condition": "seleccion"},
        "high", ["attack.lateral-movement"], ["Uso legítimo de esos equipos tras su saneamiento"])]
    return r


def generar_reglas_sigma(carpeta_salida: str, ruta_iocs: str | None = None) -> list[str]:
    iocs_path = Path(ruta_iocs) if ruta_iocs else Path(__file__).parents[1] / "analytics" / "iocs_ejercicio.json"
    iocs = json.loads(iocs_path.read_text(encoding="utf-8"))
    carpeta = Path(carpeta_salida)
    carpeta.mkdir(parents=True, exist_ok=True)
    escritos = []
    for archivo, documentos in definir_reglas(iocs).items():
        texto = "\n---\n".join(yaml.safe_dump(d, allow_unicode=True, sort_keys=False) for d in documentos)
        ruta = carpeta / archivo
        ruta.write_text(texto, encoding="utf-8")
        list(yaml.safe_load_all(ruta.read_text(encoding="utf-8")))  # validación: el YAML se puede leer
        escritos.append(str(ruta))
    return escritos


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Generador de reglas Sigma (Rol 2)")
    p.add_argument("--salida", default="data/exports/sigma")
    p.add_argument("--iocs", default=None)
    a = p.parse_args()
    archivos = generar_reglas_sigma(a.salida, a.iocs)
    print(f"{len(archivos)} reglas Sigma generadas y validadas (YAML) en {Path(a.salida).resolve()}")
    for f in archivos:
        print("  ", Path(f).name)
