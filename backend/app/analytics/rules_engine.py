"""
Motor de reglas del Rol 2 (AegisHealth-CTI).

Dos tipos de reglas, separadas a propósito:
  - IoA (Indicadores de Ataque): COMPORTAMIENTOS generales que sirven para cualquier
    atacante, aunque no lo conozcamos (por ejemplo: "100 conexiones negadas al mismo
    puerto en una hora").
  - IoC (Indicadores de Compromiso): HUELLAS concretas de este caso (una IP, una cuenta).
    Sirven para contener rápido, pero solo detectan lo que ya conocemos.

Cada hallazgo guarda las filas exactas que lo prueban (evidencia).

Uso (desde la carpeta raíz del proyecto):
  python -m backend.app.analytics.rules_engine --fw data/processed/sample_fw_200k.parquet \
      --med data/processed/sample_med_200k.parquet --salida data/exports
"""
import argparse
import ipaddress
import json
import time
from datetime import datetime
from pathlib import Path

import pandas as pd

from .carga import cargar_firewall, cargar_sistema_medico
from .ml_detector import (
    ACCION_DESCARGA, ACCION_FALLIDA, ACCION_TRANSF_CORTADA, ACCION_TRANSF_OK, ACCIONES_ADMIN,
)

# Umbrales de las reglas (en un solo lugar para poder explicarlos y ajustarlos)
UMBRALES = {
    "negados_mismo_puerto_hora": 100,       # IOA-01
    "puertos_criticos_distintos_hora": 4,   # IOA-02
    "fallidos_cuenta_hora": 50,             # IOA-03
    "interrumpidas_cuenta_hora": 50,        # IOA-04
    "segundos_ssh_antes_del_egreso": 600,   # IOA-05 (10 minutos)
    "tolerancia_correlacion_seg": 120,      # IOA-05 (cruce firewall <-> sistema médico)
    "identidades_por_cuenta": 3,            # IOA-06 (lo normal es 1 persona por cuenta)
    "ratio_admin_cuenta": 0.9,              # IOA-07
    "minimo_operaciones_admin": 100,        # IOA-07
    "ssh_misma_ip_hora": 10,                # IOA-09
}

# Puertos de administración remota y bases de datos (lista general de seguridad)
PUERTOS_CRITICOS = [22, 23, 135, 137, 139, 445, 1433, 1521, 3306, 3389, 5432, 5985, 5986, 8471]
DOCE_HORAS = pd.Timedelta(hours=12)  # desfase de reloj confirmado por Rol 1 en el sistema médico


# ----------------------------------------------------------------------------
# Utilidades
# ----------------------------------------------------------------------------
def _evidencia(filas: pd.DataFrame, dataset: str, maximo: int = 20) -> dict:
    """Referencia a las filas exactas que prueban un hallazgo."""
    columna = "event_id" if "event_id" in filas.columns else "fila_origen"
    return {
        "dataset": dataset,
        "archivo": filas.attrs.get("archivo"),
        "referencia": columna,
        "total_filas": int(len(filas)),
        "primeras_filas": [int(x) for x in filas[columna].head(maximo)],
    }


def _hallazgo(regla, tipo, nombre, descripcion, filas, dataset, entidades, conteo=None, severidad="ALTA", **extra):
    return {
        "regla": regla,
        "tipo": tipo,
        "nombre": nombre,
        "descripcion": descripcion,
        "severidad": severidad,
        "entidades": entidades,
        "inicio": str(filas["event_ts"].min()),
        "fin": str(filas["event_ts"].max()),
        "conteo": int(conteo if conteo is not None else len(filas)),
        "evidencia": _evidencia(filas, dataset),
        **extra,
    }


def _grupos_que_superan(df: pd.DataFrame, claves: list[str], minimo: int):
    """Devuelve solo las filas de los grupos con al menos `minimo` eventos (rápido con millones de filas)."""
    tam = df.groupby(claves).size()
    marcados = tam[tam >= minimo].reset_index()[claves]
    return df.merge(marcados, on=claves).groupby(claves)


def _es_externa(ip: str) -> bool:
    """True si la IP es pública (no RFC1918). Las IPs malformadas no cuentan como externas."""
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ----------------------------------------------------------------------------
# Reglas IoA (comportamiento)
# ----------------------------------------------------------------------------
def evaluar_reglas_ioa(fw: pd.DataFrame, med: pd.DataFrame) -> list[dict]:
    u = UMBRALES
    hallazgos = []
    fw = fw.assign(hora=fw["event_ts"].dt.floor("h"))
    med = med.assign(hora=med["event_ts"].dt.floor("h"))
    negados = fw[fw["action"].eq("negado")]

    # IOA-01: ráfaga de conexiones negadas al mismo puerto desde la misma máquina
    for (ip, puerto, hora), filas in _grupos_que_superan(negados, ["src_ip", "dst_port", "hora"], u["negados_mismo_puerto_hora"]):
        hallazgos.append(_hallazgo(
            "IOA-01", "IoA", "Ráfaga de conexiones negadas",
            f"{len(filas)} conexiones negadas al puerto {puerto} desde {ip} en una hora "
            f"(umbral {u['negados_mismo_puerto_hora']}).",
            filas, "firewall",
            {"src_ip": ip, "dst_port": int(puerto), "actor_token": sorted(filas["actor_token"].unique().tolist())},
        ))

    # IOA-02: escaneo de varios servicios críticos desde la misma máquina en una hora
    criticos = negados[negados["dst_port"].isin(PUERTOS_CRITICOS)]
    n_puertos = criticos.groupby(["src_ip", "hora"])["dst_port"].nunique()
    for (ip, hora) in n_puertos[n_puertos >= u["puertos_criticos_distintos_hora"]].index:
        filas = criticos[criticos["src_ip"].eq(ip) & criticos["hora"].eq(hora)]
        puertos = sorted(int(p) for p in filas["dst_port"].unique())
        hallazgos.append(_hallazgo(
            "IOA-02", "IoA", "Escaneo de servicios críticos",
            f"{ip} intentó {len(puertos)} servicios críticos distintos {puertos} en una hora.",
            filas, "firewall",
            {"src_ip": ip, "puertos": puertos, "actor_token": sorted(filas["actor_token"].unique().tolist())},
        ))

    # IOA-03: fuerza bruta contra una cuenta del sistema médico
    fallidos = med[med["action_desc"].eq(ACCION_FALLIDA)]
    for (cuenta, hora), filas in _grupos_que_superan(fallidos, ["account_token", "hora"], u["fallidos_cuenta_hora"]):
        hallazgos.append(_hallazgo(
            "IOA-03", "IoA", "Fuerza bruta contra una cuenta",
            f"{len(filas)} accesos fallidos a la cuenta {cuenta} en una hora (umbral {u['fallidos_cuenta_hora']}).",
            filas, "sistema_medico",
            {"account_token": cuenta, "actor_token": sorted(filas["actor_token"].unique().tolist())[:20]},
        ))

    # IOA-04: transferencias interrumpidas en masa (posible extracción automatizada)
    cortadas = med[med["action_desc"].eq(ACCION_TRANSF_CORTADA)]
    for (cuenta, hora), filas in _grupos_que_superan(cortadas, ["account_token", "hora"], u["interrumpidas_cuenta_hora"]):
        ok = med[med["account_token"].eq(cuenta) & med["hora"].eq(hora) & med["action_desc"].eq(ACCION_TRANSF_OK)]
        hallazgos.append(_hallazgo(
            "IOA-04", "IoA", "Transferencias masivas interrumpidas",
            f"{len(filas)} transferencias interrumpidas y {len(ok)} exitosas de la cuenta {cuenta} en una hora.",
            pd.concat([filas, ok]), "sistema_medico",
            {"account_token": cuenta, "actor_token": sorted(filas["actor_token"].unique().tolist())[:20]},
            transferencias_exitosas=int(len(ok)),
        ))

    # IOA-05: salida permitida hacia una IP pública + secuencia de exfiltración
    ips_destino = pd.Series(fw["dst_ip"].unique())
    externas = set(ips_destino[ips_destino.map(_es_externa)])
    egresos = fw[fw["action"].eq("permitido") & fw["dst_ip"].isin(externas)]
    for _, e in egresos.iterrows():
        desde = e["event_ts"] - pd.Timedelta(seconds=u["segundos_ssh_antes_del_egreso"])
        ssh_previo = fw[fw["src_ip"].eq(e["src_ip"]) & fw["dst_port"].eq(22) & fw["action"].eq("permitido")
                        & fw["event_ts"].between(desde, e["event_ts"])]
        tol = pd.Timedelta(seconds=u["tolerancia_correlacion_seg"])
        mismo_actor = med[med["actor_token"].eq(e["actor_token"])]
        cerca = (mismo_actor["event_ts"] - e["event_ts"]).abs() <= tol
        cerca_12h = (mismo_actor["event_ts"] + DOCE_HORAS - e["event_ts"]).abs() <= tol
        med_relacionado = mismo_actor[cerca | cerca_12h]
        secuencia = not ssh_previo.empty and not med_relacionado.empty
        filas_fw = pd.concat([ssh_previo, egresos.loc[[e.name]]])
        hallazgos.append(_hallazgo(
            "IOA-05", "IoA", "Salida de datos hacia IP externa",
            (f"Conexión permitida de {e['src_ip']} hacia la IP pública {e['dst_ip']}:{int(e['dst_port'])}. "
             + ("Secuencia completa: acceso SSH al servidor, actividad del mismo usuario en el sistema médico "
                f"({', '.join(med_relacionado['action_desc'].unique())}) y salida externa."
                if secuencia else "Sin secuencia completa asociada.")),
            filas_fw, "firewall",
            {"src_ip": e["src_ip"], "dst_ip": e["dst_ip"], "dst_port": int(e["dst_port"]),
             "actor_token": [e["actor_token"]],
             "account_token": sorted(med_relacionado["account_token"].unique().tolist())},
            severidad="CRITICA" if secuencia else "ALTA",
            secuencia_exfiltracion=secuencia,
            ajuste_reloj_12h=bool(cerca_12h.any() and not cerca.any()),
            evidencia_sistema_medico=_evidencia(med_relacionado, "sistema_medico") if not med_relacionado.empty else None,
        ))

    # IOA-06: una cuenta usada por varias personas (cuenta compartida o comprometida)
    identidades = med.groupby("account_token")["actor_token"].nunique()
    compartidas = identidades[identidades >= u["identidades_por_cuenta"]]
    for cuenta, n in compartidas.sort_values(ascending=False).items():
        filas = med[med["account_token"].eq(cuenta)]
        hallazgos.append(_hallazgo(
            "IOA-06", "IoA", "Cuenta usada por varias identidades",
            f"La cuenta {cuenta} fue usada por {n} identidades distintas (lo normal es 1).",
            filas, "sistema_medico",
            {"account_token": cuenta}, identidades_distintas=int(n),
        ))

    # IOA-07: cuenta dedicada casi solo a administrar usuarios (activar, reactivar, cambiar nivel)
    perfil = med.assign(admin=med["action_desc"].isin(ACCIONES_ADMIN)).groupby("account_token")["admin"].agg(["sum", "mean"])
    dedicadas = perfil[(perfil["mean"] >= u["ratio_admin_cuenta"]) & (perfil["sum"] >= u["minimo_operaciones_admin"])]
    for cuenta, fila in dedicadas.iterrows():
        filas = med[med["account_token"].eq(cuenta) & med["action_desc"].isin(ACCIONES_ADMIN)]
        acciones = filas["action_desc"].value_counts().to_dict()
        hallazgos.append(_hallazgo(
            "IOA-07", "IoA", "Abuso de privilegios administrativos",
            f"La cuenta {cuenta} hizo {int(fila['sum'])} operaciones de administración de usuarios "
            f"({fila['mean']:.0%} de su actividad): {acciones}.",
            filas, "sistema_medico", {"account_token": cuenta}, operaciones=acciones,
        ))

    # IOA-08: registros con IP malformada (posible manipulación de registros o evasión)
    malformadas = med[med["was_dotless_ip"]]
    for cuenta, filas in malformadas.groupby("account_token"):
        hallazgos.append(_hallazgo(
            "IOA-08", "IoA", "Registros con IP malformada",
            f"{len(filas)} eventos de la cuenta {cuenta} con IP escrita sin puntos (formato anómalo).",
            filas, "sistema_medico", {"account_token": cuenta}, severidad="MEDIA",
        ))
    fw_mal = fw[fw["was_dotless_ip"]]
    if not fw_mal.empty:
        hallazgos.append(_hallazgo(
            "IOA-08", "IoA", "Registros con IP malformada",
            f"{len(fw_mal)} conexiones del firewall con IP destino escrita sin puntos.",
            fw_mal, "firewall", {"actores_distintos": int(fw_mal["actor_token"].nunique())}, severidad="MEDIA",
        ))

    # IOA-09: conexiones SSH masivas desde la misma máquina en una hora
    ssh = fw[fw["protocol"].eq("SSH") | fw["dst_port"].eq(22) | fw["application"].eq("SSH")]
    for (ip, hora), filas in _grupos_que_superan(ssh, ["src_ip", "hora"], u["ssh_misma_ip_hora"]):
        hallazgos.append(_hallazgo(
            "IOA-09", "IoA", "Sesiones SSH masivas",
            f"{len(filas)} conexiones SSH desde {ip} en una hora (umbral {u['ssh_misma_ip_hora']}).",
            filas, "firewall",
            {"src_ip": ip, "dst_ip": sorted(filas["dst_ip"].unique().tolist()),
             "actor_token": sorted(filas["actor_token"].unique().tolist())},
        ))

    return hallazgos


# ----------------------------------------------------------------------------
# Reglas IoC (indicadores concretos del caso)
# ----------------------------------------------------------------------------
def evaluar_reglas_ioc(fw: pd.DataFrame, med: pd.DataFrame, iocs: dict) -> list[dict]:
    hallazgos = []
    extra = {"etiquetas": iocs.get("etiquetas", [])}

    filas = fw[fw["dst_ip"].isin(iocs["ips_destino_externas"])]
    if not filas.empty:
        hallazgos.append(_hallazgo("IOC-01", "IoC", "Conexión a IP externa conocida",
                                   f"{len(filas)} conexiones a {iocs['ips_destino_externas']}.",
                                   filas, "firewall", {"dst_ip": iocs["ips_destino_externas"]}, severidad="CRITICA", **extra))

    filas = fw[fw["dst_port"].isin(iocs["puertos_canal_sombra"])]
    if not filas.empty:
        hallazgos.append(_hallazgo("IOC-02", "IoC", "Tráfico por puerto de canal sombra",
                                   f"{len(filas)} conexiones al puerto {iocs['puertos_canal_sombra']} "
                                   f"desde {filas['src_ip'].nunique()} IPs de origen.",
                                   filas, "firewall", {"dst_port": iocs["puertos_canal_sombra"]}, severidad="MEDIA", **extra))

    for ip in iocs["ips_origen_vigiladas"]:
        filas = fw[fw["src_ip"].eq(ip)]
        if not filas.empty:
            hallazgos.append(_hallazgo("IOC-03", "IoC", "Actividad desde equipo vigilado",
                                       f"{len(filas)} conexiones desde {ip} "
                                       f"({filas['action'].value_counts().to_dict()}).",
                                       filas, "firewall", {"src_ip": ip}, **extra))

    for cuenta in iocs["cuentas_vigiladas"]:
        filas = med[med["account_token"].eq(cuenta)]
        if not filas.empty:
            hallazgos.append(_hallazgo("IOC-04", "IoC", "Actividad de cuenta vigilada",
                                       f"{len(filas)} eventos de la cuenta {cuenta}.",
                                       filas, "sistema_medico", {"account_token": cuenta}, **extra))
    return hallazgos


# ----------------------------------------------------------------------------
# Cobertura: ¿qué incidentes conocidos detectan las reglas IoA?
# ----------------------------------------------------------------------------
def cobertura(hallazgos: list[dict], referencia: dict) -> dict:
    def valores(h):
        vals = set()
        for v in h["entidades"].values():
            vals.update(v if isinstance(v, list) else [v])
        return vals

    detalle = {}
    for inc in referencia["incidentes"]:
        reglas = set()
        for v in inc["ventanas"]:
            for h in hallazgos:
                if h["tipo"] != "IoA" or v["entidad"] not in valores(h):
                    continue
                if "hora" not in v:
                    reglas.add(h["regla"])
                    continue
                hora = pd.Timestamp(v["hora"])
                if pd.Timestamp(h["inicio"]).floor("h") <= hora <= pd.Timestamp(h["fin"]).floor("h"):
                    reglas.add(h["regla"])
        detalle[inc["campana"]] = {"incidente": inc["incidente"], "detectado_por_ioa": bool(reglas),
                                   "reglas": sorted(reglas)}
    n = sum(d["detectado_por_ioa"] for d in detalle.values())
    return {"incidentes_detectados_por_ioa": f"{n}/{len(detalle)}", "detalle_por_campana": detalle}


# ----------------------------------------------------------------------------
# Orquestación
# ----------------------------------------------------------------------------
def ejecutar(ruta_fw: str, ruta_med: str, carpeta_salida: str, ruta_iocs: str | None = None) -> dict:
    inicio = time.time()
    aqui = Path(__file__).parent
    iocs = json.loads(Path(ruta_iocs or aqui / "iocs_ejercicio.json").read_text(encoding="utf-8"))
    referencia = json.loads((aqui / "incidentes_referencia.json").read_text(encoding="utf-8"))
    salida = Path(carpeta_salida)
    salida.mkdir(parents=True, exist_ok=True)

    print("1/3 Cargando datos seudonimizados...")
    fw = cargar_firewall(ruta_fw)
    med = cargar_sistema_medico(ruta_med)

    print("2/3 Evaluando reglas IoA e IoC...")
    ioa = evaluar_reglas_ioa(fw, med)
    ioc = evaluar_reglas_ioc(fw, med, iocs)
    cob = cobertura(ioa, referencia)

    resumen = pd.Series([h["regla"] for h in ioa + ioc]).value_counts().sort_index().to_dict()
    resultado = {
        "generado": datetime.now().isoformat(timespec="seconds"),
        "datos": {"firewall": str(ruta_fw), "sistema_medico": str(ruta_med)},
        "umbrales": UMBRALES,
        "resumen_por_regla": resumen,
        **cob,
        "hallazgos_ioa": ioa,
        "hallazgos_ioc": ioc,
        "nota": "Tokens seudonimizados (HMAC-SHA256). Los IoC son datos sintéticos de ejercicio.",
    }
    (salida / "hallazgos_reglas.json").write_text(json.dumps(resultado, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    print(f"3/3 Listo en {time.time() - inicio:.1f} s")
    print(f"    Hallazgos IoA: {len(ioa)} | Hallazgos IoC: {len(ioc)} | Por regla: {resumen}")
    print(f"    Incidentes detectados por reglas IoA: {cob['incidentes_detectados_por_ioa']}")
    for camp, d in cob["detalle_por_campana"].items():
        print(f"      {camp}: {'SI' if d['detectado_por_ioa'] else 'NO'} {d['reglas']}")
    print(f"    Resultado en {(salida / 'hallazgos_reglas.json').resolve()}")
    return resultado


def main():
    p = argparse.ArgumentParser(description="Motor de reglas IoA / IoC (Rol 2)")
    p.add_argument("--fw", required=True)
    p.add_argument("--med", required=True)
    p.add_argument("--salida", default="data/exports")
    p.add_argument("--iocs", default=None, help="JSON de indicadores (por defecto iocs_ejercicio.json)")
    a = p.parse_args()
    ejecutar(a.fw, a.med, a.salida, a.iocs)


if __name__ == "__main__":
    main()
