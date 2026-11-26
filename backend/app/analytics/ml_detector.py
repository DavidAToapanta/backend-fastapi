"""
Detección de anomalías SIN reglas (Rol 2 - AegisHealth-CTI).

Idea general:
  1. Resumimos los eventos en "ventanas" (una fila por entidad y periodo).
  2. Un modelo Isolation Forest da a cada ventana un puntaje de rareza (0 a 1).
  3. Ordenamos de más rara a menos rara (ranking).
  4. Medimos en qué posición quedan los 5 incidentes conocidos.
     Los incidentes NO se usan para entrenar: solo para evaluar.

Tres tablas de ventanas:
  - fw_hora     : firewall, por usuario (actor_token) y por hora   -> ráfagas
  - med_hora    : sistema médico, por cuenta y por hora            -> ráfagas
  - med_periodo : sistema médico, por cuenta en todo el periodo    -> abuso lento

Decisiones del modelo (y por qué):
  - Usamos CONTEOS por ventana, no proporciones: en una ventana de 1 solo evento una
    proporción vale 0 o 1 y parece "rara" sin serlo.
  - Aplicamos logaritmo (log1p) para que un número enorme no domine a las demás variables.
  - Cada árbol ve hasta 20.000 ventanas (max_samples): con muestras chicas el modelo
    nunca "ve" los comportamientos raros y no aprende a aislarlos.

Dos versiones de variables (para ser honestos con el jurado):
  - A_genericas : solo comportamiento general de seguridad.
  - B_dominio   : A + variables que salieron del análisis de los incidentes.

Uso (desde la carpeta raíz del proyecto):
  python -m backend.app.analytics.ml_detector --fw data/processed/sample_fw_200k.parquet \
      --med data/processed/sample_med_200k.parquet --salida data/exports
"""
import argparse
import json
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .carga import cargar_firewall, cargar_sistema_medico

# ----------------------------------------------------------------------------
# Constantes de dominio (conocimiento general de seguridad, no de los incidentes)
# ----------------------------------------------------------------------------
PUERTOS_REMOTOS = [22, 23, 135, 139, 445, 3389, 5985, 5986]  # administración remota
HORAS_NOCTURNAS = [22, 23, 0, 1, 2, 3, 4, 5]                  # reloj 24h confirmado por Rol 1

# Textos EXACTOS del sistema médico. Ojo: "TRANFERENCIA" viene SIN la S en los datos.
ACCION_FALLIDA = "ACCESO FALLIDO"
ACCION_DESCARGA = "DESCARGA EXITOSA"
ACCION_TRANSF_OK = "TRANFERENCIA EXITOSA"
ACCION_TRANSF_CORTADA = "TRANFERENCIA INTERRUMPIDA"
ACCIONES_ADMIN = [
    "USUARIOS - Activar usuario",
    "Reactivacion de usuarios",
    "Inactivacion de usuarios",
    "USUARIOS - Actualizar nivel de Usuario",
]

# Variables por tabla y por versión
VARIABLES = {
    "fw_hora": {
        "A_genericas": [
            "total_eventos", "negados", "puertos_distintos", "destinos_distintos",
            "conexiones_misma_maquina", "conexiones_externas", "conexiones_remotas",
        ],
        "B_dominio": ["conexiones_ssh", "conexiones_8443", "ip_sin_puntos"],
    },
    "med_hora": {
        "A_genericas": [
            "total_eventos", "fallidos", "descargas", "transferencias", "interrumpidas",
            "operaciones_admin", "identidades_distintas", "es_nocturno",
        ],
        "B_dominio": ["ip_sin_puntos"],
    },
    "med_periodo": {
        "A_genericas": [
            "ratio_fallidos", "ratio_admin", "identidades_distintas", "ips_distintas",
            "ratio_nocturno", "eventos_por_hora_activa",
        ],
        "B_dominio": ["ratio_ip_sin_puntos"],
    },
}

# Parámetros del modelo (fijados ANTES de correr sobre los 10M de filas)
N_ARBOLES = 200
MAX_MUESTRAS = 20_000
SEMILLA = 42


# ----------------------------------------------------------------------------
# 1. Construcción de ventanas (feature engineering)
# ----------------------------------------------------------------------------
def ventanas_fw_hora(fw: pd.DataFrame) -> pd.DataFrame:
    """Resume el firewall: una fila por usuario y por hora (conteos)."""
    df = fw.assign(
        hora=fw["event_ts"].dt.floor("h"),
        negado=fw["action"].eq("negado"),
        remoto=fw["dst_port"].isin(PUERTOS_REMOTOS),
        ssh=fw["application"].eq("SSH") | fw["protocol"].eq("SSH"),
        p8443=fw["dst_port"].eq(8443),
    )
    v = df.groupby(["actor_token", "hora"]).agg(
        total_eventos=("action", "size"),
        negados=("negado", "sum"),
        puertos_distintos=("dst_port", "nunique"),
        destinos_distintos=("dst_ip", "nunique"),
        origenes_distintos=("src_ip", "nunique"),
        conexiones_externas=("is_external_ip", "sum"),
        conexiones_remotas=("remoto", "sum"),
        ip_sin_puntos=("was_dotless_ip", "sum"),
        conexiones_ssh=("ssh", "sum"),
        conexiones_8443=("p8443", "sum"),
    ).reset_index()
    # Conexiones repetidas desde la MISMA máquina en una hora (lo normal es 1 por máquina)
    v["conexiones_misma_maquina"] = v["total_eventos"] - v["origenes_distintos"]
    return v.rename(columns={"actor_token": "entidad"})


def ventanas_med_hora(med: pd.DataFrame) -> pd.DataFrame:
    """Resume el sistema médico: una fila por cuenta y por hora (conteos)."""
    df = med.assign(
        hora=med["event_ts"].dt.floor("h"),
        fallido=med["action_desc"].eq(ACCION_FALLIDA),
        descarga=med["action_desc"].eq(ACCION_DESCARGA),
        transf=med["action_desc"].isin([ACCION_TRANSF_OK, ACCION_TRANSF_CORTADA]),
        cortada=med["action_desc"].eq(ACCION_TRANSF_CORTADA),
        admin=med["action_desc"].isin(ACCIONES_ADMIN),
    )
    v = df.groupby(["account_token", "hora"]).agg(
        total_eventos=("action_desc", "size"),
        fallidos=("fallido", "sum"),
        descargas=("descarga", "sum"),
        transferencias=("transf", "sum"),
        interrumpidas=("cortada", "sum"),
        operaciones_admin=("admin", "sum"),
        identidades_distintas=("actor_token", "nunique"),
        ip_sin_puntos=("was_dotless_ip", "sum"),
    ).reset_index()
    v["es_nocturno"] = v["hora"].dt.hour.isin(HORAS_NOCTURNAS).astype(int)
    return v.rename(columns={"account_token": "entidad"})


def ventanas_med_periodo(med: pd.DataFrame) -> pd.DataFrame:
    """Perfil de cada cuenta en TODO el periodo (detecta abuso lento y constante)."""
    df = med.assign(
        hora=med["event_ts"].dt.floor("h"),
        fallido=med["action_desc"].eq(ACCION_FALLIDA),
        admin=med["action_desc"].isin(ACCIONES_ADMIN),
        nocturno=med["event_ts"].dt.hour.isin(HORAS_NOCTURNAS),
    )
    v = df.groupby("account_token").agg(
        total_eventos=("action_desc", "size"),
        horas_activas=("hora", "nunique"),
        ratio_fallidos=("fallido", "mean"),
        ratio_admin=("admin", "mean"),
        identidades_distintas=("actor_token", "nunique"),
        ips_distintas=("conn_ip", "nunique"),
        ratio_nocturno=("nocturno", "mean"),
        ratio_ip_sin_puntos=("was_dotless_ip", "mean"),
    ).reset_index()
    v["eventos_por_hora_activa"] = v["total_eventos"] / v["horas_activas"]
    return v.rename(columns={"account_token": "entidad"})


# ----------------------------------------------------------------------------
# 2. Modelo: Isolation Forest (no necesita ejemplos de ataques)
# ----------------------------------------------------------------------------
def puntuar(ventanas: pd.DataFrame, variables: list[str]) -> pd.DataFrame:
    """Da a cada ventana un puntaje de rareza de 0 (normal) a 1 (muy rara) y las ordena."""
    X = ventanas[variables].astype(float).fillna(0).clip(lower=0).to_numpy()
    X = np.log1p(X)                                  # un número enorme no domina a los demás
    X = StandardScaler().fit_transform(X)            # todas las variables en la misma escala
    modelo = IsolationForest(
        n_estimators=N_ARBOLES,
        max_samples=min(MAX_MUESTRAS, len(X)),
        contamination="auto",
        random_state=SEMILLA,
        n_jobs=-1,
    )
    modelo.fit(X)
    rareza = -modelo.score_samples(X)                # más alto = más raro
    rango = rareza.max() - rareza.min()
    puntaje = (rareza - rareza.min()) / rango if rango > 0 else np.zeros(len(rareza))
    res = ventanas.assign(anomaly_score=puntaje.round(4))
    # Posición en el ranking; los empates comparten la mejor posición
    res["posicion"] = res["anomaly_score"].rank(method="min", ascending=False).astype(int)
    return res.sort_values(["posicion", "entidad"]).reset_index(drop=True)


# ----------------------------------------------------------------------------
# 3. Evaluación honesta contra los incidentes conocidos
# ----------------------------------------------------------------------------
def evaluar(rankings: dict, referencia: dict, top_n: int) -> dict:
    """Busca cada incidente en los rankings y cuenta cuántos quedan en el top N."""
    detalle, claves_incidente = {}, {t: set() for t in rankings}
    for inc in referencia["incidentes"]:
        hallazgos = []
        for v in inc["ventanas"]:
            r = rankings[v["tabla"]]
            filtro = r["entidad"].eq(v["entidad"])
            if "hora" in v:
                filtro &= r["hora"].eq(pd.Timestamp(v["hora"]))
                claves_incidente[v["tabla"]].add((v["entidad"], pd.Timestamp(v["hora"])))
            else:
                claves_incidente[v["tabla"]].add((v["entidad"], None))
            fila = r[filtro]
            if fila.empty:
                hallazgos.append({**v, "encontrada_en_datos": False})
                continue
            fila = fila.iloc[0]
            hallazgos.append({
                **v,
                "encontrada_en_datos": True,
                "posicion_en_ranking": int(fila["posicion"]),
                "de_un_total_de": int(len(r)),
                "anomaly_score": float(fila["anomaly_score"]),
                "en_top_n": bool(fila["posicion"] <= top_n),
            })
        detalle[inc["campana"]] = {
            "incidente": inc["incidente"],
            "detectado_sin_reglas": any(h.get("en_top_n") for h in hallazgos),
            "mejor_posicion": min((h["posicion_en_ranking"] for h in hallazgos if h.get("encontrada_en_datos")), default=None),
            "ventanas": hallazgos,
        }

    # Ventanas del top N que NO son de los incidentes conocidos -> para revisión del analista
    no_confirmadas = {}
    for tabla, r in rankings.items():
        top = r[r["posicion"] <= top_n]
        if "hora" in top.columns:
            claves = zip(top["entidad"], top["hora"])
        else:
            claves = zip(top["entidad"], [None] * len(top))
        no_confirmadas[tabla] = sum(1 for k in claves if k not in claves_incidente[tabla])

    detectados = sum(d["detectado_sin_reglas"] for d in detalle.values())
    return {
        "incidentes_en_top_n": f"{detectados}/{len(detalle)}",
        "detalle_por_campana": detalle,
        "anomalias_no_confirmadas_en_top_n": no_confirmadas,
    }


# ----------------------------------------------------------------------------
# 4. Orquestación
# ----------------------------------------------------------------------------
def ejecutar(ruta_fw: str, ruta_med: str, carpeta_salida: str, top_n: int = 50,
             ruta_referencia: str | None = None) -> dict:
    inicio = time.time()
    salida = Path(carpeta_salida)
    salida.mkdir(parents=True, exist_ok=True)
    ruta_referencia = ruta_referencia or Path(__file__).with_name("incidentes_referencia.json")
    referencia = json.loads(Path(ruta_referencia).read_text(encoding="utf-8"))

    print("1/4 Cargando datos seudonimizados...")
    fw = cargar_firewall(ruta_fw)
    med = cargar_sistema_medico(ruta_med)
    print(f"    firewall: {len(fw):,} filas | sistema médico: {len(med):,} filas")

    print("2/4 Construyendo ventanas...")
    tablas = {
        "fw_hora": ventanas_fw_hora(fw),
        "med_hora": ventanas_med_hora(med),
        "med_periodo": ventanas_med_periodo(med),
    }
    del fw, med  # liberar memoria
    for nombre, t in tablas.items():
        print(f"    {nombre}: {len(t):,} ventanas")

    resultados = {}
    for version in ["A_genericas", "B_dominio"]:
        print(f"3/4 Isolation Forest - versión {version}...")
        rankings = {}
        for nombre, t in tablas.items():
            variables = VARIABLES[nombre]["A_genericas"] + (
                VARIABLES[nombre]["B_dominio"] if version == "B_dominio" else [])
            rankings[nombre] = puntuar(t, variables)
            columnas = ["posicion", "anomaly_score", "entidad"] + (["hora"] if "hora" in t.columns else []) + variables
            rankings[nombre].head(200)[columnas].to_csv(salida / f"ranking_{nombre}_{version}.csv", index=False)

        metricas = {
            "modelo": f"log1p + StandardScaler + IsolationForest(n_estimators={N_ARBOLES}, max_samples={MAX_MUESTRAS}, random_state={SEMILLA}) en CPU local",
            "version_variables": version,
            "variables_usadas": {n: VARIABLES[n]["A_genericas"] + (VARIABLES[n]["B_dominio"] if version == "B_dominio" else []) for n in tablas},
            "generado": datetime.now().isoformat(timespec="seconds"),
            "datos": {"firewall": str(ruta_fw), "sistema_medico": str(ruta_med)},
            "total_ventanas_evaluadas": {n: int(len(t)) for n, t in tablas.items()},
            "top_n_evaluado": top_n,
            **evaluar(rankings, referencia, top_n),
            "nota": ("Las anomalías no confirmadas NO son falsos positivos: quedan para revisión del analista. "
                     "Los incidentes conocidos solo se usan para evaluar, nunca para entrenar."),
        }
        (salida / f"ml_metrics_{version}.json").write_text(json.dumps(metricas, indent=2, ensure_ascii=False), encoding="utf-8")
        resultados[version] = metricas
        print(f"    -> incidentes en el top {top_n}: {metricas['incidentes_en_top_n']}")

    print(f"4/4 Listo en {time.time() - inicio:.1f} s. Resultados en {salida.resolve()}")
    return resultados


def main():
    p = argparse.ArgumentParser(description="Detección de anomalías sin reglas (Rol 2)")
    p.add_argument("--fw", required=True, help="Parquet (o CSV) del firewall seudonimizado")
    p.add_argument("--med", required=True, help="Parquet (o CSV) del sistema médico seudonimizado")
    p.add_argument("--salida", default="data/exports", help="Carpeta de resultados")
    p.add_argument("--top", type=int, default=50, help="Tamaño del top N para evaluar")
    a = p.parse_args()
    ejecutar(a.fw, a.med, a.salida, a.top)


if __name__ == "__main__":
    main()
