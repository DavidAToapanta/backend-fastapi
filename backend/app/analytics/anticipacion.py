"""
Motor de ANTICIPACIÓN de amenazas (Rol 2 - AegisHealth-CTI).

Idea central: no "adivinamos" la fecha de un ataque (con pocos incidentes eso no se puede
aprender sin sobreajustar). Anticipamos de tres formas que SÍ son defendibles y que se
adaptan solas cuando cambian los datos (no hay IPs, cuentas ni umbrales absolutos fijos):

  1. RIESGO PREVIO POR CUENTA (días/semanas antes)
     Cada día se calcula, con los datos HASTA ESE DÍA, qué tan lejos está cada cuenta de lo
     normal del propio sistema (z robusto = distancia a la mediana medida en MADs).
     Las condiciones que habilitan un ataque (cuenta compartida, cuenta que solo administra
     usuarios, IPs malformadas) aparecen ANTES que el ataque.

  2. ALERTA TEMPRANA POR LÍNEA BASE (minutos/horas)
     Para cada señal se aprende lo normal de cada hora del día con los 7 días anteriores
     (sin mirar el futuro). Si la hora actual se aleja mucho, se alerta en la misma hora.

  3. PRONÓSTICO DE LA SIGUIENTE FASE (kill chain)
     Matriz de transición entre fases del ataque (MITRE ATT&CK): parte de conocimiento
     experto (prior) y se ACTUALIZA con las secuencias observadas. Con datos reales,
     la matriz aprende cómo atacan a ESTA organización.

Todo se valida con BACKTESTING sin fuga de información: para evaluar el día D solo se usan
datos anteriores a D.
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .ml_detector import ACCION_FALLIDA, ACCIONES_ADMIN, HORAS_NOCTURNAS

# Parámetros (se pueden cambiar con --config sin tocar el código)
PARAMS = {
    "minimo_eventos_para_ratio": 20,   # una proporción con pocos eventos no es evidencia
    "z_medio": 3.0,
    "z_alto": 6.0,
    "z_critico": 10.0,
    "dias_linea_base": 7,
    "minimo_dias_historia": 3,         # la alerta empieza a funcionar desde el día 4
    "z_alerta_hora": 6.0,
    "peso_prior_transiciones": 10.0,   # cuánto pesa el conocimiento experto frente a lo observado
}
NIVELES = ["BAJO", "MEDIO", "ALTO", "CRITICO"]

# ----------------------------------------------------------------------------
# Utilidad: z robusto (no se deja engañar por valores extremos como la media)
# ----------------------------------------------------------------------------
def z_robusto(serie: pd.Series) -> pd.Series:
    x = serie.astype(float)
    validos = x.dropna()
    if validos.empty:
        return pd.Series(np.nan, index=x.index)
    mediana = validos.median()
    escala = 1.4826 * (validos - mediana).abs().median()
    if escala == 0:  # casi todos iguales: usamos la distancia al percentil 99 (o 1)
        escala = (validos.quantile(0.99) - mediana) or 1.0
    return (x - mediana) / escala


def nivel(z: float) -> str:
    if pd.isna(z) or z < PARAMS["z_medio"]:
        return "BAJO"
    if z < PARAMS["z_alto"]:
        return "MEDIO"
    if z < PARAMS["z_critico"]:
        return "ALTO"
    return "CRITICO"


# ----------------------------------------------------------------------------
# 1. Riesgo previo por cuenta (panel diario, acumulado, sin mirar el futuro)
# ----------------------------------------------------------------------------
FACTORES = {
    "identidades_distintas": "cuenta usada por muchas personas",
    "ratio_admin": "cuenta dedicada a administrar usuarios",
    "ratio_fallidos": "muchos accesos fallidos",
    "ips_malformadas": "registros con IP malformada",
    "ratio_nocturno": "actividad nocturna",
    "ips_distintas": "conexiones desde muchas IPs",
}


def panel_riesgo_cuentas(med: pd.DataFrame) -> pd.DataFrame:
    """Para cada cuenta y cada día: factores acumulados hasta ese día y su nivel de riesgo."""
    m = med.assign(
        dia=med["event_ts"].dt.normalize(),
        admin=med["action_desc"].isin(ACCIONES_ADMIN),
        fallido=med["action_desc"].eq(ACCION_FALLIDA),
        nocturno=med["event_ts"].dt.hour.isin(HORAS_NOCTURNAS),
    )
    dias = pd.date_range(m["dia"].min(), m["dia"].max(), freq="D")
    cuentas = m["account_token"].unique()
    grilla = pd.MultiIndex.from_product([cuentas, dias], names=["account_token", "dia"])

    diario = m.groupby(["account_token", "dia"]).agg(
        eventos=("action_desc", "size"), admin=("admin", "sum"), fallidos=("fallido", "sum"),
        nocturnos=("nocturno", "sum"), ips_malformadas=("was_dotless_ip", "sum"),
    ).reindex(grilla, fill_value=0)
    acumulado = diario.groupby(level="account_token").cumsum()

    # Distintos acumulados: cuento cada par (cuenta, identidad) el día en que aparece por primera vez
    for col, nombre in [("actor_token", "identidades_distintas"), ("conn_ip", "ips_distintas")]:
        primera = m.groupby(["account_token", col])["dia"].min().reset_index()
        nuevos = primera.groupby(["account_token", "dia"]).size().reindex(grilla, fill_value=0)
        acumulado[nombre] = nuevos.groupby(level="account_token").cumsum()

    p = acumulado.reset_index()
    p = p[p["eventos"] > 0].copy()  # la cuenta ya existe ese día
    suficientes = p["eventos"] >= PARAMS["minimo_eventos_para_ratio"]
    for ratio, num in [("ratio_admin", "admin"), ("ratio_fallidos", "fallidos"), ("ratio_nocturno", "nocturnos")]:
        p[ratio] = np.where(suficientes, p[num] / p["eventos"], np.nan)

    # z robusto de cada factor, calculado DÍA POR DÍA contra todas las cuentas de ese día
    for f in FACTORES:
        p[f"z_{f}"] = p.groupby("dia")[f].transform(z_robusto)
    zcols = [f"z_{f}" for f in FACTORES]
    p["z_max"] = p[zcols].max(axis=1)
    p["factor_principal"] = p[zcols].idxmax(axis=1).str.replace("z_", "", regex=False)
    p["nivel"] = p["z_max"].map(nivel)
    return p


def razones(fila: pd.Series) -> list[str]:
    out = []
    for f, texto in FACTORES.items():
        z = fila.get(f"z_{f}")
        if pd.notna(z) and z >= PARAMS["z_medio"]:
            valor = fila[f]
            valor = f"{valor:.0%}" if f.startswith("ratio") else f"{int(valor)}"
            out.append(f"{texto} ({valor}; {z:.0f} veces más lejos de lo normal)")
    return out


# ----------------------------------------------------------------------------
# 2. Línea base por hora y alerta temprana (ventana móvil de 7 días, sin futuro)
# ----------------------------------------------------------------------------
def senales_por_hora(fw: pd.DataFrame, med: pd.DataFrame) -> pd.DataFrame:
    horas = pd.date_range(min(fw["event_ts"].min(), med["event_ts"].min()).floor("h"),
                          max(fw["event_ts"].max(), med["event_ts"].max()).floor("h"), freq="h")
    hf, hm = fw["event_ts"].dt.floor("h"), med["event_ts"].dt.floor("h")
    s = pd.DataFrame({
        "negados_firewall": fw[fw["action"].eq("negado")].groupby(hf).size(),
        "ssh_firewall": fw[fw["dst_port"].eq(22) | fw["protocol"].eq("SSH")].groupby(hf).size(),
        "conexiones_externas": fw[fw["is_external_ip"]].groupby(hf).size(),
        "accesos_fallidos": med[med["action_desc"].eq(ACCION_FALLIDA)].groupby(hm).size(),
        "transferencias_interrumpidas": med[med["action_desc"].eq("TRANFERENCIA INTERRUMPIDA")].groupby(hm).size(),
        "cuentas_nuevas_activas": med.groupby("account_token")["event_ts"].min().dt.floor("h").value_counts(),
    }).reindex(horas, fill_value=0).fillna(0)
    s.index.name = "hora"
    return s


def alertas_linea_base(senales: pd.DataFrame) -> pd.DataFrame:
    """Compara cada hora con la MISMA hora de los días anteriores (solo pasado)."""
    filas = []
    d = PARAMS["dias_linea_base"]
    for col in senales.columns:
        s = senales[col]
        historia = pd.concat([s.shift(24 * k) for k in range(1, d + 1)], axis=1)
        mediana = historia.median(axis=1)
        mad = 1.4826 * historia.sub(mediana, axis=0).abs().median(axis=1)
        escala = mad.where(mad > 0, np.sqrt(mediana.clip(lower=1)))  # conteos: ruido tipo Poisson
        z = (s - mediana) / escala
        nunca_visto = historia.max(axis=1).fillna(0).eq(0) & s.gt(0)  # señal que nunca había ocurrido
        alerta = (z >= PARAMS["z_alerta_hora"]) | nunca_visto
        alerta &= historia.notna().sum(axis=1) >= PARAMS["minimo_dias_historia"]
        for hora in s.index[alerta]:
            filas.append({"hora": hora, "senal": col, "valor": int(s[hora]), "esperado": float(mediana[hora]),
                          "z": None if nunca_visto[hora] else round(float(z[hora]), 1),
                          "tipo": "NOVEDAD" if nunca_visto[hora] else "DESVIO"})
    if not filas:
        return pd.DataFrame(columns=["hora", "senal", "valor", "esperado", "z", "tipo", "nivel_alerta"])
    a = pd.DataFrame(filas).sort_values("hora")
    # Confirmación cruzada (práctica de SOC para evitar fatiga de alertas):
    # CONFIRMADA = 2 o más señales a la vez, o algo que nunca había ocurrido (NOVEDAD).
    por_hora = a.groupby("hora").agg(n=("senal", "nunique"), novedad=("tipo", lambda t: (t == "NOVEDAD").any()))
    confirmada = (por_hora["n"] >= 2) | por_hora["novedad"]
    a["nivel_alerta"] = a["hora"].map(confirmada).map({True: "CONFIRMADA", False: "AVISO"})
    return a


# ----------------------------------------------------------------------------
# 3. Pronóstico de la siguiente fase (cadena de Markov sobre fases de ATT&CK)
# ----------------------------------------------------------------------------
FASES = ["RECONOCIMIENTO", "ACCESO_CREDENCIALES", "CUENTAS_VALIDAS", "PERSISTENCIA_PRIVILEGIOS",
         "MOVIMIENTO_LATERAL", "RECOLECCION", "EXFILTRACION", "IMPACTO"]
TECNICA_A_FASE = {
    "T1046": "RECONOCIMIENTO", "T1110.001": "ACCESO_CREDENCIALES", "T1110.003": "ACCESO_CREDENCIALES",
    "T1078": "CUENTAS_VALIDAS", "T1098": "PERSISTENCIA_PRIVILEGIOS", "T1021": "MOVIMIENTO_LATERAL",
    "T1021.001": "MOVIMIENTO_LATERAL", "T1021.002": "MOVIMIENTO_LATERAL", "T1021.004": "MOVIMIENTO_LATERAL",
    "T1213": "RECOLECCION", "T1074": "RECOLECCION", "T1048.002": "EXFILTRACION", "T1531": "IMPACTO",
}
# Conocimiento experto: progresión típica de una intrusión (cada fila suma 1)
PRIOR = {
    "RECONOCIMIENTO": {"ACCESO_CREDENCIALES": .5, "MOVIMIENTO_LATERAL": .3, "CUENTAS_VALIDAS": .2},
    "ACCESO_CREDENCIALES": {"CUENTAS_VALIDAS": .6, "MOVIMIENTO_LATERAL": .3, "RECOLECCION": .1},
    "CUENTAS_VALIDAS": {"RECOLECCION": .4, "MOVIMIENTO_LATERAL": .35, "PERSISTENCIA_PRIVILEGIOS": .25},
    "PERSISTENCIA_PRIVILEGIOS": {"RECOLECCION": .4, "MOVIMIENTO_LATERAL": .2, "EXFILTRACION": .2, "IMPACTO": .2},
    "MOVIMIENTO_LATERAL": {"RECOLECCION": .6, "PERSISTENCIA_PRIVILEGIOS": .2, "EXFILTRACION": .2},
    "RECOLECCION": {"EXFILTRACION": .7, "IMPACTO": .3},
    "EXFILTRACION": {"IMPACTO": 1.0},
    "IMPACTO": {},
}
CONTROLES = {
    "RECONOCIMIENTO": "Bloquear o aislar el equipo de origen; segmentar el acceso al servidor médico.",
    "ACCESO_CREDENCIALES": "Bloqueo temporal por intentos fallidos; MFA en cuentas privilegiadas.",
    "CUENTAS_VALIDAS": "Revisar sesiones activas, forzar cambio de credenciales y eliminar cuentas compartidas.",
    "PERSISTENCIA_PRIVILEGIOS": "Auditar y revertir cambios de nivel, activaciones y reactivaciones recientes.",
    "MOVIMIENTO_LATERAL": "Restringir SSH/RDP/SMB al servidor médico a un bastión autorizado; cerrar Telnet.",
    "RECOLECCION": "Límite de descargas y transferencias por cuenta (DLP); alerta de consultas masivas.",
    "EXFILTRACION": "Bloquear salida a internet desde la red clínica salvo lista blanca; contención automática.",
    "IMPACTO": "Activar respaldos y continuidad; preparar notificación según LOPDP y la normativa de ciberseguridad.",
}


def matriz_transicion(campanas: list[dict]) -> tuple[pd.DataFrame, int]:
    """Prior experto + transiciones observadas en las campañas (aprende con datos reales)."""
    w = PARAMS["peso_prior_transiciones"]
    M = pd.DataFrame(0.0, index=FASES, columns=FASES)
    for origen, destinos in PRIOR.items():
        for destino, p in destinos.items():
            M.loc[origen, destino] += w * p
    observadas = 0
    for c in campanas:
        fases = sorted({TECNICA_A_FASE[t["id"]] for t in c["mitre_techniques"] if t["id"] in TECNICA_A_FASE},
                       key=FASES.index)
        for a, b in zip(fases, fases[1:]):
            M.loc[a, b] += 1
            observadas += 1
    filas = M.sum(axis=1).replace(0, 1)
    return M.div(filas, axis=0), observadas


def pronosticar(campanas: list[dict], M: pd.DataFrame) -> list[dict]:
    out = []
    for c in campanas:
        fases = sorted({TECNICA_A_FASE[t["id"]] for t in c["mitre_techniques"] if t["id"] in TECNICA_A_FASE},
                       key=FASES.index)
        if not fases:
            continue
        actual = fases[-1]
        siguientes = M.loc[actual].drop(labels=fases, errors="ignore").sort_values(ascending=False)
        siguientes = siguientes[siguientes > 0].head(3)
        out.append({
            "campaign_code": c["campaign_code"],
            "fases_observadas": fases,
            "fase_actual": actual,
            "siguientes_fases_probables": [
                {"fase": f, "probabilidad": round(float(p), 2), "control_recomendado": CONTROLES[f]}
                for f, p in siguientes.items()],
        })
    return out


def backtest_fases(campanas: list[dict]) -> dict:
    """Oculto la última fase de cada campaña y veo si el modelo (sin esa campaña) la predice en su top 3."""
    pruebas = []
    for i, c in enumerate(campanas):
        fases = sorted({TECNICA_A_FASE[t["id"]] for t in c["mitre_techniques"] if t["id"] in TECNICA_A_FASE},
                       key=FASES.index)
        if len(fases) < 2:
            continue
        M, _ = matriz_transicion(campanas[:i] + campanas[i + 1:])
        oculta, previa = fases[-1], fases[-2]
        top3 = list(M.loc[previa].drop(labels=fases[:-1], errors="ignore").sort_values(ascending=False).head(3).index)
        pruebas.append({"campaign_code": c["campaign_code"], "fase_previa": previa, "fase_oculta": oculta,
                        "top3_predicho": top3, "acierto": oculta in top3})
    aciertos = sum(p["acierto"] for p in pruebas)
    return {"aciertos_top3": f"{aciertos}/{len(pruebas)}", "pruebas": pruebas,
            "nota": "Validación limitada: pocas campañas. Con datos reales del SOC la matriz se recalibra sola."}


# ----------------------------------------------------------------------------
# Orquestación + backtesting contra los incidentes conocidos
# ----------------------------------------------------------------------------
def ejecutar(fw: pd.DataFrame, med: pd.DataFrame, carpeta_salida: str) -> dict:
    carpeta = Path(carpeta_salida)
    referencia = json.loads((Path(__file__).parent / "incidentes_referencia.json").read_text(encoding="utf-8"))
    campanas = json.loads((carpeta / "campanas.json").read_text(encoding="utf-8"))["campaigns"]

    print("  a) Riesgo previo por cuenta (día a día, sin mirar el futuro)...")
    panel = panel_riesgo_cuentas(med)
    ultimo = panel[panel["dia"].eq(panel["dia"].max())].sort_values("z_max", ascending=False)
    top = ultimo[ultimo["nivel"].isin(["ALTO", "CRITICO"])]
    top.assign(razones=top.apply(razones, axis=1))[
        ["account_token", "nivel", "z_max", "factor_principal", "eventos", "identidades_distintas", "razones"]
    ].to_csv(carpeta / "riesgo_cuentas.csv", index=False)

    print("  b) Línea base por hora y alertas tempranas...")
    senales = senales_por_hora(fw, med)
    alertas = alertas_linea_base(senales)
    alertas.to_csv(carpeta / "alertas_tempranas.csv", index=False)

    print("  c) Pronóstico de la siguiente fase (kill chain)...")
    M, observadas = matriz_transicion(campanas)
    pronostico = pronosticar(campanas, M)

    # ---- Backtesting por incidente
    backtest = []
    for inc in referencia["incidentes"]:
        cuentas = [v["entidad"] for v in inc["ventanas"] if v["entidad"].startswith("ACC-")]
        horas = [pd.Timestamp(v["hora"]) for v in inc["ventanas"] if "hora" in v]
        inicio = min(horas) if horas else None
        res = {"campana": inc["campana"], "incidente": inc["incidente"]}
        if inicio is not None:
            dia_ant = inicio.normalize() - pd.Timedelta(days=1)
            previo = panel[panel["account_token"].isin(cuentas) & panel["dia"].le(dia_ant)]
            riesgo_previo = previo[previo["dia"].eq(dia_ant)]
            alto = previo[previo["nivel"].isin(["ALTO", "CRITICO"])]
            res["riesgo_dia_anterior"] = riesgo_previo["nivel"].tolist() or ["SIN_HISTORIAL"]
            res["dias_de_anticipacion"] = int((inicio.normalize() - alto["dia"].min()).days) if not alto.empty else 0
            conf = alertas[alertas["nivel_alerta"].eq("CONFIRMADA")] if not alertas.empty else alertas
            ventana = conf[(conf["hora"] >= inicio) & (conf["hora"] <= inicio + pd.Timedelta(hours=12))]
            res["alerta_temprana"] = (
                {"horas_hasta_alerta": int((ventana["hora"].min() - inicio) / pd.Timedelta(hours=1)),
                 "senales": sorted(ventana[ventana["hora"].eq(ventana["hora"].min())]["senal"].unique().tolist())}
                if not ventana.empty else None)
        else:  # incidente de periodo (abuso lento)
            alto = panel[panel["account_token"].isin(cuentas) & panel["nivel"].isin(["ALTO", "CRITICO"])]
            primer = alto.groupby("account_token")["dia"].min()
            res["primer_dia_en_riesgo_alto"] = {k: str(v.date()) for k, v in primer.items()}
        backtest.append(res)

    resumen = {
        "principio": "Anticipar, no adivinar: riesgo previo + alerta temprana + siguiente fase.",
        "parametros": PARAMS,
        "riesgo_actual": {"cuentas_evaluadas": int(len(ultimo)),
                          "cuentas_alto_o_critico": int(len(top)),
                          "por_nivel": ultimo["nivel"].value_counts().reindex(NIVELES, fill_value=0).to_dict()},
        "alertas_tempranas": {
            "horas_confirmadas": int(alertas.loc[alertas["nivel_alerta"].eq("CONFIRMADA"), "hora"].nunique()) if not alertas.empty else 0,
            "horas_solo_aviso": int(alertas.loc[alertas["nivel_alerta"].eq("AVISO"), "hora"].nunique()) if not alertas.empty else 0,
            "horas_evaluadas": int(len(senales)),
            "por_senal": alertas["senal"].value_counts().to_dict() if not alertas.empty else {}},
        "matriz_transicion": {"transiciones_observadas": observadas,
                              "peso_prior": PARAMS["peso_prior_transiciones"],
                              "probabilidades": M.round(2).to_dict(orient="index")},
        "pronostico_siguiente_fase": pronostico,
        "backtest_incidentes": backtest,
        "backtest_siguiente_fase": backtest_fases(campanas),
    }
    (carpeta / "anticipacion.json").write_text(json.dumps(resumen, indent=2, ensure_ascii=False, default=str),
                                               encoding="utf-8")
    print(f"     Cuentas en riesgo ALTO/CRÍTICO hoy: {len(top)} de {len(ultimo)}")
    at = resumen["alertas_tempranas"]
    print(f"     Alertas tempranas: {at['horas_confirmadas']} horas CONFIRMADAS y {at['horas_solo_aviso']} horas de AVISO, de {at['horas_evaluadas']} horas")
    for b in backtest:
        print(f"     {b['campana']}: {json.dumps({k: v for k, v in b.items() if k not in ('campana', 'incidente')}, ensure_ascii=False, default=str)}")
    print(f"     Backtest siguiente fase (top 3): {resumen['backtest_siguiente_fase']['aciertos_top3']}")
    return resumen
