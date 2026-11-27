"""
Guardián de Cuenta: regla para detectar una posible toma de cuenta (Rol 2).

Idea: en los casos de robo, el atacante cambia el celular y/o el correo,
después cambia la cuenta bancaria y al final pide un préstamo, todo en
pocas horas. Si vemos esa secuencia en el mismo afiliado, retenemos el
préstamo y preguntamos al afiliado por su canal anterior.

Son reglas explícitas (no aprendizaje automático), para que el jurado
pueda ver exactamente por qué se activó cada alerta.

Solo datos sintéticos. Los afiliados vienen seudonimizados (AFI-xxxx).
Solo usa la biblioteca estándar de Python.
"""

import re
from datetime import datetime, timedelta, timezone

# --- Tipos de evento que entiende la regla ---------------------------------
CAMBIO_CELULAR = "CAMBIO_CELULAR"
CAMBIO_CORREO = "CAMBIO_CORREO"
CAMBIO_BANCO = "CAMBIO_CUENTA_BANCARIA"
PRESTAMO = "SOLICITUD_PRESTAMO"
CAMBIOS_CONTACTO = {CAMBIO_CELULAR, CAMBIO_CORREO}
TIPOS_CONOCIDOS = CAMBIOS_CONTACTO | {CAMBIO_BANCO, PRESTAMO}

# Eventos que NO cuentan como riesgo (no los hizo una persona en línea):
#  - PROCESO_MASIVO: por ejemplo, un banco cerró y se migraron miles de cuentas.
#  - SISTEMA: renovaciones automáticas.
ORIGENES_EXCLUIDOS = {"PROCESO_MASIVO", "SISTEMA"}

# Canal donde la identidad ya se verificó en persona (huella o biometría).
CANALES_VERIFICADOS = {"AGENCIA_BIOMETRICO"}

# Valores por defecto. Se pueden cambiar sin tocar el código.
CONFIG_POR_DEFECTO = {
    "ventana_horas": 24,          # "todo en pocas horas"
    "horas_rapido": 6,            # secuencia completa en <= 6 h: confianza ALTA
    "dias_phishing": 7,           # reporte de phishing reciente del afiliado
    "funcionario_min_afiliados": 5,   # GUARD-04: cambios a afiliados distintos
    "hora_inicio_laboral": 7,     # fuera de horario: antes de las 07:00
    "hora_fin_laboral": 19,       #                    o desde las 19:00
}

ZONA_ECUADOR = timezone(timedelta(hours=-5))
PATRON_AFILIADO = re.compile(r"^AFI-[0-9A-F]{12}$")
PATRON_CEDULA = re.compile(r"^\d{10}$")

NOMBRES = {
    CAMBIO_CELULAR: "cambio de celular",
    CAMBIO_CORREO: "cambio de correo",
    CAMBIO_BANCO: "cambio de cuenta bancaria",
    PRESTAMO: "solicitud de préstamo",
}


# --- Utilidades --------------------------------------------------------------
def leer_fecha(texto):
    """Convierte '2026-10-24T22:40:00' en fecha. Si trae zona, la pasa a hora de Ecuador."""
    fecha = datetime.fromisoformat(texto)
    if fecha.tzinfo is not None:
        fecha = fecha.astimezone(ZONA_ECUADOR).replace(tzinfo=None)
    return fecha


def validar_afiliado(codigo):
    """Protección de datos: solo aceptamos seudónimos, nunca una cédula."""
    if PATRON_CEDULA.match(str(codigo)):
        raise ValueError("Se recibió algo con forma de cédula. Use el seudónimo AFI-xxxxxxxxxxxx.")
    if not PATRON_AFILIADO.match(str(codigo)):
        raise ValueError(f"Código de afiliado no válido: {codigo!r}")


def preparar_eventos(eventos):
    """Valida, ordena por hora y separa los eventos que no cuentan como riesgo."""
    listos, ignorados = [], []
    for e in eventos:
        validar_afiliado(e["afiliado"])
        if e.get("tipo") not in TIPOS_CONOCIDOS or e.get("origen") in ORIGENES_EXCLUIDOS:
            ignorados.append(e)
            continue
        copia = dict(e)
        copia["_fecha"] = leer_fecha(e["fecha_hora"])
        listos.append(copia)
    listos.sort(key=lambda x: x["_fecha"])
    return listos, ignorados


def canal_de_verificacion(cambios_contacto):
    """A dónde preguntamos '¿Usted hizo este cambio?'. Nunca al dato nuevo."""
    tipos = {c["tipo"] for c in cambios_contacto}
    if tipos == {CAMBIO_CELULAR, CAMBIO_CORREO}:
        return "Celular y correo ANTERIORES; si no responde en 24 h, validación presencial en agencia"
    if CAMBIO_CELULAR in tipos:
        # Si cambiaron el celular puede haber robo de SIM: usamos el correo de siempre.
        return "Correo registrado (sin cambios) y celular ANTERIOR"
    if CAMBIO_CORREO in tipos:
        return "Celular registrado (sin cambios) y correo ANTERIOR"
    return "Celular y correo registrados"


def buscar_vinculo_phishing(afiliado, cambios_banco, fecha_ref, reportes, dias):
    """Vínculo verificable con Centinela. Devuelve un texto de evidencia o None.

    a) La cuenta bancaria nueva (como hash) aparece en un mensaje de phishing reportado.
    b) El mismo afiliado reportó un phishing en los últimos `dias` días.
    """
    for r in reportes or []:
        hashes = set(r.get("cuentas_hash", []))
        if hashes and any(c.get("valor_hash") in hashes and leer_fecha(r["fecha_hora"]) <= c["_fecha"]
                          for c in cambios_banco):
            return (f"La cuenta bancaria nueva aparece en la campaña de phishing {r.get('campana_id', '?')}",
                    r.get("reporte_id"))
    for r in reportes or []:
        if r.get("afiliado") == afiliado:
            fecha_r = leer_fecha(r["fecha_hora"])
            if fecha_ref - timedelta(days=dias) <= fecha_r <= fecha_ref:
                return (f"El afiliado reportó un phishing el {fecha_r:%d-%m %H:%M} (campaña {r.get('campana_id', '?')})",
                        r.get("reporte_id"))
    return None, None


def linea_de_tiempo(eventos):
    return [
        {"id_evento": e.get("id_evento"), "hora": e["_fecha"].isoformat(timespec="minutes"),
         "evento": NOMBRES[e["tipo"]], "canal": e.get("canal", "?")}
        for e in eventos
    ]


def nueva_alerta(regla, afiliado, severidad, confianza, accion, explicacion, eventos, **extra):
    alerta = {
        "regla": regla, "afiliado": afiliado, "severidad": severidad,
        "confianza": confianza, "accion": accion, "explicacion": explicacion,
        "eventos": [e.get("id_evento") for e in eventos],
        "linea_tiempo": linea_de_tiempo(eventos),
    }
    alerta.update(extra)
    return alerta


# --- Reglas ------------------------------------------------------------------
def reglas_de_un_afiliado(afiliado, eventos, reportes, cfg):
    """GUARD-01, GUARD-02 y GUARD-03 para los eventos de un solo afiliado."""
    alertas = []
    ventana = timedelta(hours=cfg["ventana_horas"])
    contactos = [e for e in eventos if e["tipo"] in CAMBIOS_CONTACTO]
    bancos = [e for e in eventos if e["tipo"] == CAMBIO_BANCO]
    prestamos = [e for e in eventos if e["tipo"] == PRESTAMO]

    # GUARD-01 (CRÍTICA): cambio de contacto + cambio de banco + préstamo,
    # los dos cambios dentro de las `ventana_horas` ANTES del préstamo.
    for p in prestamos:
        c_ok = [c for c in contactos if p["_fecha"] - ventana <= c["_fecha"] <= p["_fecha"]]
        b_ok = [b for b in bancos if p["_fecha"] - ventana <= b["_fecha"] <= p["_fecha"]]
        if not (c_ok and b_ok):
            continue
        secuencia = sorted(c_ok + b_ok + [p], key=lambda x: x["_fecha"])
        minutos = int((p["_fecha"] - secuencia[0]["_fecha"]).total_seconds() // 60)
        vinculo, reporte = buscar_vinculo_phishing(afiliado, b_ok, p["_fecha"], reportes, cfg["dias_phishing"])
        todos_verificados = all(e.get("canal") in CANALES_VERIFICADOS for e in c_ok + b_ok)

        if todos_verificados:
            severidad, confianza, accion = "BAJA", "BAJA", "REGISTRAR"
            explicacion = (f"Secuencia de cambios y préstamo en {minutos} min, pero todos los cambios "
                           "se hicieron en agencia con verificación biométrica. Solo se registra.")
        else:
            severidad, accion = "CRITICA", "RETENER_PRESTAMO_Y_VERIFICAR"
            confianza = "ALTA" if (vinculo or minutos <= cfg["horas_rapido"] * 60) else "MEDIA"
            pasos = ", ".join(NOMBRES[e["tipo"]] for e in secuencia)
            explicacion = (f"{pasos[0].upper() + pasos[1:]} en {minutos} min en la misma cuenta. "
                           "Se retiene el préstamo hasta que el afiliado confirme por su canal anterior.")
        alertas.append(nueva_alerta(
            "GUARD-01", afiliado, severidad, confianza, accion, explicacion, secuencia,
            minutos_totales=minutos, vinculo_phishing=vinculo, reporte_phishing_id=reporte,
            canal_verificacion=canal_de_verificacion(c_ok)))

    # GUARD-02 (MEDIA, aviso temprano): contacto + banco cambiados en la ventana.
    # Todavía no hay préstamo: no se bloquea nada, solo se verifica antes de prestar.
    for b in bancos:
        c_ok = [c for c in contactos if b["_fecha"] - ventana <= c["_fecha"] <= b["_fecha"]]
        if not c_ok or all(e.get("canal") in CANALES_VERIFICADOS for e in c_ok + [b]):
            continue
        secuencia = sorted(c_ok + [b], key=lambda x: x["_fecha"])
        alertas.append(nueva_alerta(
            "GUARD-02", afiliado, "MEDIA", "MEDIA", "VERIFICACION_PREVENTIVA",
            "Cambió datos de contacto y la cuenta bancaria en pocas horas. Antes de aprobar "
            "cualquier préstamo, confirmar con el afiliado por su canal anterior.",
            secuencia, canal_verificacion=canal_de_verificacion(c_ok)))

    # GUARD-03 (ALTA): primero el préstamo y DESPUÉS cambian la cuenta bancaria
    # (el atacante desvía el desembolso). La secuencia original no lo cubre.
    for p in prestamos:
        b_ok = [b for b in bancos if p["_fecha"] < b["_fecha"] <= p["_fecha"] + ventana
                and b.get("canal") not in CANALES_VERIFICADOS]
        if b_ok:
            secuencia = [p] + b_ok
            alertas.append(nueva_alerta(
                "GUARD-03", afiliado, "ALTA", "MEDIA", "RETENER_DESEMBOLSO",
                "Se cambió la cuenta bancaria después de pedir un préstamo. Retener el "
                "desembolso hasta confirmar con el afiliado.", secuencia))
    return alertas


def regla_funcionarios(eventos, cfg):
    """GUARD-04 (ALTA, opcional): un funcionario cambia cuentas bancarias de muchos
    afiliados distintos fuera de horario el mismo día (posible insider o red de cuentas)."""
    grupos = {}
    for e in eventos:
        if e["tipo"] != CAMBIO_BANCO or not e.get("funcionario"):
            continue
        hora = e["_fecha"].hour
        if cfg["hora_inicio_laboral"] <= hora < cfg["hora_fin_laboral"]:
            continue
        clave = (e["funcionario"], e["_fecha"].date())
        grupos.setdefault(clave, []).append(e)
    alertas = []
    for (funcionario, dia), lista in grupos.items():
        afiliados = {e["afiliado"] for e in lista}
        if len(afiliados) >= cfg["funcionario_min_afiliados"]:
            alertas.append(nueva_alerta(
                "GUARD-04", None, "ALTA", "MEDIA", "REVISAR_FUNCIONARIO",
                f"El funcionario {funcionario} cambió la cuenta bancaria de {len(afiliados)} "
                f"afiliados distintos fuera de horario el {dia:%d-%m-%Y}.",
                lista, funcionario=funcionario, afiliados_afectados=sorted(afiliados)))
    return alertas


# --- Función principal (la que llama FastAPI) --------------------------------
def evaluar_eventos(eventos, reportes_phishing=None, config=None):
    """Recibe una lista de eventos (diccionarios) y devuelve las alertas.

    Evento: {"id_evento", "afiliado": "AFI-…", "tipo", "fecha_hora": "AAAA-MM-DDTHH:MM:SS",
             "canal": "WEB|APP|CALL_CENTER|AGENCIA|AGENCIA_BIOMETRICO",
             "origen": "AFILIADO|FUNCIONARIO|PROCESO_MASIVO|SISTEMA",
             "valor_hash": "hash HMAC de la cuenta nueva (opcional)",
             "funcionario": "FUN-… (opcional)"}
    """
    cfg = dict(CONFIG_POR_DEFECTO)
    cfg.update(config or {})
    listos, ignorados = preparar_eventos(eventos)

    por_afiliado = {}
    for e in listos:
        por_afiliado.setdefault(e["afiliado"], []).append(e)

    alertas = []
    for afiliado, lista in por_afiliado.items():
        alertas.extend(reglas_de_un_afiliado(afiliado, lista, reportes_phishing, cfg))
    alertas.extend(regla_funcionarios(listos, cfg))

    orden = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BAJA": 3}
    alertas.sort(key=lambda a: (orden[a["severidad"]], a["linea_tiempo"][0]["hora"]))
    for i, a in enumerate(alertas, start=1):
        a["id_alerta"] = f"GRD-{i:04d}"
    return {"alertas": alertas, "eventos_evaluados": len(listos),
            "eventos_ignorados": len(ignorados), "config": cfg}


# --- Demo por consola: python -m app.servicios.guardian_cuenta ----------------
if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path

    ruta = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parents[1] / "datos_demo" / "escenarios_guardian.json"
    datos = json.loads(ruta.read_text(encoding="utf-8"))
    resultado = evaluar_eventos(datos["eventos"], datos.get("reportes_phishing"))
    print(f"Eventos evaluados: {resultado['eventos_evaluados']} | ignorados: {resultado['eventos_ignorados']}")
    for a in resultado["alertas"]:
        print(f"\n[{a['severidad']}] {a['id_alerta']} {a['regla']} {a['afiliado'] or a.get('funcionario')}")
        print(f"  {a['explicacion']}")
        print(f"  Acción: {a['accion']} | Confianza: {a['confianza']}")
        if a.get("vinculo_phishing"):
            print(f"  Vínculo Centinela: {a['vinculo_phishing']}")
        for paso in a["linea_tiempo"]:
            print(f"    {paso['hora']}  {paso['evento']}  ({paso['canal']})")
