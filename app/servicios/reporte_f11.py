import hashlib
import json
import os
import re
from datetime import timedelta
from pathlib import Path

import psycopg

from app.core.conexion_postgres import conectar_postgres
from app.cti_exports.contenido_f11 import (
    ACCIONES_PRIORITARIAS,
    BRECHAS_LIMITACIONES,
    CAMPANAS_PRIORIDAD,
    CATALOGO_IOA,
    DETALLE_OPERATIVO_CAMPANAS,
    FUENTES_ADMIRALTY,
    HALLAZGOS,
    IMPACTO_ESTRATEGICO,
    JUICIO_CLAVE,
    MARCO_LEGAL,
    MATRIZ_TACTICA,
    METADATA_F11,
    MODELO_DIAMANTE,
    TABLA_ANTICIPACION,
    TABLA_IOC,
    TECNICAS,
    TEXTO,
)
from app.cti_exports.graficos import dibujar_graficos
from app.cti_exports.pdf_compiler import Audiencia, renderizar_pdf
from app.servicios.auditoria import AuditoriaNoDisponible, comprobar_cadena_auditoria, listar_eventos_auditoria
from app.servicios.campanas import ESCENARIOS_IPE, consultar_campanas, consultar_linea_tiempo
from app.servicios.conclusiones import DatosF11NoDisponibles, hechos_para_conclusiones
from app.servicios.exportaciones import leer_paquete_stix, leer_reglas_sigma
from app.servicios.panel import consultar_mapa_horario, consultar_resumen_panel
from backend.app.core.security import registrar_evento_auditoria

RUTA_EVIDENCIAS = Path(__file__).resolve().parents[2] / "docs" / "evidencias" / "evidencias.json"
IP_EXTERNA_RE = re.compile(r"\b186\.46\.219\.18\b")

NOMBRE_FUENTE_LEGIBLE = {
    "FIREWALL": "Firewall perimetral",
    "MEDSYS": "Sistema médico",
}


def formato_entero(valor: int) -> str:
    return f"{valor:,}".replace(",", ".")


def defang_ips(texto: str) -> str:
    """Garantiza que la IP pública sintética aparezca siempre defangeada."""
    return IP_EXTERNA_RE.sub("186.46.219[.]18", texto)


def _leer_json_opcional(nombre: str) -> dict | None:
    ruta = Path(os.getenv("METRICAS_ML_DIR", "data/exports")) / nombre
    try:
        datos = json.loads(ruta.read_text(encoding="utf-8-sig"))
        return datos if isinstance(datos, dict) else None
    except (OSError, ValueError):
        return None


def _extraer_anticipacion(anticipacion: dict | None) -> tuple[int, int, str, list[tuple[str, str]]]:
    """Obtiene métricas de anticipación de JSON si existe o usa los valores verificados."""
    dias = 16
    falsas_744 = 2
    siguiente_fase = "4/5"
    if isinstance(anticipacion, dict):
        alertas = anticipacion.get("alertas_tempranas")
        if isinstance(alertas, dict) and type(alertas.get("falsas_alarmas_744h")) is int:
            falsas_744 = alertas["falsas_alarmas_744h"]
        sig = anticipacion.get("backtest_siguiente_fase")
        if isinstance(sig, dict) and isinstance(sig.get("aciertos_top_3"), str):
            siguiente_fase = sig["aciertos_top_3"]
    tabla = [
        ("Riesgo previo por cuenta", f"Cuenta del incidente B en riesgo CRÍTICO {dias} días antes; las de E, desde el día 1."),
        ("Alerta temprana", f"Incidentes A, B, C y D alertados en la misma hora; {falsas_744} falsas alarmas en 744 h."),
        ("Siguiente fase", f"Acierta {siguiente_fase} en su Top-3 de transición, con un control recomendado por fase."),
        ("Velocidad del ataque", "Caso 001: 30 s del SSH a la exfiltración → la contención debe ser automática."),
    ]
    return dias, falsas_744, siguiente_fase, tabla


def _extraer_calidad(calidad_json: dict | None, evidencias_doc: dict) -> tuple[str, int, int, int, int]:
    """Devuelve texto de calidad FW/MedSys, duplicados FW/Med y cuentas especiales."""
    resumen_ds = evidencias_doc.get("resumen_datasets", {})
    dup_fw = int(resumen_ds.get("firewall", {}).get("duplicados_exactos", 2607))
    dup_med = int(resumen_ds.get("sistema_medico", {}).get("duplicados_exactos", 5220))
    cuentas_esp = int(resumen_ds.get("sistema_medico", {}).get("cuentas_especiales_unicas", 16))
    puntaje_fw = "99,99%"
    puntaje_med = "99,97%"
    if isinstance(calidad_json, dict):
        fw_q = calidad_json.get("firewall", {}).get("puntaje_calidad")
        med_q = calidad_json.get("sistema_medico", {}).get("puntaje_calidad")
        if isinstance(fw_q, (int, float)):
            puntaje_fw = f"{fw_q:.2f}%".replace(".", ",")
        if isinstance(med_q, (int, float)):
            puntaje_med = f"{med_q:.2f}%".replace(".", ",")
    return f"{puntaje_fw} / {puntaje_med}", dup_fw, dup_med, cuentas_esp, int(
        resumen_ds.get("firewall", {}).get("total_filas", 5009031)
    )


def _extraer_ioas(hallazgos_json: dict | None) -> tuple[str, list[tuple[str, str, str, str]], int, int]:
    """Extrae cobertura IoA y umbral actualizado desde hallazgos_reglas.json si existe."""
    cobertura_ioa = "5/5"
    cuentas_compartidas = 11
    max_identidades = 1737
    if isinstance(hallazgos_json, dict):
        if isinstance(hallazgos_json.get("incidentes_detectados_por_ioa"), str):
            cobertura_ioa = hallazgos_json["incidentes_detectados_por_ioa"]
        hallazgos_ioa = hallazgos_json.get("hallazgos_ioa")
        if isinstance(hallazgos_ioa, list):
            ioa06 = [h for h in hallazgos_ioa if isinstance(h, dict) and h.get("regla") == "IOA-06"]
            if ioa06:
                cuentas_compartidas = len(ioa06)
                identidades = []
                for h in ioa06:
                    m = re.search(r"(\d+)\s+identidades", str(h.get("descripcion", "")))
                    if m:
                        identidades.append(int(m.group(1)))
                if identidades:
                    max_identidades = max(identidades)
    return cobertura_ioa, CATALOGO_IOA, cuentas_compartidas, max_identidades


def verificar_fuentes(resumen: dict) -> list[tuple[str, str, str]]:
    evidencia = json.loads(RUTA_EVIDENCIAS.read_text(encoding="utf-8-sig"))["resumen_datasets"]
    eventos = listar_eventos_auditoria()
    fuentes = []
    for datos, clave, operacion in zip(
        resumen["por_fuente"],
        ("firewall", "sistema_medico"),
        ("INGEST_FIREWALL_10M", "INGEST_MEDSYS_10M"),
        strict=True,
    ):
        fuente = evidencia[clave]
        huella = fuente["sha256"]
        if not re.fullmatch(r"[a-f0-9]{64}", huella) or datos["eventos"] != fuente["total_filas"]:
            raise DatosF11NoDisponibles("El conteo de la ingesta difiere de las evidencias.")
        if not any(
            evento["operacion"] == operacion
            and evento["sha256_dataset"] == huella
            and evento["filas_leidas"] == datos["eventos"]
            and evento["pii_depurada"]
            for evento in eventos
        ):
            raise DatosF11NoDisponibles("No se encontró la ingesta seudonimizada con la huella esperada.")
        fuentes.append((datos["fuente"], formato_entero(datos["eventos"]), huella))
    if resumen["total_eventos"] != evidencia["total_registros_combinados"]:
        raise DatosF11NoDisponibles("El total de eventos difiere de las evidencias.")
    return fuentes


def _formatear_cronologia_local(linea: list[dict]) -> list[tuple[str, str, str, str]]:
    """Convierte eventos de campaña 001 a hora local sin +00:00 ni UTC mostrando el +12 h."""
    filas = []
    for evento in linea:
        dt = evento["fecha"]
        dt_local = dt.replace(tzinfo=None)
        ajustado = bool(evento["ajuste_de_reloj"])
        if ajustado:
            hora_original = (dt_local - timedelta(hours=12)).strftime("%Y-%m-%d %H:%M:%S")
            hora_ajustada = f"{dt_local.strftime('%Y-%m-%d %H:%M:%S')} (+12 h)"
        else:
            hora_original = dt_local.strftime("%Y-%m-%d %H:%M:%S")
            hora_ajustada = "—"
        fuente_legible = NOMBRE_FUENTE_LEGIBLE.get(evento["fuente"], str(evento["fuente"]))
        detalle = defang_ips(str(evento.get("resumen") or "Evento correlacionado"))
        filas.append((hora_original, hora_ajustada, fuente_legible, detalle))
    return filas


def recopilar_insumos() -> tuple[dict, dict, dict[str, int]]:
    resumen = consultar_resumen_panel()
    hechos = hechos_para_conclusiones(resumen)
    fuentes = verificar_fuentes(resumen)
    mapa = consultar_mapa_horario()
    if len(mapa["dias"]) != 31 or resumen["horas"] != 744:
        raise DatosF11NoDisponibles("El agregado horario de octubre está incompleto.")

    campanas = consultar_campanas()
    if {campana["codigo"] for campana in campanas} != HALLAZGOS.keys():
        raise DatosF11NoDisponibles("Faltan campañas del ejercicio.")
    linea = consultar_linea_tiempo("CAMP-2026-001")
    if not linea:
        raise DatosF11NoDisponibles("La cronología del caso 001 no está disponible.")

    evidencias_doc = json.loads(RUTA_EVIDENCIAS.read_text(encoding="utf-8-sig"))
    calidad_json = _leer_json_opcional("calidad_datos.json")
    hallazgos_json = _leer_json_opcional("hallazgos_reglas.json")
    anticipacion_json = _leer_json_opcional("anticipacion.json")

    calidad_texto, dup_fw, dup_med, cuentas_esp, _ = _extraer_calidad(calidad_json, evidencias_doc)
    cobertura_ioa, catalogo_ioa, _, _ = _extraer_ioas(hallazgos_json)
    dias_antic, falsas_744, _, tabla_anticipacion = _extraer_anticipacion(anticipacion_json)

    cronologia = _formatear_cronologia_local(linea)
    tecnicas = sorted(
        {
            tecnica
            for campana in campanas
            for tecnica in campana["tecnicas_mitre"]
            if re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", tecnica)
        }
    )
    sigma = leer_reglas_sigma()
    stix = json.loads(leer_paquete_stix())
    indicadores_stix = sum(objeto.get("type") == "indicator" for objeto in stix["objects"])
    total_objetos_stix = len(stix["objects"])
    genericas = resumen["ml"]["genericas"]
    dominio = resumen["ml"]["dominio"]
    anomalias = genericas.anomalias_sin_confirmar

    escenarios = [
        (escenario["nombre"], probabilidad, impacto, defang_ips(escenario["descripcion"]))
        for escenario, (probabilidad, impacto) in zip(
            ESCENARIOS_IPE,
            (("Alta", "Alto"), ("Media", "Crítico")),
            strict=True,
        )
    ]

    fw_ips = next((f["ips_sin_puntos"] for f in resumen["por_fuente"] if f["fuente"] == "FIREWALL"), 0)
    med_ips = next((f["ips_sin_puntos"] for f in resumen["por_fuente"] if f["fuente"] == "MEDSYS"), 0)

    datos = {
        **TEXTO,
        "metadata": dict(METADATA_F11),
        "juicio_clave": JUICIO_CLAVE,
        "indicadores": [
            ("1 crítica", "Exfiltración simulada (24-oct)"),
            (f"{dominio.incidentes_top_n} · {cobertura_ioa}", "Campañas detectadas (ML / IoA)"),
            ("0 / 10.000", "Falsas alarmas en cuentas normales"),
            (f"{dias_antic} días", "Anticipación previa al ataque"),
        ],
        "campanas_prioridad": CAMPANAS_PRIORIDAD,
        "cifras_clave": [
            (formato_entero(resumen["total_eventos"]), "Registros"),
            (calidad_texto, "Calidad FW / Med"),
            (cobertura_ioa, "Reglas IoA"),
            (f"{genericas.incidentes_top_n} ({dominio.incidentes_top_n} dom.)", "ML sin reglas"),
            ("0 / 10.000", "Normales marcadas"),
            (f"{dias_antic} días", "Anticipación"),
            (f"{falsas_744} en {resumen['horas']} h", "Falsas alarmas"),
        ],
        "acciones_prioritarias": ACCIONES_PRIORITARIAS,
        "fuentes_admiralty": FUENTES_ADMIRALTY,
        "modelo_diamante": MODELO_DIAMANTE,
        "impacto_estrategico": IMPACTO_ESTRATEGICO,
        "tecnicas": [(tecnica, TECNICAS.get(tecnica, "Técnica registrada en el catálogo.")) for tecnica in tecnicas],
        "matriz_tactica": MATRIZ_TACTICA,
        "detalle_operativo": DETALLE_OPERATIVO_CAMPANAS,
        "nota_temporal": (
            "Cronología del incidente CAMP-2026-001 en hora local del registro: conserva el orden causal "
            "de los cuatro eventos y muestra la hora original del sistema médico junto al ajuste selectivo de +12 h."
        ),
        "cronologia": cronologia,
        "tabla_ioc": TABLA_IOC,
        "catalogo_ioa": catalogo_ioa,
        "metricas": (
            f"IsolationForest sin reglas: variables genéricas detectan {genericas.incidentes_top_n} campañas "
            f"en Top-{genericas.top_n} y variables de dominio detectan {dominio.incidentes_top_n} en Top-{dominio.top_n} "
            f"(las {cuentas_esp} cuentas especiales ocupan los puestos 1 a {cuentas_esp} de 10.016 cuentas). "
            f"En anomalías sin confirmar del modelo genérico ({anomalias.firewall_por_hora} FW/h, "
            f"{anomalias.medsys_por_hora} médico/h y {anomalias.medsys_por_periodo} médico/período), las primeras "
            f"{cuentas_esp} coinciden con las cuentas especiales confirmadas por las reglas IoA; el resto queda para revisión."
        ),
        "exportaciones": (
            f"Sigma: {len(sigma['ioa'])} archivos IoA y {len(sigma['ioc'])} IoC "
            f"({len(sigma['ioa']) + len(sigma['ioc'])} reglas). "
            f"STIX 2.1: {total_objetos_stix} objetos ({indicadores_stix} indicadores) compatibles con MISP bajo TLP:AMBER."
        ),
        "muestra_sigma": [
            ("IoA", sigma["ioa"][0]["titulo"]),
            ("IoC", sigma["ioc"][0]["titulo"]),
        ],
        "escenarios": escenarios,
        "tabla_anticipacion": tabla_anticipacion,
        "brechas": BRECHAS_LIMITACIONES,
        "anexo_hashes": fuentes,
        "anexo_calidad": [
            ("Calidad estructural", f"{calidad_texto} (BOM UTF-8 y errata TRANFERENCIA normalizados en ETL)"),
            (
                "IP sin puntos normalizadas",
                f"{formato_entero(resumen['ips_sin_puntos'])} registros reparados "
                f"({formato_entero(fw_ips)} Firewall y {formato_entero(med_ips)} Sistema médico)",
            ),
            ("Duplicados exactos registrados", f"{formato_entero(dup_fw)} en Firewall y {formato_entero(dup_med)} en Sistema médico"),
            ("Privacidad y seudonimización", "0 PII expuesta; identidades y cuentas técnicas con HMAC-SHA256 truncado a 12 hex"),
            ("Cumplimiento normativo", MARCO_LEGAL),
        ],
    }
    return datos, mapa, hechos


def huella_insumos(datos: dict, mapa: dict, hechos: dict[str, int]) -> str:
    contenido = json.dumps(
        {"version": 3, "reporte": datos, "horas": mapa, "hechos": hechos},
        default=lambda fecha: fecha.isoformat(),
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(contenido.encode("utf-8")).hexdigest()


def preparar_f11(verificacion: dict, summary: str | None) -> tuple[dict, dict]:
    from app.cti_exports.cache_f11 import leer_cache

    datos, mapa, hechos = recopilar_insumos()
    huella = huella_insumos(datos, mapa, hechos)
    cache = leer_cache(huella)
    horario, matriz_ipe = dibujar_graficos(mapa, datos["escenarios"])
    datos_pdf = dict(
        datos,
        conclusiones=defang_ips(cache.text),
        estado=(
            "Edición técnica validada · TLP:AMBER · Datos sintéticos"
            if cache.revisado
            else "Edición técnica generada · TLP:AMBER · Datos sintéticos"
        ),
        grafico_horario=horario,
        grafico_ipe=matriz_ipe,
        nota_solicitante=defang_ips(summary) if isinstance(summary, str) and summary.strip() else None,
        huella_insumos=huella,
        estado_evidencias=(
            f"Cadena SHA-256 íntegra verificada antes de emitir este documento: "
            f"{verificacion['checked_rows']} registros auditados. "
            "La huella criptográfica de esta descarga queda registrada en su evento de auditoría."
        ),
    )
    return datos_pdf, {"sourceSha256": huella, "reviewed": cache.revisado}


def preparar_ejecutivo_medico() -> tuple[dict, dict]:
    archivo = RUTA_EVIDENCIAS.read_bytes()
    evidencia = json.loads(archivo)
    cuentas = evidencia["resumen_datasets"]["sistema_medico"]["cuentas_especiales_unicas"]
    incidente = evidencia["verificacion_5_incidentes"]["incidente_D_exfiltracion_8443_desfase_12h"]
    if type(cuentas) is not int or cuentas < 1 or not any(
        evento["accion"] == "DESCARGA EXITOSA" and evento["fecha"] == "20261024"
        for evento in incidente["med_eventos_account"]
    ):
        raise DatosF11NoDisponibles("Falta evidencia para el informe de octubre.")

    hallazgos_json = _leer_json_opcional("hallazgos_reglas.json")
    _, _, cuentas_compartidas, max_identidades = _extraer_ioas(hallazgos_json)
    anticipacion_json = _leer_json_opcional("anticipacion.json")
    dias_antic, _, _, _ = _extraer_anticipacion(anticipacion_json)

    datos = {
        "cuentas": cuentas,
        "cuentas_compartidas": cuentas_compartidas,
        "max_identidades_cuenta": formato_entero(max_identidades),
        "millones_registros": "10 millones",
        "ataques_detectados": "5 de 5",
        "cuentas_normales_falsas": "0 de 10.000",
        "dias_anticipacion": dias_antic,
        "fecha_evento": "24 de octubre",
        "hora_evento": "22:40 (hora local del registro)",
        "clasificacion": METADATA_F11["clasificacion"],
        "version": METADATA_F11["version"],
        "fecha_emision": METADATA_F11["fecha_emision"],
    }
    return datos, {"sourceSha256": hashlib.sha256(archivo).hexdigest()}


def generar_reporte_auditado(
    audiencia: Audiencia = "technical",
    summary: str | None = None,
) -> tuple[bytes, str, int, str]:
    verificacion = comprobar_cadena_auditoria()
    if not verificacion["intact"]:
        raise AuditoriaNoDisponible("La cadena de auditoría no está íntegra.")

    if audiencia == "technical":
        datos_pdf, metadata = preparar_f11(verificacion, summary)
        nombre = "Reporte_CTI_Tecnico_F11_AegisHealth.pdf"
        operacion = "EXPORT_TECHNICAL_F11_PDF"
    elif audiencia == "medical":
        datos_pdf, metadata = preparar_ejecutivo_medico()
        nombre = "Reporte_Ejecutivo_Medico_AegisHealth.pdf"
        operacion = "EXPORT_MEDICAL_PDF"
    else:
        raise ValueError("Audiencia desconocida.")

    contenido = renderizar_pdf(datos_pdf, audiencia)
    sha256 = hashlib.sha256(contenido).hexdigest()
    try:
        with conectar_postgres() as conexion:
            audit_id, _ = registrar_evento_auditoria(
                conexion,
                operation=operacion,
                dataset_name=nombre,
                dataset_sha256=sha256,
                total_rows_read=0,
                rows_persisted=0,
                metadata=metadata,
            )
    except (psycopg.Error, ValueError) as error:
        raise AuditoriaNoDisponible from error
    return contenido, nombre, audit_id, sha256
