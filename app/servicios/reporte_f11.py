import hashlib
import json
import re
from pathlib import Path

import psycopg

from app.core.conexion_postgres import conectar_postgres
from app.cti_exports.contenido_f11 import HALLAZGOS, TECNICAS, TEXTO
from app.cti_exports.graficos import dibujar_graficos
from app.cti_exports.pdf_compiler import Audiencia, renderizar_pdf
from app.servicios.auditoria import AuditoriaNoDisponible, comprobar_cadena_auditoria, listar_eventos_auditoria
from app.servicios.campanas import ESCENARIOS_IPE, consultar_campanas, consultar_linea_tiempo
from app.servicios.conclusiones import DatosF11NoDisponibles, hechos_para_conclusiones
from app.servicios.exportaciones import leer_paquete_stix, leer_reglas_sigma
from app.servicios.panel import consultar_mapa_horario, consultar_resumen_panel
from backend.app.core.security import registrar_evento_auditoria

RUTA_EVIDENCIAS = Path(__file__).resolve().parents[2] / "docs" / "evidencias" / "evidencias.json"


def formato_entero(valor: int) -> str:
    return f"{valor:,}".replace(",", ".")


def verificar_fuentes(resumen: dict) -> list[tuple[str, str, str]]:
    evidencia = json.loads(RUTA_EVIDENCIAS.read_text(encoding="utf-8-sig"))["resumen_datasets"]
    eventos = listar_eventos_auditoria()
    fuentes = []
    for datos, clave, operacion in zip(
        resumen["por_fuente"], ("firewall", "sistema_medico"),
        ("INGEST_FIREWALL_10M", "INGEST_MEDSYS_10M"), strict=True,
    ):
        fuente = evidencia[clave]
        huella = fuente["sha256"]
        if not re.fullmatch(r"[a-f0-9]{64}", huella) or datos["eventos"] != fuente["total_filas"]:
            raise DatosF11NoDisponibles("El conteo de la ingesta difiere de las evidencias.")
        if not any(
            evento["operacion"] == operacion and evento["sha256_dataset"] == huella
            and evento["filas_leidas"] == datos["eventos"] and evento["pii_depurada"]
            for evento in eventos
        ):
            raise DatosF11NoDisponibles("No se encontró la ingesta seudonimizada con la huella esperada.")
        fuentes.append((datos["fuente"], formato_entero(datos["eventos"]), huella))
    if resumen["total_eventos"] != evidencia["total_registros_combinados"]:
        raise DatosF11NoDisponibles("El total de eventos difiere de las evidencias.")
    return fuentes


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
    cronologia = [
        (evento["fecha"].isoformat(sep=" ", timespec="seconds"),
         evento["fuente"], "Sí" if evento["ajuste_de_reloj"] else "No")
        for evento in linea
    ]
    tecnicas = sorted({
        tecnica for campana in campanas for tecnica in campana["tecnicas_mitre"]
        if re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", tecnica)
    })
    sigma = leer_reglas_sigma()
    stix = json.loads(leer_paquete_stix())
    indicadores = sum(objeto.get("type") == "indicator" for objeto in stix["objects"])
    genericas = resumen["ml"]["genericas"]
    dominio = resumen["ml"]["dominio"]
    anomalias = genericas.anomalias_sin_confirmar
    escenarios = [
        (escenario["nombre"], probabilidad, impacto, escenario["descripcion"])
        for escenario, (probabilidad, impacto) in zip(
            ESCENARIOS_IPE, (("Alta", "Alto"), ("Media", "Crítico")), strict=True,
        )
    ]

    datos = {
        **TEXTO,
        "indicadores": [
            (formato_entero(resumen["total_eventos"]), "Eventos analizados"),
            (len(campanas), "Campañas correlacionadas"),
            (formato_entero(resumen["ips_sin_puntos"]), "IP sin puntos"),
        ],
        "fuentes": fuentes,
        "tecnicas": [(tecnica, TECNICAS.get(tecnica, "Técnica registrada en el catálogo.")) for tecnica in tecnicas],
        "campanas": [
            (campana["codigo"], campana["calificacion_admiralty"], HALLAZGOS[campana["codigo"]])
            for campana in campanas
        ],
        "nota_temporal": "La cronología de 001 conserva el orden de los eventos y marca el ajuste de 12 h.",
        "cronologia": cronologia,
        "metricas": (
            f"IsolationForest sin reglas. Variables genéricas: {genericas.incidentes_top_n} campañas "
            f"en Top-{genericas.top_n}. Variables de dominio: {dominio.incidentes_top_n} "
            f"en Top-{dominio.top_n}. Las anomalías sin confirmar del modelo genérico "
            f"({anomalias.firewall_por_hora} FW/h, {anomalias.medsys_por_hora} médico/h y "
            f"{anomalias.medsys_por_periodo} médico/período) requieren revisión."
        ),
        "exportaciones": (
            f"Sigma: {len(sigma['ioa'])} archivos IoA y {len(sigma['ioc'])} IoC. "
            f"STIX 2.1: {indicadores} indicadores etiquetados como datos sintéticos."
        ),
        "muestra_sigma": [
            ("IoA", sigma["ioa"][0]["titulo"]), ("IoC", sigma["ioc"][0]["titulo"]),
        ],
        "escenarios": escenarios,
    }
    return datos, mapa, hechos


def huella_insumos(datos: dict, mapa: dict, hechos: dict[str, int]) -> str:
    contenido = json.dumps(
        {"version": 2, "reporte": datos, "horas": mapa, "hechos": hechos},
        default=lambda fecha: fecha.isoformat(),
        ensure_ascii=False, sort_keys=True,
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
        conclusiones=cache.text,
        estado="Versión revisada · Datos sintéticos" if cache.revisado else "Pendiente de revisión del Rol 5",
        grafico_horario=horario,
        grafico_ipe=matriz_ipe,
        nota_solicitante=summary,
        huella_insumos=huella,
        estado_evidencias=(
            f"Cadena SHA-256 íntegra antes de generar el documento: "
            f"{verificacion['checked_rows']} registros verificados. "
            "La huella de esta descarga se conserva en su evento de auditoría."
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
    return {"cuentas": cuentas}, {"sourceSha256": hashlib.sha256(archivo).hexdigest()}


def generar_reporte_auditado(
    audiencia: Audiencia = "technical", summary: str | None = None,
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
