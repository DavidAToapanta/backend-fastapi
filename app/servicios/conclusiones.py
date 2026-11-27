from app.servicios.panel import MetricasML, consultar_resumen_panel


class DatosF11NoDisponibles(Exception):
    """Faltan agregados o evidencias requeridos para el informe."""


def hechos_para_conclusiones(resumen: dict[str, object] | None = None) -> dict[str, int]:
    if resumen is None:
        resumen = consultar_resumen_panel()
    ml = resumen["ml"]
    genericas, dominio = ml["genericas"], ml["dominio"]
    if not isinstance(genericas, MetricasML) or not isinstance(dominio, MetricasML):
        raise DatosF11NoDisponibles("Faltan las métricas de ML del ejercicio.")
    casos_genericas, total_genericas = map(int, genericas.incidentes_top_n.split("/"))
    casos_dominio, total_dominio = map(int, dominio.incidentes_top_n.split("/"))
    if resumen["total_eventos"] <= 0 or total_genericas != total_dominio or total_dominio <= 0:
        raise DatosF11NoDisponibles("Los agregados del ejercicio están incompletos.")
    if not 0 <= casos_genericas <= total_genericas or not 0 <= casos_dominio <= total_dominio:
        raise DatosF11NoDisponibles("La cobertura de campañas quedó fuera del rango válido.")
    return {
        "eventos_analizados": resumen["total_eventos"],
        "ips_sin_puntos": resumen["ips_sin_puntos"],
        "horas_observadas": resumen["horas"],
        "campanas_evaluadas": total_dominio,
        "campanas_detectadas_ml_genericas": casos_genericas,
        "campanas_detectadas_ml_dominio": casos_dominio,
        "top_n_genericas": genericas.top_n,
        "top_n_dominio": dominio.top_n,
    }
