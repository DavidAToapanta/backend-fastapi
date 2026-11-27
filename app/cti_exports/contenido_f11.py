"""Texto editorial del ejercicio que revisa el Rol 5 antes de la entrega."""

TECNICAS = {
    "T1021": "Uso de servicios remotos.",
    "T1021.001": "Servicios remotos mediante RDP.",
    "T1021.002": "Uso de recursos compartidos SMB.",
    "T1021.004": "Servicios remotos mediante SSH.",
    "T1046": "Reconocimiento de servicios de red.",
    "T1048.002": "Egreso simulado por canal cifrado ajeno a C2.",
    "T1074": "Preparación de datos antes de transferencias.",
    "T1078": "Uso de cuentas válidas.",
    "T1098": "Manipulación de cuentas y privilegios.",
    "T1110.001": "Intentos repetidos de adivinar contraseñas.",
    "T1110.003": "Intentos de autenticación distribuidos entre cuentas.",
    "T1213": "Consulta de repositorios de información.",
    "T1531": "Eliminación del acceso a cuentas.",
}

HALLAZGOS = {
    "CAMP-2026-001": "Correlación entre acceso SSH, actividad en el sistema médico y una salida externa simulada.",
    "CAMP-2026-002": "Transferencias masivas observadas sobre SSH en la simulación.",
    "CAMP-2026-003": "Intentos repetidos contra un servicio Telnet del ejercicio.",
    "CAMP-2026-004": "Reconocimiento de servicios internos, incluidos RDP, SMB y bases de datos.",
    "CAMP-2026-005": "Cambios de nivel y activaciones o reactivaciones de cuentas especiales.",
}

TEXTO = {
    "resumen": "Ejercicio sintético de octubre de 2026 que correlaciona la actividad del firewall y del sistema médico.",
    "metodologia": (
        "El ciclo CTI orienta la recolección y el análisis. IPE compara cursos de acción. "
        "El Modelo Diamante relaciona actor, capacidad, infraestructura y objetivo. "
        "El Rol 1 registró huellas SHA-256 y seudonimizó identificadores con HMAC-SHA256."
    ),
    "admiralty": (
        "Evaluación por campaña. Se consideraron el BOM, la errata TRANFERENCIA, "
        "las IP sin puntos y los desfases de reloj al valorar cada fuente."
    ),
    "adversarios": (
        "Las campañas permiten comparar abuso interno, credenciales comprometidas e hipótesis "
        "de operación híbrida. La motivación y el objetivo se mantienen como inferencias del ejercicio."
    ),
    "impacto": (
        "El acceso indebido comprometería la confidencialidad de datos de salud. Los cambios de "
        "privilegios afectarían la integridad y una interrupción afectaría la disponibilidad asistencial. "
        "Referencias del ejercicio: política IESS Art. 27, EGSI 1.7 y LOPDP Art. 25, 37 y 40."
    ),
    "comportamiento_observable": "Patrones repetibles de fallos de acceso y cambios de privilegios.",
    "indicador_compromiso": "Observaciones puntuales del conjunto sintético, como el destino externo del caso 001.",
    "alcance_ipe": (
        "Comparación de los dos cursos de acción del ejercicio. La cadena 005 → 001 sigue como hipótesis."
    ),
    "controles": [
        ("Inmediato", "Revisar privilegios, restringir el egreso 8443 y desactivar Telnet 23 y SMBv1 445."),
        ("Corto plazo", "Migrar los servicios simulados tipo IBM i de 8470–8478 a TLS 9470–9476. "
                        "Normalizar NTP, horario de 24 h y marcas UTC."),
        ("Mediano plazo", "Desplegar Sigma, consolidar indicadores STIX en MISP y verificar la bitácora SHA-256."),
    ],
}
