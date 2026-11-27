"""Contenido editorial estructurado para el Reporte Técnico CTI (Ficha F-11).

Sigue el principio BLUF (conclusión y acciones prioritarias primero en la Sección 0),
mantiene el orden formal 1..8 de la ficha F-11 y ubica integridad y calidad en Anexos A y B.
"""

METADATA_F11 = {
    "codigo_ficha": "F-11",
    "clasificacion": "TLP:AMBER",
    "version": "1.0",
    "periodo": "01–31 oct 2026",
    "destinatario": "SOC / Seguridad de la Información IESS",
    "fecha_emision": "27-nov-2026",
    "nota_datos": "Datos sintéticos de ejercicio",
}

TECNICAS = {
    "T1021": "Uso de servicios remotos en la red interna.",
    "T1021.001": "Servicios remotos mediante RDP (250 registros sobre 3389/tcp).",
    "T1021.002": "Uso de recursos compartidos SMB (250 intentos sobre SMBv1 445/tcp).",
    "T1021.004": "Servicios remotos mediante SSH.",
    "T1046": "Reconocimiento de servicios de red (137/udp, 445/tcp, 3389/tcp, 8471/tcp).",
    "T1048.002": "Exfiltración por canal cifrado ajeno a C2 (186.46.219[.]18:8443/tcp).",
    "T1074": "Preparación o acumulación previa a transferencias en el servidor clínico.",
    "T1078": "Uso de cuentas válidas para acceso o administración.",
    "T1098": "Manipulación de cuentas y privilegios (131 cambios de nivel, 1.098 activaciones, 826 reactivaciones).",
    "T1110.001": "Fuerza bruta por adivinación de contraseñas (2.000 intentos en Telnet 23/tcp).",
    "T1110.003": "Password spraying distribuido sobre cuentas técnicas.",
    "T1213": "Consulta y descarga desde el repositorio de información clínica (10.10.100.30).",
    "T1531": "Eliminación o inactivación masiva del acceso a cuentas.",
}

HALLAZGOS = {
    "CAMP-2026-001": "Acceso SSH, descarga clínica y salida externa hacia 186.46.219[.]18:8443 en 30 segundos (ajuste +12 h).",
    "CAMP-2026-002": "30 sesiones SSH y 2.970 transferencias interrumpidas desde 10.10.100.50 hacia el servidor clínico.",
    "CAMP-2026-003": "2.000 intentos negados sobre Telnet 23/tcp correlacionados con 2.000 accesos fallidos en cuenta técnica.",
    "CAMP-2026-004": "Escaneo horizontal multiservicio (137, 445, 3389, 8471) y password spraying desde 10.10.100.20.",
    "CAMP-2026-005": "Abuso persistente en 16 cuentas especiales: 11 compartidas por decenas o cientos de usuarios (hasta 1.737).",
}

JUICIO_CLAVE = (
    "Es probable que la plataforma médica enfrente abuso interno persistente de cuentas privilegiadas "
    "(CAMP-2026-005: 11 cuentas especiales compartidas por hasta 1.737 identidades, activas desde el 1-oct). "
    "Es posible que esa actividad esté vinculada a la posible exfiltración del 24-oct (CAMP-2026-001: SSH al "
    "servidor clínico → descarga → salida hacia 186.46.219[.]18:8443 en 30 segundos). Confianza en el vínculo: "
    "baja-media (solo 1 de 811 conexiones al puerto 8443 sale al exterior)."
)

CAMPANAS_PRIORIDAD = [
    {
        "prioridad": 1,
        "codigo": "CAMP-2026-001",
        "resumen": "SSH → descarga → salida externa por 8443",
        "fecha_local": "24-oct 22:40",
        "severidad": "CRÍTICA",
        "confianza": "Alta",
        "accion": "Bloquear el egreso no autorizado e investigar la descarga",
    },
    {
        "prioridad": 2,
        "codigo": "CAMP-2026-005",
        "resumen": "Abuso de 11 cuentas especiales compartidas (activaciones, reactivaciones, cambios de nivel)",
        "fecha_local": "1–31 oct",
        "severidad": "ALTA",
        "confianza": "Alta",
        "accion": "Suspender, rotar credenciales y exigir cuentas nominales + MFA",
    },
    {
        "prioridad": 3,
        "codigo": "CAMP-2026-004",
        "resumen": "Escaneo de RDP, SMB, BD y NetBIOS + spraying",
        "fecha_local": "19-oct 14:00",
        "severidad": "ALTA",
        "confianza": "Alta",
        "accion": "Aislar 10.10.100.20; cerrar SMBv1",
    },
    {
        "prioridad": 4,
        "codigo": "CAMP-2026-002",
        "resumen": "30 sesiones SSH + 2.970 transferencias interrumpidas",
        "fecha_local": "7-oct 13:00",
        "severidad": "ALTA",
        "confianza": "Alta",
        "accion": "Limitar SSH al servidor por bastión; DLP",
    },
    {
        "prioridad": 5,
        "codigo": "CAMP-2026-003",
        "resumen": "Fuerza bruta Telnet (2.000 intentos)",
        "fecha_local": "10-oct 00:00",
        "severidad": "ALTA",
        "confianza": "Alta",
        "accion": "Desactivar Telnet 23",
    },
]

ACCIONES_PRIORITARIAS = [
    "Bloquear el egreso desde la red clínica salvo lista blanca; IoC 186.46.219[.]18:8443 (regla ioc_01).",
    "Suspender las 16 cuentas especiales compartidas, rotar credenciales, exigir cuentas nominales y MFA.",
    "Restringir el acceso al servidor 10.10.100.30 (SSH/RDP/SMB) a un bastión; desactivar Telnet 23 y SMBv1.",
    "Desplegar las 10 reglas Sigma y cargar el paquete STIX 2.1 (TLP:AMBER) en MISP.",
    "Conservar la evidencia y evaluar la notificación a la Superintendencia de Protección de Datos Personales (LOPDP art. 43: máximo 5 días).",
]

FUENTES_ADMIRALTY = [
    (
        "Registros del firewall (5.009.031)",
        "Interna (técnica)",
        "B2",
        "Fuente fiable; información probable (2.607 duplicados, 493 IP sin puntos reparadas).",
    ),
    (
        "Registros del sistema médico (5.014.501)",
        "Interna (técnica)",
        "B3",
        "Fuente fiable; credibilidad media por el desfase de 12 h y el formato de las IP.",
    ),
    (
        "Mentorías del IESS",
        "HUMINT",
        "B2",
        "Validación de contexto operativo por especialistas de la institución.",
    ),
    (
        "MITRE ATT&CK",
        "OSINT",
        "A1",
        "Marco de referencia de la industria para técnicas y tácticas.",
    ),
]

MODELO_DIAMANTE = [
    (
        "001",
        "Híbrido: insider o cuenta comprometida",
        "SSH + cuenta válida + egreso cifrado",
        "10.10.100.40 → 186.46.219[.]18:8443",
        "Servidor clínico 10.10.100.30",
        "Venta o extorsión de datos de salud",
    ),
    (
        "005",
        "Insider con privilegios",
        "Administración de cuentas",
        "11 cuentas especiales compartidas",
        "Control de acceso del sistema médico",
        "Persistencia / preparación de accesos",
    ),
    (
        "004",
        "Actor con presencia interna",
        "Escaneo + spraying",
        "10.10.100.20",
        "Servicios RDP, SMB, BD (8471)",
        "Reconocimiento previo a un acceso",
    ),
    (
        "002",
        "Actor con presencia interna",
        "Automatización por SSH",
        "10.10.100.50",
        "Repositorio clínico",
        "Extracción masiva",
    ),
    (
        "003",
        "Actor con presencia interna",
        "Fuerza bruta",
        "10.10.100.10",
        "Telnet del servidor",
        "Obtener credenciales",
    ),
]

IMPACTO_ESTRATEGICO = [
    (
        "Confidencialidad",
        "ALTO",
        "1 posible exfiltración el 24-oct hacia 186.46.219[.]18:8443 tras descarga en el sistema médico.",
    ),
    (
        "Integridad",
        "MEDIO-ALTO",
        "131 cambios de nivel, 1.098 activaciones y 826 reactivaciones usando 11 cuentas compartidas (hasta 1.737 identidades).",
    ),
    (
        "Disponibilidad",
        "POR CONFIRMAR",
        "Sin evidencia de caída en las 744 horas analizadas; requiere confirmación operativa con jefaturas clínicas.",
    ),
]

MARCO_LEGAL = (
    "Obligación regulatoria clave: si se confirma vulneración o fuga de datos personales de salud, "
    "el art. 43 de la LOPDP (reformado por la Ley Orgánica para el Fortalecimiento de la Ciberseguridad "
    "del 22 de mayo de 2026) exige notificar a la Superintendencia de Protección de Datos Personales tan "
    "pronto sea posible y como máximo hasta en 5 días. Se consideran además los arts. 25 y 30 (datos relativos "
    "a la salud como categoría especial), art. 40 (análisis de riesgos), "
    "la Política de Seguridad del IESS art. 27 y el estándar EGSI 1.7."
)

MATRIZ_TACTICA = [
    ("Reconocimiento", "—", "—", "—", "T1046", "—"),
    ("Acceso a credenciales", "—", "—", "T1110.001", "T1110.001, T1110.003", "—"),
    ("Cuentas válidas", "T1078", "—", "—", "T1078", "T1078"),
    ("Persistencia / privilegios", "—", "—", "—", "—", "T1098"),
    ("Movimiento lateral", "T1021.004", "T1021.004", "T1021", "T1021.001, T1021.002", "—"),
    ("Recolección", "T1213", "T1213, T1074", "—", "—", "—"),
    ("Exfiltración", "T1048.002", "—", "—", "—", "—"),
    ("Impacto", "—", "—", "—", "—", "T1531"),
]

DETALLE_OPERATIVO_CAMPANAS = [
    (
        "CAMP-2026-001",
        "24-oct 22:40",
        "SSH permitido + descarga + egreso en 30 s (desfase +12 h corregido)",
        "IOA-05",
        "Alta",
        HALLAZGOS["CAMP-2026-001"],
    ),
    (
        "CAMP-2026-005",
        "01–31 oct",
        "14.501 eventos en 16 cuentas; 131 cambios de nivel, 1.098 activaciones, 826 reactivaciones",
        "IOA-06, IOA-07, IOA-08",
        "Alta",
        HALLAZGOS["CAMP-2026-005"],
    ),
    (
        "CAMP-2026-004",
        "19-oct 14:00",
        "1.000 eventos en 4 puertos críticos (137, 445, 3389, 8471) + 1.076 fallos en spraying",
        "IOA-01, IOA-02, IOA-03, IOA-06, IOA-08",
        "Alta",
        HALLAZGOS["CAMP-2026-004"],
    ),
    (
        "CAMP-2026-002",
        "07-oct 13:00",
        "30 sesiones SSH exitosas y 2.970 transferencias interrumpidas en 1 h",
        "IOA-04, IOA-09",
        "Alta",
        HALLAZGOS["CAMP-2026-002"],
    ),
    (
        "CAMP-2026-003",
        "10-oct 00:00",
        "2.000 intentos negados por Telnet 23/tcp ↔ 2.000 accesos fallidos en sistema médico",
        "IOA-01, IOA-03",
        "Alta",
        HALLAZGOS["CAMP-2026-003"],
    ),
]

TABLA_IOC = [
    ("186.46.219[.]18:8443", "IP:puerto destino", "Exfiltración 001 (sintético)", "Bloquear", "AMBER"),
    ("10.10.100.10, .20, .40, .50", "IP origen interna", "Equipos de las campañas", "Aislar o revisar", "AMBER"),
    ("10.10.100.30", "Activo crítico", "Servidor del sistema médico", "Proteger o monitorear", "AMBER"),
    ("16 cuentas ACC-…", "Cuenta técnica seudonimizada", "Abuso o compromiso", "Suspender o rotar", "AMBER"),
]

CATALOGO_IOA = [
    ("IOA-01", "Ráfaga de conexiones negadas", "≥ 100 conexiones negadas mismo puerto/hora", "Detecta CAMP-2026-003 y 004"),
    ("IOA-02", "Escaneo de servicios críticos", "≥ 4 puertos críticos distintos/hora (137, 445, 3389, 8471)", "Detecta CAMP-2026-004"),
    ("IOA-03", "Fuerza bruta contra una cuenta", "≥ 50 accesos fallidos por cuenta/hora", "Detecta CAMP-2026-003 y 004"),
    ("IOA-04", "Transferencias masivas interrumpidas", "≥ 50 transferencias interrumpidas/hora (typo TRANFERENCIA)", "Detecta CAMP-2026-002"),
    ("IOA-05", "Salida de datos hacia IP externa", "SSH → ingreso + descarga + egreso externo ≤ 600 s (+12 h)", "Detecta CAMP-2026-001"),
    ("IOA-06", "Cuenta usada por varias identidades", "> 3 identidades distintas operando una cuenta (máx. 1.737)", "Detecta CAMP-2026-004 y 005"),
    ("IOA-07", "Abuso de privilegios administrativos", "≥ 100 operaciones admin y ratio ≥ 0,90", "Detecta CAMP-2026-005"),
    ("IOA-08", "Registros con IP malformada", "Detección de IP sin puntos (^10\\d{9}$) en eventos admin", "Detecta CAMP-2026-004 y 005"),
    ("IOA-09", "Sesiones SSH masivas", "≥ 10 conexiones SSH por IP origen/hora", "Detecta CAMP-2026-002"),
]

TABLA_ANTICIPACION = [
    ("Riesgo previo por cuenta", "Cuenta de CAMP-2026-004 en riesgo CRÍTICO 16 días antes; las de CAMP-2026-005, desde el día 1."),
    ("Alerta temprana", "CAMP-2026-001, 002, 003 y 004 alertadas en la misma hora; solo 2 falsas alarmas en 744 h."),
    ("Siguiente fase", "Acierta 4/5 en su Top-3 de transición, con un control recomendado por fase."),
    ("Velocidad del ataque", "Caso 001: 30 s del SSH a la exfiltración → la contención debe ser automática."),
]

BRECHAS_LIMITACIONES = [
    "No se conoce el volumen ni el contenido específico de la descarga registrada el 24-oct.",
    "El vínculo CAMP-2026-005 → CAMP-2026-001 se mantiene como posible, no probable (baja-media confianza).",
    "No existe atribución confirmada a un actor o persona concreta sin autorización Break-Glass y cotejo de Talento Humano.",
    "Los datos pertenecen a un ejercicio sintético; todos los umbrales deben recalibrarse sobre telemetría productiva real.",
    "Las cuentas de CAMP-2026-001, 002 y 003 no tenían historial previo para anticipar el ataque (se detectaron en la misma hora).",
]

# Señales de que un escenario IPE está empezando (salen de las reglas propias, no de supuestos).
SENALES_ESCENARIO = {
    "Más probable": "Una cuenta especial operada por más de 3 usuarios (IOA-06) o una ráfaga de accesos fallidos sobre una cuenta (IOA-03).",
    "Más peligroso": "Descarga clínica seguida de conexión externa en menos de 600 s (IOA-05) o 50 o más transferencias interrumpidas en una hora (IOA-04).",
}

TEXTO = {
    "resumen": JUICIO_CLAVE,
    "metodologia": (
        "Se aplicó el ciclo CTI, comparación IPE de cursos de acción, Modelo Diamante por campaña, "
        "aprendizaje no supervisado local (Isolation Forest sin reglas) y reglas Sigma IoA/IoC. "
        "El equipo de ingeniería de datos registró huellas SHA-256 de ingesta y seudonimizó identificadores "
        "con HMAC-SHA256 truncado a 12 caracteres hexadecimales. Las huellas criptográficas completas figuran en el Anexo A."
    ),
    "admiralty": (
        "La escala Admiralty evalúa la fiabilidad de la fuente y la credibilidad de la información por fuente (ver tabla superior), "
        "no por campaña. Se ponderaron BOM UTF-8, errata TRANFERENCIA, IP sin puntos y desfase de 12 h."
    ),
    "adversarios": "Caracterización por campaña bajo Modelo Diamante (actor, capacidad, infraestructura, víctima y motivación probable).",
    "impacto": MARCO_LEGAL,
    "comportamiento_observable": "Patrones de comportamiento generalizables (IOA-01 a IOA-09) para detección independiente de direcciones IP.",
    "indicador_compromiso": "Indicadores puntuales de contención inmediata (TLP:AMBER) derivados del análisis del periodo.",
    "alcance_ipe": "Escenarios globales del adversario (IPE) y señales que indican que cada uno está empezando.",
    "controles": [
        ("Inmediato (hoy)", "Bloquear egreso hacia 186.46.219[.]18:8443 y salidas no autorizadas; suspender las 16 cuentas especiales; desactivar Telnet 23 y SMBv1 445; preservar evidencias e iniciar evaluación LOPDP art. 43 (máx. 5 días)."),
        ("Corto plazo (48 h – 1 sem.)", "Aislar 10.10.100.20, restringir 10.10.100.30 a bastión con MFA y cuentas nominales, migrar servicios 8470–8476 a TLS 9470–9476 y homologar registro horario local institucional."),
        ("Mediano plazo", "Desplegar las 10 reglas Sigma en SIEM, automatizar respuesta para ataques menores a 30 s, cargar los 82 objetos STIX 2.1 en MISP y auditar la cadena SHA-256."),
    ],
    "nota_mapa_calor": "Hora local del registro. Los picos corresponden a CAMP-2026-002 (7-oct 13 h), CAMP-2026-003 (10-oct 00 h) y CAMP-2026-004 (19-oct 14 h).",
}
