"""Consecuencias de cada compromiso: qué puede hacer el atacante con lo que obtuvo.

Regla de este catálogo: cada consecuencia tiene un caso real y público que demuestra
que ya ocurrió, con su fuente. No se incluyen suposiciones sin precedente.
Se usa en los dos reportes PDF y en la API (/api/v1/consequences).
No contiene nombres de víctimas ni de personas investigadas.
"""

import re

# --- Casos reales verificables --------------------------------------------------
CASOS = {
    "vastaamo": {
        "nombre": "Vastaamo (Finlandia, 2020)",
        "dato_simple": "unas 22.000 personas recibieron amenazas de extorsión",
        "hecho": (
            "Robaron la base de una clínica de psicoterapia. Al no pagar la clínica, el atacante "
            "escribió a cada paciente exigiendo dinero para no publicar sus notas de terapia; "
            "unas 22.000 víctimas denunciaron la extorsión."
        ),
        "fuente": "Krebs on Security, 30-abr-2024",
        "url": "https://krebsonsecurity.com/2024/04/man-who-mass-extorted-psychotherapy-patients-gets-six-years/",
    },
    "medibank": {
        "nombre": "Medibank (Australia, 2022)",
        "dato_simple": "se publicaron listas de abortos y tratamientos de salud mental",
        "hecho": (
            "Robaron datos de 9,7 millones de clientes de una aseguradora de salud y, al no recibir "
            "el rescate, publicaron datos de procedimientos como abortos y tratamientos de salud mental."
        ),
        "fuente": "SBS News, nov-2022",
        "url": "https://www.sbs.com.au/news/article/we-can-make-discount-new-details-on-medibank-ransom-emerge-as-suspected-hackers-release-more-data/acp4ilp36",
    },
    "ftc_identidad_medica": {
        "nombre": "Robo de identidad médica (FTC, EE.UU.)",
        "dato_simple": "la historia clínica de la víctima queda mezclada con la del ladrón",
        "hecho": (
            "Con los datos de un paciente, otra persona obtiene atención, medicinas o beneficios a su "
            "nombre; su historia clínica queda mezclada con la del ladrón y eso afecta su atención."
        ),
        "fuente": "Comisión Federal de Comercio de EE.UU. (FTC)",
        "url": "https://consumer.ftc.gov/articles/what-know-about-medical-identity-theft",
    },
    "iess_prestamos_2024": {
        "nombre": "Préstamos fraudulentos a jubilados (Ecuador, 2024)",
        "dato_simple": "préstamos de hasta USD 30.000 que los jubilados nunca pidieron",
        "hecho": (
            "A afiliados jubilados les cambiaron el celular, el correo y la cuenta bancaria en el sistema "
            "y obtuvieron préstamos a su nombre de hasta USD 30.000; se lo descontaban de la pensión. "
            "La institución denunció el caso y se investigó a funcionarios."
        ),
        "fuente": "Primicias y Diario Expreso, dic-2024",
        "url": "https://primicias.ec/sociedad/jubilados-denuncian-suplantacion-identidad-prestamos-quirografarios-guayaquil-85104",
    },
    "iess_cesantia": {
        "nombre": "Intento de retiro de cesantía (Ecuador)",
        "dato_simple": "intentaron retirar más de USD 40.000 de un afiliado",
        "hecho": (
            "Una persona suplantó la identidad de un afiliado para retirar más de USD 40.000 de su "
            "fondo de cesantía; el cruce automático de datos lo detectó y un juez dictó prisión preventiva."
        ),
        "fuente": "Diario Expreso",
        "url": "https://www.expreso.ec/actualidad/economia/prision-preventiva-por-intento-de-fraude-en-el-iess-buscaba-retirar-40-000-256612.html",
    },
    "change_healthcare": {
        "nombre": "Change Healthcare (EE.UU., 2024)",
        "dato_simple": "meses de interrupción y USD 22 millones de rescate",
        "hecho": (
            "Entraron con una clave robada a un acceso remoto sin doble verificación, se movieron por la "
            "red, copiaron datos y bloquearon los sistemas: meses de interrupción en pagos y farmacias "
            "y un rescate de USD 22 millones."
        ),
        "fuente": "TechCrunch y Dark Reading (testimonio ante el Congreso), abr-may 2024",
        "url": "https://techcrunch.com/2024/04/30/uhg-change-healthcare-ransomware-compromised-credentials-mfa",
    },
    "wannacry_nhs": {
        "nombre": "WannaCry en el NHS (Reino Unido, 2017)",
        "dato_simple": "unas 19.000 citas médicas canceladas",
        "hecho": (
            "Un programa malicioso se propagó por una falla de SMB en equipos sin actualizar: más de un "
            "tercio de los hospitales públicos (trusts) de Inglaterra afectados y unas 19.000 citas canceladas."
        ),
        "fuente": "National Audit Office (NAO), 2017",
        "url": "https://www.nao.org.uk/reports/investigation-wannacry-cyber-attack-and-the-nhs/",
    },
}

# --- Consecuencias por activo vulnerado ---------------------------------------------
CONSECUENCIAS = [
    {
        "id": "datos-salud",
        "activo": "Datos de salud de pacientes",
        "activo_simple": "Datos de salud de pacientes (la descarga del 24-oct)",
        "campanas": ["CAMP-2026-001", "CAMP-2026-002"],
        "reglas": ["IOA-04", "IOA-05"],
        "evidencia": "Descarga en el sistema médico y salida a 186.46.219[.]18:8443 en 30 s (CAMP-2026-001).",
        "consecuencias": [
            {
                "accion": "Extorsionar a cada paciente con su propio diagnóstico.",
                "accion_simple": "Extorsionar a cada paciente con su diagnóstico",
                "caso": "vastaamo",
            },
            {
                "accion": "Publicar diagnósticos sensibles (salud mental, abortos, adicciones) para presionar a la institución.",
                "accion_simple": "Publicar diagnósticos sensibles para presionar a la institución",
                "caso": "medibank",
            },
            {
                "accion": "Usar la identidad del paciente para obtener atención, medicinas o beneficios a su nombre.",
                "accion_simple": "Atenderse o sacar medicinas a nombre del paciente",
                "caso": "ftc_identidad_medica",
            },
        ],
        "control": "Bloquear el egreso no autorizado, DLP sobre descargas clínicas y contención automática de IOA-05.",
        "control_simple": "Bloquear salidas no autorizadas a internet",
        "obligacion": "LOPDP art. 43: notificar a la Superintendencia de Protección de Datos Personales en máximo 5 días.",
    },
    {
        "id": "cuentas-privilegiadas",
        "activo": "Cuentas administrativas compartidas",
        "activo_simple": "Cuentas administrativas compartidas",
        "campanas": ["CAMP-2026-005"],
        "reglas": ["IOA-06", "IOA-07", "GUARD-04"],
        "evidencia": "11 cuentas usadas por hasta 1.737 usuarios; 131 cambios de nivel, 1.098 activaciones y 826 reactivaciones.",
        "consecuencias": [
            {
                "accion": (
                    "Cambiar celular, correo y cuenta bancaria de afiliados y sacar préstamos a su nombre; "
                    "con cuentas compartidas no se puede probar quién lo hizo."
                ),
                "accion_simple": "Cambiar los datos de afiliados y sacar préstamos a su nombre, sin que se sepa quién fue",
                "caso": "iess_prestamos_2024",
            },
        ],
        "control": "Suspender las cuentas compartidas, cuentas nominales con MFA y doble aprobación para cambios de cuenta bancaria.",
        "control_simple": "Una cuenta personal por funcionario, con doble verificación",
        "obligacion": None,
    },
    {
        "id": "credenciales",
        "activo": "Claves de cuentas técnicas",
        "activo_simple": "Claves de acceso (intentos de adivinarlas)",
        "campanas": ["CAMP-2026-003", "CAMP-2026-004"],
        "reglas": ["IOA-01", "IOA-03"],
        "evidencia": "2.000 intentos de fuerza bruta por Telnet (CAMP-2026-003) y 1.076 fallos de spraying (CAMP-2026-004).",
        "consecuencias": [
            {
                "accion": "Entrar con una clave robada, moverse por la red, copiar datos y cifrar los sistemas para pedir rescate.",
                "accion_simple": "Entrar con una clave robada, copiar datos y bloquear los sistemas a cambio de un rescate",
                "caso": "change_healthcare",
            },
        ],
        "control": "MFA en todo acceso remoto, desactivar Telnet 23 y bloqueo por intentos fallidos (IOA-03).",
        "control_simple": "Doble verificación en todo acceso remoto",
        "obligacion": None,
    },
    {
        "id": "servicios-expuestos",
        "activo": "Servicios antiguos expuestos en la red interna",
        "activo_simple": "Equipos con servicios antiguos abiertos (escaneo del 19-oct)",
        "campanas": ["CAMP-2026-004"],
        "reglas": ["IOA-02"],
        "evidencia": "Escaneo de SMBv1 445, RDP 3389, NetBIOS 137 y base de datos 8471 desde 10.10.100.20.",
        "consecuencias": [
            {
                "accion": "Propagar un programa malicioso por SMB de equipo en equipo y paralizar la atención.",
                "accion_simple": "Un programa malicioso se copia solo de equipo en equipo y detiene la atención",
                "caso": "wannacry_nhs",
            },
        ],
        "control": "Cerrar SMBv1, RDP solo por bastión y segmentar la red clínica.",
        "control_simple": "Cerrar los servicios antiguos y separar la red clínica",
        "obligacion": None,
    },
    {
        "id": "identidad-afiliado",
        "activo": "Identidad y datos de contacto de afiliados",
        "activo_simple": "Identidad y datos de contacto de afiliados",
        "campanas": [],
        "reglas": ["GUARD-01", "GUARD-02", "GUARD-03", "CENTINELA"],
        "evidencia": "Piloto Guardián: cambio de contacto + cambio de cuenta bancaria + préstamo en 40 minutos.",
        "consecuencias": [
            {
                "accion": "Tomar la cuenta del afiliado y sacar préstamos que se le descuentan de su pensión.",
                "accion_simple": "Tomar la cuenta del afiliado y sacar préstamos a su nombre",
                "caso": "iess_prestamos_2024",
            },
            {
                "accion": "Suplantar al afiliado para retirar sus fondos (por ejemplo, la cesantía).",
                "accion_simple": "Retirar los fondos del afiliado suplantándolo",
                "caso": "iess_cesantia",
            },
        ],
        "control": "Guardián: retener la operación y confirmar con el afiliado por su canal anterior.",
        "control_simple": "Retener la operación y confirmar con el afiliado por su contacto anterior",
        "obligacion": None,
    },
]

ORDEN_EJECUTIVO = ("datos-salud", "cuentas-privilegiadas", "credenciales", "servicios-expuestos")
PATRON_CODIGO = re.compile(r"^(CAMP-2026-00[1-5]|IOA-0[1-9]|GUARD-0[1-4]|CENTINELA|CEN-\d{3})$")


def _con_caso(item: dict) -> dict:
    caso = CASOS[item["caso"]]
    return {**item, "caso_nombre": caso["nombre"], "caso_hecho": caso["hecho"],
            "caso_dato_simple": caso["dato_simple"], "fuente": caso["fuente"], "url": caso["url"]}


def consecuencias_por_codigo(codigo: str) -> list[dict]:
    """Devuelve las consecuencias de una campaña (CAMP-…), regla (IOA-…, GUARD-…) o campaña de Centinela (CEN-…)."""
    if not PATRON_CODIGO.match(codigo):
        raise ValueError("Código no reconocido.")
    clave = "CENTINELA" if codigo.startswith("CEN-") else codigo
    encontrados = []
    for grupo in CONSECUENCIAS:
        if clave in grupo["campanas"] or clave in grupo["reglas"]:
            encontrados.append({**grupo, "consecuencias": [_con_caso(c) for c in grupo["consecuencias"]]})
    return encontrados


def catalogo_completo() -> list[dict]:
    return [{**g, "consecuencias": [_con_caso(c) for c in g["consecuencias"]]} for g in CONSECUENCIAS]


def filas_tecnico() -> list[dict]:
    """Filas para la sección 3.1 del reporte técnico (todas las campañas de AegisHealth)."""
    return [g for g in catalogo_completo() if g["campanas"]]


def filas_ejecutivo() -> list[dict]:
    """Filas en lenguaje simple para el informe de Dirección Médica."""
    por_id = {g["id"]: g for g in catalogo_completo()}
    return [por_id[i] for i in ORDEN_EJECUTIVO]


def fuentes_usadas(grupos: list[dict]) -> list[tuple[str, str, str]]:
    vistos, salida = set(), []
    for g in grupos:
        for c in g["consecuencias"]:
            if c["caso"] not in vistos:
                vistos.add(c["caso"])
                salida.append((c["caso_nombre"], c["fuente"], c["url"]))
    return salida
