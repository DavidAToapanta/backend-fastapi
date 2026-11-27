"""
Primitivas de privacidad LOPDP (Art. 25), normalización de identidades,
validación estricta de IPs sin puntos y bitácora de auditoría con hash encadenado.
"""

import hashlib
import hmac
import ipaddress
import json
import re
import unicodedata
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from psycopg.types.json import Jsonb

PARTICULAS = {
    "de",
    "del",
    "la",
    "las",
    "los",
    "san",
    "santa",
    "da",
    "di",
    "van",
    "von",
    "y",
}

_PATRON_IP_SIN_PUNTOS = re.compile(r"^10(\d{3})(\d{3})(\d{3})$")


def normalizar_texto(texto: str) -> str:
    """Elimina tildes mediante NFKD, normaliza espacios y convierte a minúsculas ASCII."""
    if not texto:
        return ""
    depurado = (
        unicodedata.normalize("NFKD", str(texto))
        .encode("ascii", "ignore")
        .decode("ascii")
    )
    return " ".join(depurado.lower().split())


def separar_apellidos_y_nombres(nombre_completo: str) -> tuple[list[str], list[str]]:
    """
    Separa apellidos compuestos y nombres con respaldo obligatorio para entradas
    de dos palabras, evitando listas de nombres vacías.
    """
    tokens = normalizar_texto(nombre_completo).split()
    apellidos: list[str] = []
    i = 0
    while len(apellidos) < 2 and i < len(tokens):
        actual: list[str] = []
        while i < len(tokens) and tokens[i] in PARTICULAS:
            actual.append(tokens[i])
            i += 1
        if i < len(tokens):
            actual.append(tokens[i])
            i += 1
        if actual:
            apellidos.append(" ".join(actual))

    nombres = tokens[i:]
    # Respaldo obligatorio: evita nombres vacíos ante formatos de 2 tokens ("GOMEZ JUAN")
    if not nombres and len(apellidos) == 2:
        nombres = [apellidos.pop()]
    elif not nombres and len(apellidos) == 1:
        nombres = [apellidos[0]]
    return apellidos, nombres


def derivar_canonico_fw(nombre_completo: str) -> str:
    """
    Convierte un nombre completo formato MedSys (APELLIDOS NOMBRES) al formato
    canónico del Firewall ('nombre1.apellido1' sin espacios en apellido compuesto).
    """
    apellidos, nombres = separar_apellidos_y_nombres(nombre_completo)
    if not apellidos or not nombres:
        return ""
    primer_nombre = nombres[0].replace(" ", "")
    primer_apellido = apellidos[0].replace(" ", "")
    return f"{primer_nombre}.{primer_apellido}"


def generar_token_hmac(valor: str, clave: str, prefijo: str) -> str:
    """Genera un seudónimo determinístico HMAC-SHA256 truncado a 12 caracteres hexadecimales."""
    valor_limpio = str(valor).strip() if valor is not None else ""
    if not valor_limpio:
        return f"{prefijo}-DESCONOCIDO"
    digest = (
        hmac.new(
            clave.encode("utf-8"),
            valor_limpio.encode("utf-8"),
            hashlib.sha256,
        )
        .hexdigest()[:12]
        .upper()
    )
    return f"{prefijo}-{digest}"


def construir_mapa_hmac_unicos(
    valores_unicos: Iterable[str],
    clave: str,
    prefijo: str,
) -> dict[str, str]:
    """
    Calcula tokens HMAC-SHA256 exclusivamente sobre el conjunto deduplicado de
    entradas para mapear millones de filas de forma vectorizada en Polars.
    """
    unicos = set(valores_unicos)
    return {
        valor: generar_token_hmac(valor, clave=clave, prefijo=prefijo)
        for valor in unicos
    }


def detectar_colisiones_canonicas(
    nombres_completos_unicos: Iterable[str],
) -> tuple[dict[str, str], set[str], dict[str, int]]:
    """
    Mapea cada nombre completo único hacia su identificador canónico 'nombre1.apellido1'
    y detecta colisiones donde más de una persona normalizada comparte el mismo canónico.
    """
    mapa_canonico: dict[str, str] = {}
    nombres_por_canonico: dict[str, set[str]] = {}

    for nombre_raw in nombres_completos_unicos:
        canonico = derivar_canonico_fw(nombre_raw)
        mapa_canonico[nombre_raw] = canonico
        nombre_norm = normalizar_texto(nombre_raw)
        if canonico:
            nombres_por_canonico.setdefault(canonico, set()).add(nombre_norm)

    conteos_por_canonico = {
        canonico: len(distintos)
        for canonico, distintos in nombres_por_canonico.items()
    }
    canonicos_ambiguos = {
        canonico for canonico, total in conteos_por_canonico.items() if total > 1
    }
    return mapa_canonico, canonicos_ambiguos, conteos_por_canonico


def validar_y_reparar_ip_sin_puntos(ip_str: str) -> tuple[str | None, bool, bool]:
    """
    Valida IPs IPv4 y repara cadenas sin puntos con patrón '^10\\d{9}$' exigiendo
    estrictamente que los tres octetos reconstruidos cumplan 100 <= octeto <= 255.

    Retorna: (ip_limpia, was_dotless_ip, ip_reparable).
    """
    valor = str(ip_str).strip() if ip_str is not None else ""
    if not valor:
        return None, False, False

    coincidencia = _PATRON_IP_SIN_PUNTOS.match(valor)
    if coincidencia:
        octetos = [int(bloque) for bloque in coincidencia.groups()]
        if all(100 <= octeto <= 255 for octeto in octetos):
            ip_reconstruida = f"10.{octetos[0]}.{octetos[1]}.{octetos[2]}"
            return ip_reconstruida, True, True
        return None, True, False

    try:
        ip_obj = ipaddress.IPv4Address(valor)
        return str(ip_obj), False, True
    except ipaddress.AddressValueError:
        return None, False, False


def es_ip_externa_publica(ip_limpia: str | None) -> bool:
    """Determina si una dirección IPv4 válida corresponde a espacio público enrutable."""
    if not ip_limpia:
        return False
    try:
        ip_obj = ipaddress.IPv4Address(ip_limpia)
    except ipaddress.AddressValueError:
        return False
    return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)


def calcular_sha256_archivo(ruta: str | Path) -> str:
    """Calcula el resumen criptográfico SHA-256 leyendo el archivo en bloques de 64 KiB."""
    hasher = hashlib.sha256()
    with Path(ruta).open("rb") as archivo:
        while bloque := archivo.read(65536):
            hasher.update(bloque)
    return hasher.hexdigest()


def _construir_payload_auditoria(
    operation: str,
    dataset_name: str,
    dataset_sha256: str,
    total_rows_read: int,
    rows_persisted: int,
    pii_scrubbed: bool,
    metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    """Construye la estructura canónica usada tanto para registrar como para verificar."""
    return {
        "operation": operation,
        "dataset_name": dataset_name,
        "dataset_sha256": dataset_sha256,
        "total_rows_read": int(total_rows_read),
        "rows_persisted": int(rows_persisted),
        "pii_scrubbed": bool(pii_scrubbed),
        "metadata": metadata or {},
    }


def calcular_hash_encadenado(prev_hash: str, payload: dict[str, Any]) -> str:
    """Calcula el SHA-256 encadenado sobre la serialización JSON canónica ordenada."""
    canonico = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(f"{prev_hash}|{canonico}".encode("utf-8")).hexdigest()


def registrar_evento_auditoria(
    conn: Any,
    operation: str,
    dataset_name: str,
    dataset_sha256: str,
    total_rows_read: int,
    rows_persisted: int,
    pii_scrubbed: bool = True,
    metadata: dict[str, Any] | None = None,
) -> tuple[int, str]:
    """
    Inserta un evento inmutable en cti_audit.audit_events encadenado al último
    row_hash existente (o 'GENESIS' si la bitácora está vacía).
    """
    meta_normalizada = metadata or {}
    payload = _construir_payload_auditoria(
        operation=operation,
        dataset_name=dataset_name,
        dataset_sha256=dataset_sha256,
        total_rows_read=total_rows_read,
        rows_persisted=rows_persisted,
        pii_scrubbed=pii_scrubbed,
        metadata=meta_normalizada,
    )

    with conn.transaction(), conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock('cti_audit.audit_events'::regclass::oid::bigint)")
        cur.execute(
            "SELECT row_hash FROM cti_audit.audit_events ORDER BY audit_id DESC LIMIT 1"
        )
        ultimo = cur.fetchone()
        prev_hash = ultimo[0] if ultimo else "GENESIS"
        row_hash = calcular_hash_encadenado(prev_hash, payload)

        cur.execute(
            """
            INSERT INTO cti_audit.audit_events (
                operation,
                dataset_name,
                dataset_sha256,
                total_rows_read,
                rows_persisted,
                pii_scrubbed,
                metadata,
                prev_hash,
                row_hash
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING audit_id
            """,
            (
                operation,
                dataset_name,
                dataset_sha256,
                total_rows_read,
                rows_persisted,
                pii_scrubbed,
                Jsonb(meta_normalizada),
                prev_hash,
                row_hash,
            ),
        )
        audit_id = cur.fetchone()[0]
    return int(audit_id), row_hash


def verificar_cadena_auditoria(conn: Any) -> dict[str, Any]:
    """
    Recorre íntegramente cti_audit.audit_events en orden de audit_id y valida
    tanto la continuidad de prev_hash como el recálculo exacto de cada row_hash.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                audit_id,
                operation,
                dataset_name,
                dataset_sha256,
                total_rows_read,
                rows_persisted,
                pii_scrubbed,
                metadata,
                prev_hash,
                row_hash
            FROM cti_audit.audit_events
            ORDER BY audit_id ASC
            """
        )
        filas = cur.fetchall()

    esperado_prev = "GENESIS"
    errores: list[dict[str, Any]] = []

    for fila in filas:
        (
            audit_id,
            operation,
            dataset_name,
            dataset_sha256,
            total_rows_read,
            rows_persisted,
            pii_scrubbed,
            metadata,
            prev_hash,
            row_hash,
        ) = fila

        if prev_hash != esperado_prev:
            errores.append(
                {
                    "audit_id": audit_id,
                    "motivo": "prev_hash discontinuo",
                    "esperado": esperado_prev,
                    "observado": prev_hash,
                }
            )

        payload = _construir_payload_auditoria(
            operation=operation,
            dataset_name=dataset_name,
            dataset_sha256=dataset_sha256,
            total_rows_read=total_rows_read,
            rows_persisted=rows_persisted,
            pii_scrubbed=pii_scrubbed,
            metadata=metadata if isinstance(metadata, dict) else {},
        )
        hash_recalculado = calcular_hash_encadenado(prev_hash, payload)
        if hash_recalculado != row_hash:
            errores.append(
                {
                    "audit_id": audit_id,
                    "motivo": "row_hash alterado",
                    "esperado": hash_recalculado,
                    "observado": row_hash,
                }
            )

        esperado_prev = row_hash

    return {
        "intact": len(errores) == 0,
        "checked_rows": len(filas),
        "errores": errores,
    }


def resumir_distribucion_palabras(nombres: Iterable[str]) -> dict[int, int]:
    """Cuenta la distribución de longitud en tokens normalizados (sin exponer nombres)."""
    contador = Counter(len(normalizar_texto(nombre).split()) for nombre in nombres)
    return dict(sorted(contador.items()))
