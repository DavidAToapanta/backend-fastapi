import hashlib
import hmac
import json
import os
import re

import psycopg
from psycopg.conninfo import conninfo_to_dict

from app.core.conexion_postgres import conectar_postgres
from app.servicios.auditoria import AuditoriaNoDisponible
from backend.app.core.security import registrar_evento_auditoria


class CredencialesInvestigacionInvalidas(Exception):
    """La clave no autoriza al analista."""


class CuentaTecnicaNoEncontrada(Exception):
    """El token no se encuentra en la bóveda."""


def autorizar_analista(
    analista: str, clave: str | None, *, variable: str = "BREAK_GLASS_ANALYST_KEYS_JSON",
) -> None:
    if not clave:
        raise CredencialesInvestigacionInvalidas

    try:
        huellas = json.loads(os.getenv(variable, ""))
    except ValueError as error:
        raise AuditoriaNoDisponible from error

    if not isinstance(huellas, dict) or not huellas or not all(
        isinstance(huella, str) and re.fullmatch(r"[A-Fa-f0-9]{64}", huella)
        for huella in huellas.values()
    ):
        raise AuditoriaNoDisponible

    esperada = huellas.get(analista)
    calculada = hashlib.sha256(clave.encode("utf-8")).hexdigest()
    coincide = hmac.compare_digest(calculada, esperada.lower() if esperada else "0" * 64)
    if esperada is None or not coincide:
        raise CredencialesInvestigacionInvalidas


def revelar_cuenta(analista: str, clave: str | None, motivo: str, token: str) -> tuple[str, int]:
    autorizar_analista(analista, clave)
    dsn = os.getenv("BREAK_GLASS_DATABASE_URL", "").strip()

    try:
        if not dsn or conninfo_to_dict(dsn).get("user") != "aegis_break_glass":
            raise AuditoriaNoDisponible

        with psycopg.connect(
            dsn,
            connect_timeout=2,
            options="-c default_transaction_read_only=on -c statement_timeout=1000",
            autocommit=True,
        ) as boveda:
            fila = boveda.execute(
                "SELECT system_account_id FROM cti_core.account_vault WHERE account_token = %s",
                (token,),
            ).fetchone()

        if fila is None:
            raise CuentaTecnicaNoEncontrada

        with conectar_postgres() as bitacora, bitacora.transaction():
            audit_id, _ = registrar_evento_auditoria(
                bitacora,
                operation="BREAK_GLASS_REVEAL",
                dataset_name="account_vault",
                dataset_sha256="",
                total_rows_read=1,
                rows_persisted=0,
                metadata={"analystId": analista, "reason": motivo, "accountToken": token},
            )
    except (psycopg.Error, ValueError) as error:
        raise AuditoriaNoDisponible from error

    return fila[0], audit_id
