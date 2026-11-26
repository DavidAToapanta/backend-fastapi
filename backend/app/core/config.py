"""
Configuración centralizada de AegisHealth-CTI cargada estrictamente desde .env.
Valida rutas de origen, parámetros de PostgreSQL 16 y robustez de la clave HMAC.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Raíz del repositorio calculada de forma determinística respecto a este archivo
PROJECT_ROOT = Path(__file__).resolve().parents[3]
ENV_FILE_PATH = PROJECT_ROOT / ".env"

_CLAVES_PLACEHOLDER = {
    "generar_clave_hex_64_chars",
    "changeme",
    "secret",
}


class Settings(BaseSettings):
    """Parámetros de entorno tipados y validados para el pipeline ETL y la base de datos."""

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE_PATH),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    POSTGRES_HOST: str = Field(default="127.0.0.1")
    POSTGRES_PORT: int = Field(default=5433, ge=1, le=65535)
    POSTGRES_DB: str = Field(default="aegis_cti")
    POSTGRES_USER: str = Field(default="aegis_admin")
    POSTGRES_PASSWORD: str = Field(default="cambiar_clave_segura")
    POSTGRES_APP_USER: str = Field(default="aegis_app")
    POSTGRES_APP_PASSWORD: str = Field(default="cambiar_clave_app")

    PSEUDONYMIZATION_KEY: str = Field(...)
    FW_CSV_PATH: str = Field(default="data/raw/Registros_conexiones_FW_10_2026.csv")
    IESS_CSV_PATH: str = Field(default="data/raw/Registros_conexiones_sist_med_iess.csv")

    @field_validator("PSEUDONYMIZATION_KEY")
    @classmethod
    def validar_clave_seudonimizacion(cls, valor: str) -> str:
        """Exige una clave HMAC no genérica de al menos 16 caracteres efectivos."""
        limpia = valor.strip()
        if len(limpia) < 16:
            raise ValueError(
                "PSEUDONYMIZATION_KEY debe tener al menos 16 caracteres para cumplir LOPDP."
            )
        if limpia.lower() in _CLAVES_PLACEHOLDER:
            raise ValueError(
                "PSEUDONYMIZATION_KEY no puede usar un valor de ejemplo o placeholder."
            )
        return limpia

    def resolver_ruta_csv(self, ruta_configurada: str) -> Path:
        """Resuelve una ruta absoluta o relativa respecto a la raíz del proyecto."""
        ruta = Path(ruta_configurada)
        if ruta.is_absolute():
            return ruta
        return (PROJECT_ROOT / ruta).resolve()

    @property
    def fw_csv_absoluto(self) -> Path:
        """Ruta absoluta al archivo CSV de eventos del Firewall."""
        return self.resolver_ruta_csv(self.FW_CSV_PATH)

    @property
    def iess_csv_absoluto(self) -> Path:
        """Ruta absoluta al archivo CSV de eventos del Sistema Médico."""
        return self.resolver_ruta_csv(self.IESS_CSV_PATH)

    @property
    def dsn_admin(self) -> str:
        """Cadena de conexión PostgreSQL con privilegios administrativos de carga."""
        return (
            f"host={self.POSTGRES_HOST} "
            f"port={self.POSTGRES_PORT} "
            f"dbname={self.POSTGRES_DB} "
            f"user={self.POSTGRES_USER} "
            f"password={self.POSTGRES_PASSWORD}"
        )

    @property
    def dsn_app(self) -> str:
        """Cadena de conexión PostgreSQL restringida para la aplicación (solo INSERT/SELECT en auditoría)."""
        return (
            f"host={self.POSTGRES_HOST} "
            f"port={self.POSTGRES_PORT} "
            f"dbname={self.POSTGRES_DB} "
            f"user={self.POSTGRES_APP_USER} "
            f"password={self.POSTGRES_APP_PASSWORD}"
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Devuelve la instancia singleton cacheada de configuración."""
    return Settings()
