from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    log_level: str = "INFO"
    secret_key: str = "dev-secret-change-me"

    database_url: str = "postgresql+asyncpg://vulnvista:vulnvista@postgres:5432/vulnvista"

    backend_cors_origins: str = "http://localhost:5173"
    backend_storage_dir: str = "/data/uploads"

    zap_api_url: str = "http://zap:8080"
    zap_api_key: str = "vulnvista-dev-key"

    # Default-deny allowlist: a target is only auto-approved for scanning when
    # its host is one of these known lab hosts. This keeps the platform from
    # ever pointing its active detectors at something it wasn't meant to.
    lab_allowed_hosts: str = (
        "dvwa,juice-shop,vulnvista_dvwa,vulnvista_juice_shop,localhost,127.0.0.1"
    )

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.backend_cors_origins.split(",") if origin.strip()]

    @property
    def allowed_hosts(self) -> list[str]:
        return [host.strip().lower() for host in self.lab_allowed_hosts.split(",") if host.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
